#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readFile, stat } from "node:fs/promises";
import { parseArgs } from "node:util";
import {
  DEFAULT_MAX_INPUT_LENGTH,
  ScrappyError,
  createPatternDetector,
  defaultDetectors,
  domainDetector,
  ipAddressDetector,
  sanitize,
  sanitizeJson,
  type Detector,
  type SdkOptions,
  type SensitiveType,
} from "@scrappy/sdk";
import { systemClipboard } from "./clipboard.ts";
import { inputReader, terminalFallback } from "./terminal.ts";
import { CliError } from "./errors.ts";
import { readSettings, settingsPath, writeSettings, type Settings } from "./settings.ts";
import { checkForUpdate, npmLatest } from "./update.ts";
import { destination, runSession, summarize } from "./session.ts";

const HELP = `scrappy: strip secrets and personal data from text before it goes to an AI tool.
Runs locally; nothing leaves your machine.

Usage
  scrappy sanitize [--input <file> | --clipboard] [--format text|json] [--config <file>] [--ip] [--domains]
  scrappy inspect  [--input <file> | --clipboard] [--format text|json] [--config <file>] [--ip] [--domains]
  scrappy session  [--config <file>] [--ip] [--domains]
  scrappy config   [--global --enable-<setting> | --disable-<setting>]   settings: ip-masking, domain-masking, update-check
  scrappy help

Commands
  sanitize   Replace sensitive values with placeholders like [EMAIL_1]; prints the result.
             With --clipboard, the result goes back to the clipboard instead.
  inspect    Report what was found (types, offsets, placeholders; never the values) as JSON.
  session    Interactive clipboard round trip. Keys: s = sanitize the clipboard,
             r = restore originals in the AI's reply, q = quit. Originals stay in memory
             only and are discarded when you quit.
  config     Show saved settings, or change them with --global.
  help       Show this page.

Options
  -i, --input <file>        Read a file instead of stdin. The file is never modified.
      --clipboard           Read the clipboard. Works everywhere: uses pbpaste, wl-clipboard, xclip, xsel or
                            the Windows clipboard; with none of them, asks you to paste into the terminal.
  -f, --format <fmt>        "text" (default) or "json": sanitizes JSON values and keys, keeps structure.
  -c, --config <file>       JSON config with "policy" and "customDetectors" (see the README).
      --ip                  Also mask IPv4/IPv6 addresses for this run (off by default).
      --domains             Also mask domain names such as db01.acme.internal for this run (off by default).
  -g, --global              With config: change a saved setting.
      --enable-ip-masking   With config --global: always mask IP addresses.
      --disable-ip-masking  With config --global: stop masking IP addresses by default.
      --enable-domain-masking
                            With config --global: always mask domain names.
      --disable-domain-masking
                            With config --global: stop masking domain names by default.
      --enable-update-check With config --global: check npm once a day for a newer version (default).
      --disable-update-check
                            With config --global: never check. SCRAPPY_NO_UPDATE_CHECK=1 also turns it off.
  -v, --version             Print the version.
  -h, --help                Show this page.

Examples
  scrappy sanitize --clipboard                 copy text, run this, then paste into your AI tool
  cat app.log | scrappy sanitize > safe.log    clean a log file
  scrappy inspect -i app.log                   see what would be replaced
  scrappy sanitize --ip -i access.log          also mask IP addresses
  scrappy sanitize --domains -i notes.txt      also mask domain names
  scrappy config --global --enable-ip-masking  mask IPs in every run from now on

Update notice: once a day, on a terminal only, scrappy asks the npm registry for the latest version
number (nothing about your text is sent) and tells you when a newer one exists.

Exit codes: 0 success, 1 input/config/processing error, 2 invalid usage.
`;

// src/ and the bundled dist/ both sit one level below package.json.
const PKG = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { name: string; version: string };

/**
 * Starts the daily update check (terminal only, never in CI or when turned off) and returns a function
 * that prints the notice once the command is done. Only the package's public version number is fetched.
 */
function startUpdateCheck(settings: Settings): () => Promise<void> {
  const env = process.env;
  if (!process.stdout.isTTY || !process.stderr.isTTY || env.CI || env.SCRAPPY_NO_UPDATE_CHECK || !settings.updateCheck) return async () => {};
  const pending = checkForUpdate({
    current: PKG.version,
    cachePath: join(dirname(settingsPath()), "update-check.json"),
    fetchLatest: npmLatest(PKG.name, env.SCRAPPY_REGISTRY_URL),
  });
  return async () => {
    const latest = await pending;
    if (latest) process.stderr.write(`\nscrappy ${latest} is available (you have ${PKG.version}). Update: npm i -g ${PKG.name}@latest\n`);
  };
}

const usageError = (problem: string) => {
  process.stderr.write(`scrappy: ${problem}\nRun \`scrappy help\` to see all commands and options.\n`);
  return 2;
};

async function main(argv: string[]): Promise<number> {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        input: { type: "string", short: "i" },
        clipboard: { type: "boolean" },
        ip: { type: "boolean" },
        domains: { type: "boolean" },
        global: { type: "boolean", short: "g" },
        "enable-ip-masking": { type: "boolean" },
        "disable-ip-masking": { type: "boolean" },
        "enable-domain-masking": { type: "boolean" },
        "disable-domain-masking": { type: "boolean" },
        "enable-update-check": { type: "boolean" },
        "disable-update-check": { type: "boolean" },
        format: { type: "string", short: "f", default: "text" },
        config: { type: "string", short: "c" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (error) {
    return usageError((error as Error).message);
  }
  const { values, positionals } = args;
  if (values.version) {
    process.stdout.write(`${PKG.version}\n`);
    return 0;
  }
  const [command, ...extra] = positionals;
  if (values.help || command === "help" || command === undefined) {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === "config") return await configCommand(values, extra);
  const usageProblem =
    command !== "sanitize" && command !== "inspect" && command !== "session" ? "expected a command: sanitize, inspect or session"
    : extra.length > 0 ? `unexpected argument: ${extra[0]}`
    : values.global || values["enable-ip-masking"] || values["disable-ip-masking"] || values["enable-domain-masking"] || values["disable-domain-masking"] || values["enable-update-check"] || values["disable-update-check"]
      ? "--global and the --enable/--disable settings belong to `scrappy config`"
    : command === "session" && (values.input !== undefined || values.clipboard || values.format !== "text") ? "session takes only --config, --ip and --domains"
    : values.format !== "text" && values.format !== "json" ? "--format must be text or json"
    : values.input !== undefined && values.clipboard ? "use either --input or --clipboard, not both"
    : command !== "session" && values.input === undefined && !values.clipboard && process.stdin.isTTY ? "no input: pipe text to stdin, or pass --input or --clipboard"
    : undefined;
  if (usageProblem) return usageError(usageProblem);

  // Clipboard modes share one stdin reader: it feeds session keys and the paste-into-terminal fallback.
  const reader = values.clipboard || command === "session" ? inputReader() : undefined;
  let showUpdate = async () => {};
  try {
    const settings = await readSettings();
    showUpdate = startUpdateCheck(settings);
    const options = values.config ? await loadConfig(values.config) : {};
    if (values.ip || settings.ipMasking) options.detectors = [...(options.detectors ?? defaultDetectors), ipAddressDetector];
    if (values.domains || settings.domainMasking) options.detectors = [...(options.detectors ?? defaultDetectors), domainDetector];
    const maxBytes = maxBytesFor(options);
    const clipboard = reader && systemClipboard({ fallback: terminalFallback(reader) });
    if (command === "session") {
      const code = await runSession(options, clipboard!, reader!, maxBytes);
      await showUpdate();
      return code;
    }
    const raw = clipboard ? await clipboard.read(maxBytes) : await readInput(values.input, maxBytes);
    let result;
    let text;
    if (values.format === "json") {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new CliError("input is not valid JSON"); // JSON.parse messages quote the input
      }
      result = sanitizeJson(parsed, options);
      text = JSON.stringify(result.value, null, 2) + "\n";
    } else {
      result = sanitize(raw, options);
      text = result.text;
    }

    if (command === "inspect") process.stdout.write(JSON.stringify({ findings: result.findings, stats: result.stats }, null, 2) + "\n");
    else if (!clipboard) process.stdout.write(text);
    else {
      const via = await clipboard.write(text);
      process.stderr.write(`scrappy: sanitized ${summarize(result.findings)} ${destination(via)}\n`);
    }
    await showUpdate();
    return 0;
  } catch (error) {
    const safe = error instanceof ScrappyError || error instanceof CliError;
    process.stderr.write(`scrappy: ${safe ? error.message : "internal error"}\n`);
    return 1;
  } finally {
    reader?.close();
  }
}

/** On/off settings: `--enable-<flag>` / `--disable-<flag>` with `scrappy config --global`. */
const TOGGLES = { "ip-masking": "ipMasking", "domain-masking": "domainMasking", "update-check": "updateCheck" } as const satisfies Record<string, keyof Settings>;

/** `scrappy config` shows settings; `--global` with `--enable-…` / `--disable-…` saves them. */
async function configCommand(values: Record<string, unknown>, extra: string[]): Promise<number> {
  const changes: Partial<Settings> = {};
  let conflict: string | undefined;
  for (const [flag, key] of Object.entries(TOGGLES)) {
    const on = values[`enable-${flag}`] === true;
    const off = values[`disable-${flag}`] === true;
    if (on && off) conflict = `use either --enable-${flag} or --disable-${flag}, not both`;
    else if (on || off) changes[key] = on;
  }
  const allowed = ["global", "format", ...Object.keys(TOGGLES).flatMap((f) => [`enable-${f}`, `disable-${f}`])];
  const other = Object.keys(values).find((k) => !allowed.includes(k));
  const changing = Object.keys(changes).length > 0;
  const problem =
    extra.length > 0 ? `unexpected argument: ${extra[0]}`
    : other ? `config does not take --${other}`
    : conflict ? conflict
    : changing && !values.global ? "settings are global: add --global"
    : values.global && !changing ? "--global needs a setting to change, e.g. --enable-ip-masking"
    : undefined;
  if (problem) return usageError(problem);
  try {
    const path = settingsPath();
    const settings = { ...(await readSettings(path)), ...changes };
    if (changing) await writeSettings(settings, path);
    const lines = Object.entries(TOGGLES).map(([flag, key]) => `${flag}: ${settings[key] ? "on" : "off"}`);
    process.stdout.write(`${lines.join("\n")}\n(settings file: ${path})\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`scrappy: ${error instanceof CliError ? error.message : "cannot save settings"}\n`);
    return 1;
  }
}

// A UTF-16 code unit takes at most 3 UTF-8 bytes, so more bytes than this is always too long.
const maxBytesFor = (options: SdkOptions) => (options.policy?.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH) * 3;

async function readInput(path: string | undefined, maxBytes: number): Promise<string> {
  if (path !== undefined) {
    try {
      if ((await stat(path)).size > maxBytes) throw new ScrappyError("INPUT_TOO_LARGE");
      return await readFile(path, "utf8");
    } catch (error) {
      if (error instanceof ScrappyError) throw error;
      throw new CliError(`cannot read input file (${(error as NodeJS.ErrnoException).code ?? "unknown error"})`);
    }
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
    total += chunk.length;
    if (total > maxBytes) throw new ScrappyError("INPUT_TOO_LARGE");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function loadConfig(path: string): Promise<SdkOptions> {
  let config: unknown;
  try {
    config = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new CliError(code ? `cannot read config file (${code})` : "config file is not valid JSON");
  }
  if (typeof config !== "object" || config === null || Array.isArray(config)) throw new CliError("config must be a JSON object");
  const { policy, customDetectors = [], ...unknown } = config as { policy?: SdkOptions["policy"]; customDetectors?: unknown };
  const unknownKey = Object.keys(unknown)[0];
  if (unknownKey !== undefined) throw new CliError(`unknown config key: ${unknownKey}`);
  if (!Array.isArray(customDetectors)) throw new CliError("config customDetectors must be an array");

  const custom: Detector[] = customDetectors.map((d: { id: string; type: SensitiveType; pattern: unknown; flags?: string; confidence?: number }, i) => {
    if (typeof d?.pattern !== "string") throw new CliError(`config customDetectors[${i}].pattern must be a string`);
    return createPatternDetector({ id: d.id, type: d.type, pattern: d.pattern, flags: d.flags, confidence: d.confidence });
  });
  return { policy, detectors: [...defaultDetectors, ...custom] };
}

process.exitCode = await main(process.argv.slice(2));
