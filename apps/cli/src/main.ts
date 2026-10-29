#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { parseArgs } from "node:util";
import {
  DEFAULT_MAX_INPUT_LENGTH,
  ScrappyError,
  createPatternDetector,
  defaultDetectors,
  sanitize,
  sanitizeJson,
  type Detector,
  type SdkOptions,
  type SensitiveType,
} from "@scrappy/sdk";
import { CliError, systemClipboard } from "./clipboard.ts";
import { runSession, summarize } from "./session.ts";

const USAGE = `Usage: scrappy <sanitize|inspect> [--input <file> | --clipboard] [--format text|json] [--config <file>]
       scrappy session [--config <file>]

  sanitize   Print the sanitized input to stdout.
  inspect    Print findings (types, offsets, placeholders; never values) as JSON.
  session    Interactive: sanitize the clipboard, then restore originals in the AI's reply.
             Mappings stay in memory and are discarded on quit.

  -i, --input <file>   Read from a file instead of stdin. The file is never modified.
      --clipboard      Read the clipboard; "sanitize" writes the result back to the clipboard.
  -f, --format <fmt>   "text" (default) or "json" (sanitizes values and keys, keeps structure).
  -c, --config <file>  JSON config: { "policy": {...}, "customDetectors": [{ "id", "type", "pattern", "flags"?, "confidence"? }] }
  -v, --version        Print the version.
`;

async function main(argv: string[]): Promise<number> {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        input: { type: "string", short: "i" },
        clipboard: { type: "boolean" },
        format: { type: "string", short: "f", default: "text" },
        config: { type: "string", short: "c" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (error) {
    process.stderr.write(`scrappy: ${(error as Error).message}\n\n${USAGE}`);
    return 2;
  }
  const { values, positionals } = args;
  if (values.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (values.version) {
    // src/ and the bundled dist/ both sit one level below package.json.
    process.stdout.write(`${JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version}\n`);
    return 0;
  }
  const [command, ...extra] = positionals;
  const usageProblem =
    command !== "sanitize" && command !== "inspect" && command !== "session" ? "expected a command: sanitize, inspect or session"
    : extra.length > 0 ? `unexpected argument: ${extra[0]}`
    : command === "session" && (values.input !== undefined || values.clipboard || values.format !== "text") ? "session takes only --config"
    : values.format !== "text" && values.format !== "json" ? "--format must be text or json"
    : values.input !== undefined && values.clipboard ? "use either --input or --clipboard, not both"
    : command !== "session" && values.input === undefined && !values.clipboard && process.stdin.isTTY ? "no input: pipe text to stdin, or pass --input or --clipboard"
    : undefined;
  if (usageProblem) {
    process.stderr.write(`scrappy: ${usageProblem}\n\n${USAGE}`);
    return 2;
  }

  try {
    const options = values.config ? await loadConfig(values.config) : {};
    const maxBytes = maxBytesFor(options);
    if (command === "session") return await runSession(options, systemClipboard(), maxBytes);
    const clipboard = values.clipboard ? systemClipboard() : undefined;
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
      await clipboard.write(text);
      process.stderr.write(`scrappy: sanitized ${summarize(result.findings)} → clipboard\n`);
    }
    return 0;
  } catch (error) {
    const safe = error instanceof ScrappyError || error instanceof CliError;
    process.stderr.write(`scrappy: ${safe ? error.message : "internal error"}\n`);
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
