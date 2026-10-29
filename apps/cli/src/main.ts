#!/usr/bin/env node
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

const USAGE = `Usage: scrappy <sanitize|inspect> [--input <file>] [--format text|json] [--config <file>]

  sanitize   Print the sanitized input to stdout.
  inspect    Print findings (types, offsets, placeholders; never values) as JSON.

  -i, --input <file>   Read from a file instead of stdin. The file is never modified.
  -f, --format <fmt>   "text" (default) or "json" (sanitizes values and keys, keeps structure).
  -c, --config <file>  JSON config: { "policy": {...}, "customDetectors": [{ "id", "type", "pattern", "flags"?, "confidence"? }] }
`;

/** Errors whose message is safe to print: it never contains input text. */
class CliError extends Error {}

async function main(argv: string[]): Promise<number> {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        input: { type: "string", short: "i" },
        format: { type: "string", short: "f", default: "text" },
        config: { type: "string", short: "c" },
        help: { type: "boolean", short: "h" },
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
  const [command, ...extra] = positionals;
  const usageProblem =
    command !== "sanitize" && command !== "inspect" ? "expected a command: sanitize or inspect"
    : extra.length > 0 ? `unexpected argument: ${extra[0]}`
    : values.format !== "text" && values.format !== "json" ? "--format must be text or json"
    : values.input === undefined && process.stdin.isTTY ? "no input: pipe text to stdin or pass --input"
    : undefined;
  if (usageProblem) {
    process.stderr.write(`scrappy: ${usageProblem}\n\n${USAGE}`);
    return 2;
  }

  try {
    const options = values.config ? await loadConfig(values.config) : {};
    const raw = await readInput(values.input, options.policy?.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH);
    let result;
    if (values.format === "json") {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new CliError("input is not valid JSON"); // JSON.parse messages quote the input
      }
      result = sanitizeJson(parsed, options);
      if (command === "sanitize") process.stdout.write(JSON.stringify(result.value, null, 2) + "\n");
    } else {
      result = sanitize(raw, options);
      if (command === "sanitize") process.stdout.write(result.text);
    }
    if (command === "inspect") process.stdout.write(JSON.stringify({ findings: result.findings, stats: result.stats }, null, 2) + "\n");
    return 0;
  } catch (error) {
    const safe = error instanceof ScrappyError || error instanceof CliError;
    process.stderr.write(`scrappy: ${safe ? error.message : "internal error"}\n`);
    return 1;
  }
}

async function readInput(path: string | undefined, maxLength: number): Promise<string> {
  // A UTF-16 code unit takes at most 3 UTF-8 bytes, so more bytes than this is always too long.
  const maxBytes = maxLength * 3;
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
