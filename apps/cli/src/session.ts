import { ScrappyError, createSession, type Finding, type SdkOptions } from "@scrappy/sdk";
import { CliError, type Clipboard } from "./clipboard.ts";

const HELP = `scrappy session: original values stay in memory only and are gone when you quit.
  s  sanitize the clipboard in place (then paste it into your AI tool)
  r  restore originals into the clipboard (after copying the AI's reply)
  q  quit
`;

const plural = (n: number) => `${n} value${n === 1 ? "" : "s"}`;

/** "2 values (1 EMAIL, 1 PASSWORD)": counts and types only, never values. */
export function summarize(findings: readonly Finding[]): string {
  const counts = new Map<string, number>();
  for (const f of findings) counts.set(f.type, (counts.get(f.type) ?? 0) + 1);
  const types = [...counts].map(([type, n]) => `${n} ${type}`).join(", ");
  return plural(findings.length) + (types ? ` (${types})` : "");
}

/** Reads single keys from stdin (raw mode on a terminal) until q, Ctrl-C, Ctrl-D or end of input. */
export async function runSession(options: SdkOptions, clipboard: Clipboard, maxBytes: number): Promise<number> {
  const session = createSession({ ...options, mode: "reversible" });
  const say = (line: string) => process.stderr.write(`scrappy: ${line}\n`);
  const raw = process.stdin.isTTY;
  if (raw) process.stdin.setRawMode(true);
  process.stderr.write(HELP);
  try {
    for await (const chunk of process.stdin) {
      for (const key of String(chunk)) {
        if (key === "q" || key === "\u0003" || key === "\u0004") return 0;
        if (key !== "s" && key !== "r") continue;
        try {
          const text = await clipboard.read(maxBytes);
          if (key === "s") {
            const result = session.sanitize(text);
            await clipboard.write(result.text);
            say(`sanitized ${summarize(result.findings)} → clipboard`);
          } else {
            const result = session.restore(text);
            await clipboard.write(result.text);
            say(`restored ${plural(result.restoredCount)} → clipboard`);
          }
        } catch (error) {
          // Keep the session (and its mappings) alive after a recoverable failure.
          if (!(error instanceof ScrappyError || error instanceof CliError)) throw error;
          say(error.message);
        }
      }
    }
    return 0;
  } finally {
    session.dispose();
    if (raw) process.stdin.setRawMode(false);
  }
}
