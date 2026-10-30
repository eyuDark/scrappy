import { ScrappyError } from "@scrappy/sdk";
import type { TerminalFallback } from "./clipboard.ts";
import { CliError } from "./errors.ts";

/** One shared reader over stdin, so session keys and a paste can take turns on the same stream. */
export interface InputReader {
  /** The next key, or undefined at end of input. */
  key(): Promise<string | undefined>;
  /** Everything up to Ctrl-D (or Ctrl-Z) or end of input. Ctrl-C cancels. */
  paste(maxBytes: number): Promise<string>;
  /** Stops reading so the process can exit. */
  close(): void;
}

const END = /[\x03\x04\x1a]/; // Ctrl-C, Ctrl-D, Ctrl-Z

export function inputReader(stream: NodeJS.ReadStream = process.stdin): InputReader {
  const chunks = (stream as AsyncIterable<Buffer | string>)[Symbol.asyncIterator]();
  let buffer = "";
  let ended = false;
  const more = async () => {
    if (ended) return false;
    const next = await chunks.next();
    if (next.done) ended = true;
    else buffer += String(next.value);
    return !ended;
  };

  return {
    async key() {
      while (buffer === "") if (!(await more())) return undefined;
      const key = buffer[0]!;
      buffer = buffer.slice(1);
      return key;
    },
    async paste(maxBytes) {
      // Raw mode avoids the terminal's ~4 KB line limit on long pasted lines; it also turns newlines into \r.
      const tty = stream.isTTY === true;
      const enterRaw = tty && !stream.isRaw;
      if (enterRaw) stream.setRawMode(true);
      try {
        for (;;) {
          const end = buffer.search(END);
          if (end !== -1 || !(await more())) {
            const stop = end === -1 ? buffer.length : end;
            const text = buffer.slice(0, stop);
            if (buffer[stop] === "\x03") throw new CliError("cancelled");
            buffer = buffer.slice(stop + 1);
            return tty ? text.replace(/\r\n?/g, "\n") : text;
          }
          // A UTF-16 unit is at most 3 UTF-8 bytes, matching how maxBytes is derived.
          if (buffer.length * 3 > maxBytes) throw new ScrappyError("INPUT_TOO_LARGE");
        }
      } finally {
        if (enterRaw) stream.setRawMode(false);
      }
    },
    close() {
      void chunks.return?.();
    },
  };
}

/** Asks for a paste on stderr; shows results on stdout and, on a real terminal, copies them via OSC 52. */
export function terminalFallback(reader: InputReader, out: NodeJS.WriteStream = process.stdout, err: NodeJS.WriteStream = process.stderr): TerminalFallback {
  return {
    async paste(prompt, maxBytes) {
      err.write(`scrappy: ${prompt}\n`);
      const text = await reader.paste(maxBytes);
      err.write(`scrappy: got ${text.length} characters\n`);
      return text;
    },
    show(text) {
      out.write(text.endsWith("\n") ? text : `${text}\n`);
      // OSC 52 asks the terminal itself to set the clipboard; unsupported terminals ignore it.
      const terminal = err.isTTY ? err : out.isTTY ? out : undefined;
      terminal?.write(`\x1b]52;c;${Buffer.from(text).toString("base64")}\x07`);
    },
  };
}
