import { spawn } from "node:child_process";

export interface Clipboard {
  read(maxBytes: number): Promise<string>;
  write(text: string): Promise<void>;
}

/** Errors whose message is safe to print: it never contains input text. */
export class CliError extends Error {}

type Command = { file: string; args: string[]; shell?: boolean };

const UNAVAILABLE = "clipboard unavailable: on Linux install wl-clipboard or xclip, or set SCRAPPY_PASTE_CMD and SCRAPPY_COPY_CMD";

function commands(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): { paste: Command; copy: Command } {
  if (env.SCRAPPY_PASTE_CMD && env.SCRAPPY_COPY_CMD) {
    return { paste: { file: env.SCRAPPY_PASTE_CMD, args: [], shell: true }, copy: { file: env.SCRAPPY_COPY_CMD, args: [], shell: true } };
  }
  if (platform === "darwin") return { paste: { file: "pbpaste", args: [] }, copy: { file: "pbcopy", args: [] } };
  // shortcut: Windows clipboard via PowerShell is untested, verify on a Windows machine before claiming support.
  if (platform === "win32") {
    const ps = (script: string): Command => ({ file: "powershell.exe", args: ["-NoProfile", "-NonInteractive", "-Command", script] });
    return {
      paste: ps("[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw"),
      copy: ps("[Console]::InputEncoding=[Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())"),
    };
  }
  if (env.WAYLAND_DISPLAY) return { paste: { file: "wl-paste", args: ["--no-newline"] }, copy: { file: "wl-copy", args: [] } };
  return { paste: { file: "xclip", args: ["-selection", "clipboard", "-o"] }, copy: { file: "xclip", args: ["-selection", "clipboard", "-i"] } };
}

function run(command: Command, input: string | undefined, maxBytes = Infinity): Promise<string> {
  return new Promise((resolve, reject) => {
    // Tool stderr is ignored: it is never shown, so it can't leak clipboard content.
    const child = spawn(command.file, command.args, { shell: command.shell, stdio: ["pipe", "pipe", "ignore"] });
    const chunks: Buffer[] = [];
    let total = 0;
    let failure: Error | undefined;
    child.on("error", () => (failure ??= new CliError(UNAVAILABLE)));
    child.stdout.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        failure ??= new CliError("clipboard content exceeds the maximum allowed length");
        child.kill();
      } else chunks.push(chunk);
    });
    child.on("close", (code) => {
      if (failure) return reject(failure);
      if (code !== 0) return reject(new CliError(UNAVAILABLE));
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    child.stdin.on("error", () => {}); // a tool that exits early is reported through "close"
    child.stdin.end(input);
  });
}

export function systemClipboard(env = process.env, platform = process.platform): Clipboard {
  const { paste, copy } = commands(env, platform);
  return {
    read: (maxBytes) => run(paste, undefined, maxBytes),
    write: async (text) => void (await run(copy, text)),
  };
}
