import { spawn } from "node:child_process";
import { CliError } from "./errors.ts";

export interface Clipboard {
  /** The clipboard text. With no working tool, asks the user to paste into the terminal instead. */
  read(maxBytes: number): Promise<string>;
  /** Returns what took the text: a tool name, or "terminal" when it was shown there instead. */
  write(text: string): Promise<string>;
}

/** The last resort, which always works: the user's terminal can always paste. */
export interface TerminalFallback {
  paste(prompt: string, maxBytes: number): Promise<string>;
  show(text: string): void;
}

interface Tool {
  name: string;
  file: string;
  args: string[];
  shell?: boolean;
}

const tool = (file: string, ...args: string[]): Tool => ({ name: file, file, args });
const powershell = (script: string) => tool("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script);
// shortcut: PowerShell paths are verified with fakes only; check on real Windows/WSL before claiming more.
const WINDOWS = {
  paste: powershell("[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw"),
  copy: powershell("[Console]::InputEncoding=[Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())"),
};
const WL = { paste: tool("wl-paste", "--no-newline"), copy: tool("wl-copy") };
const XCLIP = { paste: tool("xclip", "-selection", "clipboard", "-o"), copy: tool("xclip", "-selection", "clipboard", "-i") };
const XSEL = { paste: tool("xsel", "--clipboard", "--output"), copy: tool("xsel", "--clipboard", "--input") };

/** Tools to try, in order, plus a hint for when none of them work. */
function plan(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): { pairs: { paste: Tool; copy: Tool }[]; hint: string } {
  if (env.SCRAPPY_PASTE_CMD && env.SCRAPPY_COPY_CMD) {
    const custom = (name: string, cmd: string): Tool => ({ name, file: cmd, args: [], shell: true });
    return { pairs: [{ paste: custom("SCRAPPY_PASTE_CMD", env.SCRAPPY_PASTE_CMD), copy: custom("SCRAPPY_COPY_CMD", env.SCRAPPY_COPY_CMD) }], hint: "check SCRAPPY_PASTE_CMD and SCRAPPY_COPY_CMD" };
  }
  if (platform === "darwin") return { pairs: [{ paste: tool("pbpaste"), copy: tool("pbcopy") }], hint: "pbpaste/pbcopy ship with macOS; check that /usr/bin is on your PATH" };
  if (platform === "win32") return { pairs: [WINDOWS], hint: "Scrappy uses PowerShell for the clipboard; check that powershell.exe is on your PATH" };

  const wayland = Boolean(env.WAYLAND_DISPLAY);
  const linux = wayland ? [WL, XCLIP, XSEL] : [XCLIP, XSEL, WL];
  const wsl = Boolean(env.WSL_DISTRO_NAME || env.WSL_INTEROP);
  const want = wayland ? "wl-clipboard" : "xclip";
  const hint =
    wsl ? "Scrappy uses the Windows clipboard through powershell.exe; check that Windows interop is enabled"
    : !wayland && !env.DISPLAY ? "this session has no graphical display (SSH, server or container), so there is no clipboard to read"
    : `to use the clipboard directly, install ${want} (e.g. sudo apt install ${want})`;
  return { pairs: wsl ? [WINDOWS, ...linux] : linux, hint };
}

class ToolFailed extends Error {
  readonly missing: boolean;
  constructor(missing: boolean) {
    super("clipboard tool failed");
    this.missing = missing;
  }
}

function run(command: Tool, env: NodeJS.ProcessEnv, input?: string, maxBytes = Infinity): Promise<string> {
  return new Promise((resolve, reject) => {
    // Tool stderr is ignored: it is never shown, so it can't leak clipboard content.
    const child = spawn(command.file, command.args, { shell: command.shell, env, stdio: ["pipe", "pipe", "ignore"] });
    const chunks: Buffer[] = [];
    let total = 0;
    let failure: Error | undefined;
    child.on("error", (error: NodeJS.ErrnoException) => (failure ??= new ToolFailed(error.code === "ENOENT")));
    child.stdout.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        failure ??= new CliError("clipboard content exceeds the maximum allowed length");
        child.kill();
      } else chunks.push(chunk);
    });
    child.on("close", (code) => {
      if (failure) return reject(failure);
      if (code !== 0) return reject(new ToolFailed(false));
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    child.stdin.on("error", () => {}); // a tool that exits early is reported through "close"
    child.stdin.end(input);
  });
}

export function systemClipboard({ fallback, env = process.env, platform = process.platform }: { fallback: TerminalFallback; env?: NodeJS.ProcessEnv; platform?: NodeJS.Platform }): Clipboard {
  const { pairs, hint } = plan(env, platform);
  return {
    async read(maxBytes) {
      let anyInstalled = false;
      for (const { paste } of pairs) {
        try {
          return await run(paste, env, undefined, maxBytes);
        } catch (error) {
          if (!(error instanceof ToolFailed)) throw error;
          anyInstalled ||= !error.missing;
        }
      }
      const tried = [...new Set(pairs.map((p) => p.paste.name))].join(", ");
      const problem = anyInstalled ? `couldn't read the clipboard (tried ${tried}; it may be empty)` : `no clipboard tool found (looked for ${tried}); ${hint}`;
      return fallback.paste(`${problem}.\nPaste your text below, then press Ctrl-D on an empty line:`, maxBytes);
    },
    async write(text) {
      for (const { copy } of pairs) {
        try {
          await run(copy, env, text);
          return copy.name;
        } catch (error) {
          if (!(error instanceof ToolFailed)) throw error;
        }
      }
      fallback.show(text);
      return "terminal";
    },
  };
}
