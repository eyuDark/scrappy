import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { systemClipboard, type TerminalFallback } from "../src/clipboard.ts";

/**
 * Fake clipboard tools on a private PATH. Paste tools print "from-<tool>"; copy tools save stdin to
 * <dir>/<tool>.out. `broken` tools exist but fail, like xclip with no X display.
 */
function fakeTools(tools: Record<string, "ok" | "broken">) {
  const dir = mkdtempSync(join(tmpdir(), "scrappy-tools-"));
  for (const [name, mode] of Object.entries(tools)) {
    const body =
      mode === "broken"
        ? "exit 1"
        : `case "${name}:$*" in
  wl-paste:*|pbpaste:*|*:*" -o"*|*:*--output*|*:*Get-Clipboard*) printf 'from-${name}' ;;
  *) /bin/cat > '${dir}/${name}.out' ;;
esac`;
    writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(dir, name), 0o755);
  }
  return { dir, saved: (name: string) => readFileSync(join(dir, `${name}.out`), "utf8") };
}

function fallback() {
  const calls = { prompts: [] as string[], shown: [] as string[] };
  const terminal: TerminalFallback = {
    paste: async (prompt) => (calls.prompts.push(prompt), "pasted-in-terminal"),
    show: (text) => void calls.shown.push(text),
  };
  return { terminal, calls };
}

const clipboard = (platform: NodeJS.Platform, path: string, terminal: TerminalFallback, extra: NodeJS.ProcessEnv = {}) =>
  systemClipboard({ fallback: terminal, platform, env: { PATH: path, ...extra } });

test("linux wayland: wl-clipboard first, matching tool for write", async () => {
  const tools = fakeTools({ "wl-paste": "ok", "wl-copy": "ok", xclip: "ok" });
  const cb = clipboard("linux", tools.dir, fallback().terminal, { WAYLAND_DISPLAY: "wayland-0" });
  assert.equal(await cb.read(1000), "from-wl-paste");
  assert.equal(await cb.write("safe text"), "wl-copy");
  assert.equal(tools.saved("wl-copy"), "safe text");
});

test("linux x11: xclip, then xsel when xclip is missing or broken", async () => {
  const onlyXsel = fakeTools({ xsel: "ok" });
  const cb = clipboard("linux", onlyXsel.dir, fallback().terminal, { DISPLAY: ":0" });
  assert.equal(await cb.read(1000), "from-xsel");
  assert.equal(await cb.write("safe"), "xsel");
  assert.equal(onlyXsel.saved("xsel"), "safe");

  const brokenXclip = fakeTools({ xclip: "broken", xsel: "ok" });
  assert.equal(await clipboard("linux", brokenXclip.dir, fallback().terminal, { DISPLAY: ":0" }).read(1000), "from-xsel");
});

test("WSL uses the Windows clipboard first", async () => {
  const tools = fakeTools({ "powershell.exe": "ok", xclip: "ok" });
  const cb = clipboard("linux", tools.dir, fallback().terminal, { WSL_DISTRO_NAME: "Ubuntu" });
  assert.equal(await cb.read(1000), "from-powershell.exe");
});

test("no clipboard tool anywhere: paste into the terminal, show the result", async () => {
  const empty = fakeTools({});
  const { terminal, calls } = fallback();
  const cb = clipboard("linux", empty.dir, terminal);
  assert.equal(await cb.read(1000), "pasted-in-terminal");
  assert.match(calls.prompts[0]!, /no clipboard tool found/i);
  assert.match(calls.prompts[0]!, /wl-clipboard|xclip/, "tells the user what to install");
  assert.match(calls.prompts[0]!, /Ctrl-D/);
  assert.equal(await cb.write("safe text"), "terminal");
  assert.deepEqual(calls.shown, ["safe text"]);
});

test("macOS and Windows hints never mention Linux tools", async () => {
  for (const platform of ["darwin", "win32"] as const) {
    const { terminal, calls } = fallback();
    await clipboard(platform, fakeTools({}).dir, terminal).read(1000);
    assert.doesNotMatch(calls.prompts[0]!, /xclip|wl-clipboard|apt/, platform);
  }
});

test("SCRAPPY_PASTE_CMD / SCRAPPY_COPY_CMD override everything", async () => {
  const tools = fakeTools({ "wl-paste": "ok" });
  const out = join(tools.dir, "override.out");
  const cb = clipboard("linux", `${tools.dir}:/bin:/usr/bin`, fallback().terminal, {
    WAYLAND_DISPLAY: "wayland-0",
    SCRAPPY_PASTE_CMD: "printf from-override",
    SCRAPPY_COPY_CMD: `cat > '${out}'`,
  });
  assert.equal(await cb.read(1000), "from-override");
  assert.equal(await cb.write("x"), "SCRAPPY_COPY_CMD");
  assert.equal(readFileSync(out, "utf8"), "x");
});

test("terminal fallback: prints the text, and sends OSC 52 only to a real terminal", async () => {
  const { terminalFallback } = await import("../src/terminal.ts");
  const stream = (isTTY: boolean) => {
    const written: string[] = [];
    return { isTTY, written, write: (s: string) => (written.push(s), true) };
  };
  const reader = { key: async () => undefined, paste: async () => "", close: () => {} };

  const out = stream(false);
  const err = stream(true);
  terminalFallback(reader, out as never, err as never).show("safe [EMAIL_1]");
  assert.deepEqual(out.written, ["safe [EMAIL_1]\n"], "stdout gets the text, never escape codes");
  assert.deepEqual(err.written, [`\x1b]52;c;${Buffer.from("safe [EMAIL_1]").toString("base64")}\x07`]);

  const pipedOut = stream(false);
  const pipedErr = stream(false);
  terminalFallback(reader, pipedOut as never, pipedErr as never).show("x");
  assert.deepEqual(pipedErr.written, [], "no OSC 52 when nothing is a terminal");
});
