import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const MAIN = new URL("../src/main.ts", import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), "scrappy-cli-"));
const CLIP = join(dir, "clipboard.txt");
// A file-backed fake clipboard at the system boundary; the real OS clipboard has its own test.
const fakeClipboard = { SCRAPPY_PASTE_CMD: `cat '${CLIP}'`, SCRAPPY_COPY_CMD: `cat > '${CLIP}'` };
const cli = (args: string[], input = "") =>
  spawnSync(process.execPath, ["--conditions=source", "--no-warnings", MAIN, ...args], { input, encoding: "utf8", env: { ...process.env, ...fakeClipboard } });

test("sanitize: stdin to stdout, byte-for-byte apart from placeholders", () => {
  const r = cli(["sanitize"], "user=john@example.com\npassword=hunter2\n");
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "user=[EMAIL_1]\npassword=[PASSWORD_1]\n");
  assert.equal(r.stderr, "");
});

test("sanitize --input never modifies the file", () => {
  const file = join(dir, "app.log");
  writeFileSync(file, "contact a@b.io");
  const r = cli(["sanitize", "--input", file]);
  assert.equal(r.stdout, "contact [EMAIL_1]");
  assert.equal(readFileSync(file, "utf8"), "contact a@b.io");
});

test("inspect reports findings without values", () => {
  const r = cli(["inspect"], "contact a@b.io");
  assert.equal(r.status, 0);
  const report = JSON.parse(r.stdout);
  assert.deepEqual(report.findings.map((f: { type: string; start: number; end: number }) => [f.type, f.start, f.end]), [["EMAIL", 8, 14]]);
  assert.ok(!r.stdout.includes("a@b.io"));
});

test("--format json keeps structure", () => {
  const r = cli(["sanitize", "--format", "json"], '{"user":{"email":"a@b.io","age":30}}');
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout), { user: { email: "[EMAIL_1]", age: 30 } });
});

test("--config adds custom detectors and policy", () => {
  const config = join(dir, "scrappy.config.json");
  writeFileSync(config, JSON.stringify({ policy: { enabledTypes: ["ACCOUNT_NUMBER"] }, customDetectors: [{ id: "account", type: "ACCOUNT_NUMBER", pattern: "account (?<value>\\d{6})" }] }));
  const r = cli(["sanitize", "-c", config], "account 100284 for a@b.io");
  assert.equal(r.stdout, "account [ACCOUNT_NUMBER_1] for a@b.io");
});

test("--clipboard sanitizes the clipboard in place and reports only types", () => {
  writeFileSync(CLIP, "mail john@example.com\npassword=hunter2");
  const r = cli(["sanitize", "--clipboard"]);
  assert.equal(r.status, 0);
  assert.equal(readFileSync(CLIP, "utf8"), "mail [EMAIL_1]\npassword=[PASSWORD_1]");
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /2 values .*EMAIL.*PASSWORD/);
  assert.ok(!/john|hunter2/.test(r.stderr));
});

test("inspect --clipboard reads the clipboard and leaves it untouched", () => {
  writeFileSync(CLIP, "a@b.io");
  const r = cli(["inspect", "--clipboard"]);
  assert.equal(JSON.parse(r.stdout).stats.findingCount, 1);
  assert.equal(readFileSync(CLIP, "utf8"), "a@b.io");
});

test("session: sanitize clipboard, paste AI reply back, restore originals, quit", async () => {
  writeFileSync(CLIP, "Refund john@example.com, password=hunter2");
  const child = spawn(process.execPath, ["--conditions=source", "--no-warnings", MAIN, "session"], { env: { ...process.env, ...fakeClipboard } });
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (d: string) => (stderr += d));
  const closed = once(child, "close");
  const waitFor = async (pattern: RegExp) => {
    while (!pattern.test(stderr)) {
      const exited = await Promise.race([once(child.stderr, "data").then(() => false), closed.then(() => true)]);
      if (exited && !pattern.test(stderr)) assert.fail(`exited before ${pattern}; stderr: ${stderr}`);
    }
  };

  child.stdin.write("s");
  await waitFor(/sanitized 2 values/);
  assert.equal(readFileSync(CLIP, "utf8"), "Refund [EMAIL_1], password=[PASSWORD_1]");

  writeFileSync(CLIP, "Done: refunded [EMAIL_1]. Rotate [PASSWORD_1]. Ignore [EMAIL_7].");
  child.stdin.write("r");
  await waitFor(/restored 2 values/);
  assert.equal(readFileSync(CLIP, "utf8"), "Done: refunded john@example.com. Rotate hunter2. Ignore [EMAIL_7].");

  child.stdin.write("q");
  const [code] = await closed;
  assert.equal(code, 0);
  assert.match(stderr, /memory only/);
  assert.ok(!/john|hunter2/.test(stderr), "originals must never be printed");
});

test("real macOS clipboard via pbcopy/pbpaste", { skip: process.platform !== "darwin" && "macOS only" }, (t) => {
  const saved = spawnSync("pbpaste", { encoding: "utf8" }).stdout;
  t.after(() => spawnSync("pbcopy", { input: saved }));
  const { SCRAPPY_PASTE_CMD, SCRAPPY_COPY_CMD, ...env } = { ...process.env, ...fakeClipboard };
  spawnSync("pbcopy", { input: "mail a@b.io ✓" });
  const r = spawnSync(process.execPath, ["--conditions=source", "--no-warnings", MAIN, "sanitize", "--clipboard"], { encoding: "utf8", env });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(spawnSync("pbpaste", { encoding: "utf8" }).stdout, "mail [EMAIL_1] ✓");
});

test("--version prints the package version", () => {
  const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  for (const flag of ["--version", "-v"]) {
    const r = cli([flag]);
    assert.equal(r.status, 0);
    assert.equal(r.stdout, `${version}\n`);
  }
});

test("invalid usage exits 2", () => {
  for (const args of [[], ["explode"], ["sanitize", "extra"], ["sanitize", "--format", "xml"], ["sanitize", "--nope"], ["sanitize", "--clipboard", "-i", "x"], ["session", "-i", "x"], ["session", "--format", "json"]]) {
    const r = cli(args);
    assert.equal(r.status, 2, args.join(" "));
    assert.equal(r.stdout, "");
  }
});

test("processing errors exit 1 without echoing input", () => {
  const secret = "hunter2-SECRET";
  const badJson = cli(["sanitize", "--format", "json"], `{"password": ${secret}`);
  assert.equal(badJson.status, 1);
  assert.equal(badJson.stdout, "");
  assert.ok(!badJson.stderr.includes(secret));

  const config = join(dir, "bad.json");
  writeFileSync(config, JSON.stringify({ policy: { maxInputLength: 4 } }));
  const tooLarge = cli(["sanitize", "-c", config], secret);
  assert.equal(tooLarge.status, 1);
  assert.match(tooLarge.stderr, /exceeds the maximum/);
  assert.ok(!tooLarge.stderr.includes(secret));

  assert.equal(cli(["sanitize", "-i", join(dir, "missing.log")]).status, 1);
  writeFileSync(config, JSON.stringify({ policies: {} }));
  assert.match(cli(["sanitize", "-c", config], "x").stderr, /unknown config key: policies/);
});
