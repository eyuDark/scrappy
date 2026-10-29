import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const MAIN = new URL("../src/main.ts", import.meta.url).pathname;
const cli = (args: string[], input = "") => spawnSync(process.execPath, ["--conditions=source", "--no-warnings", MAIN, ...args], { input, encoding: "utf8" });
const dir = mkdtempSync(join(tmpdir(), "scrappy-cli-"));

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

test("invalid usage exits 2", () => {
  for (const args of [[], ["explode"], ["sanitize", "extra"], ["sanitize", "--format", "xml"], ["sanitize", "--nope"]]) {
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
