import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { checkForUpdate } from "../src/update.ts";

const DAY = 24 * 60 * 60 * 1000;
const cachePath = () => join(mkdtempSync(join(tmpdir(), "scrappy-update-")), "update-check.json");
/** A fake registry that counts calls. */
const registry = (latest: string | Error) => {
  const fake = { calls: 0, fetchLatest: async () => (fake.calls++, latest instanceof Error ? Promise.reject(latest) : latest) };
  return fake;
};

test("reports a newer version and caches the answer for a day", async () => {
  const path = cachePath();
  const reg = registry("0.4.0");
  assert.equal(await checkForUpdate({ current: "0.3.1", cachePath: path, now: 1000, fetchLatest: reg.fetchLatest }), "0.4.0");
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), { checkedAt: 1000, latest: "0.4.0" });

  // Within a day: no network, same answer.
  assert.equal(await checkForUpdate({ current: "0.3.1", cachePath: path, now: 1000 + DAY - 1, fetchLatest: reg.fetchLatest }), "0.4.0");
  assert.equal(reg.calls, 1);

  // A day later: asks again.
  await checkForUpdate({ current: "0.3.1", cachePath: path, now: 1000 + DAY, fetchLatest: reg.fetchLatest });
  assert.equal(reg.calls, 2);
});

test("says nothing when current is the same, newer, or the registry answer is odd", async () => {
  for (const [current, latest] of [["0.3.1", "0.3.1"], ["0.4.0", "0.3.1"], ["0.3.1", "0.10.0-beta.1"], ["0.3.1", "not-a-version"], ["0.3.1", ""]]) {
    assert.equal(await checkForUpdate({ current: current!, cachePath: cachePath(), now: 1, fetchLatest: registry(latest!).fetchLatest }), undefined, `${current} vs ${latest}`);
  }
  // Numeric, not string, comparison: 0.10.0 is newer than 0.9.0.
  assert.equal(await checkForUpdate({ current: "0.9.0", cachePath: cachePath(), now: 1, fetchLatest: registry("0.10.0").fetchLatest }), "0.10.0");
});

test("offline: silent, and no retry for a day", async () => {
  const path = cachePath();
  const reg = registry(new Error("ENOTFOUND registry.npmjs.org"));
  assert.equal(await checkForUpdate({ current: "0.3.1", cachePath: path, now: 1, fetchLatest: reg.fetchLatest }), undefined);
  await checkForUpdate({ current: "0.3.1", cachePath: path, now: 2, fetchLatest: reg.fetchLatest });
  assert.equal(reg.calls, 1, "a failed check is not retried on every command");
});

test("gives up after the timeout instead of delaying the command", async () => {
  const hang = (signal: AbortSignal) => new Promise<string>((_, reject) => signal.addEventListener("abort", () => reject(signal.reason)));
  const started = performance.now();
  assert.equal(await checkForUpdate({ current: "0.3.1", cachePath: cachePath(), now: 1, timeoutMs: 100, fetchLatest: hang }), undefined);
  assert.ok(performance.now() - started < 1000);
});

test("a corrupt cache file is treated as stale, never an error", async () => {
  const path = cachePath();
  writeFileSync(path, "{not json");
  assert.equal(await checkForUpdate({ current: "0.3.1", cachePath: path, now: 1, fetchLatest: registry("0.4.0").fetchLatest }), "0.4.0");
});
