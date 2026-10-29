import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const CLI_DIR = new URL("..", import.meta.url).pathname;

test("the packed tarball installs and runs as `scrappy` with no dependencies", () => {
  const dir = mkdtempSync(join(tmpdir(), "scrappy-pack-"));
  // pnpm pack runs prepack (the bundle) and rewrites workspace: ranges, like pnpm publish.
  execFileSync("pnpm", ["pack", "--pack-destination", dir], { cwd: CLI_DIR, stdio: "ignore" });
  const tarball = join(dir, readdirSync(dir).find((f) => f.endsWith(".tgz"))!);

  const files = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" }).trim().split("\n").sort();
  assert.deepEqual(files, ["package/LICENSE", "package/README.md", "package/dist/scrappy.js", "package/package.json"]);
  const manifest = JSON.parse(execFileSync("tar", ["-xzOf", tarball, "package/package.json"], { encoding: "utf8" }));
  assert.equal(manifest.name, "scrappy-redact");
  assert.equal(manifest.dependencies, undefined, "the bundle must be self-contained");

  const prefix = join(dir, "install");
  execFileSync("npm", ["install", "--prefix", prefix, "--no-audit", "--no-fund", "--offline", tarball], { stdio: "ignore" });
  const bin = join(prefix, "node_modules", ".bin", "scrappy");

  assert.equal(execFileSync(bin, ["--version"], { encoding: "utf8" }), `${manifest.version}\n`);
  const r = spawnSync(bin, ["sanitize"], { input: "ping ops@corp.io", encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, "ping [EMAIL_1]");
});

