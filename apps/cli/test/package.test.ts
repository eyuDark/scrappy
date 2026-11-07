import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const CLI_DIR = new URL("..", import.meta.url).pathname;

test("the packed tarball installs and runs as `scrappy` with no dependencies", async () => {
  const dir = mkdtempSync(join(tmpdir(), "scrappy-pack-"));
  // pnpm pack runs prepack (the bundle) and rewrites workspace: ranges, like pnpm publish.
  execFileSync("pnpm", ["pack", "--pack-destination", dir], { cwd: CLI_DIR, stdio: "ignore" });
  const tarball = join(dir, readdirSync(dir).find((f) => f.endsWith(".tgz"))!);

  const files = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" }).trim().split("\n").sort();
  assert.deepEqual(files, ["package/LICENSE", "package/README.md", "package/dist/scrappy.js", "package/package.json"]);
  const manifest = JSON.parse(execFileSync("tar", ["-xzOf", tarball, "package/package.json"], { encoding: "utf8" }));
  assert.equal(manifest.name, "scrappy-redact");
  assert.equal(manifest.dependencies, undefined, "the bundle must be self-contained");
  assert.equal(manifest.devDependencies, undefined, "build tools live in the workspace root, not on the npm page");

  const prefix = join(dir, "install");
  execFileSync("npm", ["install", "--prefix", prefix, "--no-audit", "--no-fund", "--offline", tarball], { stdio: "ignore" });
  const bin = join(prefix, "node_modules", ".bin", "scrappy");

  assert.equal(execFileSync(bin, ["--version"], { encoding: "utf8" }), `${manifest.version}\n`);
  const env = { ...process.env, XDG_CONFIG_HOME: join(dir, "config-home") };
  const r = spawnSync(bin, ["sanitize"], { input: "ping ops@corp.io from 10.0.0.7", encoding: "utf8", env });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, "ping [EMAIL_1] from 10.0.0.7");
  assert.equal(spawnSync(bin, ["sanitize", "--ip"], { input: "from 10.0.0.7", encoding: "utf8", env }).stdout, "from [IP_ADDRESS_1]");
  assert.match(execFileSync(bin, ["help"], { encoding: "utf8", env }), /scrappy config +\[--global --enable-<setting>/);

  // On a real terminal, a registry that never answers must not hang the installed CLI.
  const hang = createServer(() => {}).listen(0, "127.0.0.1");
  await once(hang, "listening");
  try {
    const logFile = join(dir, "in.log");
    execFileSync("sh", ["-c", `printf 'mail a@b.io' > '${logFile}'`]);
    const termEnv: NodeJS.ProcessEnv = { ...env, SCRAPPY_REGISTRY_URL: `http://127.0.0.1:${(hang.address() as { port: number }).port}` };
    delete termEnv.CI;
    const args = [bin, "sanitize", "-i", logFile];
    const child =
      process.platform === "darwin"
        ? spawn("/usr/bin/script", ["-q", "/dev/null", ...args], { env: termEnv, stdio: ["ignore", "pipe", "pipe"] })
        : spawn("script", ["-qec", args.map((a) => `'${a}'`).join(" "), "/dev/null"], { env: termEnv, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.setEncoding("utf8").on("data", (d: string) => (output += d));
    const started = performance.now();
    const [code] = await once(child, "close");
    assert.equal(code, 0, output);
    assert.ok(output.includes("mail [EMAIL_1]"), output);
    assert.ok(!output.includes("is available"));
    assert.ok(performance.now() - started < 4000, "the update check must give up quickly");
  } finally {
    hang.closeAllConnections();
    hang.close();
  }
});

