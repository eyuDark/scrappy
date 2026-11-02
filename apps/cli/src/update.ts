import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const DAY = 24 * 60 * 60 * 1000;
const VERSION = /^(\d+)\.(\d+)\.(\d+)$/; // releases only; pre-releases never trigger a notice

export interface UpdateCheck {
  current: string;
  cachePath: string;
  /** Asks the registry for the latest version. Must honor the signal. */
  fetchLatest: (signal: AbortSignal) => Promise<string>;
  now?: number;
  timeoutMs?: number;
}

function isNewer(latest: string, current: string): boolean {
  const a = VERSION.exec(latest);
  const b = VERSION.exec(current);
  if (!a || !b) return false;
  for (let i = 1; i <= 3; i++) if (Number(a[i]) !== Number(b[i])) return Number(a[i]) > Number(b[i]);
  return false;
}

/**
 * Returns the newer version if one exists, otherwise undefined. Hits the network at most once a day
 * (failures included), gives up after `timeoutMs`, and never throws.
 */
export async function checkForUpdate({ current, cachePath, fetchLatest, now = Date.now(), timeoutMs = 1000 }: UpdateCheck): Promise<string | undefined> {
  let cached: { checkedAt?: unknown; latest?: unknown } = {};
  try {
    cached = JSON.parse(await readFile(cachePath, "utf8"));
  } catch {
    // Missing or corrupt cache: treat as stale.
  }
  let latest = typeof cached.latest === "string" ? cached.latest : undefined;

  if (!(typeof cached.checkedAt === "number" && now - cached.checkedAt < DAY)) {
    // A plain timer, not AbortSignal.timeout(): that one is unref'd, so a hung request could let the
    // process exit before the timeout ever fires.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("update check timed out")), timeoutMs);
    try {
      latest = await fetchLatest(controller.signal);
    } catch {
      // Offline or slow: keep the old answer, and don't retry until tomorrow.
    } finally {
      clearTimeout(timer);
    }
    try {
      await mkdir(dirname(cachePath), { recursive: true });
      await writeFile(cachePath, JSON.stringify({ checkedAt: now, latest }) + "\n");
    } catch {
      // An unwritable cache only means we check again next time.
    }
  }
  return latest !== undefined && isNewer(latest, current) ? latest : undefined;
}

/** Fetches `<registry>/<name>/latest` (public package metadata only; nothing about the user). */
export const npmLatest = (name: string, registry = "https://registry.npmjs.org") => async (signal: AbortSignal) => {
  const response = await fetch(`${registry.replace(/\/$/, "")}/${name}/latest`, { signal, headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`registry answered ${response.status}`);
  const { version } = (await response.json()) as { version?: unknown };
  if (typeof version !== "string") throw new Error("registry answer has no version");
  return version;
};
