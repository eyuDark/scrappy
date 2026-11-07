import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { CliError } from "./errors.ts";

/** Saved preferences only. Never input text or mappings. */
export interface Settings {
  ipMasking: boolean;
  domainMasking: boolean;
  /** Daily check for a newer version; on unless turned off. */
  updateCheck: boolean;
}

const DEFAULTS: Settings = { ipMasking: false, domainMasking: false, updateCheck: true };

export function settingsPath(env = process.env, platform = process.platform): string {
  const base = env.XDG_CONFIG_HOME || (platform === "win32" && env.APPDATA) || join(homedir(), ".config");
  return join(base, "scrappy", "config.json");
}

export async function readSettings(path = settingsPath()): Promise<Settings> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { ...DEFAULTS };
    throw new CliError(`cannot read settings file ${path} (${code ?? "unknown error"})`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new CliError(`settings file is not valid JSON: ${path}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new CliError(`settings file must be a JSON object: ${path}`);
  const saved = parsed as Partial<Record<keyof Settings, unknown>>;
  return { ipMasking: saved.ipMasking === true, domainMasking: saved.domainMasking === true, updateCheck: saved.updateCheck !== false };
}

export async function writeSettings(settings: Settings, path = settingsPath()): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(settings, null, 2) + "\n");
}
