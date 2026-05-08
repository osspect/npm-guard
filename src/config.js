import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";

const HOME = os.homedir();

export const DATA_DIR = process.env.NPM_GUARD_HOME || path.join(HOME, ".npm-guard");
export const ALLOWLIST_FILE = path.join(DATA_DIR, "allowlist.json");
export const EVENTS_LOG = path.join(DATA_DIR, "events.log");
export const CONFIG_FILE = path.join(DATA_DIR, "config.json");
export const WATCH_REGISTRY_FILE = path.join(DATA_DIR, "watch-registry.json");

export const UPSTREAM = process.env.NPM_GUARD_UPSTREAM || "https://registry.npmjs.org";
export const DOWNLOADS_API = "https://api.npmjs.org/downloads";
export const OSV_API = "https://api.osv.dev/v1/query";

export const DEFAULT_PORT = Number(process.env.NPM_GUARD_PORT || 7878);
export const DEFAULT_HOST = process.env.NPM_GUARD_HOST || "127.0.0.1";

export const THRESHOLDS = {
  ask: 3,
  block: 8,
};

export const FRESHNESS_DAYS = 14;
export const TYPOSQUAT_DISTANCE = 2;

export const FETCH_TIMEOUT_MS = 8000;

export async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

export async function readUserConfig() {
  try {
    const raw = await fs.readFile(CONFIG_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

export async function writeUserConfig(patch) {
  await ensureDataDir();
  const cur = await readUserConfig();
  const next = { ...cur, ...patch };
  await fs.writeFile(CONFIG_FILE, JSON.stringify(next, null, 2));
  return next;
}
