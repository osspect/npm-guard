import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DATA_DIR, ensureDataDir } from "../config.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BUNDLED = path.join(__dirname, "..", "data", "compromised.txt");
const LOCAL_OVERRIDE = path.join(DATA_DIR, "compromised.txt");

let cache = null;

function parse(text) {
  const set = new Set();
  const versionsByName = new Map();
  const meta = { source: "unknown", lastUpdated: null, lines: 0 };

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("#")) {
      const m = line.match(/Last updated:\s*(.+)/i);
      if (m) meta.lastUpdated = m[1].trim();
      continue;
    }
    meta.lines++;
    const colon = line.lastIndexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim();
    const version = line.slice(colon + 1).trim();
    if (!name || !version) continue;
    set.add(`${name}@${version}`);
    if (!versionsByName.has(name)) versionsByName.set(name, new Set());
    versionsByName.get(name).add(version);
  }

  return { set, versionsByName, meta };
}

export async function loadBlocklist({ force = false } = {}) {
  if (cache && !force) return cache;
  await ensureDataDir();

  let source = BUNDLED;
  let text;
  try {
    text = await fs.readFile(LOCAL_OVERRIDE, "utf8");
    source = LOCAL_OVERRIDE;
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    text = await fs.readFile(BUNDLED, "utf8");
  }

  const parsed = parse(text);
  parsed.meta.source = source;
  cache = parsed;
  return cache;
}

export async function isCompromised(name, version) {
  const bl = await loadBlocklist();
  if (!name) return null;
  if (version && bl.set.has(`${name}@${version}`)) {
    return { name, version, exact: true, bundle: bl.meta.source };
  }
  if (bl.versionsByName.has(name)) {
    const versions = [...bl.versionsByName.get(name)];
    return { name, version, exact: false, otherCompromisedVersions: versions, bundle: bl.meta.source };
  }
  return null;
}

export async function checkBlocklist(name, version) {
  const hit = await isCompromised(name, version);
  if (!hit) return [];
  if (hit.exact) {
    return [
      {
        kind: "blocklist:exact",
        msg: `既知の侵害パッケージ ${name}@${version}（Shai-Hulud / 公開アドバイザリで確認済み）`,
        weight: 100,
        severity: "critical",
        source: hit.bundle,
      },
    ];
  }
  return [
    {
      kind: "blocklist:other-version",
      msg: `${name} は別バージョン (${hit.otherCompromisedVersions.join(", ")}) が侵害されています`,
      weight: 8,
      severity: "high",
      source: hit.bundle,
      otherCompromisedVersions: hit.otherCompromisedVersions,
    },
  ];
}

export async function blocklistMeta() {
  const bl = await loadBlocklist();
  return { ...bl.meta, totalEntries: bl.set.size, totalNames: bl.versionsByName.size };
}

export function clearBlocklistCache() {
  cache = null;
}
