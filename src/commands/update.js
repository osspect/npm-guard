import fs from "node:fs/promises";
import path from "node:path";
import { DATA_DIR, ensureDataDir, readUserConfig, writeUserConfig } from "../config.js";
import { fetchWithTimeout } from "../util/fetch.js";
import { clearBlocklistCache, blocklistMeta, loadBlocklist } from "../analyzer/blocklist.js";
import { appendAudit } from "../store/audit.js";
import { log } from "../util/log.js";
import kleur from "kleur";

const DEFAULT_SOURCE =
  "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt";

const LOCAL_FILE = path.join(DATA_DIR, "compromised.txt");

export async function updateCommand({ json = false, source } = {}) {
  await ensureDataDir();
  const cfg = await readUserConfig();
  const url = source || cfg.blocklistSource || DEFAULT_SOURCE;

  if (!json) log.info(kleur.cyan(`fetching blocklist from: ${url}`));

  let text;
  try {
    const res = await fetchWithTimeout(url, {}, 30000);
    if (!res.ok) {
      const out = { ok: false, status: res.status, url };
      if (json) console.log(JSON.stringify(out, null, 2));
      else log.error(`HTTP ${res.status} from ${url}`);
      return { code: 1, ...out };
    }
    text = await res.text();
  } catch (e) {
    const out = { ok: false, error: String(e?.message || e), url };
    if (json) console.log(JSON.stringify(out, null, 2));
    else log.error(`fetch failed: ${out.error}`);
    return { code: 1, ...out };
  }

  if (text.length < 200) {
    const out = { ok: false, error: "downloaded file looks too small", url, size: text.length };
    if (json) console.log(JSON.stringify(out, null, 2));
    else log.error(`refusing to overwrite: file too small (${text.length} bytes)`);
    return { code: 1, ...out };
  }

  await fs.writeFile(LOCAL_FILE, text);
  await writeUserConfig({ blocklistSource: url, blocklistUpdatedAt: new Date().toISOString() });

  clearBlocklistCache();
  const before = await blocklistMetaSafe();
  await loadBlocklist({ force: true });
  const after = await blocklistMeta();

  await appendAudit({ command: "update", url, totalEntries: after.totalEntries });

  const out = {
    ok: true,
    url,
    file: LOCAL_FILE,
    totalEntries: after.totalEntries,
    totalNames: after.totalNames,
    lastUpdated: after.lastUpdated,
  };
  if (json) console.log(JSON.stringify(out, null, 2));
  else {
    log.ok(`blocklist updated: ${after.totalEntries} entries (${after.totalNames} unique packages)`);
    if (after.lastUpdated) log.info(`upstream last updated: ${after.lastUpdated}`);
    log.info(`stored at: ${LOCAL_FILE}`);
  }
  return { code: 0, ...out };
}

async function blocklistMetaSafe() {
  try {
    return await blocklistMeta();
  } catch {
    return null;
  }
}

export async function blocklistInfoCommand({ json = false } = {}) {
  const meta = await blocklistMeta();
  if (json) {
    console.log(JSON.stringify(meta, null, 2));
    return meta;
  }
  log.info(`blocklist source : ${meta.source}`);
  log.info(`total entries    : ${meta.totalEntries}`);
  log.info(`unique names     : ${meta.totalNames}`);
  if (meta.lastUpdated) log.info(`upstream date    : ${meta.lastUpdated}`);
  return meta;
}
