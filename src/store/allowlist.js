import fs from "node:fs/promises";
import { ALLOWLIST_FILE, ensureDataDir } from "../config.js";
import { log } from "../util/log.js";

async function load() {
  await ensureDataDir();
  try {
    const raw = await fs.readFile(ALLOWLIST_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch {
    return [];
  }
}

async function save(list) {
  const unique = [...new Set(list.filter(Boolean))].sort();
  await fs.writeFile(ALLOWLIST_FILE, JSON.stringify(unique, null, 2) + "\n");
}

export async function isAllowed(name, version) {
  const list = await load();
  if (list.includes(name)) return true;
  if (version && list.includes(`${name}@${version}`)) return true;
  return false;
}

export async function addAllow(spec) {
  const list = await load();
  list.push(spec);
  await save(list);
  log.ok(`allowlist: + ${spec}`);
}

export async function removeAllow(spec) {
  const list = (await load()).filter((e) => e !== spec);
  await save(list);
  log.ok(`allowlist: - ${spec}`);
}

export async function listAllow() {
  return await load();
}
