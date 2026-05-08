import fs from "node:fs/promises";
import path from "node:path";
import { WATCH_REGISTRY_FILE, ensureDataDir } from "../config.js";

const SCHEMA_VERSION = 1;

function normCwd(cwd) {
  return path.resolve(cwd);
}

export async function loadWatchRegistry() {
  await ensureDataDir();
  try {
    const raw = await fs.readFile(WATCH_REGISTRY_FILE, "utf8");
    const j = JSON.parse(raw);
    if (!j.projects || typeof j.projects !== "object") return emptyRegistry();
    return j;
  } catch (e) {
    if (e.code === "ENOENT") return emptyRegistry();
    throw e;
  }
}

function emptyRegistry() {
  return { version: SCHEMA_VERSION, projects: {} };
}

export async function saveWatchRegistry(reg) {
  await ensureDataDir();
  reg.version = SCHEMA_VERSION;
  await fs.writeFile(WATCH_REGISTRY_FILE, JSON.stringify(reg, null, 2));
}

/**
 * Record dependency keys without fetching snapshots (fast path after install).
 */
export async function recordDependencyKeys(cwd, packages, { label } = {}) {
  const reg = await loadWatchRegistry();
  const key = normCwd(cwd);
  const now = new Date().toISOString();
  if (!reg.projects[key]) {
    reg.projects[key] = { deps: {}, createdAt: now };
  }
  const proj = reg.projects[key];
  if (label) proj.label = label;
  proj.updatedAt = now;

  for (const p of packages) {
    if (!p?.name || !p?.version) continue;
    const id = `${p.name}@${p.version}`;
    if (!proj.deps[id]) {
      proj.deps[id] = { recordedAt: now, last: null };
    } else {
      proj.deps[id].recordedAt = now;
    }
  }

  await saveWatchRegistry(reg);
}

export async function listProjectEntries(cwd) {
  const reg = await loadWatchRegistry();
  const proj = reg.projects[normCwd(cwd)];
  if (!proj?.deps) return [];
  return Object.entries(proj.deps).map(([id, entry]) => ({ id, ...entry }));
}

export async function updateSnapshot(cwd, depId, snapshot) {
  const reg = await loadWatchRegistry();
  const key = normCwd(cwd);
  const proj = reg.projects[key];
  if (!proj?.deps?.[depId]) return;
  proj.deps[depId].last = snapshot;
  proj.updatedAt = new Date().toISOString();
  await saveWatchRegistry(reg);
}

export async function listAllProjects() {
  const reg = await loadWatchRegistry();
  return Object.entries(reg.projects).map(([cwdPath, p]) => ({
    cwd: cwdPath,
    label: p.label,
    depCount: Object.keys(p.deps || {}).length,
    updatedAt: p.updatedAt,
  }));
}
