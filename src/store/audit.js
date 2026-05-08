import fs from "node:fs/promises";
import path from "node:path";
import { DATA_DIR, ensureDataDir } from "../config.js";

const AUDIT_LOG = path.join(DATA_DIR, "audit.log");
const ROTATE_SIZE = 5 * 1024 * 1024;
const KEEP = 3;

async function rotateIfNeeded() {
  try {
    const st = await fs.stat(AUDIT_LOG);
    if (st.size < ROTATE_SIZE) return;
    for (let i = KEEP; i >= 1; i--) {
      const src = i === 1 ? AUDIT_LOG : `${AUDIT_LOG}.${i - 1}`;
      const dst = `${AUDIT_LOG}.${i}`;
      try {
        await fs.rename(src, dst);
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
      }
    }
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
}

export async function appendAudit(entry) {
  await ensureDataDir();
  await rotateIfNeeded();
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
  await fs.appendFile(AUDIT_LOG, line);
}

export async function readAudit({ limit = 100 } = {}) {
  try {
    const raw = await fs.readFile(AUDIT_LOG, "utf8");
    const lines = raw.split(/\r?\n/).filter(Boolean);
    const slice = lines.slice(-limit);
    return slice.map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return { raw: l };
      }
    });
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
}

export const AUDIT_LOG_PATH = AUDIT_LOG;
