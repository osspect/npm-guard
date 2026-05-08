import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const RC_FILENAME = ".npmguardrc";

async function readLines(file) {
  try {
    const raw = await fs.readFile(file, "utf8");
    return raw
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
}

export async function readProjectAllow(cwd = process.cwd()) {
  return await readLines(path.join(cwd, RC_FILENAME));
}

export async function readHomeAllow() {
  return await readLines(path.join(os.homedir(), RC_FILENAME));
}

export async function loadAllowEntries({ cwd = process.cwd(), extra = [] } = {}) {
  const home = await readHomeAllow();
  const proj = await readProjectAllow(cwd);
  return [...new Set([...home, ...proj, ...extra])];
}

export function matches(entries, name) {
  for (const e of entries) {
    if (!e) continue;
    if (e === name) return true;
    if (e.endsWith("/*") && name.startsWith(e.slice(0, -1))) return true;
    if (e === name.split("@")[0]) return true;
  }
  return false;
}
