import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const SNAPSHOT_DIR = ".npmguard-snapshot";

function projectKey(cwd) {
  return crypto.createHash("sha1").update(cwd).digest("hex").slice(0, 12);
}

function snapshotPath(cwd) {
  return path.join(cwd, SNAPSHOT_DIR, `${projectKey(cwd)}.json`);
}

export async function readSnapshot(cwd = process.cwd()) {
  try {
    const raw = await fs.readFile(snapshotPath(cwd), "utf8");
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

export async function writeSnapshot(data, cwd = process.cwd()) {
  const file = snapshotPath(cwd);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(
    file,
    JSON.stringify({ ts: new Date().toISOString(), ...data }, null, 2),
  );
  return file;
}

export function snapshotPathFor(cwd = process.cwd()) {
  return snapshotPath(cwd);
}
