import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { log } from "./log.js";

const NPMRC = path.join(os.homedir(), ".npmrc");
const BACKUP = NPMRC + ".npm-guard.bak";
const REGISTRY_RE = /^\s*registry\s*=/i;
const MARKER = "# managed-by: npm-guard";

const buildBlock = (port, host = "127.0.0.1") => [
  MARKER,
  `registry=http://${host}:${port}/`,
].join("\n");

async function readNpmrc() {
  try {
    return await fs.readFile(NPMRC, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return "";
    throw e;
  }
}

async function writeNpmrc(content) {
  const trimmed = content.replace(/\n+$/g, "") + "\n";
  await fs.writeFile(NPMRC, trimmed);
}

export async function installNpmrc({ port, host = "127.0.0.1" }) {
  const original = await readNpmrc();
  const lines = original.split(/\r?\n/);

  const previousRegistry = lines.find((l) => REGISTRY_RE.test(l));
  if (previousRegistry && !previousRegistry.includes("127.0.0.1")) {
    await fs.writeFile(BACKUP, previousRegistry + "\n");
    log.info(`Backed up previous registry line to ${BACKUP}`);
  }

  const filtered = lines.filter(
    (l) => !REGISTRY_RE.test(l) && l.trim() !== MARKER,
  );
  const next = [...filtered, "", buildBlock(port, host)].join("\n");
  await writeNpmrc(next);
  log.ok(`~/.npmrc configured to use http://${host}:${port}/`);
}

export async function uninstallNpmrc() {
  const original = await readNpmrc();
  const lines = original.split(/\r?\n/);
  let filtered = lines.filter(
    (l) => !REGISTRY_RE.test(l) && l.trim() !== MARKER,
  );

  let restored = null;
  try {
    const bak = (await fs.readFile(BACKUP, "utf8")).trim();
    if (bak) {
      filtered.push(bak);
      restored = bak;
    }
  } catch {}

  await writeNpmrc(filtered.join("\n"));
  if (restored) {
    log.ok(`~/.npmrc restored to: ${restored}`);
  } else {
    log.ok("~/.npmrc cleared (npm will use default registry).");
  }
}

export async function npmrcStatus() {
  const content = await readNpmrc();
  const reg = content.split(/\r?\n/).find((l) => REGISTRY_RE.test(l));
  if (reg) log.info("registry:", reg.trim());
  else log.info("registry: (default https://registry.npmjs.org)");

  try {
    const bak = (await fs.readFile(BACKUP, "utf8")).trim();
    if (bak) log.info("backup  :", bak);
  } catch {}
}
