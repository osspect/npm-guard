import crypto from "node:crypto";
import { readSnapshot, writeSnapshot } from "../store/snapshot.js";

export function hashScript(s) {
  return "sha256:" + crypto.createHash("sha256").update(s || "").digest("hex").slice(0, 16);
}

export function summarizeScripts(meta, version) {
  const v = meta?.versions?.[version];
  const scripts = v?.scripts || {};
  return {
    preinstall: scripts.preinstall ? hashScript(scripts.preinstall) : null,
    install: scripts.install ? hashScript(scripts.install) : null,
    postinstall: scripts.postinstall ? hashScript(scripts.postinstall) : null,
    bodies: {
      preinstall: scripts.preinstall || "",
      install: scripts.install || "",
      postinstall: scripts.postinstall || "",
    },
  };
}

export async function diffAgainstSnapshot({ entries, cwd = process.cwd(), commit = false } = {}) {
  const old = (await readSnapshot(cwd)) || { packages: {} };
  const newSnap = { packages: {} };
  const findings = [];

  for (const e of entries) {
    const key = `${e.name}@${e.version}`;
    newSnap.packages[e.name] = { version: e.version, scripts: e.scripts || {} };
    const prev = old.packages?.[e.name];
    if (!prev) continue;
    if (prev.version === e.version) continue;

    for (const hook of ["preinstall", "install", "postinstall"]) {
      const a = prev.scripts?.[hook];
      const b = e.scripts?.[hook];
      if (a !== b) {
        findings.push({
          kind: `behavior:${hook}-changed`,
          msg: `${e.name} の ${hook} スクリプトが ${prev.version} → ${e.version} で変化しました`,
          weight: a && b ? 5 : 3,
          severity: "medium",
          name: e.name,
          previousVersion: prev.version,
          newVersion: e.version,
          previousHash: a ? hashScript(a) : null,
          newHash: b ? hashScript(b) : null,
        });
      }
    }
  }

  if (commit) await writeSnapshot(newSnap, cwd);
  return { findings, snapshot: newSnap };
}
