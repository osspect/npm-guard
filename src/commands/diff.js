import { discoverPackages } from "../installer/plan.js";
import { diffAgainstSnapshot, hashScript } from "../analyzer/behavior.js";
import { writeSnapshot, snapshotPathFor } from "../store/snapshot.js";
import { log } from "../util/log.js";
import kleur from "kleur";

export async function diffCommand({ snapshot = false, json = false, cwd = process.cwd() } = {}) {
  const pkgs = await discoverPackages(cwd);
  const entries = pkgs.map((p) => ({ name: p.name, version: p.version, scripts: p.hooks }));

  if (snapshot) {
    const snap = { packages: Object.fromEntries(entries.map((e) => [e.name, { version: e.version, scripts: e.scripts }])) };
    const file = await writeSnapshot(snap, cwd);
    if (json) console.log(JSON.stringify({ snapshot: true, path: file, count: entries.length }, null, 2));
    else log.info(`snapshot saved: ${file} (${entries.length} packages)`);
    return { snapshot: true, file, count: entries.length };
  }

  const { findings } = await diffAgainstSnapshot({ entries, cwd, commit: false });
  if (json) {
    console.log(JSON.stringify({ findings, snapshotPath: snapshotPathFor(cwd) }, null, 2));
    return { findings };
  }

  if (findings.length === 0) {
    log.info("変化はありません。");
    return { findings };
  }
  log.info(kleur.cyan(`== changes since last snapshot (${findings.length}) ==`));
  for (const f of findings) {
    log.info(`  · ${f.msg}`);
    if (f.previousHash) log.info(kleur.gray(`      - prev: ${f.previousHash}`));
    if (f.newHash) log.info(kleur.gray(`      + new : ${f.newHash}`));
  }
  return { findings };
}
