import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { discoverPackages } from "../installer/plan.js";
import { scanPackage } from "../analyzer/index.js";
import { appendAudit } from "../store/audit.js";
import { log } from "../util/log.js";
import kleur from "kleur";

function npm(args, cwd) {
  return new Promise((resolve) => {
    const cmd = process.platform === "win32" ? "npm.cmd" : "npm";
    const child = spawn(cmd, args, { cwd, stdio: "inherit" });
    child.on("close", (code) => resolve({ code: code ?? -1 }));
    child.on("error", () => resolve({ code: -1 }));
  });
}

async function readPj(cwd) {
  try {
    return JSON.parse(await fs.readFile(path.join(cwd, "package.json"), "utf8"));
  } catch {
    return null;
  }
}

async function writePj(cwd, pj) {
  await fs.writeFile(path.join(cwd, "package.json"), JSON.stringify(pj, null, 2) + "\n");
}

export async function fixCommand({ json = false, dryRun = false, cwd = process.cwd() } = {}) {
  const pkgs = await discoverPackages(cwd);
  const actions = [];

  for (const p of pkgs) {
    const r = await scanPackage(`${p.name}@${p.version}`);
    const top = r.findings
      .filter((f) => f.kind?.startsWith("typosquat") && f.similarTo)
      .sort((a, b) => (b.weight || 0) - (a.weight || 0))[0];
    if (top) {
      actions.push({
        kind: "typosquat-replace",
        from: p.name,
        to: top.similarTo,
        reason: top.msg,
      });
    }
  }

  if (actions.length === 0) {
    if (json) console.log(JSON.stringify({ actions: [] }, null, 2));
    else log.info("修正対象は見つかりませんでした。");
    return { actions };
  }

  if (dryRun) {
    if (json) console.log(JSON.stringify({ dryRun: true, actions }, null, 2));
    else {
      log.info(kleur.cyan("=== dry-run: would apply ==="));
      for (const a of actions) log.info(`  ${a.from} -> ${a.to}  (${a.reason})`);
    }
    return { dryRun: true, actions };
  }

  const pj = await readPj(cwd);
  for (const a of actions) {
    if (!json) log.info(kleur.cyan(`[fix] ${a.from} -> ${a.to}`));
    const u = await npm(["uninstall", a.from], cwd);
    if (u.code !== 0 && pj) {
      for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
        if (pj[field]?.[a.from]) delete pj[field][a.from];
      }
      try {
        await fs.rm(path.join(cwd, "node_modules", a.from), { recursive: true, force: true });
      } catch {}
    }
    await npm(["install", "--ignore-scripts", a.to], cwd);
  }
  if (pj) await writePj(cwd, pj);

  await appendAudit({ command: "fix", actions });
  if (json) console.log(JSON.stringify({ actions }, null, 2));
  return { actions };
}
