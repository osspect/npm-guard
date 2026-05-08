import { discoverPackages } from "../installer/plan.js";
import { auditLockfile } from "../analyzer/lockfile.js";
import { scanPackage } from "../analyzer/index.js";
import { reputationOf, aggregateReputation } from "../analyzer/reputation.js";
import { checkLifecycle, lifecycleRiskLevel } from "../analyzer/lifecycle.js";
import { fetchMetadata } from "../analyzer/registry.js";
import { diffAgainstSnapshot } from "../analyzer/behavior.js";
import { appendAudit } from "../store/audit.js";
import { log } from "../util/log.js";
import kleur from "kleur";
import fs from "node:fs/promises";
import path from "node:path";

const WEIGHTS = {
  lockfile: 20,
  scripts: 25,
  typosquats: 20,
  reputation: 15,
  behavior: 10,
  hygiene: 10,
};

function gradeOf(score) {
  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 87) return "B+";
  if (score >= 83) return "B";
  if (score >= 80) return "B-";
  if (score >= 77) return "C+";
  if (score >= 73) return "C";
  if (score >= 70) return "C-";
  if (score >= 60) return "D";
  return "F";
}

async function readPackageJson(cwd) {
  try {
    return JSON.parse(await fs.readFile(path.join(cwd, "package.json"), "utf8"));
  } catch {
    return null;
  }
}

export async function doctorCommand({ json = false, cwd = process.cwd() } = {}) {
  const sections = {};
  const fixes = [];

  // 1. Lockfile
  const lock = await auditLockfile(cwd);
  sections.lockfile = { score: lock.score, issues: lock.issues, weight: WEIGHTS.lockfile };
  for (const i of lock.issues) {
    if (i.kind === "lockfile:missing") fixes.push("npm install で package-lock.json を生成");
    if (i.kind === "lockfile:stale") fixes.push("rm package-lock.json && npm install で再生成");
  }

  // 2. Install scripts
  const pkgs = await discoverPackages(cwd);
  const scriptHits = [];
  let scriptsScore = 100;
  for (const p of pkgs) {
    if (!p.hasHooks) continue;
    const meta = await fetchMetadata(p.name);
    if (!meta) continue;
    const lf = checkLifecycle(meta, p.version);
    const total = lf.reduce((s, f) => s + (f.weight || 0), 0);
    const level = lifecycleRiskLevel(total);
    if (level === "critical") scriptsScore = Math.min(scriptsScore, 10);
    else if (level === "suspicious") scriptsScore = Math.min(scriptsScore, 50);
    else if (level === "low") scriptsScore = Math.min(scriptsScore, 80);
    if (total > 0) scriptHits.push({ name: p.name, version: p.version, total, level });
  }
  sections.scripts = { score: scriptsScore, hits: scriptHits, weight: WEIGHTS.scripts };
  if (scriptsScore < 70) fixes.push("リスクの高いスクリプトを持つパッケージを `npm-guard scan <pkg>` で確認");

  // 3. Typosquats
  let typoScore = 100;
  const typos = [];
  for (const p of pkgs) {
    const r = await scanPackage(`${p.name}@${p.version}`);
    const t = r.findings.filter((f) => f.kind?.startsWith("typosquat"));
    if (t.length > 0) {
      typos.push({ name: p.name, version: p.version, findings: t });
      typoScore = Math.min(typoScore, 10);
    }
  }
  sections.typosquats = { score: typoScore, items: typos, weight: WEIGHTS.typosquats };
  if (typos.length > 0) fixes.push(`npm-guard fix で ${typos.length} 件のタイポスクワット候補を置き換え`);

  // 4. Reputation
  const reps = [];
  for (const p of pkgs.slice(0, 50)) {
    reps.push(await reputationOf(p.name, p.version));
  }
  const agg = aggregateReputation(reps);
  sections.reputation = { score: agg.overallScore || 50, count: agg.count, weight: WEIGHTS.reputation };

  // 5. Behavior
  const entries = pkgs.map((p) => ({ name: p.name, version: p.version, scripts: p.hooks }));
  const { findings } = await diffAgainstSnapshot({ entries, cwd, commit: false });
  const behaviorScore = Math.max(0, 100 - findings.length * 10);
  sections.behavior = { score: behaviorScore, findings, weight: WEIGHTS.behavior };

  // 6. Hygiene
  const pj = await readPackageJson(cwd);
  let hygiene = 100;
  const hygieneIssues = [];
  if (!pj) {
    hygiene = 0;
    hygieneIssues.push("package.json が無い");
  } else {
    if (!pj.engines) {
      hygiene -= 10;
      hygieneIssues.push("engines フィールドが無い");
      fixes.push('package.json に "engines": { "node": "..." } を追加');
    }
    const allDeps = { ...pj.dependencies, ...pj.devDependencies };
    let wildcards = 0;
    for (const v of Object.values(allDeps || {})) {
      if (v === "*" || v?.startsWith?.("*")) wildcards++;
    }
    if (wildcards > 0) {
      hygiene -= 20;
      hygieneIssues.push(`ワイルドカード版指定が ${wildcards} 件`);
      fixes.push("ワイルドカード指定を `^` または `~` に変更");
    }
    try {
      await fs.stat(path.join(cwd, ".npmguardrc"));
    } catch {
      hygiene -= 5;
      hygieneIssues.push(".npmguardrc が無い（任意）");
    }
  }
  sections.hygiene = { score: hygiene, issues: hygieneIssues, weight: WEIGHTS.hygiene };

  const totalWeight = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);
  const composite =
    Object.entries(WEIGHTS).reduce((s, [k, w]) => s + (sections[k].score * w) / totalWeight, 0);
  const score = Math.round(composite);
  const grade = gradeOf(score);

  await appendAudit({ command: "doctor", score, grade });

  const out = { score, grade, sections, fixes };
  if (json) {
    console.log(JSON.stringify(out, null, 2));
  } else {
    log.info(kleur.cyan("== npm-guard doctor =="));
    log.info(`grade: ${kleur.bold(grade)}  score: ${score}/100`);
    for (const [k, s] of Object.entries(sections)) {
      log.info(`  ${k.padEnd(12)} ${String(s.score).padStart(3)}/100 (weight ${s.weight}%)`);
    }
    if (fixes.length > 0) {
      log.info(kleur.cyan("\n== suggested fixes =="));
      for (const f of fixes) log.info(`  · ${f}`);
    }
  }
  return out;
}
