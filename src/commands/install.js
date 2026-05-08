import path from "node:path";
import { runNpmInstall } from "../installer/npmInstall.js";
import { discoverPackages } from "../installer/plan.js";
import { runHooksSandboxed } from "../installer/runScripts.js";
import { loadAllowEntries } from "../store/rcfile.js";
import { scanPackage } from "../analyzer/index.js";
import { hashScript } from "../analyzer/behavior.js";
import { auditLockfile, listLockedDependencies } from "../analyzer/lockfile.js";
import { reputationOf, aggregateReputation } from "../analyzer/reputation.js";
import { diffAgainstSnapshot } from "../analyzer/behavior.js";
import { listAllow, addAllow } from "../store/allowlist.js";
import { appendAudit } from "../store/audit.js";
import { recordDependencyKeys } from "../store/watchRegistry.js";
import { reportSignal, checkIntel } from "../intel/client.js";
import { log } from "../util/log.js";
import kleur from "kleur";
import { choose } from "../util/prompt.js";

export async function installCommand({
  packages = [],
  json = false,
  scan = false,
  dryRun = false,
  loose = false,
  allow = [],
  noReport = false,
  interactive = false,
  cwd = process.cwd(),
} = {}) {
  if (noReport) process.env.NPM_GUARD_NO_REPORT = "1";

  const ownAllow = await listAllow();
  const rcAllow = await loadAllowEntries({ cwd, extra: allow });
  const allowList = [...new Set([...rcAllow, ...ownAllow])];

  // Pre-scan: detect typosquats / known malware before installing anything
  let acceptedPackages = [...packages];
  if (packages.length > 0) {
    if (!json) log.info(kleur.cyan("== pre-install scan =="));
    const blocks = [];
    const skipped = [];
    for (const spec of packages) {
      const r = await scanPackage(spec);
      if (!json) printScanLine(r);
      if (r.decision !== "allow") {
        await reportSignal({
          name: r.name,
          version: r.version,
          category: pickCategory(r.findings),
          severity: r.decision === "block" ? "high" : "medium",
        });
      }

      if (r.decision === "allow") continue;

      if (interactive && !json && !dryRun) {
        const ans = await choose(
          `${r.name}@${r.version || "?"} の判定: ${r.decision}. どうしますか？`,
          [
            { key: "skip", aliases: ["s"] },
            { key: "abort", aliases: ["a"] },
            { key: "allow", aliases: ["y", "yes"] },
          ],
        );
        if (ans === "abort") {
          const out = { ok: false, aborted: true };
          log.error("aborted by user");
          return { code: 2, ...out };
        }
        if (ans === "skip") {
          skipped.push({ name: r.name, version: r.version, decision: r.decision });
          acceptedPackages = acceptedPackages.filter((p) => p !== spec);
          continue;
        }
        if (ans === "allow") {
          await addAllow(r.version ? `${r.name}@${r.version}` : r.name);
          continue;
        }
      }

      if (r.decision === "block") blocks.push(r);
    }
    if (blocks.length > 0 && !dryRun) {
      const out = { ok: false, blocked: blocks.map((b) => ({ name: b.name, version: b.version, score: b.score })) };
      if (json) console.log(JSON.stringify(out, null, 2));
      else log.error(`pre-install scan blocked ${blocks.length} package(s); aborting.`);
      return { code: 2, ...out };
    }
  }

  if (dryRun) {
    if (!json) log.info(kleur.cyan("dry-run: no install performed"));
    return { code: 0, dryRun: true };
  }

  if (!json) log.info(kleur.cyan("== npm install --ignore-scripts =="));
  const npmRes = await runNpmInstall({ args: acceptedPackages, cwd });
  if (npmRes.code !== 0) {
    if (json) console.log(JSON.stringify({ ok: false, npm: npmRes }, null, 2));
    return { code: npmRes.code, npm: npmRes };
  }

  if (!json) log.info(kleur.cyan("== sandboxed lifecycle scripts =="));
  const pkgs = await discoverPackages(cwd);
  const { backend, backendDesc, results } = await runHooksSandboxed({
    packages: pkgs,
    cwd,
    allowList,
    loose,
    json,
  });

  // Behavioral diff (compare scripts to last snapshot)
  const entries = pkgs.map((p) => ({
    name: p.name,
    version: p.version,
    scripts: p.hooks,
  }));
  const { findings: behavioralFindings } = await diffAgainstSnapshot({
    entries,
    cwd,
    commit: true,
  });

  // Optional deep scan
  let lockfileAudit = null;
  let reputationSummary = null;
  let typosquats = [];
  if (scan) {
    if (!json) log.info(kleur.cyan("== deep scan =="));
    lockfileAudit = await auditLockfile(cwd);
    if (!json && lockfileAudit) {
      log.info(`lockfile score: ${lockfileAudit.score}/100`);
      for (const i of lockfileAudit.issues) log.warn(`  · ${i.msg}`);
    }

    const reps = [];
    for (const p of pkgs.slice(0, 50)) {
      const r = await reputationOf(p.name, p.version);
      reps.push(r);
    }
    reputationSummary = aggregateReputation(reps);
    if (!json && reputationSummary) {
      log.info(`reputation overall: ${reputationSummary.overallScore}/100 (n=${reputationSummary.count})`);
    }

    for (const p of pkgs) {
      const r = await scanPackage(`${p.name}@${p.version}`);
      const t = r.findings.filter((f) => f.kind?.startsWith("typosquat"));
      if (t.length > 0) typosquats.push({ name: r.name, version: r.version, findings: t });
    }
    if (!json && typosquats.length > 0) {
      log.warn(`typosquat suspects: ${typosquats.length}`);
    }
  }

  // Intel check (always)
  const intelHits = [];
  for (const p of pkgs) {
    const ic = await checkIntel(p.name, p.version);
    if (ic?.flagged) intelHits.push(ic);
  }
  if (!json && intelHits.length > 0) {
    log.warn(`intel flagged: ${intelHits.length}`);
  }

  // Audit log
  const summary = {
    total: results.length,
    blocked: results.filter((r) => r.status === "violation" || r.status === "blocked-no-sandbox").length,
    clean: results.filter((r) => r.status === "ok").length,
    allowed: results.filter((r) => r.status === "allowed").length,
    behavioralFindings: behavioralFindings.length,
    typosquats: typosquats.length,
    lockfileIssues: lockfileAudit?.issues?.length || 0,
    reputationScore: reputationSummary?.overallScore ?? null,
    intelFlagged: intelHits.length,
  };
  await appendAudit({ command: "install", backend, packages, summary });

  try {
    const locked = await listLockedDependencies(cwd);
    const label = path.basename(cwd);
    if (locked?.length) await recordDependencyKeys(cwd, locked, { label });
    else {
      const uniq = new Map();
      for (const p of pkgs) {
        if (!p.name || !p.version) continue;
        uniq.set(`${p.name}@${p.version}`, { name: p.name, version: p.version });
      }
      await recordDependencyKeys(cwd, [...uniq.values()], { label });
    }
  } catch (e) {
    log.debug("watch registry:", e?.message);
  }

  // Report signals for sandbox violations
  for (const r of results.filter((x) => x.status === "violation")) {
    const pkg = pkgs.find((p) => p.name === r.name);
    const cmd = pkg?.hooks?.[r.hook] || "";
    await reportSignal({
      name: r.name,
      version: r.version,
      scriptHash: hashScript(cmd),
      category: "sandbox-violation",
      severity: "high",
    });
  }

  const out = {
    ok: summary.blocked === 0,
    version: "0.2.0",
    backend: backendDesc,
    packages: results,
    behavioralFindings,
    typosquats,
    lockfileAudit,
    reputationSummary,
    intelFlagged: intelHits,
    summary,
  };

  if (json) console.log(JSON.stringify(out, null, 2));
  else printSummary(out);

  return { code: summary.blocked > 0 ? 2 : 0, ...out };
}

function printScanLine(r) {
  const tag =
    r.decision === "block" ? kleur.red("[block]") :
    r.decision === "ask" ? kleur.yellow("[ask]") :
    kleur.gray("[ok]");
  log.info(`${tag} ${r.name}@${r.version || "?"} score=${r.score}`);
  for (const f of r.findings.slice(0, 5)) {
    if ((f.weight || 0) === 0) continue;
    log.info(`    · ${f.msg} (+${f.weight})`);
  }
}

function pickCategory(findings) {
  for (const f of findings) {
    if (f.kind?.startsWith("typosquat")) return "typosquat";
    if (f.kind?.includes("network-fetch")) return "network-fetch";
    if (f.kind?.includes("secret-read")) return "secret-read";
    if (f.kind?.includes("dns-exfil")) return "dns-exfil";
    if (f.kind === "advisory") return "malware-osv";
  }
  return "other";
}

function printSummary(o) {
  log.info(kleur.cyan("== summary =="));
  log.info(`backend            : ${o.backend}`);
  log.info(`scripts run        : ${o.summary.total}`);
  log.info(`clean              : ${o.summary.clean}`);
  log.info(`allowed            : ${o.summary.allowed}`);
  log.info(`blocked            : ${o.summary.blocked}`);
  log.info(`behavior changes   : ${o.summary.behavioralFindings}`);
  log.info(`typosquat suspects : ${o.summary.typosquats}`);
  log.info(`lockfile issues    : ${o.summary.lockfileIssues}`);
  log.info(`reputation overall : ${o.summary.reputationScore ?? "(skipped)"}`);
  log.info(`intel flagged      : ${o.summary.intelFlagged}`);
}
