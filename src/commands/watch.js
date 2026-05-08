import path from "node:path";
import kleur from "kleur";
import { discoverPackages } from "../installer/plan.js";
import { listLockedDependencies } from "../analyzer/lockfile.js";
import {
  loadWatchRegistry,
  saveWatchRegistry,
  recordDependencyKeys,
  listProjectEntries,
  listAllProjects,
} from "../store/watchRegistry.js";
import { computeRiskSnapshot, riskWorsened, formatRiskSummary } from "../watch/riskSnapshot.js";
import { notifyWatchAlerts } from "../watch/notify.js";
import { log } from "../util/log.js";

const DEFAULT_CONCURRENCY = Number(process.env.NPM_GUARD_WATCH_CONCURRENCY || 5);
const MAX_PACKAGES = Number(process.env.NPM_GUARD_WATCH_MAX_PACKAGES || 12000);

async function poolMap(items, limit, fn) {
  const ret = new Array(items.length);
  let i = 0;
  async function worker() {
    for (;;) {
      const idx = i++;
      if (idx >= items.length) break;
      ret[idx] = await fn(items[idx], idx);
    }
  }
  const n = Math.min(limit, items.length);
  await Promise.all(Array.from({ length: n }, worker));
  return ret;
}

async function resolveDependencyList(cwd) {
  const fromLock = await listLockedDependencies(cwd);
  if (fromLock?.length) return fromLock;
  const pkgs = await discoverPackages(cwd);
  const map = new Map();
  for (const p of pkgs) {
    if (!p.name || !p.version) continue;
    map.set(`${p.name}@${p.version}`, { name: p.name, version: p.version });
  }
  return [...map.values()];
}

export async function watchSyncCommand({
  cwd = process.cwd(),
  json = false,
  label,
}) {
  const deps = await resolveDependencyList(cwd);
  if (!deps.length) {
    if (!json) log.warn("依存が見つかりません（package-lock.json または node_modules を確認）");
    return { code: 1, recorded: 0 };
  }
  let list = deps;
  if (list.length > MAX_PACKAGES) {
    if (!json) log.warn(`依存が ${list.length} 件あります。先頭 ${MAX_PACKAGES} 件のみ登録します（NPM_GUARD_WATCH_MAX_PACKAGES で変更可）`);
    list = list.slice(0, MAX_PACKAGES);
  }

  await recordDependencyKeys(cwd, list, {
    label: label || path.basename(cwd),
  });

  if (!json) {
    log.ok(`監視レジストリを更新しました（${list.length} パッケージ）`);
    log.info(`次回 \`npm-guard watch check\` でベースラインを取得し、以降はリスク悪化時に通知します`);
  }

  return { code: 0, recorded: list.length };
}

export async function watchCheckCommand({
  cwd = process.cwd(),
  allProjects = false,
  json = false,
  concurrency = DEFAULT_CONCURRENCY,
  silent = false,
}) {
  if (allProjects) {
    const projects = await listAllProjects();
    let totalChecked = 0;
    let exitCode = 0;
    const aggregatedAlerts = [];
    for (const p of projects) {
      const r = await watchCheckCommand({
        cwd: p.cwd,
        allProjects: false,
        json: false,
        concurrency,
        silent: true,
      });
      totalChecked += r.checked || 0;
      if (r.code !== 0) exitCode = 1;
      if (r.alerts?.length) {
        aggregatedAlerts.push(...r.alerts.map((a) => ({ ...a, projectCwd: p.cwd })));
      }
    }
    if (json) {
      console.log(JSON.stringify({
        ok: aggregatedAlerts.length === 0,
        projectsChecked: projects.length,
        packagesChecked: totalChecked,
        alerts: aggregatedAlerts,
      }, null, 2));
    } else if (!silent) {
      log.info(kleur.cyan("== watch check (all projects) =="));
      log.info(`projects: ${projects.length}, packages scanned: ${totalChecked}`);
      if (aggregatedAlerts.length > 0) {
        log.warn(`合計リスク悪化: ${aggregatedAlerts.length} 件`);
        for (const a of aggregatedAlerts.slice(0, 30)) {
          log.warn(`  · ${a.projectCwd} → ${a.summary}`);
        }
      } else {
        log.ok("全プロジェクトでリスク悪化なし");
      }
    }
    return {
      code: exitCode,
      checked: totalChecked,
      alerts: aggregatedAlerts,
    };
  }

  const reg = await loadWatchRegistry();
  const norm = path.resolve(cwd);
  const proj = reg.projects[norm];
  if (!proj?.deps || Object.keys(proj.deps).length === 0) {
    if (!json && !silent) log.warn("このプロジェクトはまだ監視リストにありません。`npm-guard watch sync` を実行してください");
    return { code: 1, checked: 0, alerts: [] };
  }

  const entries = Object.entries(proj.deps);
  let slice = entries;
  if (slice.length > MAX_PACKAGES) {
    if (!json && !silent) log.warn(`監視対象が ${slice.length} 件です。先頭 ${MAX_PACKAGES} 件のみチェックします`);
    slice = slice.slice(0, MAX_PACKAGES);
  }

  const updates = await poolMap(slice, concurrency, async ([depId]) => {
    const idx = depId.lastIndexOf("@");
    const name = idx <= 0 ? depId : depId.slice(0, idx);
    const version = idx <= 0 ? "" : depId.slice(idx + 1);
    const prev = proj.deps[depId]?.last ?? null;

    try {
      const snap = await computeRiskSnapshot(name, version);
      return { depId, name, version, snap, prev };
    } catch (e) {
      log.debug("watch snapshot failed:", depId, e?.message);
      return null;
    }
  });

  const alerts = [];
  let baselineCount = 0;

  for (const u of updates) {
    if (!u) continue;
    const { depId, name, version, snap, prev } = u;

    if (prev === null) {
      baselineCount++;
      proj.deps[depId].last = snap;
      continue;
    }

    if (riskWorsened(prev, snap)) {
      alerts.push({
        id: depId,
        name,
        version,
        summary: formatRiskSummary(snap, name, version),
        previous: prev,
        current: snap,
      });
    }

    proj.deps[depId].last = snap;
  }

  proj.updatedAt = new Date().toISOString();
  await saveWatchRegistry(reg);

  const label = proj.label || path.basename(norm);

  if (alerts.length > 0) {
    await notifyWatchAlerts({
      projectLabel: label,
      cwd: norm,
      alerts,
    });
  }

  if (!json && !silent) {
    log.info(kleur.cyan("== watch check =="));
    log.info(`project : ${label}`);
    log.info(`resolved: ${norm}`);
    log.info(`packages: ${slice.length}（新規ベースライン ${baselineCount}）`);
    if (alerts.length > 0) {
      log.warn(`リスク悪化: ${alerts.length} 件`);
      for (const a of alerts.slice(0, 20)) {
        log.warn(`  · ${a.summary}`);
      }
      if (alerts.length > 20) log.warn(`  …他 ${alerts.length - 20} 件`);
    } else {
      log.ok("リスク悪化なし");
    }
  } else if (json && !silent) {
    console.log(JSON.stringify({
      ok: alerts.length === 0,
      cwd: norm,
      label,
      checked: slice.length,
      baselines: baselineCount,
      alerts,
    }, null, 2));
  }

  return {
    code: alerts.length > 0 ? 1 : 0,
    checked: slice.length,
    baselines: baselineCount,
    alerts,
  };
}

export async function watchListCommand({ cwd = process.cwd(), json = false }) {
  const rows = await listProjectEntries(cwd);
  if (json) {
    console.log(JSON.stringify(rows, null, 2));
    return { code: 0 };
  }
  if (rows.length === 0) {
    log.info("(empty — run `npm-guard watch sync`)");
    return { code: 0 };
  }
  log.info(`${rows.length} packages under watch:`);
  for (const r of rows.slice(0, 50)) {
    const st = r.last
      ? `${r.last.decision} intel=${r.last.intelFlagged} blocklist=${r.last.blocklist}`
      : "(baseline pending)";
    log.info(`  ${r.id}  ${st}`);
  }
  if (rows.length > 50) log.info(`  …${rows.length - 50} more`);
  return { code: 0 };
}

export async function watchProjectsCommand({ json = false }) {
  const rows = await listAllProjects();
  if (json) {
    console.log(JSON.stringify(rows, null, 2));
    return { code: 0 };
  }
  if (rows.length === 0) {
    log.info("(no projects)");
    return { code: 0 };
  }
  for (const r of rows) {
    log.info(`${r.cwd}  (${r.depCount} deps)  updated ${r.updatedAt || "?"}`);
  }
  return { code: 0 };
}
