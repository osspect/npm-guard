import fs from "node:fs/promises";
import path from "node:path";

export async function auditLockfile(cwd = process.cwd()) {
  const lockPath = path.join(cwd, "package-lock.json");
  const issues = [];
  let raw;
  try {
    raw = await fs.readFile(lockPath, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") {
      return {
        score: 50,
        issues: [
          {
            kind: "lockfile:missing",
            msg: "package-lock.json が存在しません",
            severity: "medium",
            weight: 50,
          },
        ],
      };
    }
    throw e;
  }

  let lock;
  try {
    lock = JSON.parse(raw);
  } catch {
    return {
      score: 0,
      issues: [
        {
          kind: "lockfile:invalid-json",
          msg: "package-lock.json が壊れています",
          severity: "high",
          weight: 100,
        },
      ],
    };
  }

  const lockfileVersion = lock.lockfileVersion ?? 1;
  if (lockfileVersion < 2) {
    issues.push({
      kind: "lockfile:legacy-version",
      msg: `lockfileVersion ${lockfileVersion} は古い形式です（2 以上を推奨）`,
      severity: "low",
      weight: 5,
    });
  }

  const packages = lock.packages || {};
  const entries = Object.entries(packages).filter(([k]) => k && k !== "");

  let gitDeps = 0;
  let fileDeps = 0;
  let httpDeps = 0;
  let missingIntegrity = 0;
  let weakAlgo = 0;
  let customRegistry = 0;

  for (const [pkgPath, info] of entries) {
    if (!info || typeof info !== "object") continue;
    const resolved = info.resolved || "";
    if (resolved.startsWith("git+") || resolved.includes("github.com") && resolved.includes(".git")) {
      gitDeps++;
    } else if (resolved.startsWith("file:") || resolved.startsWith("link:")) {
      fileDeps++;
    } else if (resolved.startsWith("http://")) {
      httpDeps++;
    } else if (
      resolved &&
      !resolved.startsWith("https://registry.npmjs.org/") &&
      resolved.startsWith("https://")
    ) {
      customRegistry++;
    }

    if (info.integrity) {
      if (/^sha1-/.test(info.integrity) || /^md5-/.test(info.integrity)) weakAlgo++;
    } else if (resolved && !resolved.startsWith("file:") && !resolved.startsWith("link:")) {
      missingIntegrity++;
    }
  }

  if (gitDeps > 0)
    issues.push({
      kind: "lockfile:git-dep",
      msg: `git 依存が ${gitDeps} 件あります（npm registry 外なので監査困難）`,
      severity: "medium",
      weight: 10,
    });
  if (fileDeps > 0)
    issues.push({
      kind: "lockfile:file-dep",
      msg: `file: / link: 依存が ${fileDeps} 件あります`,
      severity: "low",
      weight: 3,
    });
  if (httpDeps > 0)
    issues.push({
      kind: "lockfile:http",
      msg: `平文 HTTP 取得が ${httpDeps} 件あります（中間者改ざんリスク）`,
      severity: "high",
      weight: 25,
    });
  if (missingIntegrity > 0)
    issues.push({
      kind: "lockfile:missing-integrity",
      msg: `integrity 欠落が ${missingIntegrity} 件あります`,
      severity: "high",
      weight: 20,
    });
  if (weakAlgo > 0)
    issues.push({
      kind: "lockfile:weak-algo",
      msg: `弱いハッシュアルゴリズム (sha1/md5) が ${weakAlgo} 件あります`,
      severity: "medium",
      weight: 10,
    });
  if (customRegistry > 0)
    issues.push({
      kind: "lockfile:custom-registry",
      msg: `公式以外のレジストリが ${customRegistry} 件あります`,
      severity: "low",
      weight: 3,
    });

  // staleness: compare with package.json mtime
  try {
    const pkgPath = path.join(cwd, "package.json");
    const [a, b] = await Promise.all([fs.stat(pkgPath), fs.stat(lockPath)]);
    if (b.mtimeMs < a.mtimeMs - 1000) {
      issues.push({
        kind: "lockfile:stale",
        msg: "package.json より lockfile が古い（再生成を推奨）",
        severity: "medium",
        weight: 8,
      });
    }
  } catch {}

  const totalWeight = issues.reduce((s, i) => s + (i.weight || 0), 0);
  const score = Math.max(0, 100 - totalWeight);

  return { score, issues, totalPackages: entries.length };
}
