import { LIFECYCLE_PATTERNS } from "../data/patterns.js";

const HOOKS = ["preinstall", "install", "postinstall"];
const SCORE_CAP = 100;

function truncate(s, n = 140) {
  if (typeof s !== "string") return "";
  return s.length > n ? s.slice(0, n) + "..." : s;
}

export function checkLifecycle(meta, version) {
  const v = meta?.versions?.[version];
  if (!v) return [];
  const scripts = v.scripts || {};
  const findings = [];
  let total = 0;

  for (const hook of HOOKS) {
    const body = scripts[hook];
    if (!body) continue;

    findings.push({
      kind: `lifecycle:${hook}:exists`,
      msg: `${hook} スクリプトが定義されています: ${truncate(body)}`,
      weight: 1,
      hook,
      severity: "info",
    });
    total += 1;

    for (const p of LIFECYCLE_PATTERNS) {
      if (p.re.test(body)) {
        const w = total + p.weight > SCORE_CAP ? SCORE_CAP - total : p.weight;
        if (w <= 0) continue;
        total += w;
        findings.push({
          kind: `${p.kind}:${hook}`,
          msg: `${hook}: ${p.msg}`,
          weight: w,
          severity: p.severity,
          hook,
          snippet: truncate(body),
        });
      }
    }
  }

  return findings;
}

export function lifecycleRiskLevel(score) {
  if (score >= 60) return "critical";
  if (score >= 30) return "suspicious";
  if (score >= 1) return "low";
  return "clean";
}
