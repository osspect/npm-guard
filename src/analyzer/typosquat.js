import { POPULAR } from "../data/popular.js";
import { leven } from "../util/leven.js";
import { TYPOSQUAT_DISTANCE } from "../config.js";
import { detectAttackPatterns } from "../data/attack-patterns.js";

const POPULAR_SET = new Set(POPULAR);

export function checkTyposquat(name) {
  if (!name || POPULAR_SET.has(name)) return [];

  const findings = [];

  let best = null;
  for (const p of POPULAR) {
    if (Math.abs(p.length - name.length) > TYPOSQUAT_DISTANCE) continue;
    const d = leven(name, p);
    if (d > 0 && d <= TYPOSQUAT_DISTANCE) {
      if (!best || d < best.distance) {
        best = { popular: p, distance: d };
        if (d === 1) break;
      }
    }
  }
  if (best) {
    findings.push({
      kind: "typosquat:leven",
      msg: `人気パッケージ ${best.popular} と編集距離 ${best.distance}（タイポスクワット疑い）`,
      weight: best.distance === 1 ? 5 : 4,
      similarTo: best.popular,
      distance: best.distance,
      severity: "high",
    });
  }

  for (const f of detectAttackPatterns(name)) {
    findings.push({
      kind: f.kind,
      msg: f.msg,
      weight: f.weight,
      similarTo: f.popular,
      severity: "high",
    });
  }

  return findings;
}
