// Typosquat attack pattern detectors beyond simple Levenshtein distance.
// Each returns null or an array of { popular, kind, weight } findings.

import { POPULAR } from "./popular.js";

const POPULAR_SET = new Set(POPULAR);

function lookalike(name) {
  return name
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/rn/g, "m")
    .replace(/cl/g, "d")
    .replace(/vv/g, "w");
}

function charSwapVariants(name) {
  const out = new Set();
  for (let i = 0; i < name.length - 1; i++) {
    out.add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2));
  }
  return [...out];
}

function omittedChar(name) {
  const out = new Set();
  for (let i = 0; i < name.length; i++) {
    out.add(name.slice(0, i) + name.slice(i + 1));
  }
  return [...out];
}

export function detectAttackPatterns(name) {
  const findings = [];
  if (POPULAR_SET.has(name)) return findings;

  // 1. Lookalike substitution (0->o, rn->m etc.)
  const sub = lookalike(name);
  if (sub !== name && POPULAR_SET.has(sub)) {
    findings.push({
      popular: sub,
      kind: "typosquat:substitution",
      msg: `文字置換 (0→o, rn→m など) で人気パッケージ ${sub} と一致`,
      weight: 8,
    });
  }

  // 2. Character swap (axois -> axios)
  for (const v of charSwapVariants(name)) {
    if (POPULAR_SET.has(v)) {
      findings.push({
        popular: v,
        kind: "typosquat:char-swap",
        msg: `隣接文字の入れ替えで人気パッケージ ${v} と一致`,
        weight: 8,
      });
      break;
    }
  }

  // 3a. Typo has an EXTRA char vs legitimate (lodashx -> lodash)
  for (const v of omittedChar(name)) {
    if (v.length >= 3 && POPULAR_SET.has(v)) {
      findings.push({
        popular: v,
        kind: "typosquat:omitted-char",
        msg: `1文字省略で人気パッケージ ${v} と一致`,
        weight: 7,
      });
      break;
    }
  }

  // 3b. Typo is MISSING a char vs legitimate (reac -> react, lodas -> lodash)
  if (!findings.some((x) => x.kind === "typosquat:omitted-char")) {
    for (const p of POPULAR) {
      if (p.length - name.length !== 1) continue;
      for (const variant of omittedChar(p)) {
        if (variant === name) {
          findings.push({
            popular: p,
            kind: "typosquat:omitted-char",
            msg: `1文字不足で人気パッケージ ${p} と一致`,
            weight: 7,
          });
          break;
        }
      }
      if (findings.some((x) => x.kind === "typosquat:omitted-char")) break;
    }
  }

  // 4. Scope confusion (@types/lodash vs lodash)
  if (name.startsWith("@") && name.includes("/")) {
    const bare = name.slice(name.indexOf("/") + 1);
    if (POPULAR_SET.has(bare) && !POPULAR_SET.has(name)) {
      findings.push({
        popular: bare,
        kind: "typosquat:scope-confusion",
        msg: `スコープ付きパッケージ ${name} がスコープ無しの人気パッケージ ${bare} を装っている可能性`,
        weight: 6,
      });
    }
  } else {
    // Reverse: bare name imitating a known scoped package
    for (const p of POPULAR) {
      if (p.startsWith("@") && p.endsWith(`/${name}`)) {
        findings.push({
          popular: p,
          kind: "typosquat:scope-strip",
          msg: `${p} のスコープ部分を取り除いた名前と一致`,
          weight: 5,
        });
        break;
      }
    }
  }

  // 5. Common suffix attack (lodash-helper, lodash-utils, lodash-cli)
  const suffixes = ["-helper", "-utils", "-utility", "-cli", "-fix", "-fixed", "-patch"];
  for (const suf of suffixes) {
    if (name.endsWith(suf)) {
      const base = name.slice(0, -suf.length);
      if (POPULAR_SET.has(base)) {
        findings.push({
          popular: base,
          kind: "typosquat:suffix-attack",
          msg: `人気パッケージ ${base} に "${suf}" を付けたなりすまし疑い`,
          weight: 4,
        });
        break;
      }
    }
  }

  return findings;
}
