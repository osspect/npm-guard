import { fetchMetadata } from "./registry.js";
import { checkLifecycle } from "./lifecycle.js";
import { checkFreshness } from "./freshness.js";
import { checkMaintainers } from "./maintainers.js";
import { checkDownloads } from "./downloads.js";
import { checkTyposquat } from "./typosquat.js";
import { checkAdvisories } from "./advisories.js";
import { checkBlocklist } from "./blocklist.js";
import { checkMaintainerChange } from "./maintainerChange.js";
import { isAllowed } from "../store/allowlist.js";
import { THRESHOLDS } from "../config.js";
import { parseSpec } from "./spec.js";

function decide(score) {
  if (score >= THRESHOLDS.block) return "block";
  if (score >= THRESHOLDS.ask) return "ask";
  return "allow";
}

export async function scanPackage(spec, opts = {}) {
  const { name, version: specVersion } = parseSpec(spec);
  if (!name) {
    return {
      decision: "allow",
      score: 0,
      name: spec,
      version: undefined,
      findings: [{ kind: "input", msg: "パッケージ名を解釈できませんでした", weight: 0 }],
    };
  }

  // 1. Known-compromised package list (Shai-Hulud / curated). Highest priority.
  const blocklistFindings = await checkBlocklist(name, specVersion);
  const exact = blocklistFindings.find((f) => f.kind === "blocklist:exact");
  if (exact && !(await isAllowed(name, specVersion))) {
    return {
      decision: "block",
      score: exact.weight,
      name,
      version: specVersion,
      findings: blocklistFindings,
    };
  }

  const meta = await fetchMetadata(name);
  if (!meta) {
    if (blocklistFindings.length > 0) {
      const score = blocklistFindings.reduce((s, f) => s + (f.weight || 0), 0);
      return { decision: decide(score), score, name, version: specVersion, findings: blocklistFindings };
    }
    return {
      decision: "allow",
      score: 0,
      name,
      version: specVersion,
      findings: [{ kind: "metadata:missing", msg: "メタデータを取得できませんでした（pass-through）", weight: 0 }],
    };
  }

  const version = specVersion || meta["dist-tags"]?.latest;
  if (!version || !meta.versions?.[version]) {
    const findings = [...blocklistFindings];
    findings.push(...checkTyposquat(name));
    findings.push(...await checkDownloads(name));
    const score = findings.reduce((s, f) => s + (f.weight || 0), 0);
    return { decision: decide(score), score, name, version, findings };
  }

  if (await isAllowed(name, version)) {
    return {
      decision: "allow",
      score: 0,
      name,
      version,
      findings: [{ kind: "allowlist", msg: "allowlist に登録されています", weight: 0 }],
    };
  }

  // Re-check blocklist with resolved version (in case spec was bare name)
  const versionedBlocklist = specVersion ? blocklistFindings : await checkBlocklist(name, version);
  const exactRevisited = versionedBlocklist.find((f) => f.kind === "blocklist:exact");
  if (exactRevisited) {
    return {
      decision: "block",
      score: exactRevisited.weight,
      name,
      version,
      findings: versionedBlocklist,
    };
  }

  const findings = [...versionedBlocklist];
  findings.push(...checkLifecycle(meta, version));
  findings.push(...checkFreshness(meta, version));
  findings.push(...checkMaintainers(meta, version));
  findings.push(...await checkDownloads(name));
  findings.push(...checkTyposquat(name));
  findings.push(...await checkAdvisories(name, version));
  findings.push(...await checkMaintainerChange(name, version));

  const score = findings.reduce((s, f) => s + (f.weight || 0), 0);
  return { decision: decide(score), score, name, version, findings };
}
