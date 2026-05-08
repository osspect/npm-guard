import { scanPackage } from "../analyzer/index.js";
import { checkIntel } from "../intel/client.js";

/**
 * Risk snapshot for a single dependency @ version (used by continuous watch).
 */
export async function computeRiskSnapshot(name, version) {
  const r = await scanPackage(`${name}@${version}`);
  let intel = null;
  try {
    intel = await checkIntel(name, version);
  } catch {
    intel = null;
  }
  const blocklistExact = r.findings.some((f) => f.kind === "blocklist:exact");

  return {
    decision: r.decision,
    score: r.score,
    blocklist: blocklistExact,
    intelFlagged: intel?.flagged === true,
    checkedAt: new Date().toISOString(),
  };
}

function riskTier(snap) {
  if (!snap) return 0;
  if (snap.blocklist || snap.intelFlagged || snap.decision === "block") return 3;
  if (snap.decision === "ask") return 2;
  return 1;
}

/**
 * First snapshot after registration → no alert (baseline).
 * Alert when risk strictly worsens vs previous stored snapshot.
 */
export function riskWorsened(prev, next) {
  if (!prev || !next) return false;
  return riskTier(next) > riskTier(prev);
}

export function formatRiskSummary(snap, name, version) {
  const bits = [];
  if (snap.blocklist) bits.push("blocklist");
  if (snap.intelFlagged) bits.push("intel-flagged");
  bits.push(`${snap.decision}(${snap.score})`);
  return `${name}@${version}: ${bits.join(", ")}`;
}
