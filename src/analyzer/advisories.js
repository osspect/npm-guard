import { OSV_API } from "../config.js";
import { getCache, setCache } from "../store/cache.js";
import { fetchWithTimeout } from "../util/fetch.js";
import { log } from "../util/log.js";

function severityWeight(severity) {
  if (!severity) return 4;
  const upper = String(severity).toUpperCase();
  if (upper.includes("CRITICAL")) return 8;
  if (upper.includes("HIGH")) return 6;
  if (upper.includes("MODERATE") || upper.includes("MEDIUM")) return 4;
  if (upper.includes("LOW")) return 2;
  return 4;
}

function pickSeverity(vuln) {
  const ds = vuln?.database_specific?.severity;
  if (ds) return ds;
  const arr = vuln?.severity;
  if (Array.isArray(arr) && arr.length > 0) {
    return arr[0]?.score || arr[0]?.type || "";
  }
  return "";
}

export async function checkAdvisories(name, version) {
  const k = `osv:${name}@${version}`;
  const cached = getCache(k);
  if (cached !== undefined) return cached;

  let result = [];
  try {
    const res = await fetchWithTimeout(OSV_API, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        package: { ecosystem: "npm", name },
        version,
      }),
    });

    if (res.ok) {
      const data = await res.json();
      const vulns = data?.vulns || [];
      for (const v of vulns) {
        const sev = pickSeverity(v);
        const id = v.id || "OSV";
        const aliases = (v.aliases || []).join(", ");
        const summary = v.summary || v.details?.slice(0, 120) || "";
        result.push({
          kind: "advisory",
          msg: `脆弱性 ${id}${aliases ? ` (${aliases})` : ""}${sev ? ` [${sev}]` : ""}: ${summary}`,
          weight: severityWeight(sev),
          osvId: id,
          severity: sev,
        });
      }
    }
  } catch (e) {
    log.debug("OSV query failed:", e?.message);
  }

  setCache(k, result);
  return result;
}
