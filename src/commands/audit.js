import { readAudit, AUDIT_LOG_PATH } from "../store/audit.js";
import { log } from "../util/log.js";

export async function auditCommand({ json = false, limit = 30 } = {}) {
  const items = await readAudit({ limit });
  if (json) {
    console.log(JSON.stringify({ path: AUDIT_LOG_PATH, items }, null, 2));
    return { items };
  }
  if (items.length === 0) {
    log.info("(no audit entries)");
    return { items };
  }
  log.info(`audit log: ${AUDIT_LOG_PATH}`);
  for (const e of items) {
    const ts = e.ts || "?";
    const c = e.command || e.decision || "?";
    let detail = "";
    if (e.summary) {
      detail = `blocked=${e.summary.blocked} clean=${e.summary.clean}`;
    } else if (e.name) {
      detail = `${e.name}@${e.version || "?"} score=${e.score ?? "?"}`;
    }
    log.info(`  ${ts} [${c}] ${detail}`);
  }
  return { items };
}
