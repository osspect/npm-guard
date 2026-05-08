import crypto from "node:crypto";
import { fetchWithTimeout } from "../util/fetch.js";
import { log } from "../util/log.js";
import { readUserConfig, writeUserConfig } from "../config.js";

// Canonical community endpoint operated by @osspect.
// Override per machine with `npm-guard intel set <url>` or `NPM_GUARD_INTEL_URL`.
// Disable with `npm-guard intel disable` or `NPM_GUARD_NO_REPORT=1`.
export const DEFAULT_INTEL_URL = "https://intel.npmguard.dev";

const DEFAULT_BASE = process.env.NPM_GUARD_INTEL_URL || DEFAULT_INTEL_URL;

function dailySalt() {
  const day = new Date().toISOString().slice(0, 10);
  return crypto.createHash("sha256").update(`npmguard-${day}`).digest("hex");
}

export function reporterId() {
  return crypto.createHash("sha256").update(dailySalt()).digest("hex").slice(0, 32);
}

/** True when anonymous signal reporting to the intel server is allowed. */
export async function intelReportingEnabled() {
  if (process.env.NPM_GUARD_NO_REPORT === "1") return false;
  const cfg = await readUserConfig();
  if (cfg.intelReporting === false) return false;
  return await intelQueriesEnabled();
}

/** True when GET /v1/check queries are allowed (independent of reporting). */
export async function intelQueriesEnabled() {
  if (process.env.NPM_GUARD_NO_INTEL === "1") return false;
  const cfg = await readUserConfig();
  return Boolean(process.env.NPM_GUARD_INTEL_URL || cfg.intelBaseUrl || DEFAULT_BASE);
}

/** @deprecated use intelReportingEnabled */
export async function intelEnabled() {
  return intelReportingEnabled();
}

async function baseUrl() {
  const cfg = await readUserConfig();
  return cfg.intelBaseUrl || DEFAULT_BASE;
}

export async function configureIntel({ baseUrl: url, reporting } = {}) {
  return await writeUserConfig({
    intelBaseUrl: url,
    intelReporting: reporting !== false,
  });
}

export async function checkIntel(name, version) {
  if (!(await intelQueriesEnabled())) return null;
  const url = `${await baseUrl()}/v1/check?name=${encodeURIComponent(name)}&version=${encodeURIComponent(version || "")}`;
  try {
    const res = await fetchWithTimeout(url, {}, 4000);
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    log.debug("intel check failed:", e?.message);
    return null;
  }
}

export async function reportSignal({ name, version, scriptHash, category, severity }) {
  if (!(await intelReportingEnabled())) return;
  try {
    await fetchWithTimeout(
      `${await baseUrl()}/v1/signal`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-reporter-id": reporterId(),
        },
        body: JSON.stringify({
          package: name,
          version,
          scriptHash: scriptHash || null,
          category,
          severity,
          ts: new Date().toISOString(),
        }),
      },
      4000,
    );
  } catch (e) {
    log.debug("intel signal failed:", e?.message);
  }
}
