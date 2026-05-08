import crypto from "node:crypto";
import { fetchWithTimeout } from "../util/fetch.js";
import { log } from "../util/log.js";
import { readUserConfig, writeUserConfig } from "../config.js";

const DEFAULT_BASE = process.env.NPM_GUARD_INTEL_URL || "";

function dailySalt() {
  const day = new Date().toISOString().slice(0, 10);
  return crypto.createHash("sha256").update(`npmguard-${day}`).digest("hex");
}

export function reporterId() {
  return crypto.createHash("sha256").update(dailySalt()).digest("hex").slice(0, 32);
}

export async function intelEnabled() {
  if (process.env.NPM_GUARD_NO_REPORT === "1") return false;
  const cfg = await readUserConfig();
  if (cfg.intelReporting === false) return false;
  return Boolean(cfg.intelBaseUrl || DEFAULT_BASE);
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
  if (!(await intelEnabled())) return null;
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
  if (!(await intelEnabled())) return;
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
