import { UPSTREAM, DOWNLOADS_API } from "../config.js";
import { getCache, setCache } from "../store/cache.js";
import { fetchWithTimeout } from "../util/fetch.js";
import { log } from "../util/log.js";

function pkgPath(name) {
  if (name.startsWith("@")) {
    const [scope, rest] = name.split("/", 2);
    return `${scope}/${encodeURIComponent(rest)}`;
  }
  return encodeURIComponent(name);
}

export async function fetchMetadata(name) {
  const k = `meta:${name}`;
  const cached = getCache(k);
  if (cached !== undefined) return cached;
  const url = `${UPSTREAM}/${pkgPath(name)}`;
  try {
    const res = await fetchWithTimeout(url, {
      headers: { accept: "application/json" },
    });
    if (!res.ok) {
      setCache(k, null);
      return null;
    }
    const json = await res.json();
    setCache(k, json);
    return json;
  } catch (e) {
    log.debug("metadata fetch error:", e?.message);
    return null;
  }
}

export async function fetchDownloads(name, period = "last-week") {
  const k = `dl:${period}:${name}`;
  const cached = getCache(k);
  if (cached !== undefined) return cached;
  const url = `${DOWNLOADS_API}/point/${period}/${pkgPath(name)}`;
  try {
    const res = await fetchWithTimeout(url);
    if (!res.ok) {
      setCache(k, null);
      return null;
    }
    const json = await res.json();
    setCache(k, json);
    return json;
  } catch (e) {
    log.debug("downloads fetch error:", e?.message);
    return null;
  }
}
