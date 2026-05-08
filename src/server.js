import http from "node:http";
import { URL } from "node:url";
import { Readable } from "node:stream";
import { scanPackage } from "./analyzer/index.js";
import {
  UPSTREAM,
  DEFAULT_PORT,
  DEFAULT_HOST,
  ensureDataDir,
} from "./config.js";
import { log, appendEvent } from "./util/log.js";
import { fetchWithTimeout } from "./util/fetch.js";
import { renderReport } from "./report.js";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

// fetch() decodes responses automatically, so we must NOT forward the upstream
// content-encoding/length to the client (otherwise it tries to gunzip plain bytes).
const STRIP_FROM_RESPONSE = new Set([
  "content-encoding",
  "content-length",
]);

function copyReqHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    if (Array.isArray(v)) out[key] = v.join(", ");
    else if (typeof v === "string") out[key] = v;
  }
  return out;
}

function copyResHeaders(headers, contentTypeOverride) {
  const out = {};
  for (const [k, v] of headers) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    if (STRIP_FROM_RESPONSE.has(key)) continue;
    out[key] = v;
  }
  if (contentTypeOverride) out["content-type"] = contentTypeOverride;
  return out;
}

function isTarballPath(p) {
  return /\/-\/[^/]+\.tgz$/i.test(p);
}

function isReservedPath(p) {
  return p.startsWith("/-/");
}

function parsePkgPath(p) {
  // /<pkg> or /<pkg>/<version> or /@scope/<pkg> or /@scope/<pkg>/<version>
  const stripped = p.replace(/^\//, "").replace(/\/$/, "");
  if (!stripped) return null;
  const parts = stripped.split("/");
  if (parts[0].startsWith("@")) {
    if (parts.length < 2) return null;
    const name = `${parts[0]}/${decodeURIComponent(parts[1])}`;
    const version = parts[2] ? decodeURIComponent(parts[2]) : undefined;
    if (parts.length > 3) return null;
    return { name, version };
  }
  const name = decodeURIComponent(parts[0]);
  const version = parts[1] ? decodeURIComponent(parts[1]) : undefined;
  if (parts.length > 2) return null;
  return { name, version };
}

export async function startServer({
  port = DEFAULT_PORT,
  host = DEFAULT_HOST,
} = {}) {
  await ensureDataDir();

  const server = http.createServer(async (req, res) => {
    const start = Date.now();
    try {
      await handle(req, res);
    } catch (err) {
      log.error("handler error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "npm-guard internal error", message: String(err?.message || err) }));
      } else {
        try { res.end(); } catch {}
      }
    } finally {
      log.debug(`${req.method} ${req.url} -> ${res.statusCode} (${Date.now() - start}ms)`);
    }
  });

  return await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      log.ok(`npm-guard proxy listening on http://${host}:${port}`);
      log.info("Configure your project/global ~/.npmrc with:");
      log.info(`  registry=http://${host}:${port}/`);
      log.info("Tip: run `npm-guard install` to do that automatically.");
      resolve(server);
    });
  });
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = url.pathname;
  const method = (req.method || "GET").toUpperCase();

  if (method === "GET" && !isReservedPath(pathname) && isTarballPath(pathname)) {
    return redirectTarball(req, res, pathname);
  }

  if (method === "GET" && !isReservedPath(pathname)) {
    const parsed = parsePkgPath(pathname);
    if (parsed) {
      return await handleMetadata(req, res, parsed);
    }
  }

  return passthrough(req, res);
}

function redirectTarball(req, res, pathname) {
  const target = `${UPSTREAM}${pathname}`;
  res.writeHead(302, { location: target });
  res.end();
  log.debug("tarball redirect:", target);
}

async function handleMetadata(req, res, { name, version }) {
  const spec = version ? `${name}@${version}` : name;
  let result;
  try {
    result = await scanPackage(spec);
  } catch (e) {
    log.error("scan failed:", e?.message);
    return passthrough(req, res);
  }

  if (result.decision === "allow") {
    log.allow(`${result.name}${result.version ? "@" + result.version : ""} score=${result.score}`);
    appendEvent({ decision: "allow", name: result.name, version: result.version, score: result.score });
    return passthrough(req, res);
  }

  const text = renderReport(result);
  if (result.decision === "block") {
    log.blocked(`${result.name}@${result.version} score=${result.score}`);
    for (const f of result.findings) log.warn(`  · ${f.msg}`);
    appendEvent({ decision: "block", name: result.name, version: result.version, score: result.score, findings: result.findings });
  } else {
    log.ask(`${result.name}@${result.version} score=${result.score}`);
    for (const f of result.findings) log.warn(`  · ${f.msg}`);
    appendEvent({ decision: "ask", name: result.name, version: result.version, score: result.score, findings: result.findings });
  }

  res.writeHead(403, {
    "content-type": "application/json; charset=utf-8",
    "x-npm-guard-decision": result.decision,
    "x-npm-guard-score": String(result.score),
  });
  res.end(JSON.stringify(
    {
      error: "npm-guard",
      decision: result.decision,
      name: result.name,
      version: result.version,
      score: result.score,
      message: text,
      findings: result.findings,
      hint:
        result.decision === "ask"
          ? `許可するには: npm-guard allow ${result.name}@${result.version}`
          : "ブロックされました。詳細はサーバログを確認してください。",
    },
    null,
    2,
  ));
}

async function passthrough(req, res) {
  const target = UPSTREAM + req.url;
  const headers = copyReqHeaders(req.headers);
  let body;
  if (!["GET", "HEAD"].includes(req.method)) {
    body = req;
  }

  let upstreamRes;
  try {
    upstreamRes = await fetchWithTimeout(
      target,
      {
        method: req.method,
        headers,
        body,
        duplex: body ? "half" : undefined,
        redirect: "manual",
      },
      30000,
    );
  } catch (e) {
    log.error("upstream error:", e?.message);
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "upstream-error", message: String(e?.message || e) }));
    return;
  }

  // Stream metadata responses while rewriting tarball URLs (best effort)
  const contentType = upstreamRes.headers.get("content-type") || "";
  const isJsonMeta =
    req.method === "GET" &&
    contentType.includes("application/json") &&
    !isReservedPath(new URL(req.url, "http://x").pathname) &&
    !isTarballPath(new URL(req.url, "http://x").pathname);

  const outHeaders = copyResHeaders(upstreamRes.headers, contentType);

  if (isJsonMeta && upstreamRes.body) {
    const text = await upstreamRes.text();
    res.writeHead(upstreamRes.status, outHeaders);
    res.end(text);
    return;
  }

  res.writeHead(upstreamRes.status, outHeaders);
  if (!upstreamRes.body) {
    res.end();
    return;
  }
  const nodeStream = Readable.fromWeb(upstreamRes.body);
  nodeStream.pipe(res);
}
