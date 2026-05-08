import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import crypto from "node:crypto";
import { macosProfile, firejailArgs } from "./profile.js";

function which(cmd) {
  const r = spawnSync(process.platform === "win32" ? "where" : "which", [cmd], {
    encoding: "utf8",
  });
  if (r.status === 0) return r.stdout.trim().split(/\r?\n/)[0];
  return null;
}

export function detectBackend() {
  if (process.platform === "darwin") {
    return which("sandbox-exec") ? "macos-sandbox-exec" : "none";
  }
  if (process.platform === "linux") {
    return which("firejail") ? "linux-firejail" : "none";
  }
  if (process.platform === "win32") {
    return "windows-best-effort";
  }
  return "none";
}

export function backendDescription(b = detectBackend()) {
  switch (b) {
    case "macos-sandbox-exec":
      return "sandbox-exec (macOS)";
    case "linux-firejail":
      return "firejail (Linux)";
    case "windows-best-effort":
      return "Windows (best effort - no kernel sandbox)";
    default:
      return "no sandbox available (script disabled)";
  }
}

async function writeTmpFile(content, prefix) {
  const f = path.join(
    tmpdir(),
    `${prefix}-${crypto.randomBytes(6).toString("hex")}.sb`,
  );
  await fs.writeFile(f, content);
  return f;
}

export async function runScriptSandboxed({
  command,
  cwd,
  env = process.env,
  allowPaths = [],
  loose = false,
  backend = detectBackend(),
  timeoutMs = 60000,
} = {}) {
  if (!command) {
    return { backend, status: "skipped", code: 0, stdout: "", stderr: "" };
  }

  if (backend === "macos-sandbox-exec") {
    const profile = macosProfile({ allowPaths, cwd });
    const profileFile = await writeTmpFile(profile, "npmguard");
    const args = ["-f", profileFile, "/bin/sh", "-c", command];
    const r = spawnSync("sandbox-exec", args, {
      cwd,
      env,
      encoding: "utf8",
      timeout: timeoutMs,
    });
    await fs.rm(profileFile, { force: true });
    return {
      backend,
      status: r.status === 0 ? "ok" : r.signal === "SIGTERM" ? "timeout" : "violation",
      code: r.status ?? -1,
      signal: r.signal,
      stdout: r.stdout || "",
      stderr: r.stderr || "",
    };
  }

  if (backend === "linux-firejail") {
    const args = firejailArgs({ cwd, allowPaths });
    if (loose) {
      const idx = args.indexOf("--net=none");
      if (idx >= 0) args.splice(idx, 1);
    }
    args.push("/bin/sh", "-c", command);
    const r = spawnSync("firejail", args, {
      cwd,
      env,
      encoding: "utf8",
      timeout: timeoutMs,
    });
    return {
      backend,
      status: r.status === 0 ? "ok" : "violation",
      code: r.status ?? -1,
      stdout: r.stdout || "",
      stderr: r.stderr || "",
    };
  }

  if (backend === "windows-best-effort") {
    // We don't enforce kernel-level sandboxing on Windows in this minimal port.
    // We refuse to run by default unless explicitly loose.
    if (!loose) {
      return {
        backend,
        status: "blocked-no-sandbox",
        code: -1,
        stdout: "",
        stderr: "Sandbox not available on Windows; rerun with --loose to skip enforcement.",
      };
    }
    const r = spawnSync(process.env.ComSpec || "cmd.exe", ["/c", command], {
      cwd,
      env,
      encoding: "utf8",
      timeout: timeoutMs,
    });
    return {
      backend,
      status: r.status === 0 ? "ok" : "violation",
      code: r.status ?? -1,
      stdout: r.stdout || "",
      stderr: r.stderr || "",
    };
  }

  return {
    backend: "none",
    status: "blocked-no-sandbox",
    code: -1,
    stdout: "",
    stderr: "No sandbox backend; install firejail (Linux) or run on macOS to enable.",
  };
}
