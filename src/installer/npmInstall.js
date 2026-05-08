import { spawn } from "node:child_process";

export function runNpmInstall({ args = [], cwd = process.cwd(), env = process.env } = {}) {
  return new Promise((resolve) => {
    const npm = process.platform === "win32" ? "npm.cmd" : "npm";
    const finalArgs = [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--loglevel=error",
      ...args,
    ];
    const child = spawn(npm, finalArgs, { cwd, env, stdio: "inherit" });
    child.on("close", (code) => resolve({ code: code ?? -1 }));
    child.on("error", (err) => resolve({ code: -1, error: String(err?.message || err) }));
  });
}
