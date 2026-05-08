import path from "node:path";
import {
  detectBackend,
  backendDescription,
  runScriptSandboxed,
} from "../sandbox/index.js";
import { log } from "../util/log.js";
import kleur from "kleur";

const HOOKS_ORDER = ["preinstall", "install", "postinstall"];

export async function runHooksSandboxed({
  packages,
  cwd,
  allowList = [],
  loose = false,
  json = false,
} = {}) {
  const backend = detectBackend();
  const backendDesc = backendDescription(backend);
  if (!json) log.info(kleur.gray(`sandbox backend: ${backendDesc}`));

  const results = [];
  for (const p of packages) {
    if (!p.hasHooks) continue;
    const allowed = allowList.includes(p.name) || matchScopeWildcard(allowList, p.name);

    for (const hook of HOOKS_ORDER) {
      const cmd = p.hooks[hook];
      if (!cmd) continue;

      if (allowed) {
        if (!json) log.info(kleur.gray(`[allow] ${p.name}@${p.version} ${hook} (allowlisted)`));
        results.push({ name: p.name, version: p.version, hook, status: "allowed", backend });
        continue;
      }

      const r = await runScriptSandboxed({
        command: cmd,
        cwd: p.dir,
        env: process.env,
        allowPaths: [path.join(cwd, "node_modules"), p.dir],
        loose,
        backend,
      });

      if (!json) {
        const tag =
          r.status === "ok" ? kleur.green("[ok]") :
          r.status === "violation" ? kleur.red("[block]") :
          r.status === "blocked-no-sandbox" ? kleur.red("[no-sandbox]") :
          kleur.yellow(`[${r.status}]`);
        log.info(`${tag} ${p.name}@${p.version} ${hook}`);
        if (r.stderr) log.warn("  stderr:", r.stderr.split(/\r?\n/)[0].slice(0, 200));
      }

      results.push({
        name: p.name,
        version: p.version,
        hook,
        status: r.status,
        code: r.code,
        backend: r.backend,
        stderr: r.stderr?.slice(0, 500) || "",
      });
    }
  }

  return { backend, backendDesc, results };
}

function matchScopeWildcard(list, name) {
  for (const e of list) {
    if (e.endsWith("/*") && name.startsWith(e.slice(0, -1))) return true;
  }
  return false;
}
