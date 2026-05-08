import { Command } from "commander";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { startServer } from "./server.js";
import {
  installNpmrc,
  uninstallNpmrc,
  npmrcStatus,
} from "./util/npmrc.js";
import { addAllow, removeAllow, listAllow } from "./store/allowlist.js";
import { scanPackage } from "./analyzer/index.js";
import { renderReport } from "./report.js";
import { log } from "./util/log.js";
import { DEFAULT_PORT, DEFAULT_HOST } from "./config.js";
import { installCommand } from "./commands/install.js";
import { doctorCommand } from "./commands/doctor.js";
import { fixCommand } from "./commands/fix.js";
import { diffCommand } from "./commands/diff.js";
import { auditCommand } from "./commands/audit.js";
import { configureIntel } from "./intel/client.js";
import { updateCommand, blocklistInfoCommand } from "./commands/update.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgJsonPath = path.resolve(__dirname, "..", "package.json");
const pkgJson = JSON.parse(await readFile(pkgJsonPath, "utf8"));

const program = new Command();

program
  .name("npm-guard")
  .description("Hardened npm: registry proxy + sandboxed install + threat intel")
  .version(pkgJson.version);

// === Proxy & registry control (Takumi-style) ===
program
  .command("start")
  .description("Start the npm-guard registry proxy server")
  .option("-p, --port <port>", "port to listen on", String(DEFAULT_PORT))
  .option("-h, --host <host>", "host to bind", DEFAULT_HOST)
  .action(async (opts) => {
    await startServer({ port: Number(opts.port), host: opts.host });
  });

program
  .command("npmrc-install")
  .description("Configure ~/.npmrc to use the npm-guard proxy")
  .option("-p, --port <port>", "proxy port", String(DEFAULT_PORT))
  .option("-h, --host <host>", "proxy host", DEFAULT_HOST)
  .action(async (opts) => {
    await installNpmrc({ port: Number(opts.port), host: opts.host });
  });

program
  .command("npmrc-uninstall")
  .description("Restore ~/.npmrc to the public npm registry")
  .action(async () => {
    await uninstallNpmrc();
  });

program
  .command("status")
  .description("Show current ~/.npmrc registry configuration")
  .action(async () => {
    await npmrcStatus();
  });

// === safenpm-style drop-in commands ===
program
  .command("install [packages...]")
  .alias("i")
  .description("Install npm dependencies with sandboxed lifecycle scripts")
  .option("--json", "machine-readable JSON output")
  .option("-S, --scan", "enable deep scan (lockfile, reputation, typosquat)")
  .option("-n, --dry-run", "preview without installing")
  .option("--loose", "loosen sandbox (no filesystem restrictions)")
  .option("--allow <list>", "comma-separated package allowlist", (s) => s.split(",").map((x) => x.trim()).filter(Boolean), [])
  .option("--no-report", "disable anonymous signal reporting")
  .option("-I, --interactive", "prompt on each blocked package")
  .action(async (packages, opts) => {
    const r = await installCommand({
      packages,
      json: opts.json,
      scan: opts.scan,
      dryRun: opts.dryRun,
      loose: opts.loose,
      allow: opts.allow,
      noReport: !opts.report,
      interactive: opts.interactive,
    });
    process.exit(r.code);
  });

program
  .command("doctor")
  .description("Project health report card with letter grade")
  .option("--json", "machine-readable JSON output")
  .action(async (opts) => {
    const r = await doctorCommand({ json: opts.json });
    if (r.score < 60) process.exit(2);
    if (r.score < 70) process.exit(1);
  });

program
  .command("fix")
  .description("Auto-fix typosquats and remove malicious packages")
  .option("--json", "machine-readable JSON output")
  .option("-n, --dry-run", "preview without applying")
  .action(async (opts) => {
    await fixCommand({ json: opts.json, dryRun: opts.dryRun });
  });

program
  .command("diff")
  .description("Show changes since last snapshot")
  .option("--snapshot", "save current state as the new baseline")
  .option("--json", "machine-readable JSON output")
  .action(async (opts) => {
    await diffCommand({ snapshot: opts.snapshot, json: opts.json });
  });

program
  .command("audit")
  .description("Show recent npm-guard audit log entries")
  .option("--json", "machine-readable JSON output")
  .option("-n, --limit <n>", "max entries", "30")
  .action(async (opts) => {
    await auditCommand({ json: opts.json, limit: Number(opts.limit) });
  });

// === Allowlist management ===
program
  .command("allow <package>")
  .description("Add a package (name or name@version) to the global allowlist")
  .action(async (spec) => {
    await addAllow(spec);
  });

program
  .command("disallow <package>")
  .description("Remove a package from the global allowlist")
  .action(async (spec) => {
    await removeAllow(spec);
  });

program
  .command("allowlist")
  .description("Show the current allowlist")
  .action(async () => {
    const list = await listAllow();
    if (list.length === 0) {
      log.info("(empty)");
      return;
    }
    for (const e of list) log.info(`  ${e}`);
  });

// === Single-package scan ===
program
  .command("scan <package>")
  .description("Scan a single package without installing")
  .option("--json", "print result as JSON")
  .action(async (spec, opts) => {
    const result = await scanPackage(spec);
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(renderReport(result));
    }
    if (result.decision === "block") process.exit(2);
    if (result.decision === "ask") process.exit(1);
  });

// === Compromised package blocklist (Shai-Hulud feed) ===
program
  .command("update")
  .description("Update the bundled blocklist of known-compromised packages")
  .option("--json", "machine-readable JSON output")
  .option("--source <url>", "blocklist source URL (overrides config)")
  .action(async (opts) => {
    const r = await updateCommand({ json: opts.json, source: opts.source });
    process.exit(r.code);
  });

program
  .command("blocklist-info")
  .description("Show metadata about the active compromised-package blocklist")
  .option("--json", "machine-readable JSON output")
  .action(async (opts) => {
    await blocklistInfoCommand({ json: opts.json });
  });

// === Threat intel configuration ===
const intel = program.command("intel").description("Configure the decentralized threat intel network");
intel.command("set <url>")
  .description("Set the intel server base URL")
  .action(async (url) => {
    await configureIntel({ baseUrl: url, reporting: true });
    log.ok(`intel base URL set to ${url}`);
  });
intel.command("disable")
  .description("Disable signal reporting (queries still work)")
  .action(async () => {
    await configureIntel({ baseUrl: undefined, reporting: false });
    log.ok("intel reporting disabled");
  });
intel.command("enable")
  .description("Enable signal reporting")
  .action(async () => {
    await configureIntel({ reporting: true });
    log.ok("intel reporting enabled");
  });

program.parseAsync(process.argv).catch((e) => {
  log.error(e?.stack || e);
  process.exit(1);
});
