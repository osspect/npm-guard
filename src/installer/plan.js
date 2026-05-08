import fs from "node:fs/promises";
import path from "node:path";

async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

export async function discoverPackages(cwd = process.cwd()) {
  const root = path.join(cwd, "node_modules");
  const out = [];
  await walk(root, root, out);
  return out;
}

async function walk(rootDir, dir, out, depth = 0) {
  if (depth > 6) return;
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (e.name === ".bin" || e.name === ".package-lock.json") continue;
    const full = path.join(dir, e.name);
    if (e.name.startsWith("@")) {
      await walk(rootDir, full, out, depth + 1);
      continue;
    }
    const pkgFile = path.join(full, "package.json");
    const pkg = await readJson(pkgFile);
    if (!pkg) {
      const nested = path.join(full, "node_modules");
      try {
        const st = await fs.stat(nested);
        if (st.isDirectory()) await walk(rootDir, nested, out, depth + 1);
      } catch {}
      continue;
    }
    const scripts = pkg.scripts || {};
    const hooks = {};
    for (const h of ["preinstall", "install", "postinstall"]) {
      if (typeof scripts[h] === "string" && scripts[h].length > 0) hooks[h] = scripts[h];
    }
    out.push({
      name: pkg.name,
      version: pkg.version,
      dir: full,
      hooks,
      hasHooks: Object.keys(hooks).length > 0,
    });
    const nested = path.join(full, "node_modules");
    try {
      const st = await fs.stat(nested);
      if (st.isDirectory()) await walk(rootDir, nested, out, depth + 1);
    } catch {}
  }
}
