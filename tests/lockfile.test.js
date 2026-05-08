import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { auditLockfile } from "../src/analyzer/lockfile.js";

async function tmpProject(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "npmguard-test-"));
  for (const [name, content] of Object.entries(files)) {
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

test("lockfile: missing lockfile -> medium issue", async () => {
  const dir = await tmpProject({ "package.json": "{}" });
  const r = await auditLockfile(dir);
  assert.ok(r.issues.some((i) => i.kind === "lockfile:missing"));
});

test("lockfile: missing integrity -> high issue", async () => {
  const dir = await tmpProject({
    "package.json": "{}",
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/foo": {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
        },
      },
    }),
  });
  const r = await auditLockfile(dir);
  assert.ok(r.issues.some((i) => i.kind === "lockfile:missing-integrity"));
});

test("lockfile: weak sha1 algo flagged", async () => {
  const dir = await tmpProject({
    "package.json": "{}",
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/legacy": {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/legacy/-/legacy-1.0.0.tgz",
          integrity: "sha1-abcdefg",
        },
      },
    }),
  });
  const r = await auditLockfile(dir);
  assert.ok(r.issues.some((i) => i.kind === "lockfile:weak-algo"));
});
