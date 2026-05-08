import { test } from "node:test";
import assert from "node:assert/strict";
import { checkTyposquat } from "../src/analyzer/typosquat.js";

test("typosquat: exact popular -> []", () => {
  assert.deepEqual(checkTyposquat("react"), []);
});

test("typosquat: 1-edit close to react", () => {
  const f = checkTyposquat("rect");
  assert.ok(f.length >= 1);
  const lev = f.find((x) => x.kind === "typosquat:leven");
  assert.ok(lev);
  assert.equal(lev.similarTo, "react");
  assert.equal(lev.distance, 1);
});

test("typosquat: far away -> []", () => {
  assert.deepEqual(checkTyposquat("totally-unrelated-name-xyz"), []);
});

test("typosquat: scoped package not crashing", () => {
  const f = checkTyposquat("@types/nodee");
  assert.ok(Array.isArray(f));
});
