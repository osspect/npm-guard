import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSpec } from "../src/analyzer/spec.js";

test("parseSpec: name only", () => {
  assert.deepEqual(parseSpec("lodash"), { name: "lodash", version: undefined });
});

test("parseSpec: name@version", () => {
  assert.deepEqual(parseSpec("lodash@4.17.21"), { name: "lodash", version: "4.17.21" });
});

test("parseSpec: scoped name", () => {
  assert.deepEqual(parseSpec("@types/node"), { name: "@types/node", version: undefined });
});

test("parseSpec: scoped name@version", () => {
  assert.deepEqual(parseSpec("@types/node@22.0.0"), { name: "@types/node", version: "22.0.0" });
});

test("parseSpec: empty", () => {
  assert.deepEqual(parseSpec(""), { name: "", version: undefined });
});
