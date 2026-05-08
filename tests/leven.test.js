import { test } from "node:test";
import assert from "node:assert/strict";
import { leven } from "../src/util/leven.js";

test("leven: identical", () => {
  assert.equal(leven("abc", "abc"), 0);
});

test("leven: insertion", () => {
  assert.equal(leven("abc", "abcd"), 1);
});

test("leven: substitution", () => {
  assert.equal(leven("kitten", "sitting"), 3);
});

test("leven: empty", () => {
  assert.equal(leven("", "abc"), 3);
  assert.equal(leven("abc", ""), 3);
});
