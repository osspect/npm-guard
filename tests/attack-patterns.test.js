import { test } from "node:test";
import assert from "node:assert/strict";
import { detectAttackPatterns } from "../src/data/attack-patterns.js";

test("attack: substitution rn -> m for chalk-like (no false positive)", () => {
  const f = detectAttackPatterns("totally-unrelated");
  assert.deepEqual(f, []);
});

test("attack: char-swap axois -> axios", () => {
  const f = detectAttackPatterns("axois");
  assert.ok(f.some((x) => x.kind === "typosquat:char-swap" && x.popular === "axios"));
});

test("attack: scope confusion @evil/lodash imitates lodash", () => {
  const f = detectAttackPatterns("@evil/lodash");
  assert.ok(f.some((x) => x.kind === "typosquat:scope-confusion" && x.popular === "lodash"));
});

test("attack: suffix attack lodash-helper imitates lodash", () => {
  const f = detectAttackPatterns("lodash-helper");
  assert.ok(f.some((x) => x.kind === "typosquat:suffix-attack" && x.popular === "lodash"));
});

test("attack: omitted-char react -> reac", () => {
  const f = detectAttackPatterns("reac");
  assert.ok(f.some((x) => x.kind === "typosquat:omitted-char" && x.popular === "react"));
});
