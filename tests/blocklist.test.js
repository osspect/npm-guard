import { test } from "node:test";
import assert from "node:assert/strict";
import {
  loadBlocklist,
  isCompromised,
  checkBlocklist,
  blocklistMeta,
  clearBlocklistCache,
} from "../src/analyzer/blocklist.js";

test("blocklist: bundled list loads with 1k+ entries", async () => {
  clearBlocklistCache();
  const meta = await blocklistMeta();
  assert.ok(meta.totalEntries > 1000, `expected >1000 entries, got ${meta.totalEntries}`);
});

test("blocklist: known compromised version flagged exact", async () => {
  clearBlocklistCache();
  // @ctrl/tinycolor 4.1.1 is in the Shai-Hulud list per the Cobenian dataset
  const r = await isCompromised("@ctrl/tinycolor", "4.1.1");
  assert.ok(r);
  assert.equal(r.exact, true);
});

test("blocklist: clean package returns null", async () => {
  clearBlocklistCache();
  const r = await isCompromised("definitely-not-in-blocklist-xyz", "1.0.0");
  assert.equal(r, null);
});

test("blocklist: known name with unknown version reports other-version finding", async () => {
  clearBlocklistCache();
  const findings = await checkBlocklist("@ctrl/tinycolor", "999.0.0");
  assert.ok(findings.length >= 1);
  assert.equal(findings[0].kind, "blocklist:other-version");
});

test("blocklist: exact match yields critical-severity finding with weight 100", async () => {
  clearBlocklistCache();
  const findings = await checkBlocklist("@ctrl/tinycolor", "4.1.1");
  assert.ok(findings.some((f) => f.kind === "blocklist:exact" && f.weight === 100));
});
