import { test } from "node:test";
import assert from "node:assert/strict";
import { riskWorsened } from "../src/watch/riskSnapshot.js";

test("riskWorsened: clean → intel flagged", () => {
  assert.equal(
    riskWorsened(
      { decision: "allow", score: 1, blocklist: false, intelFlagged: false },
      { decision: "allow", score: 1, blocklist: false, intelFlagged: true },
    ),
    true,
  );
});

test("riskWorsened: allow → ask", () => {
  assert.equal(
    riskWorsened(
      { decision: "allow", score: 2, blocklist: false, intelFlagged: false },
      { decision: "ask", score: 5, blocklist: false, intelFlagged: false },
    ),
    true,
  );
});

test("riskWorsened: baseline block stays block → no alert", () => {
  assert.equal(
    riskWorsened(
      { decision: "block", score: 100, blocklist: true, intelFlagged: false },
      { decision: "block", score: 100, blocklist: true, intelFlagged: true },
    ),
    false,
  );
});

test("riskWorsened: no change", () => {
  assert.equal(
    riskWorsened(
      { decision: "allow", score: 1, blocklist: false, intelFlagged: false },
      { decision: "allow", score: 1, blocklist: false, intelFlagged: false },
    ),
    false,
  );
});
