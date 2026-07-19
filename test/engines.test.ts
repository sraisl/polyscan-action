import test from "node:test";
import assert from "node:assert/strict";

import { ALL_ENGINES, resolveEngines, unknownEngines } from "../src/engines";

test("resolveEngines expands empty input to all engines", () => {
  assert.deepEqual(resolveEngines(""), [...ALL_ENGINES]);
});

test("resolveEngines expands all case-insensitively", () => {
  assert.deepEqual(resolveEngines("ALL"), [...ALL_ENGINES]);
});

test("resolveEngines keeps explicit comma-separated selections", () => {
  assert.deepEqual(resolveEngines(" semgrep, bandit ,eslint "), [
    "semgrep",
    "bandit",
    "eslint",
  ]);
});

test("unknownEngines returns empty array for all-valid input", () => {
  assert.deepEqual(unknownEngines(["semgrep", "bandit", "trivy"]), []);
});

test("unknownEngines returns typos and unknown names", () => {
  assert.deepEqual(unknownEngines(["sempgrep", "bandit", "myengine"]), ["sempgrep", "myengine"]);
});

test("unknownEngines returns empty array for the full engine list", () => {
  assert.deepEqual(unknownEngines([...ALL_ENGINES]), []);
});
