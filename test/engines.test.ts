import test from "node:test";
import assert from "node:assert/strict";

import { ALL_ENGINES, resolveEngines } from "../src/engines";

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
