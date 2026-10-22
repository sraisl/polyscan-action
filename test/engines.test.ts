import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_ENGINES,
  SUPPORTED_ENGINES,
  resolveEngines,
  unknownEngines,
} from "../src/engines";

test("resolveEngines expands empty input to default engines", () => {
  assert.deepEqual(resolveEngines(""), [...DEFAULT_ENGINES]);
});

test("resolveEngines expands all case-insensitively without OpenGrep or trufflehog", () => {
  assert.deepEqual(resolveEngines("ALL"), [...DEFAULT_ENGINES]);
  assert.equal(resolveEngines("all").includes("opengrep"), false);
  assert.equal(resolveEngines("all").includes("trufflehog"), false);
});

test("resolveEngines all runs oxlint and leaves ESLint opt-in", () => {
  assert.equal(resolveEngines("all").includes("oxlint"), true);
  assert.equal(resolveEngines("all").includes("eslint"), false);
  assert.deepEqual(unknownEngines(["eslint", "oxlint"]), []);
});

test("resolveEngines keeps explicit comma-separated selections", () => {
  assert.deepEqual(resolveEngines(" opengrep, gosec ,eslint "), [
    "opengrep",
    "gosec",
    "eslint",
  ]);
});

test("unknownEngines returns empty array for all-valid input", () => {
  assert.deepEqual(unknownEngines(["semgrep", "opengrep", "bandit", "trivy"]), []);
});

test("unknownEngines returns typos and unknown names", () => {
  assert.deepEqual(unknownEngines(["sempgrep", "bandit", "myengine"]), ["sempgrep", "myengine"]);
});

test("unknownEngines returns empty array for every supported engine", () => {
  assert.deepEqual(unknownEngines([...SUPPORTED_ENGINES]), []);
});
