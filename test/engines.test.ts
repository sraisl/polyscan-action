import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_ENGINES,
  RISKY_ENGINE_REASONS,
  SUPPORTED_ENGINES,
  isRiskyEngine,
  resolveEngines,
  selectEnginesForRun,
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

test("every risky engine is a supported engine with a non-empty rationale", () => {
  for (const [engine, reason] of Object.entries(RISKY_ENGINE_REASONS)) {
    assert.ok((SUPPORTED_ENGINES as readonly string[]).includes(engine), `${engine} is supported`);
    assert.ok(reason && reason.length > 0, `${engine} has a rationale`);
  }
});

test("isRiskyEngine flags spotbugs and trufflehog only", () => {
  assert.deepEqual(SUPPORTED_ENGINES.filter(isRiskyEngine), ["spotbugs", "trufflehog"]);
});

test("selectEnginesForRun keeps every engine on a trusted run", () => {
  const requested = ["semgrep", "spotbugs", "trufflehog"];
  const selection = selectEnginesForRun(requested, { untrusted: false, allowRisky: false });
  assert.deepEqual(selection.engines, requested);
  assert.deepEqual(selection.skipped, []);
});

test("selectEnginesForRun withholds risky engines on an untrusted run", () => {
  const selection = selectEnginesForRun(["semgrep", "spotbugs", "trivy", "trufflehog"], {
    untrusted: true,
    allowRisky: false,
  });
  assert.deepEqual(selection.engines, ["semgrep", "trivy"]);
  assert.deepEqual(
    selection.skipped.map((skipped) => skipped.engine),
    ["spotbugs", "trufflehog"],
  );
  for (const skipped of selection.skipped) {
    assert.equal(skipped.reason, RISKY_ENGINE_REASONS[skipped.engine as "spotbugs"]);
  }
});

test("selectEnginesForRun honours the allow-risky-engines opt-in", () => {
  const requested = ["semgrep", "spotbugs"];
  const selection = selectEnginesForRun(requested, { untrusted: true, allowRisky: true });
  assert.deepEqual(selection.engines, requested);
  assert.deepEqual(selection.skipped, []);
});

test("selectEnginesForRun can withhold every requested engine", () => {
  const selection = selectEnginesForRun(["spotbugs"], { untrusted: true, allowRisky: false });
  assert.deepEqual(selection.engines, []);
  assert.deepEqual(
    selection.skipped.map((skipped) => skipped.engine),
    ["spotbugs"],
  );
});

test("selectEnginesForRun does not mutate the requested engine list", () => {
  const requested = ["semgrep", "spotbugs"];
  selectEnginesForRun(requested, { untrusted: true, allowRisky: false });
  assert.deepEqual(requested, ["semgrep", "spotbugs"]);
});

test("the default engine set still runs a scan when safe mode withholds risky engines", () => {
  const selection = selectEnginesForRun([...DEFAULT_ENGINES], {
    untrusted: true,
    allowRisky: false,
  });
  assert.ok(selection.engines.length > 0);
  assert.equal(selection.engines.includes("spotbugs"), false);
});
