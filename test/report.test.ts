import test from "node:test";
import assert from "node:assert/strict";

import { githubContext, JSON_REPORT_SCHEMA_VERSION, ScanContext, toJsonReport } from "../src/report";
import { countBySeverity, EngineResult, Finding } from "../src/schema";
import { evaluateGate } from "../src/gate";
import { engineVersion, TOOLS } from "../src/tool-versions";
import pkg from "../package.json";

const context: ScanContext = {
  target: "test-fixtures",
  engines: ["bandit", "detekt"],
  maxConcurrency: 2,
  startedAt: "2026-10-24T10:00:00.000Z",
  durationMs: 4200,
  github: { sha: "0123456789abcdef0123456789abcdef01234567" },
};

test("githubContext reads workflow run metadata and derives the run URL", () => {
  assert.deepEqual(
    githubContext({
      GITHUB_REPOSITORY: "octo/repo",
      GITHUB_REF: "refs/heads/main",
      GITHUB_SHA: "abc",
      GITHUB_WORKFLOW: "CI",
      GITHUB_JOB: "scan",
      GITHUB_RUN_ID: "42",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_SERVER_URL: "https://github.com",
    }),
    {
      repository: "octo/repo",
      ref: "refs/heads/main",
      sha: "abc",
      workflow: "CI",
      job: "scan",
      runId: "42",
      runAttempt: "1",
      runUrl: "https://github.com/octo/repo/actions/runs/42",
    },
  );
});

test("githubContext omits the run URL outside GitHub Actions", () => {
  assert.equal(githubContext({}).runUrl, undefined);
});

test("toJsonReport contains scan context, gate thresholds, per-engine counts and all findings", () => {
  const findings: Finding[] = [
    { engine: "bandit", ruleId: "B307", severity: "high", message: "eval", file: "a.py", line: 3 },
    { engine: "bandit", ruleId: "B101", severity: "low", message: "assert", file: "a.py", line: 9 },
  ];
  const engines: EngineResult[] = [
    { engine: "bandit", findings, status: "success", durationMs: 1500 },
    { engine: "detekt", findings: [], status: "skipped", note: "no Kotlin files" },
  ];
  const gate = evaluateGate(findings, { maxCritical: 0, maxHigh: 0, maxMedium: 10 });
  const report = JSON.parse(
    toJsonReport({ findings, counts: countBySeverity(findings), gate, gateEnforced: true, engineResults: engines, context }),
  );

  assert.equal(report.schemaVersion, JSON_REPORT_SCHEMA_VERSION);
  assert.deepEqual(report.tool, { name: "PolyScan", version: pkg.version });
  assert.deepEqual(report.scan, context);
  assert.deepEqual(report.gate, {
    enforced: true,
    passed: false,
    thresholds: { maxCritical: 0, maxHigh: 0, maxMedium: 10 },
    reasons: ["1 high (max 0)"],
  });
  assert.equal(report.counts.total, 2);
  assert.deepEqual(report.engines[0], {
    engine: "bandit",
    status: "success",
    version: TOOLS.bandit.version,
    durationMs: 1500,
    counts: { critical: 0, high: 1, medium: 0, low: 1, info: 0, total: 2 },
  });
  assert.equal(report.engines[1].note, "no Kotlin files");
  assert.deepEqual(report.findings, findings);
});

test("engineVersion reports FindSecBugs alongside SpotBugs and nothing for unknown engines", () => {
  assert.equal(engineVersion("spotbugs"), `${TOOLS.spotbugs.version} + findsecbugs ${TOOLS.findsecbugs.version}`);
  assert.equal(engineVersion("gitleaks"), TOOLS.gitleaks.version);
  assert.equal(engineVersion("nope"), undefined);
});
