import test from "node:test";
import assert from "node:assert/strict";

import { toSarif } from "../src/sarif";
import { EngineResult, Finding } from "../src/schema";
import { TOOLS } from "../src/tool-versions";

test("toSarif serializes normalized findings into SARIF results", () => {
  const findings: Finding[] = [
    {
      engine: "bandit",
      ruleId: "B307",
      severity: "high",
      message: "Use of eval",
      file: "./app.py",
      line: 12,
      column: 4,
      cwe: "CWE-95",
    },
  ];

  const sarif = JSON.parse(toSarif(findings));
  const run = sarif.runs[0];
  const result = run.results[0];

  assert.equal(sarif.version, "2.1.0");
  assert.equal(run.tool.driver.rules[0].id, "bandit/B307");
  assert.equal(result.ruleId, "bandit/B307");
  assert.equal(result.level, "error");
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "app.py");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 12);
  assert.equal(result.properties.cwe, "CWE-95");
});

test("toSarif omits file locations for container image findings", () => {
  const findings: Finding[] = [
    {
      engine: "trivy",
      ruleId: "CVE-2026-1234",
      severity: "critical",
      message: "vulnerable package",
      file: "alpine:3.20",
      line: 0,
      source: "image:example/app:latest",
    },
  ];

  const result = JSON.parse(toSarif(findings)).runs[0].results[0];
  assert.equal(result.locations, undefined);
  assert.equal(result.properties.source, "image:example/app:latest");
});

test("toSarif adds code scanning rule metadata from the highest severity of a rule", () => {
  const findings: Finding[] = [
    { engine: "trufflehog", ruleId: "AWS", severity: "critical", message: "verified", file: "a.env", line: 1 },
    { engine: "trufflehog", ruleId: "AWS", severity: "high", message: "unverified", file: "b.env", line: 2 },
    {
      engine: "gosec",
      ruleId: "G201",
      severity: "medium",
      message: "SQL string formatting",
      file: "db.go",
      line: 9,
      cwe: "CWE-89",
    },
    { engine: "semgrep", ruleId: "info-rule", severity: "info", message: "fyi", file: "x.py", line: 1 },
  ];

  const rules = JSON.parse(toSarif(findings)).runs[0].tool.driver.rules;
  const byId = new Map(rules.map((rule: { id: string }) => [rule.id, rule]));

  const aws = byId.get("trufflehog/AWS") as Record<string, any>;
  assert.equal(aws.properties["security-severity"], "9.5");
  assert.equal(aws.defaultConfiguration.level, "error");
  assert.deepEqual(aws.properties.tags, ["security", "trufflehog"]);

  const gosec = byId.get("gosec/G201") as Record<string, any>;
  assert.equal(gosec.properties["security-severity"], "5.5");
  assert.equal(gosec.helpUri, "https://securego.io/docs/rules/g201.html");
  assert.deepEqual(gosec.properties.tags, ["security", "gosec", "external/cwe/cwe-89"]);

  const info = byId.get("semgrep/info-rule") as Record<string, any>;
  assert.equal(info.properties["security-severity"], undefined);
  assert.equal(info.helpUri, undefined);
});

test("toSarif fingerprints are line-independent and distinguish repeated findings", () => {
  const base: Finding = { engine: "bandit", ruleId: "B307", severity: "high", message: "eval", file: "a.py", line: 3 };
  const prints = (findings: Finding[]) =>
    JSON.parse(toSarif(findings)).runs[0].results.map(
      (result: { partialFingerprints: Record<string, string> }) => result.partialFingerprints["polyscanFindingHash/v1"],
    );

  const [first, second] = prints([base, { ...base, line: 20 }]);
  assert.match(first, /^[0-9a-f]{32}:1$/);
  assert.equal(second, first.replace(/:1$/, ":2"));
  assert.equal(prints([{ ...base, line: 99 }])[0], first);
  assert.notEqual(prints([{ ...base, file: "b.py" }])[0], first);
});

test("toSarif records engine versions and engine failures when engine results are given", () => {
  const engines: EngineResult[] = [
    { engine: "bandit", findings: [], status: "success", durationMs: 1200 },
    { engine: "detekt", findings: [], status: "skipped", note: "no Kotlin files" },
    { engine: "semgrep", findings: [], status: "failed", note: "semgrep not installed" },
  ];
  const run = JSON.parse(toSarif([], engines)).runs[0];

  assert.deepEqual(run.tool.extensions[0], {
    name: "bandit",
    version: TOOLS.bandit.version,
    properties: { status: "success", findings: 0, durationMs: 1200 },
  });
  assert.equal(run.invocations[0].executionSuccessful, false);
  assert.deepEqual(
    run.invocations[0].toolExecutionNotifications.map((n: { level: string; descriptor: { id: string } }) => [
      n.descriptor.id,
      n.level,
    ]),
    [
      ["detekt", "note"],
      ["semgrep", "error"],
    ],
  );
});

test("toSarif without engine results omits extensions and invocations", () => {
  const run = JSON.parse(toSarif([])).runs[0];
  assert.equal(run.tool.extensions, undefined);
  assert.equal(run.invocations, undefined);
});
