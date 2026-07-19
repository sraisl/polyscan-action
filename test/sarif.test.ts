import test from "node:test";
import assert from "node:assert/strict";

import { toSarif } from "../src/sarif";
import { Finding } from "../src/schema";

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
