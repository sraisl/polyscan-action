import test from "node:test";
import assert from "node:assert/strict";

import { parseBanditJson } from "../src/engines/bandit";

const BASE_RESULT = {
  test_id: "B307",
  issue_severity: "HIGH",
  issue_text: "Use of eval",
  filename: "app.py",
  line_number: 12,
  issue_cwe: { id: 95 },
};

test("parseBanditJson: HIGH maps to high, CWE formatted correctly", () => {
  const stdout = JSON.stringify({ results: [BASE_RESULT] });
  const [f] = parseBanditJson(stdout);
  assert.equal(f.engine, "bandit");
  assert.equal(f.ruleId, "B307");
  assert.equal(f.severity, "high");
  assert.equal(f.message, "Use of eval");
  assert.equal(f.file, "app.py");
  assert.equal(f.line, 12);
  assert.equal(f.cwe, "CWE-95");
});

test("parseBanditJson: MEDIUM maps to medium", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE_RESULT, issue_severity: "MEDIUM" }],
  });
  assert.equal(parseBanditJson(stdout)[0].severity, "medium");
});

test("parseBanditJson: LOW maps to low", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE_RESULT, issue_severity: "LOW" }],
  });
  assert.equal(parseBanditJson(stdout)[0].severity, "low");
});

test("parseBanditJson: unknown severity defaults to low", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE_RESULT, issue_severity: "UNKNOWN" }],
  });
  assert.equal(parseBanditJson(stdout)[0].severity, "low");
});

test("parseBanditJson: missing issue_cwe → cwe undefined", () => {
  const { issue_cwe: _, ...noСwe } = BASE_RESULT;
  const stdout = JSON.stringify({ results: [noСwe] });
  assert.equal(parseBanditJson(stdout)[0].cwe, undefined);
});

test("parseBanditJson: issue_cwe without id → cwe undefined", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE_RESULT, issue_cwe: {} }],
  });
  assert.equal(parseBanditJson(stdout)[0].cwe, undefined);
});

test("parseBanditJson: multiple results all parsed", () => {
  const stdout = JSON.stringify({
    results: [
      BASE_RESULT,
      { ...BASE_RESULT, test_id: "B501", line_number: 20 },
    ],
  });
  const findings = parseBanditJson(stdout);
  assert.equal(findings.length, 2);
  assert.equal(findings[1].ruleId, "B501");
  assert.equal(findings[1].line, 20);
});

test("parseBanditJson: empty results returns empty array", () => {
  assert.deepEqual(parseBanditJson(JSON.stringify({ results: [] })), []);
});

test("parseBanditJson: throws on invalid JSON", () => {
  assert.throws(() => parseBanditJson("{bad json"));
});
