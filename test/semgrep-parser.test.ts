import test from "node:test";
import assert from "node:assert/strict";

import { parseSemgrepJson } from "../src/engines/semgrep";

const BASE = {
  check_id: "rules.python.lang.security.eval-injection",
  path: "app.py",
  start: { line: 10, col: 4 },
  extra: { severity: "ERROR", message: "  Use of eval detected  ", metadata: {} },
};

test("parseSemgrepJson: ERROR maps to high, trims message, uses last ruleId segment", () => {
  const stdout = JSON.stringify({ results: [BASE] });
  const [f] = parseSemgrepJson(stdout);
  assert.equal(f.engine, "semgrep");
  assert.equal(f.ruleId, "eval-injection");
  assert.equal(f.severity, "high");
  assert.equal(f.message, "Use of eval detected");
  assert.equal(f.file, "app.py");
  assert.equal(f.line, 10);
  assert.equal(f.column, 4);
});

test("parseSemgrepJson: WARNING maps to medium", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE, extra: { ...BASE.extra, severity: "WARNING" } }],
  });
  assert.equal(parseSemgrepJson(stdout)[0].severity, "medium");
});

test("parseSemgrepJson: INFO maps to low", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE, extra: { ...BASE.extra, severity: "INFO" } }],
  });
  assert.equal(parseSemgrepJson(stdout)[0].severity, "low");
});

test("parseSemgrepJson: unknown severity defaults to medium", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE, extra: { ...BASE.extra, severity: "UNKNOWN" } }],
  });
  assert.equal(parseSemgrepJson(stdout)[0].severity, "medium");
});

test("parseSemgrepJson: CWE extracted from array (first element)", () => {
  const stdout = JSON.stringify({
    results: [
      {
        ...BASE,
        extra: { ...BASE.extra, metadata: { cwe: ["CWE-95", "CWE-78"] } },
      },
    ],
  });
  assert.equal(parseSemgrepJson(stdout)[0].cwe, "CWE-95");
});

test("parseSemgrepJson: CWE extracted from plain string", () => {
  const stdout = JSON.stringify({
    results: [{ ...BASE, extra: { ...BASE.extra, metadata: { cwe: "CWE-89: SQL injection" } } }],
  });
  assert.equal(parseSemgrepJson(stdout)[0].cwe, "CWE-89");
});

test("parseSemgrepJson: no CWE metadata → cwe undefined", () => {
  const stdout = JSON.stringify({ results: [BASE] });
  assert.equal(parseSemgrepJson(stdout)[0].cwe, undefined);
});

test("parseSemgrepJson: empty results returns empty array", () => {
  assert.deepEqual(parseSemgrepJson(JSON.stringify({ results: [] })), []);
});

test("parseSemgrepJson: missing results key returns empty array", () => {
  assert.deepEqual(parseSemgrepJson(JSON.stringify({})), []);
});

test("parseSemgrepJson: throws on invalid JSON", () => {
  assert.throws(() => parseSemgrepJson("not json"));
});
