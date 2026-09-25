import test from "node:test";
import assert from "node:assert/strict";

import { parseOpengrepJson } from "../src/engines/opengrep";

const BASE = {
  check_id: "rules.python.lang.security.eval-injection",
  path: "src/app.py",
  start: { line: 12, col: 7 },
  extra: {
    severity: "ERROR",
    message: "  Use of eval detected  ",
    metadata: { cwe: ["CWE-95", "CWE-78"] },
  },
};

test("parseOpengrepJson maps OpenGrep findings to the normalized schema", () => {
  const [finding] = parseOpengrepJson(JSON.stringify({ results: [BASE] }));

  assert.deepEqual(finding, {
    engine: "opengrep",
    ruleId: BASE.check_id,
    severity: "high",
    message: "Use of eval detected",
    file: "src/app.py",
    line: 12,
    column: 7,
    cwe: "CWE-95",
  });
});

test("parseOpengrepJson preserves compatible severity mappings", () => {
  const results = ["WARNING", "INFO", "UNKNOWN"].map((severity) => ({
    ...BASE,
    extra: { ...BASE.extra, severity },
  }));

  assert.deepEqual(
    parseOpengrepJson(JSON.stringify({ results })).map((finding) => finding.severity),
    ["medium", "low", "medium"],
  );
});

test("parseOpengrepJson handles empty, incomplete and invalid output", () => {
  assert.deepEqual(parseOpengrepJson(JSON.stringify({ results: [] })), []);
  assert.deepEqual(parseOpengrepJson(JSON.stringify({})), []);
  assert.throws(() => parseOpengrepJson("not json"));
});

test("parseOpengrepJson supplies fallbacks for incomplete findings", () => {
  const [finding] = parseOpengrepJson(
    JSON.stringify({ results: [{ path: "unknown.py", start: {}, extra: {} }] }),
  );

  assert.equal(finding.ruleId, "opengrep-rule");
  assert.equal(finding.message, "OpenGrep finding");
  assert.equal(finding.line, 0);
  assert.equal(finding.cwe, undefined);
});
