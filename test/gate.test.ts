import test from "node:test";
import assert from "node:assert/strict";

import { evaluateGate } from "../src/gate";
import { Finding } from "../src/schema";

function finding(severity: Finding["severity"]): Finding {
  return {
    engine: "test",
    ruleId: `rule-${severity}`,
    severity,
    message: "test finding",
    file: "src/example.ts",
    line: 1,
  };
}

test("evaluateGate passes when thresholds are not exceeded", () => {
  const result = evaluateGate([finding("high"), finding("medium")], {
    maxCritical: 0,
    maxHigh: 1,
    maxMedium: 1,
  });

  assert.equal(result.passed, true);
  assert.deepEqual(result.reasons, []);
});

test("evaluateGate reports every exceeded threshold", () => {
  const result = evaluateGate(
    [finding("critical"), finding("high"), finding("high"), finding("medium")],
    {
      maxCritical: 0,
      maxHigh: 1,
      maxMedium: 0,
    },
  );

  assert.equal(result.passed, false);
  assert.deepEqual(result.reasons, [
    "1 critical (max 0)",
    "2 high (max 1)",
    "1 medium (max 0)",
  ]);
});
