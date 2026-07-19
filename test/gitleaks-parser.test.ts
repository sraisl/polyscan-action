import test from "node:test";
import assert from "node:assert/strict";

import { parseGitleaksSarif } from "../src/engines/gitleaks";

const ABS = "/repo";

function sarifWith(results: unknown[]): unknown {
  return { runs: [{ results }] };
}

function sarifResult(opts: {
  ruleId: string;
  level: string;
  message: string;
  ruleIdProperty?: string;
  uri: string;
  line: number;
}): unknown {
  return {
    ruleId: opts.ruleId,
    level: opts.level,
    message: { text: opts.message },
    properties: { RuleID: opts.ruleIdProperty ?? opts.ruleId },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: opts.uri },
          region: { startLine: opts.line },
        },
      },
    ],
  };
}

test("parseGitleaksSarif: critical level maps to critical", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "generic-api-key", level: "critical", message: "API key found", uri: `file://${ABS}/config.env`, line: 3 }),
  ]);
  const [f] = parseGitleaksSarif(sarif, ABS);
  assert.equal(f.engine, "gitleaks");
  assert.equal(f.ruleId, "generic-api-key");
  assert.equal(f.severity, "critical");
  assert.equal(f.message, "API key found");
  assert.equal(f.file, "config.env");
  assert.equal(f.line, 3);
});

test("parseGitleaksSarif: high level maps to high", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "aws-access-token", level: "high", message: "AWS token", uri: `file://${ABS}/.env`, line: 1 }),
  ]);
  assert.equal(parseGitleaksSarif(sarif, ABS)[0].severity, "high");
});

test("parseGitleaksSarif: warning level maps to low", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "private-key", level: "warning", message: "Private key", uri: `file://${ABS}/key.pem`, line: 1 }),
  ]);
  assert.equal(parseGitleaksSarif(sarif, ABS)[0].severity, "low");
});

test("parseGitleaksSarif: note level maps to low", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "generic-password", level: "note", message: "Password", uri: `file://${ABS}/config.yml`, line: 5 }),
  ]);
  assert.equal(parseGitleaksSarif(sarif, ABS)[0].severity, "low");
});

test("parseGitleaksSarif: RuleID from properties takes precedence over ruleId", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "some/rule", level: "high", message: "Secret", ruleIdProperty: "github-pat", uri: `file://${ABS}/src/main.ts`, line: 7 }),
  ]);
  assert.equal(parseGitleaksSarif(sarif, ABS)[0].ruleId, "github-pat");
});

test("parseGitleaksSarif: file:// prefix and abs path stripped from URI", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "generic-api-key", level: "high", message: "x", uri: `file://${ABS}/secrets/vault.env`, line: 2 }),
  ]);
  assert.equal(parseGitleaksSarif(sarif, ABS)[0].file, "secrets/vault.env");
});

test("parseGitleaksSarif: multiple results all parsed", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "rule-a", level: "critical", message: "a", uri: `file://${ABS}/a.env`, line: 1 }),
    sarifResult({ ruleId: "rule-b", level: "high", message: "b", uri: `file://${ABS}/b.env`, line: 2 }),
    sarifResult({ ruleId: "rule-c", level: "note", message: "c", uri: `file://${ABS}/c.env`, line: 3 }),
  ]);
  assert.equal(parseGitleaksSarif(sarif, ABS).length, 3);
});

test("parseGitleaksSarif: empty results returns empty array", () => {
  assert.deepEqual(parseGitleaksSarif(sarifWith([]), ABS), []);
});

test("parseGitleaksSarif: empty runs returns empty array", () => {
  assert.deepEqual(parseGitleaksSarif({ runs: [] }, ABS), []);
});
