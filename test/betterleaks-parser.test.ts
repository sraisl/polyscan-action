import test from "node:test";
import assert from "node:assert/strict";

import { parseBetterleaksJson } from "../src/engines/betterleaks";

const ABS = "/repo";

function findingWith(opts: {
  ruleId: string;
  description: string;
  file: string;
  line: number;
  validationStatus?: string;
}): unknown {
  return {
    RuleID: opts.ruleId,
    Description: opts.description,
    File: opts.file,
    StartLine: opts.line,
    ValidationStatus: opts.validationStatus,
  };
}

test("parseBetterleaksJson: valid validation status maps to critical", () => {
  const report = [
    findingWith({ ruleId: "github-pat", description: "GitHub PAT found", file: `${ABS}/config.env`, line: 3, validationStatus: "valid" }),
  ];
  const [f] = parseBetterleaksJson(report, ABS);
  assert.equal(f.engine, "betterleaks");
  assert.equal(f.ruleId, "github-pat");
  assert.equal(f.severity, "critical");
  assert.equal(f.message, "GitHub PAT found");
  assert.equal(f.file, "config.env");
  assert.equal(f.line, 3);
});

test("parseBetterleaksJson: invalid validation status maps to low", () => {
  const report = [
    findingWith({ ruleId: "aws-access-token", description: "AWS token", file: `${ABS}/.env`, line: 1, validationStatus: "invalid" }),
  ];
  assert.equal(parseBetterleaksJson(report, ABS)[0].severity, "low");
});

test("parseBetterleaksJson: revoked validation status maps to low", () => {
  const report = [
    findingWith({ ruleId: "aws-access-token", description: "AWS token", file: `${ABS}/.env`, line: 1, validationStatus: "revoked" }),
  ];
  assert.equal(parseBetterleaksJson(report, ABS)[0].severity, "low");
});

test("parseBetterleaksJson: no validation performed maps to high", () => {
  const report = [
    findingWith({ ruleId: "generic-api-key", description: "API key", file: `${ABS}/config.yml`, line: 5 }),
  ];
  assert.equal(parseBetterleaksJson(report, ABS)[0].severity, "high");
});

test("parseBetterleaksJson: needs_validation maps to high", () => {
  const report = [
    findingWith({ ruleId: "generic-api-key", description: "API key", file: `${ABS}/config.yml`, line: 5, validationStatus: "needs_validation" }),
  ];
  assert.equal(parseBetterleaksJson(report, ABS)[0].severity, "high");
});

test("parseBetterleaksJson: unknown/error validation status maps to high", () => {
  const unknownReport = [
    findingWith({ ruleId: "rule-a", description: "a", file: `${ABS}/a.env`, line: 1, validationStatus: "unknown" }),
  ];
  const errorReport = [
    findingWith({ ruleId: "rule-b", description: "b", file: `${ABS}/b.env`, line: 2, validationStatus: "error" }),
  ];
  assert.equal(parseBetterleaksJson(unknownReport, ABS)[0].severity, "high");
  assert.equal(parseBetterleaksJson(errorReport, ABS)[0].severity, "high");
});

test("parseBetterleaksJson: abs path stripped from file", () => {
  const report = [
    findingWith({ ruleId: "generic-api-key", description: "x", file: `${ABS}/secrets/vault.env`, line: 2 }),
  ];
  assert.equal(parseBetterleaksJson(report, ABS)[0].file, "secrets/vault.env");
});

test("parseBetterleaksJson: multiple findings all parsed", () => {
  const report = [
    findingWith({ ruleId: "rule-a", description: "a", file: `${ABS}/a.env`, line: 1, validationStatus: "valid" }),
    findingWith({ ruleId: "rule-b", description: "b", file: `${ABS}/b.env`, line: 2, validationStatus: "invalid" }),
    findingWith({ ruleId: "rule-c", description: "c", file: `${ABS}/c.env`, line: 3 }),
  ];
  assert.equal(parseBetterleaksJson(report, ABS).length, 3);
});

test("parseBetterleaksJson: empty array returns empty array", () => {
  assert.deepEqual(parseBetterleaksJson([], ABS), []);
});

test("parseBetterleaksJson: null report returns empty array", () => {
  assert.deepEqual(parseBetterleaksJson(null, ABS), []);
});
