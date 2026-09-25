import test from "node:test";
import assert from "node:assert/strict";

import { parseExcludedRules } from "../src/rule-exclusions";
import { semgrepArgs } from "../src/engines/semgrep";
import { opengrepArgs } from "../src/engines/opengrep";

test("rule exclusions trim and deduplicate IDs without changing their spelling", () => {
  assert.deepEqual(parseExcludedRules(""), []);
  assert.deepEqual(parseExcludedRules("rule.a"), ["rule.a"]);
  assert.deepEqual(parseExcludedRules(" rule.a, rule.b ,, rule.c , rule.a "), [
    "rule.a",
    "rule.b",
    "rule.c",
  ]);
  assert.deepEqual(parseExcludedRules("Rule.A,rule.a"), ["Rule.A", "rule.a"]);
});

test("Semgrep arguments preserve the existing scan when no rules are excluded", () => {
  assert.deepEqual(semgrepArgs("/scan"), [
    "--config", "auto", "--json", "--quiet", "--no-git-ignore", "/scan",
  ]);
});

test("Semgrep passes each excluded ID as its own rule argument", () => {
  assert.deepEqual(semgrepArgs("/scan", ["rule.a"]), [
    "--config", "auto",
    "--exclude-rule", "rule.a",
    "--json", "--quiet", "--no-git-ignore", "/scan",
  ]);
  assert.deepEqual(semgrepArgs("/scan", ["rule.a", "rule.b"]), [
    "--config", "auto",
    "--exclude-rule", "rule.a",
    "--exclude-rule", "rule.b",
    "--json", "--quiet", "--no-git-ignore", "/scan",
  ]);
});

test("OpenGrep arguments preserve the existing scan when no rules are excluded", () => {
  assert.deepEqual(opengrepArgs("/scan", "auto"), [
    "scan", "--config", "auto", "--json", "--quiet", "--no-git-ignore", "/scan",
  ]);
});

test("OpenGrep passes each excluded ID while retaining its config and target", () => {
  assert.deepEqual(opengrepArgs("/scan", "auto", ["rule.a", "rule.b"]), [
    "scan", "--config", "auto",
    "--exclude-rule", "rule.a",
    "--exclude-rule", "rule.b",
    "--json", "--quiet", "--no-git-ignore", "/scan",
  ]);
  assert.deepEqual(opengrepArgs("/scan", "rules.yml", ["rule.a"]), [
    "scan", "--config", "rules.yml",
    "--exclude-rule", "rule.a",
    "--json", "--quiet", "--no-git-ignore", "/scan",
  ]);
});
