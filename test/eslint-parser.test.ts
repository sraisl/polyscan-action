import test from "node:test";
import assert from "node:assert/strict";

import { parseEslintJson } from "../src/engines/eslint";

const BASE_FILE = {
  filePath: "/workspace/app.js",
  messages: [
    { ruleId: "no-eval", severity: 2, message: "eval can be harmful", line: 5, column: 1 },
  ],
};

test("parseEslintJson: severity 2 (error) maps to high", () => {
  const stdout = JSON.stringify([BASE_FILE]);
  const [f] = parseEslintJson(stdout);
  assert.equal(f.engine, "eslint");
  assert.equal(f.ruleId, "no-eval");
  assert.equal(f.severity, "high");
  assert.equal(f.message, "eval can be harmful");
  assert.equal(f.file, "/workspace/app.js");
  assert.equal(f.line, 5);
  assert.equal(f.column, 1);
});

test("parseEslintJson: severity 1 (warning) maps to medium", () => {
  const stdout = JSON.stringify([
    { ...BASE_FILE, messages: [{ ...BASE_FILE.messages[0], severity: 1 }] },
  ]);
  assert.equal(parseEslintJson(stdout)[0].severity, "medium");
});

test("parseEslintJson: message with null ruleId is skipped", () => {
  const stdout = JSON.stringify([
    {
      filePath: "/workspace/app.js",
      messages: [
        { ruleId: null, severity: 2, message: "Parsing error", line: 1 },
        { ruleId: "no-new-func", severity: 2, message: "no new Function", line: 10 },
      ],
    },
  ]);
  const findings = parseEslintJson(stdout);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "no-new-func");
});

test("parseEslintJson: multiple files and messages", () => {
  const stdout = JSON.stringify([
    {
      filePath: "/workspace/a.js",
      messages: [
        { ruleId: "no-eval", severity: 2, message: "eval", line: 1 },
        { ruleId: "no-implied-eval", severity: 1, message: "implied eval", line: 2 },
      ],
    },
    {
      filePath: "/workspace/b.js",
      messages: [{ ruleId: "no-new-func", severity: 2, message: "new Function", line: 3 }],
    },
  ]);
  const findings = parseEslintJson(stdout);
  assert.equal(findings.length, 3);
  assert.equal(findings[0].file, "/workspace/a.js");
  assert.equal(findings[2].file, "/workspace/b.js");
});

test("parseEslintJson: empty messages array returns empty array", () => {
  const stdout = JSON.stringify([{ filePath: "/workspace/app.js", messages: [] }]);
  assert.deepEqual(parseEslintJson(stdout), []);
});

test("parseEslintJson: empty top-level array returns empty array", () => {
  assert.deepEqual(parseEslintJson(JSON.stringify([])), []);
});

test("parseEslintJson: throws on invalid JSON", () => {
  assert.throws(() => parseEslintJson("not json"));
});
