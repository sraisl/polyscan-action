import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { hasJsSources, oxlintRuleId, parseOxlintJson } from "../src/engines/oxlint";

function report(diagnostics: unknown[]): string {
  return JSON.stringify({ diagnostics, number_of_files: 1, number_of_rules: 5 });
}

function diagnostic(opts: {
  code?: string;
  severity?: string;
  message?: string;
  filename?: string;
  line?: number;
  column?: number;
  url?: string;
}): unknown {
  return {
    message: opts.message ?? "eval can be harmful.",
    ...(opts.code === undefined ? {} : { code: opts.code }),
    severity: opts.severity ?? "error",
    ...(opts.url ? { url: opts.url } : {}),
    filename: opts.filename ?? "src/vuln.ts",
    labels: [{ span: { offset: 0, length: 4, line: opts.line ?? 10, column: opts.column ?? 3 } }],
  };
}

test("parseOxlintJson maps a TypeScript diagnostic to a finding", () => {
  const url = "https://oxc.rs/docs/guide/usage/linter/rules/eslint/no-eval.html";
  const { findings, parseErrorFiles } = parseOxlintJson(
    report([diagnostic({ code: "eslint(no-eval)", url })]),
  );
  assert.deepEqual(findings, [
    {
      engine: "oxlint",
      ruleId: "no-eval",
      severity: "high",
      message: "eval can be harmful.",
      file: "src/vuln.ts",
      line: 10,
      column: 3,
      url,
    },
  ]);
  assert.deepEqual(parseErrorFiles, []);
});

test("parseOxlintJson maps error/warning/advice severities", () => {
  const { findings } = parseOxlintJson(
    report([
      diagnostic({ code: "eslint(no-eval)", severity: "error" }),
      diagnostic({ code: "react(no-danger)", severity: "warning" }),
      diagnostic({ code: "eslint(no-script-url)", severity: "advice" }),
    ]),
  );
  assert.deepEqual(
    findings.map((finding) => finding.severity),
    ["high", "medium", "low"],
  );
});

test("parseOxlintJson reports diagnostics without a rule code as unparsed files", () => {
  const { findings, parseErrorFiles } = parseOxlintJson(
    report([
      diagnostic({ message: "Unexpected token", filename: "b.ts" }),
      diagnostic({ message: "Unexpected token", filename: "a.ts" }),
      diagnostic({ message: "Unexpected token", filename: "a.ts" }),
      diagnostic({ code: "eslint(no-new-func)", filename: "c.js" }),
    ]),
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "no-new-func");
  assert.deepEqual(parseErrorFiles, ["a.ts", "b.ts"]);
});

test("parseOxlintJson tolerates missing labels and filename", () => {
  const { findings } = parseOxlintJson(
    report([{ code: "eslint(no-eval)", severity: "error", message: "eval" }]),
  );
  assert.equal(findings[0].file, "unknown");
  assert.equal(findings[0].line, 0);
  assert.equal(findings[0].column, undefined);
  assert.equal("url" in findings[0], false);
});

test("parseOxlintJson returns no findings for an empty report", () => {
  assert.deepEqual(parseOxlintJson(report([])), { findings: [], parseErrorFiles: [] });
});

test("parseOxlintJson rejects malformed output", () => {
  assert.throws(() => parseOxlintJson("Failed to parse oxlint configuration file."));
  assert.throws(() => parseOxlintJson("{}"), /no diagnostics array/);
});

test("oxlintRuleId keeps core rules bare and prefixes plugin rules", () => {
  assert.equal(oxlintRuleId("eslint(no-eval)"), "no-eval");
  assert.equal(oxlintRuleId("react(no-danger)"), "react/no-danger");
  assert.equal(oxlintRuleId("eslint-plugin-react(no-danger)"), "react/no-danger");
  assert.equal(oxlintRuleId("unexpected"), "unexpected");
});

test("hasJsSources finds JS/TS files and ignores dependency and build directories", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-oxlint-test-"));
  try {
    fs.mkdirSync(path.join(root, "node_modules", "dep"), { recursive: true });
    fs.writeFileSync(path.join(root, "node_modules", "dep", "index.js"), "eval(x);\n");
    fs.mkdirSync(path.join(root, "dist"));
    fs.writeFileSync(path.join(root, "dist", "bundle.js"), "eval(x);\n");
    fs.writeFileSync(path.join(root, "README.md"), "# docs\n");
    assert.equal(hasJsSources(root), false);

    fs.mkdirSync(path.join(root, "src"));
    fs.writeFileSync(path.join(root, "src", "app.TSX"), "export {};\n");
    assert.equal(hasJsSources(root), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
