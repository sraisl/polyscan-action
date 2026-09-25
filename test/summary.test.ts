import test from "node:test";
import assert from "node:assert/strict";

import { renderSummary } from "../src/summary";
import { countBySeverity, EngineResult, Finding } from "../src/schema";
import { evaluateGate } from "../src/gate";
import { parseSemgrepJson } from "../src/engines/semgrep";
import { parseOpengrepJson } from "../src/engines/opengrep";

test("renderSummary shows engine states and escapes dynamic table content", () => {
  const findings: Finding[] = [
    {
      engine: "semgrep",
      ruleId: "rule|id",
      severity: "high",
      message: "first line\nsecond | line",
      file: "src/a|b.ts",
      line: 4,
    },
  ];
  const engines: EngineResult[] = [
    { engine: "semgrep", findings, status: "failed", note: "parse\nfailed | hard" },
    { engine: "detekt", findings: [], status: "skipped", note: "no Kotlin" },
  ];
  const counts = countBySeverity(findings);
  const gate = evaluateGate(findings, { maxCritical: 0, maxHigh: 0, maxMedium: 50 });

  const summary = renderSummary(findings, counts, gate, true, engines);
  assert.match(summary, /semgrep.*failed/);
  assert.match(summary, /detekt.*skipped/);
  assert.match(summary, /rule\\\|id/);
  assert.match(summary, /src\/a\\\|b\.ts/);
  assert.doesNotMatch(summary, /parse\nfailed/);
  assert.match(summary, /first line second \\\| line/);
});

function renderFor(finding: Finding): string {
  const engines: EngineResult[] = [{ engine: finding.engine, findings: [finding], status: "success" }];
  const counts = countBySeverity([finding]);
  const gate = evaluateGate([finding], { maxCritical: 0, maxHigh: 0, maxMedium: 50 });
  return renderSummary([finding], counts, gate, true, engines);
}

test("renderSummary shows full Semgrep and OpenGrep rule IDs from scanner output", () => {
  const checkId = "rules.python.lang.security.eval-injection";
  const stdout = JSON.stringify({
    results: [{
      check_id: checkId,
      path: "app.py",
      start: { line: 10 },
      extra: { severity: "ERROR", message: "Use of eval detected" },
    }],
  });

  for (const parse of [parseSemgrepJson, parseOpengrepJson]) {
    const [finding] = parse(stdout);
    const summary = renderFor(finding);
    assert.ok(summary.includes("| `" + checkId + "` |"));
    assert.doesNotMatch(summary, /\| `eval-injection` \|/);
  }
});

test("renderSummary links hadolint DL rules to the hadolint wiki", () => {
  const summary = renderFor({
    engine: "hadolint",
    ruleId: "DL3008",
    severity: "medium",
    message: "Pin versions in apt get install",
    file: "Dockerfile",
    line: 5,
  });
  assert.match(summary, /\[`DL3008`]\(<https:\/\/github\.com\/hadolint\/hadolint\/wiki\/DL3008>\)/);
});

test("renderSummary leaves hadolint's fallback ruleId ('hadolint') unlinked", () => {
  // src/engines/hadolint.ts falls back to the literal engine name when SARIF omits ruleId.
  const summary = renderFor({
    engine: "hadolint",
    ruleId: "hadolint",
    severity: "low",
    message: "Unrecognized Dockerfile issue",
    file: "Dockerfile",
    line: 1,
  });
  assert.match(summary, /`hadolint`/);
  assert.doesNotMatch(summary, /\[`hadolint`]/);
});

test("renderSummary links hadolint SC (ShellCheck) rules to the shellcheck wiki", () => {
  const summary = renderFor({
    engine: "hadolint",
    ruleId: "SC2086",
    severity: "low",
    message: "Double quote to prevent globbing",
    file: "Dockerfile",
    line: 7,
  });
  assert.match(summary, /\[`SC2086`]\(<https:\/\/www\.shellcheck\.net\/wiki\/SC2086>\)/);
});

test("renderSummary links eslint core rules to eslint.org docs", () => {
  const summary = renderFor({
    engine: "eslint",
    ruleId: "no-eval",
    severity: "high",
    message: "eval is dangerous",
    file: "src/a.js",
    line: 1,
  });
  assert.match(summary, /\[`no-eval`]\(<https:\/\/eslint\.org\/docs\/latest\/rules\/no-eval>\)/);
});

test("renderSummary links gosec rules to securego.io docs", () => {
  const summary = renderFor({
    engine: "gosec",
    ruleId: "G101",
    severity: "high",
    message: "Potential hardcoded credentials",
    file: "main.go",
    line: 12,
  });
  assert.match(summary, /\[`G101`]\(<https:\/\/securego\.io\/docs\/rules\/g101\.html>\)/);
});

test("renderSummary leaves gosec's fallback ruleId ('gosec') unlinked", () => {
  // src/engines/gosec.ts falls back to the literal engine name when SARIF omits ruleId.
  const summary = renderFor({
    engine: "gosec",
    ruleId: "gosec",
    severity: "low",
    message: "Unrecognized gosec issue",
    file: "main.go",
    line: 1,
  });
  assert.match(summary, /`gosec`/);
  assert.doesNotMatch(summary, /\[`gosec`]/);
});

test("renderSummary links zizmor rules to the zizmor docs", () => {
  const summary = renderFor({
    engine: "zizmor",
    ruleId: "zizmor/dangerous-triggers",
    severity: "high",
    message: "pull_request_target is almost always used insecurely",
    file: ".github/workflows/ci.yml",
    line: 2,
  });
  assert.match(
    summary,
    /\[`zizmor\/dangerous-triggers`]\(<https:\/\/docs\.zizmor\.sh\/audits\/#dangerous-triggers>\)/,
  );
});

test("renderSummary leaves zizmor's fallback ruleId ('zizmor') unlinked", () => {
  // src/engines/zizmor.ts falls back to the literal engine name when SARIF omits ruleId.
  const summary = renderFor({
    engine: "zizmor",
    ruleId: "zizmor",
    severity: "low",
    message: "Unrecognized zizmor issue",
    file: ".github/workflows/ci.yml",
    line: 1,
  });
  assert.match(summary, /`zizmor`/);
  assert.doesNotMatch(summary, /\[`zizmor`]/);
});

test("renderSummary shows gitleaks and trufflehog findings together in one Secrets section", () => {
  const findings: Finding[] = [
    {
      engine: "gitleaks",
      ruleId: "aws-access-token",
      severity: "critical",
      message: "AWS access token detected",
      file: "config.py",
      line: 3,
    },
    {
      engine: "trufflehog",
      ruleId: "AWS",
      severity: "critical",
      message: "Found verified result for detector AWS.",
      file: "config.py",
      line: 3,
    },
  ];
  const engines: EngineResult[] = [
    { engine: "gitleaks", findings: [findings[0]], status: "success" },
    { engine: "trufflehog", findings: [findings[1]], status: "success" },
  ];
  const counts = countBySeverity(findings);
  const gate = evaluateGate(findings, { maxCritical: 0, maxHigh: 0, maxMedium: 50 });
  const summary = renderSummary(findings, counts, gate, true, engines);

  assert.match(summary, /### 🔑 Secrets Detected/);
  assert.doesNotMatch(summary, /Secrets Detected \(gitleaks\)/);
  assert.match(summary, /gitleaks.*aws-access-token/);
  assert.match(summary, /trufflehog.*`AWS`/);
});

test("renderSummary falls back to a CWE link when no engine-specific link applies", () => {
  const summary = renderFor({
    engine: "bandit",
    ruleId: "B608",
    severity: "high",
    message: "Possible SQL injection",
    file: "app.py",
    line: 3,
    cwe: "CWE-89",
  });
  assert.match(summary, /\[`B608`]\(<https:\/\/cwe\.mitre\.org\/data\/definitions\/89\.html>\)/);
});

test("renderSummary leaves the rule as plain text with no link source", () => {
  const summary = renderFor({
    engine: "detekt",
    ruleId: "SomeCustomRule",
    severity: "low",
    message: "Custom detekt finding",
    file: "src/A.kt",
    line: 9,
  });
  assert.match(summary, /`SomeCustomRule`/);
  assert.doesNotMatch(summary, /\[`SomeCustomRule`]/);
});

test("renderSummary rejects a non-http(s) finding.url and falls back to CWE", () => {
  const summary = renderFor({
    engine: "trivy",
    ruleId: "CVE-9999-0001",
    severity: "high",
    message: "some vuln",
    file: "go.sum",
    line: 0,
    url: "javascript:alert(1)",
    cwe: "CWE-79",
  });
  assert.doesNotMatch(summary, /javascript:alert/);
  assert.match(summary, /\[`CVE-9999-0001`]\(<https:\/\/cwe\.mitre\.org\/data\/definitions\/79\.html>\)/);
});

test("renderSummary rejects a malformed finding.url with no fallback available", () => {
  const summary = renderFor({
    engine: "trivy",
    ruleId: "CVE-9999-0002",
    severity: "medium",
    message: "some other vuln",
    file: "go.sum",
    line: 0,
    url: "not a valid url",
  });
  assert.doesNotMatch(summary, /not a valid url/);
  assert.match(summary, /`CVE-9999-0002`/);
  assert.doesNotMatch(summary, /\[`CVE-9999-0002`]/);
});

test("renderSummary shows the finding message in the Details column", () => {
  const summary = renderFor({
    engine: "trivy",
    ruleId: "CVE-2021-1234",
    severity: "high",
    message: "lodash@4.17.20: Prototype pollution (fixed in 4.17.21)",
    file: "package-lock.json",
    line: 0,
    url: "https://avd.aquasec.com/nvd/cve-2021-1234",
  });
  assert.match(summary, /lodash@4\.17\.20: Prototype pollution \(fixed in 4\.17\.21\)/);
  assert.match(summary, /\[`CVE-2021-1234`]\(<https:\/\/avd\.aquasec\.com\/nvd\/cve-2021-1234>\)/);
});

test("renderSummary neutralizes markdown link/image syntax embedded in a finding message", () => {
  // A custom Semgrep rule's interpolated message could echo attacker-controlled
  // source text; this must not render as a live markdown link or image.
  const summary = renderFor({
    engine: "semgrep",
    ruleId: "custom-rule",
    severity: "high",
    message: "matched: ![pixel](https://evil.example/x.png?leak=1)",
    file: "src/a.ts",
    line: 1,
  });
  assert.ok(summary.includes(String.raw`matched: !\[pixel](https://evil.example/x.png?leak=1)`));
});
