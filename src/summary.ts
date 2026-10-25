// Render a Markdown job summary for GitHub Actions.
import { EngineResult, Finding, SEVERITY_ORDER, Severity, SeverityCounts, countBySeverity } from "./schema";
import { GateResult } from "./gate";
import { EngineName } from "./engines";
import { findingUrl } from "./links";
import { ScanContext } from "./report";
import { reportedPinnedVersion } from "./tool-versions";
import pkg from "../package.json";

const SEV_EMOJI: Record<Severity, string> = {
  critical: "🟣",
  high: "🔴",
  medium: "🟠",
  low: "🟡",
  info: "⚪",
};

function tableCell(value: string): string {
  return value
    .replaceAll(/\r?\n/g, " ")
    .replaceAll("|", String.raw`\|`)
    .trim();
}

function code(value: string): string {
  return `\`${tableCell(value).replaceAll("`", "'")}\``;
}

// Neutralizes markdown link/image syntax so untrusted, engine-sourced finding text
// (e.g. a custom Semgrep rule's interpolated `message:`) can't render as a live
// link or image in the job summary. Safe to use anywhere the text is NOT already
// wrapped in a code span (code spans are never parsed as markdown by CommonMark).
function textCell(value: string): string {
  return tableCell(value).replaceAll("[", String.raw`\[`);
}

function ruleCell(finding: Finding): string {
  const label = code(finding.ruleId);
  const url = findingUrl(finding);
  // Angle-bracket the destination so a URL containing "(" or ")" (unlikely today,
  // but not guaranteed for future engine-supplied PrimaryURL values) can't
  // truncate the link.
  return url ? `[${label}](<${url}>)` : label;
}

function severitySection(counts: SeverityCounts): string[] {
  return [
    "| Severity | Count |",
    "|---|---|",
    `| ${SEV_EMOJI.critical} Critical | ${counts.critical} |`,
    `| ${SEV_EMOJI.high} High | ${counts.high} |`,
    `| ${SEV_EMOJI.medium} Medium | ${counts.medium} |`,
    `| ${SEV_EMOJI.low} Low | ${counts.low} |`,
    `| ${SEV_EMOJI.info} Info | ${counts.info} |`,
    `| **Total** | **${counts.total}** |`,
    "",
  ];
}

function engineIcon(result: EngineResult): string {
  if (result.status === "success") return "✅";
  if (result.status === "skipped") return "ℹ️";
  return "⚠️";
}

export function formatDuration(ms: number): string {
  const seconds = ms / 1000;
  if (seconds < 59.95) return `${seconds.toFixed(1)}s`;
  // Round before splitting so 119.6s carries into the minutes ("2m 0s", not "1m 60s").
  const total = Math.round(seconds);
  return `${Math.floor(total / 60)}m ${total % 60}s`;
}

// A zero count renders as "·" so the non-zero cells stand out in wide tables.
function countCell(count: number): string {
  return count === 0 ? "·" : String(count);
}

function engineSection(results: EngineResult[]): string[] {
  const lines = [
    "### Engines",
    "",
    `| Engine | Status | Pinned version | Duration | ${SEVERITY_ORDER.map((sev) => SEV_EMOJI[sev]).join(" | ")} | Note |`,
    `|---|---|---|---|${SEVERITY_ORDER.map(() => "---:").join("|")}|---|`,
  ];
  for (const result of results) {
    const counts = countBySeverity(result.findings);
    const version = reportedPinnedVersion(result);
    const duration = result.durationMs === undefined ? "–" : formatDuration(result.durationMs);
    lines.push(
      `| **${tableCell(result.engine)}** | ${engineIcon(result)} ${result.status} | ` +
        `${version ? code(version) : "–"} | ${duration} | ` +
        `${SEVERITY_ORDER.map((sev) => countCell(counts[sev])).join(" | ")} | ` +
        `${result.note ? textCell(result.note) : ""} |`,
    );
  }
  return [...lines, ""];
}

function shortSha(sha: string): string {
  return /^[0-9a-f]{40}$/i.test(sha) ? sha.slice(0, 7) : sha;
}

function contextSection(context: ScanContext): string[] {
  const parts = [`**Target:** ${code(context.target)}`];
  const { github } = context;
  if (github.sha) {
    const ref = github.ref ? ` on ${code(github.ref)}` : "";
    parts.push(`**Commit:** ${code(shortSha(github.sha))}${ref}`);
  }
  parts.push(`**Engines:** ${context.engines.length}`, `**Duration:** ${formatDuration(context.durationMs)}`);
  parts.push(`**PolyScan:** ${code(`v${pkg.version}`)}`);
  return [parts.join(" · "), ""];
}

function findingLocation(finding: Finding): string {
  const cleanFile = finding.file.startsWith("./") ? finding.file.slice(2) : finding.file;
  return finding.line > 0 ? `${cleanFile}:${finding.line}` : cleanFile;
}

const SECRET_ENGINES: ReadonlySet<EngineName> = new Set<EngineName>(["gitleaks", "betterleaks", "trufflehog"]);

function secretsSection(findings: Finding[]): string[] {
  const secrets = findings.filter((finding) => SECRET_ENGINES.has(finding.engine as EngineName));
  if (secrets.length === 0) return [];

  const lines = [
    "### 🔑 Secrets Detected",
    "",
    "| Engine | Rule | Details | Location | Severity |",
    "|---|---|---|---|---|",
  ];
  for (const finding of secrets) {
    lines.push(
      `| ${tableCell(finding.engine)} | ${ruleCell(finding)} | ${textCell(finding.message)} | ` +
        `${code(findingLocation(finding))} | ${SEV_EMOJI[finding.severity]} ${finding.severity} |`,
    );
  }
  return [
    ...lines,
    "",
    "_gitleaks is run with `--redact`: secret values are masked at source. " +
      "betterleaks is also run with `--redact`, so its secret-bearing JSON fields are masked " +
      "before PolyScan reads the report. trufflehog's SARIF message never includes the secret " +
      "value either. None of these appear in logs, SARIF or this summary. " +
      "trufflehog's and betterleaks' `critical` rows are **verified live** credentials; `high` " +
      "rows matched a secret pattern but live verification did not confirm (or was not " +
      "attempted for) them._",
    "",
  ];
}

function imageSection(findings: Finding[]): string[] {
  const imageFindings = findings.filter((finding) => finding.source?.startsWith("image:"));
  if (imageFindings.length === 0) return [];

  const imageName = imageFindings[0].source?.slice("image:".length) ?? "unknown";
  const lines = [
    `### 🐳 Container Image Scan (${code(imageName)})`,
    "",
    "| Sev | CVE / Rule | Finding | Layer |",
    "|---|---|---|---|",
  ];
  for (const finding of imageFindings) {
    const cwe = finding.cwe ? ` (${finding.cwe})` : "";
    lines.push(
      `| ${SEV_EMOJI[finding.severity]} ${finding.severity} | ` +
        `${ruleCell(finding)}${cwe} | ${textCell(finding.message)} | ` +
        `${tableCell(finding.file)} |`,
    );
  }
  return [...lines, ""];
}

function findingsSection(findings: Finding[]): string[] {
  if (findings.length === 0) return [];

  const shown = findings.slice(0, 50);
  const lines = [
    "### Findings",
    "| Sev | Rule | Details | Location | Engine |",
    "|---|---|---|---|---|",
  ];
  for (const finding of shown) {
    const cwe = finding.cwe ? ` (${finding.cwe})` : "";
    lines.push(
      `| ${SEV_EMOJI[finding.severity]} ${finding.severity} | ` +
        `${ruleCell(finding)}${cwe} | ${textCell(finding.message)} | ` +
        `${code(findingLocation(finding))} | ${tableCell(finding.engine)} |`,
    );
  }
  if (findings.length > shown.length) {
    lines.push("", `_… and ${findings.length - shown.length} more findings._`);
  }
  return [...lines, ""];
}

function gateSection(gate: GateResult, enforced: boolean): string[] {
  let result: string;
  if (!enforced) {
    result = gate.passed
      ? "> ℹ️ Quality Gate not enforced (`gate: false`) — thresholds satisfied."
      : `> ℹ️ Quality Gate not enforced (\`gate: false\`) — would have failed: ${gate.reasons.join(", ")}.`;
  } else if (gate.passed) {
    result = "> ✅ **Passed** — thresholds satisfied.";
  } else {
    result = `> ❌ **Failed** — ${gate.reasons.join(", ")}.`;
  }

  const rows: [Severity, number][] = [
    ["critical", gate.thresholds.maxCritical],
    ["high", gate.thresholds.maxHigh],
    ["medium", gate.thresholds.maxMedium],
  ];
  const lines = ["### Quality Gate", result, "", "| Severity | Found | Max | Result |", "|---|---:|---:|---|"];
  for (const [severity, max] of rows) {
    const found = gate.counts[severity];
    lines.push(
      `| ${SEV_EMOJI[severity]} ${severity} | ${found} | ${max} | ${found > max ? "❌ exceeded" : "✅ ok"} |`,
    );
  }
  return [...lines, "", "_Low and info findings are reported but not gated._", ""];
}

export function renderSummary(
  findings: Finding[],
  counts: SeverityCounts,
  gate: GateResult,
  gateEnforced: boolean,
  engineResults: EngineResult[],
  context?: ScanContext,
): string {
  return [
    "## 🔍 PolyScan Report",
    "",
    ...(context ? contextSection(context) : []),
    ...severitySection(counts),
    ...engineSection(engineResults),
    ...secretsSection(findings),
    ...imageSection(findings),
    ...findingsSection(findings),
    ...gateSection(gate, gateEnforced),
  ].join("\n");
}
