// Render a Markdown job summary for GitHub Actions.
import { EngineResult, Finding, SeverityCounts } from "./schema";
import { GateResult } from "./gate";
import { EngineName } from "./engines";

const SEV_EMOJI: Record<string, string> = {
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

// Keyed by EngineName (not a bare string) so a typo in an engine key fails to
// compile instead of silently never matching.
// Only link when a canonical URL can be derived with confidence: a fixed
// engine-doc naming convention. Engine-supplied advisory URLs (Trivy) and the
// CWE fallback are handled separately in findingUrl().
const ENGINE_RULE_URL: Partial<Record<EngineName, (ruleId: string) => string | undefined>> = {
  hadolint: (ruleId) => {
    if (/^DL\d+$/.test(ruleId)) return `https://github.com/hadolint/hadolint/wiki/${ruleId}`;
    if (/^SC\d+$/.test(ruleId)) return `https://www.shellcheck.net/wiki/${ruleId}`;
    return undefined;
  },
  gosec: (ruleId) => (/^G\d+$/.test(ruleId) ? `https://securego.io/docs/rules/${ruleId.toLowerCase()}.html` : undefined),
  eslint: (ruleId) => (ruleId.includes("/") ? undefined : `https://eslint.org/docs/latest/rules/${ruleId}`),
  zizmor: (ruleId) =>
    ruleId.startsWith("zizmor/") ? `https://docs.zizmor.sh/audits/#${ruleId.slice("zizmor/".length)}` : undefined,
};

// finding.url is engine-supplied (currently only Trivy's PrimaryURL) and not
// type-enforced beyond "string" — reject anything that isn't a well-formed
// http(s) URL rather than rendering it as a link destination.
function isHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function findingUrl(finding: Finding): string | undefined {
  if (finding.url && isHttpUrl(finding.url)) return finding.url;

  const specific = ENGINE_RULE_URL[finding.engine as EngineName]?.(finding.ruleId);
  if (specific) return specific;

  const cweMatch = finding.cwe ? /^CWE-(\d+)$/.exec(finding.cwe) : null;
  return cweMatch ? `https://cwe.mitre.org/data/definitions/${cweMatch[1]}.html` : undefined;
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

function engineSection(results: EngineResult[]): string[] {
  const lines = ["### Engines"];
  for (const result of results) {
    const note = result.note ? ` — _${tableCell(result.note)}_` : "";
    lines.push(
      `- ${engineIcon(result)} **${tableCell(result.engine)}**: ` +
        `${result.findings.length} findings (${result.status})${note}`,
    );
  }
  return [...lines, ""];
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
    result = "> ℹ️ Quality Gate not enforced (`gate: false`).";
  } else if (gate.passed) {
    result = "> ✅ **Passed** — thresholds satisfied.";
  } else {
    result = `> ❌ **Failed** — ${gate.reasons.join(", ")}.`;
  }
  return ["### Quality Gate", result, ""];
}

export function renderSummary(
  findings: Finding[],
  counts: SeverityCounts,
  gate: GateResult,
  gateEnforced: boolean,
  engineResults: EngineResult[],
): string {
  return [
    "## 🔍 PolyScan Report",
    "",
    ...severitySection(counts),
    ...engineSection(engineResults),
    ...secretsSection(findings),
    ...imageSection(findings),
    ...findingsSection(findings),
    ...gateSection(gate, gateEnforced),
  ].join("\n");
}
