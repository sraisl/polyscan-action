// Render a Markdown job summary for GitHub Actions.
import { Finding, SeverityCounts } from "./schema";
import { GateResult } from "./gate";
import { EngineResult } from "./schema";

const SEV_EMOJI: Record<string, string> = {
  critical: "🟣",
  high: "🔴",
  medium: "🟠",
  low: "🟡",
  info: "⚪",
};

export function renderSummary(
  findings: Finding[],
  counts: SeverityCounts,
  gate: GateResult,
  gateEnforced: boolean,
  engineResults: EngineResult[],
): string {
  const lines: string[] = [];
  lines.push("## 🔍 PolyScan Report");
  lines.push("");

  // Severity table
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  lines.push(`| ${SEV_EMOJI.critical} Critical | ${counts.critical} |`);
  lines.push(`| ${SEV_EMOJI.high} High | ${counts.high} |`);
  lines.push(`| ${SEV_EMOJI.medium} Medium | ${counts.medium} |`);
  lines.push(`| ${SEV_EMOJI.low} Low | ${counts.low} |`);
  lines.push(`| ${SEV_EMOJI.info} Info | ${counts.info} |`);
  lines.push(`| **Total** | **${counts.total}** |`);
  lines.push("");

  // Engine status
  lines.push("### Engines");
  for (const e of engineResults) {
    const status = e.available ? "✅" : "⚠️";
    const note = e.note ? ` — _${e.note}_` : "";
    lines.push(`- ${status} **${e.engine}**: ${e.findings.length} findings${e.available ? "" : note}`);
  }
  lines.push("");

  // Findings table (top 50)
  if (findings.length > 0) {
    lines.push("### Findings");
    lines.push("| Sev | Rule | Location | Engine |");
    lines.push("|---|---|---|---|");
    const shown = findings.slice(0, 50);
    for (const f of shown) {
      const cleanFile = f.file.replace(/^\.\//, "");
      const loc = f.line > 0 ? `${cleanFile}:${f.line}` : cleanFile;
      const cwe = f.cwe ? ` (${f.cwe})` : "";
      lines.push(
        `| ${SEV_EMOJI[f.severity]} ${f.severity} | \`${f.ruleId}\`${cwe} | \`${loc}\` | ${f.engine} |`,
      );
    }
    if (findings.length > shown.length) {
      lines.push("");
      lines.push(`_… and ${findings.length - shown.length} more findings._`);
    }
    lines.push("");
  }

  // Quality Gate
  lines.push("### Quality Gate");
  if (!gateEnforced) {
    lines.push("> ℹ️ Quality Gate not enforced (`gate: false`).");
  } else if (gate.passed) {
    lines.push("> ✅ **Passed** — thresholds satisfied.");
  } else {
    lines.push(`> ❌ **Failed** — ${gate.reasons.join(", ")}.`);
  }
  lines.push("");

  return lines.join("\n");
}
