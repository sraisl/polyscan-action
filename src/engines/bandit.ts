// Bandit engine adapter (Python security linter).
import { getCore } from "../actions-core";
import { Finding, EngineResult, Severity } from "../schema";
import { run, ensurePythonTool } from "../exec";
import { resolveTarget } from "../target";
import { TOOLS } from "../tool-versions";

const BANDIT_VERSION = TOOLS.bandit.version;

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "low";
  }
}

async function ensureInstalled() {
  const core = await getCore();
  return ensurePythonTool("bandit", BANDIT_VERSION, "bandit", core);
}

export function parseBanditJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  const data = JSON.parse(stdout);
  for (const r of data.results ?? []) {
    findings.push({
      engine: "bandit",
      ruleId: r.test_id ?? "bandit-rule",
      severity: mapSeverity(r.issue_severity),
      message: r.issue_text ?? "Bandit finding",
      file: r.filename,
      line: r.line_number ?? 0,
      cwe: r.issue_cwe?.id ? `CWE-${r.issue_cwe.id}` : undefined,
    });
  }
  return findings;
}

export async function runBandit(target: string): Promise<EngineResult> {
  const tool = await ensureInstalled();
  if (!tool) {
    return { engine: "bandit", findings: [], status: "failed", note: "bandit not installed" };
  }
  try {
    const abs = resolveTarget(target);

    // bandit exits 1 when issues are found; exit codes above 1 are execution errors.
    const res = await run(tool.executable, ["-r", abs, "-f", "json", "-q"]);
    if (res.exitCode > 1) {
      return {
        engine: "bandit",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 300) || `bandit exited ${res.exitCode}`,
      };
    }

    if (!res.stdout.trim()) {
      return {
        engine: "bandit",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 300) || "bandit produced no output",
      };
    }

    let findings: Finding[];
    try {
      findings = parseBanditJson(res.stdout);
    } catch (err) {
      return {
        engine: "bandit",
        findings: [],
        status: "failed",
        note: `parse error: ${String(err).slice(0, 200)}`,
      };
    }

    return { engine: "bandit", findings, status: "success" };
  } finally {
    tool.cleanup();
  }
}
