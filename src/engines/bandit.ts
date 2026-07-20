// Bandit engine adapter (Python security linter).
import * as core from "@actions/core";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which, ensurePythonTool } from "../exec";

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

async function ensureInstalled(): Promise<boolean> {
  return ensurePythonTool("bandit", "bandit", core);
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
  const ok = await ensureInstalled();
  if (!ok) {
    return { engine: "bandit", findings: [], available: false, note: "bandit not installed" };
  }

  // bandit exits 1 when issues are found — that's fine.
  const res = await run("bandit", ["-r", target, "-f", "json", "-q"]);

  if (!res.stdout.trim()) {
    return { engine: "bandit", findings: [], available: true, note: res.stderr.slice(0, 300) };
  }

  let findings: Finding[];
  try {
    findings = parseBanditJson(res.stdout);
  } catch (err) {
    return {
      engine: "bandit",
      findings: [],
      available: true,
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }

  return { engine: "bandit", findings, available: true };
}
