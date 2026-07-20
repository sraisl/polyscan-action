// Semgrep engine adapter — installs via pip if missing, runs with auto config.
import * as core from "@actions/core";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which, ensurePythonTool } from "../exec";

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "low";
    default:
      return "medium";
  }
}

async function ensureInstalled(): Promise<boolean> {
  return ensurePythonTool("semgrep", "semgrep", core);
}

export function parseSemgrepJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  const data = JSON.parse(stdout);
  for (const r of data.results ?? []) {
    const meta = r.extra?.metadata ?? {};
    const cweRaw = meta.cwe;
    const cwe = Array.isArray(cweRaw) ? cweRaw[0] : cweRaw;
    findings.push({
      engine: "semgrep",
      ruleId: String(r.check_id ?? "semgrep-rule").split(".").pop() || "semgrep-rule",
      severity: mapSeverity(r.extra?.severity),
      message: r.extra?.message?.trim() || "Semgrep finding",
      file: r.path,
      line: r.start?.line ?? 0,
      column: r.start?.col,
      cwe: cwe ? String(cwe).match(/CWE-\d+/)?.[0] : undefined,
    });
  }
  return findings;
}

export async function runSemgrep(target: string): Promise<EngineResult> {
  const ok = await ensureInstalled();
  if (!ok) {
    return { engine: "semgrep", findings: [], available: false, note: "semgrep not installed" };
  }

  const res = await run("semgrep", [
    "--config",
    "auto",
    "--json",
    "--quiet",
    "--no-git-ignore",
    target,
  ]);

  if (!res.stdout.trim()) {
    return {
      engine: "semgrep",
      findings: [],
      available: true,
      note: res.stderr.slice(0, 300),
    };
  }

  let findings: Finding[];
  try {
    findings = parseSemgrepJson(res.stdout);
  } catch (err) {
    return {
      engine: "semgrep",
      findings: [],
      available: true,
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }

  return { engine: "semgrep", findings, available: true };
}
