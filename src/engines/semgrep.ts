// Semgrep engine adapter — installs via pip if missing, runs with auto config.
import { getCore } from "../actions-core";
import { Finding, EngineResult } from "../schema";
import { run, ensurePythonTool } from "../exec";
import { resolveTarget } from "../target";
import { TOOLS } from "../tool-versions";
import { parseSemgrepCompatibleJson } from "./semgrep-json";

const SEMGREP_VERSION = TOOLS.semgrep.version;

async function ensureInstalled() {
  const core = await getCore();
  return ensurePythonTool("semgrep", SEMGREP_VERSION, "semgrep", core);
}

export function parseSemgrepJson(stdout: string): Finding[] {
  return parseSemgrepCompatibleJson(stdout, "semgrep", "semgrep-rule", "Semgrep finding");
}

export async function runSemgrep(target: string): Promise<EngineResult> {
  const tool = await ensureInstalled();
  if (!tool) {
    return { engine: "semgrep", findings: [], status: "failed", note: "semgrep not installed" };
  }
  try {
    const abs = resolveTarget(target);

    const res = await run(tool.executable, [
      "--config",
      "auto",
      "--json",
      "--quiet",
      "--no-git-ignore",
      abs,
    ]);
    if (res.exitCode !== 0) {
      return {
        engine: "semgrep",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 300) || `semgrep exited ${res.exitCode}`,
      };
    }

    if (!res.stdout.trim()) {
      return {
        engine: "semgrep",
        findings: [],
        status: "failed",
        note: res.stderr.slice(0, 300) || "semgrep produced no output",
      };
    }

    let findings: Finding[];
    try {
      findings = parseSemgrepJson(res.stdout);
    } catch (err) {
      return {
        engine: "semgrep",
        findings: [],
        status: "failed",
        note: `parse error: ${String(err).slice(0, 200)}`,
      };
    }

    return { engine: "semgrep", findings, status: "success" };
  } finally {
    tool.cleanup();
  }
}
