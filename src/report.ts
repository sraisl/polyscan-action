// Scan context shared by all reports, and the machine-readable JSON report.
import { EngineResult, Finding, SeverityCounts, countBySeverity } from "./schema";
import { GateResult } from "./gate";
import { reportedPinnedVersion } from "./tool-versions";
import pkg from "../package.json";

export const JSON_REPORT_SCHEMA_VERSION = 1;

export interface GitHubContext {
  repository?: string;
  ref?: string;
  sha?: string;
  workflow?: string;
  job?: string;
  runId?: string;
  runAttempt?: string;
  runUrl?: string;
}

export interface ScanContext {
  target: string; // POSIX path relative to GITHUB_WORKSPACE ("." for the workspace root)
  engines: string[]; // engines requested, in run order
  maxConcurrency: number;
  startedAt: string; // ISO 8601
  durationMs: number;
  github: GitHubContext;
}

export function githubContext(env: NodeJS.ProcessEnv = process.env): GitHubContext {
  const context: GitHubContext = {
    repository: env.GITHUB_REPOSITORY || undefined,
    ref: env.GITHUB_REF || undefined,
    sha: env.GITHUB_SHA || undefined,
    workflow: env.GITHUB_WORKFLOW || undefined,
    job: env.GITHUB_JOB || undefined,
    runId: env.GITHUB_RUN_ID || undefined,
    runAttempt: env.GITHUB_RUN_ATTEMPT || undefined,
  };
  if (env.GITHUB_SERVER_URL && context.repository && context.runId) {
    context.runUrl = `${env.GITHUB_SERVER_URL}/${context.repository}/actions/runs/${context.runId}`;
  }
  return context;
}

export interface JsonReportInput {
  findings: Finding[];
  counts: SeverityCounts;
  gate: GateResult;
  gateEnforced: boolean;
  engineResults: EngineResult[];
  context: ScanContext;
}

export function toJsonReport(input: JsonReportInput): string {
  const { findings, counts, gate, gateEnforced, engineResults, context } = input;
  const report = {
    schemaVersion: JSON_REPORT_SCHEMA_VERSION,
    tool: { name: "PolyScan", version: pkg.version },
    scan: context,
    gate: {
      enforced: gateEnforced,
      passed: gate.passed,
      thresholds: gate.thresholds,
      reasons: gate.reasons,
    },
    counts,
    engines: engineResults.map((result) => ({
      engine: result.engine,
      status: result.status,
      pinnedVersion: reportedPinnedVersion(result),
      durationMs: result.durationMs,
      counts: countBySeverity(result.findings),
      note: result.note,
    })),
    findings,
  };
  return JSON.stringify(report, null, 2);
}
