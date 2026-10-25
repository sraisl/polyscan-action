// Normalized finding schema shared across all engines.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export interface Finding {
  engine: string;
  ruleId: string; // engine-native rule identifier
  severity: Severity;
  message: string;
  file: string; // POSIX path relative to GITHUB_WORKSPACE for filesystem findings
  line: number;
  column?: number;
  cwe?: string; // e.g. "CWE-89"
  source?: string; // optional sub-source tag, e.g. "image:myapp:latest"
  url?: string; // canonical advisory/details URL, only set when the engine itself provides one (e.g. Trivy's PrimaryURL, oxlint's rule docs)
}

export interface EngineResult {
  engine: string;
  findings: Finding[];
  status: "success" | "skipped" | "failed";
  note?: string;
  durationMs?: number; // wall-clock time of the engine run, set by the scheduler
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  };
  for (const f of findings) {
    counts[f.severity] += 1;
  }
  return counts;
}
