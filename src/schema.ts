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
  engine: string; // semgrep | bandit | eslint | spotbugs
  ruleId: string; // engine-native rule identifier
  severity: Severity;
  message: string;
  file: string; // path relative to the scan target when possible
  line: number;
  column?: number;
  cwe?: string; // e.g. "CWE-89"
  source?: string; // optional sub-source tag, e.g. "image:myapp:latest"
}

export interface EngineResult {
  engine: string;
  findings: Finding[];
  available: boolean; // false when the engine tool was not found / failed to run
  note?: string; // diagnostic (e.g. "tool not installed", stderr excerpt)
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
