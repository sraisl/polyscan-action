// Quality Gate: evaluate severity counts against configured thresholds.
import { Finding, SeverityCounts, countBySeverity } from "./schema";

export interface GateConfig {
  maxCritical: number;
  maxHigh: number;
  maxMedium: number;
}

export interface GateResult {
  passed: boolean;
  counts: SeverityCounts;
  reasons: string[];
}

export function evaluateGate(findings: Finding[], cfg: GateConfig): GateResult {
  const counts = countBySeverity(findings);
  const reasons: string[] = [];
  if (counts.critical > cfg.maxCritical) {
    reasons.push(`${counts.critical} critical (max ${cfg.maxCritical})`);
  }
  if (counts.high > cfg.maxHigh) {
    reasons.push(`${counts.high} high (max ${cfg.maxHigh})`);
  }
  if (counts.medium > cfg.maxMedium) {
    reasons.push(`${counts.medium} medium (max ${cfg.maxMedium})`);
  }
  return { passed: reasons.length === 0, counts, reasons };
}
