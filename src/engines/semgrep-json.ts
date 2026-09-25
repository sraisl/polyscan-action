import { Finding, Severity } from "../schema";

function mapSeverity(severity: string): Severity {
  switch ((severity || "").toUpperCase()) {
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

export function parseSemgrepCompatibleJson(
  stdout: string,
  engine: string,
  fallbackRuleId: string,
  fallbackMessage: string,
): Finding[] {
  const findings: Finding[] = [];
  const data = JSON.parse(stdout);
  for (const result of data.results ?? []) {
    const metadata = result.extra?.metadata ?? {};
    const cweRaw = metadata.cwe;
    const cwe = Array.isArray(cweRaw) ? cweRaw[0] : cweRaw;
    findings.push({
      engine,
      ruleId: String(result.check_id ?? fallbackRuleId) || fallbackRuleId,
      severity: mapSeverity(result.extra?.severity),
      message: result.extra?.message?.trim() || fallbackMessage,
      file: result.path,
      line: result.start?.line ?? 0,
      column: result.start?.col,
      cwe: cwe ? /CWE-\d+/.exec(String(cwe))?.[0] : undefined,
    });
  }
  return findings;
}
