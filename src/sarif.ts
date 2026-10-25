// SARIF 2.1.0 serializer (GitHub Code Scanning compatible).
import { EngineResult, Finding, Severity } from "./schema";
import { findingUrl } from "./links";
import { reportedPinnedVersion } from "./tool-versions";
import pkg from "../package.json";

function sarifLevel(sev: Severity): string {
  switch (sev) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

// GitHub Code Scanning buckets rules by `security-severity`:
// >= 9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low.
// Info findings carry no score so they are not shown as security alerts.
const SECURITY_SEVERITY: Partial<Record<Severity, string>> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "2.0",
};

interface RuleSummary {
  id: string;
  name: string;
  desc: string;
  severities: Set<Severity>;
  helpUris: Set<string | undefined>;
  cwes: Set<string>;
}

// A rule-level value is only meaningful when every finding of the rule agrees on it.
// Fallback IDs such as Trivy's TRIVY-VULN group unrelated findings, and a rule-level
// security-severity would then override each alert's own severity in Code Scanning.
function single<T>(values: Set<T>): T | undefined {
  return values.size === 1 ? values.values().next().value : undefined;
}

function collectRules(findings: Finding[]): Map<string, RuleSummary> {
  // Deduplicate rules by engine/ruleId.
  const ruleMap = new Map<string, RuleSummary>();
  for (const f of findings) {
    const id = `${f.engine}/${f.ruleId}`;
    let rule = ruleMap.get(id);
    if (!rule) {
      rule = { id, name: f.ruleId, desc: f.message, severities: new Set(), helpUris: new Set(), cwes: new Set() };
      ruleMap.set(id, rule);
    }
    rule.severities.add(f.severity);
    rule.helpUris.add(findingUrl(f));
    if (f.cwe) rule.cwes.add(f.cwe);
  }
  return ruleMap;
}

function sarifRule(rule: RuleSummary) {
  const severity = single(rule.severities);
  const securitySeverity = severity ? SECURITY_SEVERITY[severity] : undefined;
  const helpUri = single(rule.helpUris);
  const cweTags = [...rule.cwes].sort().map((cwe) => `external/cwe/${cwe.toLowerCase()}`);
  return {
    id: rule.id,
    name: rule.name,
    shortDescription: { text: `${rule.name}` },
    fullDescription: { text: rule.desc },
    ...(severity ? { defaultConfiguration: { level: sarifLevel(severity) } } : {}),
    ...(helpUri ? { helpUri } : {}),
    properties: {
      tags: ["security", rule.id.split("/", 1)[0], ...cweTags],
      ...(securitySeverity ? { "security-severity": securitySeverity } : {}),
    },
  };
}

function engineExtensions(engineResults: EngineResult[]) {
  return engineResults.map((result) => {
    const version = reportedPinnedVersion(result);
    return {
      name: result.engine,
      ...(version ? { version } : {}),
      properties: {
        status: result.status,
        findings: result.findings.length,
        ...(result.durationMs === undefined ? {} : { durationMs: result.durationMs }),
      },
    };
  });
}

function invocation(engineResults: EngineResult[]) {
  const notifications = engineResults
    .filter((result) => result.note)
    .map((result) => ({
      level: result.status === "failed" ? "error" : "note",
      message: { text: `${result.engine} (${result.status}): ${result.note}` },
      descriptor: { id: result.engine },
    }));
  // One failed engine must not mark the merged run unsuccessful: Code Scanning would
  // then discard the findings of every engine that did complete. The run only failed
  // when engines failed and none succeeded.
  const anyFailed = engineResults.some((result) => result.status === "failed");
  const anySucceeded = engineResults.some((result) => result.status === "success");
  return {
    executionSuccessful: !anyFailed || anySucceeded,
    ...(notifications.length > 0 ? { toolExecutionNotifications: notifications } : {}),
  };
}

export function toSarif(findings: Finding[], engineResults?: EngineResult[]): string {
  const rules = [...collectRules(findings).values()].map(sarifRule);

  const results = findings.map((f) => {
    const imageFinding = f.source?.startsWith("image:");
    return {
      ruleId: `${f.engine}/${f.ruleId}`,
      level: sarifLevel(f.severity),
      message: { text: f.message },
      properties: {
        engine: f.engine,
        severity: f.severity,
        ...(f.cwe ? { cwe: f.cwe } : {}),
        ...(f.source ? { source: f.source } : {}),
      },
      ...(!imageFinding
        ? {
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file.replace(/^\.\//, "") },
                  region: {
                    startLine: Math.max(1, f.line),
                    ...(f.column ? { startColumn: f.column } : {}),
                  },
                },
              },
            ],
          }
        : {}),
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "PolyScan",
            version: pkg.version,
            semanticVersion: pkg.version,
            informationUri: "https://github.com/sraisl/polyscan-action",
            rules,
          },
          ...(engineResults ? { extensions: engineExtensions(engineResults) } : {}),
        },
        ...(engineResults ? { invocations: [invocation(engineResults)] } : {}),
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
