// SARIF 2.1.0 serializer (GitHub Code Scanning compatible).
import * as crypto from "node:crypto";
import { EngineResult, Finding, SEVERITY_ORDER, Severity } from "./schema";
import { findingUrl } from "./links";
import { engineVersion } from "./tool-versions";
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
  severity: Severity; // highest severity among the rule's findings
  helpUri?: string;
  cwes: Set<string>;
}

function moreSevere(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function collectRules(findings: Finding[]): Map<string, RuleSummary> {
  // Deduplicate rules by engine/ruleId.
  const ruleMap = new Map<string, RuleSummary>();
  for (const f of findings) {
    const id = `${f.engine}/${f.ruleId}`;
    let rule = ruleMap.get(id);
    if (!rule) {
      rule = { id, name: f.ruleId, desc: f.message, severity: f.severity, cwes: new Set() };
      ruleMap.set(id, rule);
    }
    rule.severity = moreSevere(rule.severity, f.severity);
    rule.helpUri ??= findingUrl(f);
    if (f.cwe) rule.cwes.add(f.cwe);
  }
  return ruleMap;
}

function sarifRule(rule: RuleSummary) {
  const securitySeverity = SECURITY_SEVERITY[rule.severity];
  const cweTags = [...rule.cwes].sort().map((cwe) => `external/cwe/${cwe.toLowerCase()}`);
  return {
    id: rule.id,
    name: rule.name,
    shortDescription: { text: `${rule.name}` },
    fullDescription: { text: rule.desc },
    defaultConfiguration: { level: sarifLevel(rule.severity) },
    ...(rule.helpUri ? { helpUri: rule.helpUri } : {}),
    properties: {
      tags: ["security", rule.id.split("/", 1)[0], ...cweTags],
      ...(securitySeverity ? { "security-severity": securitySeverity } : {}),
    },
  };
}

// Line-independent fingerprint, so an alert keeps its identity when code above it
// moves. Identical findings in one file are told apart by their occurrence index.
function fingerprints(findings: Finding[]): string[] {
  const seen = new Map<string, number>();
  return findings.map((f) => {
    const hash = crypto
      .createHash("sha256")
      .update([f.engine, f.ruleId, f.source ?? "", f.file, f.message].join("\0"))
      .digest("hex")
      .slice(0, 32);
    const occurrence = (seen.get(hash) ?? 0) + 1;
    seen.set(hash, occurrence);
    return `${hash}:${occurrence}`;
  });
}

function engineExtensions(engineResults: EngineResult[]) {
  return engineResults.map((result) => {
    const version = engineVersion(result.engine);
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
  return {
    executionSuccessful: engineResults.every((result) => result.status !== "failed"),
    ...(notifications.length > 0 ? { toolExecutionNotifications: notifications } : {}),
  };
}

export function toSarif(findings: Finding[], engineResults?: EngineResult[]): string {
  const rules = [...collectRules(findings).values()].map(sarifRule);
  const prints = fingerprints(findings);

  const results = findings.map((f, index) => {
    const imageFinding = f.source?.startsWith("image:");
    return {
      ruleId: `${f.engine}/${f.ruleId}`,
      level: sarifLevel(f.severity),
      message: { text: f.message },
      partialFingerprints: { "polyscanFindingHash/v1": prints[index] },
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
