// SARIF 2.1.0 serializer (GitHub Code Scanning compatible).
import { Finding, Severity } from "./schema";

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

export function toSarif(findings: Finding[]): string {
  // Deduplicate rules by engine/ruleId.
  const ruleMap = new Map<string, { id: string; name: string; desc: string }>();
  for (const f of findings) {
    const id = `${f.engine}/${f.ruleId}`;
    if (!ruleMap.has(id)) {
      ruleMap.set(id, { id, name: f.ruleId, desc: f.message });
    }
  }

  const rules = [...ruleMap.values()].map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: { text: `${r.name}` },
    fullDescription: { text: r.desc },
  }));

  const results = findings.map((f) => ({
    ruleId: `${f.engine}/${f.ruleId}`,
    level: sarifLevel(f.severity),
    message: { text: f.message },
    properties: {
      engine: f.engine,
      severity: f.severity,
      ...(f.cwe ? { cwe: f.cwe } : {}),
    },
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
  }));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "PolyScan",
            version: "1.0.0",
            informationUri: "https://github.com/sraisl/polyscan-action",
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
