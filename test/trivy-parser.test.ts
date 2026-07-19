import test from "node:test";
import assert from "node:assert/strict";

import { parseTrivyData } from "../src/engines/trivy";

const BASE_VULN = {
  VulnerabilityID: "CVE-2021-1234",
  PkgName: "lodash",
  InstalledVersion: "4.17.20",
  FixedVersion: "4.17.21",
  Severity: "HIGH",
  Title: "Prototype pollution",
  CweIDs: ["CWE-1321"],
};

const BASE_MISCONF = {
  ID: "AVD-DS-0001",
  Title: "Missing USER instruction",
  Message: "Dockerfile should not run as root",
  Severity: "MEDIUM",
  CauseMetadata: { StartLine: 3 },
};

test("parseTrivyData: vulnerability with HIGH severity and CWE", () => {
  const data = { Results: [{ Target: "package-lock.json", Vulnerabilities: [BASE_VULN] }] };
  const [f] = parseTrivyData(data);
  assert.equal(f.engine, "trivy");
  assert.equal(f.ruleId, "CVE-2021-1234");
  assert.equal(f.severity, "high");
  assert.equal(f.message, "lodash@4.17.20: Prototype pollution (fixed in 4.17.21)");
  assert.equal(f.file, "package-lock.json");
  assert.equal(f.line, 0);
  assert.equal(f.cwe, "CWE-1321");
});

test("parseTrivyData: CRITICAL severity maps to critical", () => {
  const data = {
    Results: [{ Target: "go.sum", Vulnerabilities: [{ ...BASE_VULN, Severity: "CRITICAL" }] }],
  };
  assert.equal(parseTrivyData(data)[0].severity, "critical");
});

test("parseTrivyData: MEDIUM severity maps to medium", () => {
  const data = {
    Results: [{ Target: "pom.xml", Vulnerabilities: [{ ...BASE_VULN, Severity: "MEDIUM" }] }],
  };
  assert.equal(parseTrivyData(data)[0].severity, "medium");
});

test("parseTrivyData: LOW severity maps to low", () => {
  const data = {
    Results: [{ Target: "pom.xml", Vulnerabilities: [{ ...BASE_VULN, Severity: "LOW" }] }],
  };
  assert.equal(parseTrivyData(data)[0].severity, "low");
});

test("parseTrivyData: UNKNOWN severity maps to info", () => {
  const data = {
    Results: [{ Target: "pom.xml", Vulnerabilities: [{ ...BASE_VULN, Severity: "UNKNOWN" }] }],
  };
  assert.equal(parseTrivyData(data)[0].severity, "info");
});

test("parseTrivyData: vulnerability without FixedVersion omits fix note", () => {
  const { FixedVersion: _, ...noFix } = BASE_VULN;
  const data = { Results: [{ Target: "package.json", Vulnerabilities: [noFix] }] };
  assert.ok(!parseTrivyData(data)[0].message.includes("fixed in"));
});

test("parseTrivyData: misconfiguration with StartLine and MEDIUM severity", () => {
  const data = { Results: [{ Target: "Dockerfile", Misconfigurations: [BASE_MISCONF] }] };
  const [f] = parseTrivyData(data);
  assert.equal(f.engine, "trivy");
  assert.equal(f.ruleId, "AVD-DS-0001");
  assert.equal(f.severity, "medium");
  assert.equal(f.message, "Missing USER instruction: Dockerfile should not run as root");
  assert.equal(f.file, "Dockerfile");
  assert.equal(f.line, 3);
});

test("parseTrivyData: vulns and misconfigs in the same result are both parsed", () => {
  const data = {
    Results: [
      {
        Target: "Dockerfile",
        Vulnerabilities: [BASE_VULN],
        Misconfigurations: [BASE_MISCONF],
      },
    ],
  };
  assert.equal(parseTrivyData(data).length, 2);
});

test("parseTrivyData: empty CweIDs array → cwe undefined", () => {
  const data = {
    Results: [{ Target: "go.sum", Vulnerabilities: [{ ...BASE_VULN, CweIDs: [] }] }],
  };
  assert.equal(parseTrivyData(data)[0].cwe, undefined);
});

test("parseTrivyData: empty Results array returns empty array", () => {
  assert.deepEqual(parseTrivyData({ Results: [] }), []);
});

test("parseTrivyData: missing Results key returns empty array", () => {
  assert.deepEqual(parseTrivyData({}), []);
});

test("parseTrivyData: image scan output (multiple OS layers) all parsed", () => {
  const data = {
    Results: [
      {
        Target: "myapp:latest (ubuntu 22.04)",
        Vulnerabilities: [
          { ...BASE_VULN, VulnerabilityID: "CVE-2023-0001", Severity: "CRITICAL", PkgName: "openssl", InstalledVersion: "3.0.2", FixedVersion: "3.0.8" },
        ],
      },
      {
        Target: "myapp:latest",
        Vulnerabilities: [
          { ...BASE_VULN, VulnerabilityID: "CVE-2023-0002", Severity: "HIGH", PkgName: "libc6", InstalledVersion: "2.35", FixedVersion: undefined },
        ],
      },
    ],
  };
  const findings = parseTrivyData(data);
  assert.equal(findings.length, 2);
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].file, "myapp:latest (ubuntu 22.04)");
  assert.equal(findings[1].severity, "high");
  assert.equal(findings[1].file, "myapp:latest");
  assert.ok(findings[0].message.includes("fixed in 3.0.8"));
  assert.ok(!findings[1].message.includes("fixed in"));
});
