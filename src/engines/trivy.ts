// Trivy engine adapter — filesystem scan for vulnerable dependencies and
// misconfigurations (SCA + IaC). Installs the trivy binary on demand.
import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";

const TRIVY_VERSION = "0.72.0";

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

async function ensureTrivy(workdir: string): Promise<string | null> {
  if (await which("trivy")) return "trivy";
  core.info(`trivy not found — downloading v${TRIVY_VERSION}…`);
  const res = await run("bash", [
    "-lc",
    [
      "set -e",
      `cd ${workdir}`,
      `curl -sSL -o trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"`,
      "tar xzf trivy.tar.gz",
      "chmod +x trivy",
    ].join("\n"),
  ]);
  const bin = path.join(workdir, "trivy");
  if (res.exitCode !== 0 || !fs.existsSync(bin)) {
    core.warning(`trivy download failed: ${res.stderr.slice(0, 200)}`);
    return null;
  }
  return bin;
}

export async function runTrivy(target: string): Promise<EngineResult> {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-trivy-"));
  const bin = await ensureTrivy(workdir);
  if (!bin) {
    return { engine: "trivy", findings: [], available: false, note: "trivy not installed" };
  }

  const outFile = path.join(workdir, "trivy.json");
  // fs scan: vuln (SCA) + misconfig (IaC/Dockerfile/pom etc.).
  // --offline-scan avoids resolving parent POMs over the network (Maven Central rate limits).
  const res = await run("bash", [
    "-lc",
    `"${bin}" fs --scanners vuln,misconfig --offline-scan --format json --output "${outFile}" --quiet "${path.resolve(target)}" 2>&1 || true`,
  ]);

  if (!fs.existsSync(outFile)) {
    return {
      engine: "trivy",
      findings: [],
      available: false,
      note: `trivy run produced no output: ${res.stdout.slice(0, 200)}`,
    };
  }

  const findings: Finding[] = [];
  try {
    const data = JSON.parse(fs.readFileSync(outFile, "utf-8"));
    for (const result of data.Results ?? []) {
      const artifact = result.Target ?? "unknown";
      // Vulnerabilities (SCA)
      for (const v of result.Vulnerabilities ?? []) {
        const fixed = v.FixedVersion ? ` (fixed in ${v.FixedVersion})` : "";
        findings.push({
          engine: "trivy",
          ruleId: v.VulnerabilityID ?? "TRIVY-VULN",
          severity: mapSeverity(v.Severity),
          message: `${v.PkgName}@${v.InstalledVersion}: ${v.Title ?? v.VulnerabilityID}${fixed}`,
          file: artifact,
          line: 0,
          cwe: Array.isArray(v.CweIDs) && v.CweIDs.length ? v.CweIDs[0] : undefined,
        });
      }
      // Misconfigurations (IaC)
      for (const mc of result.Misconfigurations ?? []) {
        findings.push({
          engine: "trivy",
          ruleId: mc.ID ?? "TRIVY-MISCONF",
          severity: mapSeverity(mc.Severity),
          message: `${mc.Title ?? mc.ID}: ${mc.Message ?? ""}`.trim(),
          file: artifact,
          line: mc.CauseMetadata?.StartLine ?? 0,
        });
      }
    }
  } catch (err) {
    return {
      engine: "trivy",
      findings: [],
      available: true,
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }

  return { engine: "trivy", findings, available: true };
}
