// gitleaks engine adapter — secret / credential detection in git history + working tree.
// Downloads the gitleaks binary on demand and parses its SARIF report.
import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";

const GITLEAKS_VERSION = "8.21.0";

function resolveTarget(target: string): string {
  const ws = process.env.GITHUB_WORKSPACE;
  if (ws && !path.isAbsolute(target)) {
    return path.resolve(ws, target);
  }
  return path.resolve(target);
}

// gitleaks severities in its SARIF are "Critical"/"High"/"Low"/"Info"; map to ours.
function mapSeverity(level: string): Severity {
  switch ((level || "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    default:
      return "low";
  }
}

export async function runGitleaks(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-gitleaks-"));
  const bin = await ensureGitleaks(workdir);
  if (!bin) {
    return { engine: "gitleaks", findings: [], available: false, note: "gitleaks not installed" };
  }

  const sarifOut = path.join(workdir, "gitleaks.sarif");
  // Scan full git history + uncommitted; --no-banner; redact to avoid leaking the secret into logs.
  // gitleaks scans the git repo rooted at the current directory, so run it
  // with the target as cwd.
  const res = await run(
    bin,
    ["detect", "--report-format", "sarif", "--report-path", sarifOut, "--no-banner", "--redact"],
    { cwd: abs },
  );

  if (!fs.existsSync(sarifOut)) {
    return {
      engine: "gitleaks",
      findings: [],
      available: false,
      note: `gitleaks produced no report: ${res.stdout.slice(0, 200)}`,
    };
  }

  const findings: Finding[] = [];
  try {
    const sarif = JSON.parse(fs.readFileSync(sarifOut, "utf-8"));
    for (const runObj of sarif.runs ?? []) {
      for (const r of runObj.results ?? []) {
        const ruleId = r.ruleId ?? "gitleaks";
        const loc = r.locations?.[0]?.physicalLocation;
        const uri = loc?.artifactLocation?.uri ?? "unknown";
        const line = loc?.region?.startLine ?? 0;
        // gitleaks puts the rule/description in message + a 'RuleID' property.
        const ruleName = r.properties?.RuleID ?? ruleId;
        findings.push({
          engine: "gitleaks",
          ruleId: String(ruleName),
          severity: mapSeverity(r.level),
          message: r.message?.text ?? ruleName,
          file: uri.replace(/^file:\/\//, "").replace(abs + "/", ""),
          line,
        });
      }
    }
  } catch (err) {
    return { engine: "gitleaks", findings: [], available: true, note: `parse error: ${String(err).slice(0, 200)}` };
  }

  return { engine: "gitleaks", findings, available: true };
}

async function ensureGitleaks(workdir: string): Promise<string | null> {
  if (await which("gitleaks")) return "gitleaks";
  core.info(`gitleaks not found — downloading v${GITLEAKS_VERSION}…`);
  const url = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`;
  const res = await run("bash", [
    "-lc",
    [
      "set -e",
      `cd ${workdir}`,
      `curl -sSL -o gitleaks.tar.gz "${url}"`,
      "tar xzf gitleaks.tar.gz",
      "chmod +x gitleaks",
    ].join("\n"),
  ]);
  const bin = path.join(workdir, "gitleaks");
  if (res.exitCode !== 0 || !fs.existsSync(bin)) {
    core.warning(`gitleaks download failed: ${res.stderr.slice(0, 200)}`);
    return null;
  }
  return bin;
}
