// gitleaks engine adapter — secret / credential detection in git history + working tree.
// Downloads the gitleaks binary on demand and parses its SARIF report.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { getCore } from "../actions-core";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, TOOLS } from "../tool-versions";

const GITLEAKS = TOOLS.gitleaks;
const GITLEAKS_VERSION = GITLEAKS.version;
const GITLEAKS_SHA256 = GITLEAKS.sha256;

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

export function parseGitleaksSarif(sarif: unknown, abs: string): Finding[] {
  const findings: Finding[] = [];
  for (const runObj of (sarif as { runs?: unknown[] }).runs ?? []) {
    for (const r of (runObj as { results?: unknown[] }).results ?? []) {
      const result = r as {
        ruleId?: string;
        level?: string;
        message?: { text?: string };
        properties?: { RuleID?: string };
        locations?: { physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number } } }[];
      };
      const ruleId = result.ruleId ?? "gitleaks";
      const loc = result.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri ?? "unknown";
      const line = loc?.region?.startLine ?? 0;
      const ruleName = result.properties?.RuleID ?? ruleId;
      findings.push({
        engine: "gitleaks",
        ruleId: String(ruleName),
        severity: mapSeverity(result.level ?? ""),
        message: result.message?.text ?? ruleName,
        file: uri.replace(/^file:\/\//, "").replace(abs + "/", ""),
        line,
      });
    }
  }
  return findings;
}

export async function runGitleaks(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-gitleaks-"));
  try {
    const bin = await ensureGitleaks();
    if (!bin) {
      return { engine: "gitleaks", findings: [], status: "failed", note: "gitleaks not installed" };
    }

    const sarifOut = path.join(workdir, "gitleaks.sarif");
    // Redaction happens before PolyScan reads the report, so secrets never enter its output.
    const res = await run(
      bin,
      ["detect", "--report-format", "sarif", "--report-path", sarifOut, "--no-banner", "--redact"],
      { cwd: abs },
    );

    if (!fs.existsSync(sarifOut)) {
      return {
        engine: "gitleaks",
        findings: [],
        status: "failed",
        note: `gitleaks produced no report: ${(res.stderr || res.stdout).slice(0, 200)}`,
      };
    }

    try {
      const sarif = JSON.parse(fs.readFileSync(sarifOut, "utf-8"));
      return { engine: "gitleaks", findings: parseGitleaksSarif(sarif, abs), status: "success" };
    } catch (err) {
      return {
        engine: "gitleaks",
        findings: [],
        status: "failed",
        note: `parse error: ${String(err).slice(0, 200)}`,
      };
    }
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}

async function ensureGitleaks(): Promise<string | null> {
  const core = await getCore();
  if (await which("gitleaks")) return "gitleaks";
  core.info(`gitleaks not found — downloading v${GITLEAKS_VERSION}…`);
  try {
    return await cachedTool("gitleaks", GITLEAKS_VERSION, "gitleaks", async (directory) => {
      const archive = await downloadVerified(
        githubReleaseUrl(GITLEAKS),
        GITLEAKS_SHA256,
      );
      await tc.extractTar(archive, directory);
      fs.chmodSync(path.join(directory, "gitleaks"), 0o700);
    });
  } catch (err) {
    core.warning(`gitleaks download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}
