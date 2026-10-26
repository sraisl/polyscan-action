// TruffleHog engine adapter — secret detection with live verification.
// Opt-in (not part of "all"): unlike every other engine, verification makes
// real network calls to each credential's own provider API (AWS, GitHub,
// Slack, ...) to confirm a found secret is actually live, which is the
// point of running it but is a materially different, non-deterministic
// network posture than PolyScan's other (offline/deterministic) engines.
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { findPinnedOnPath, run } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, TOOLS } from "../tool-versions";

const TRUFFLEHOG = TOOLS.trufflehog;

// TruffleHog's SARIF writer reports a verified (live, working) credential as
// "error" and everything else (detected but not confirmed live) as
// "warning" — see pkg/output/sarif.go upstream. A verified secret is a
// confirmed active breach, so it maps to critical; anything else defaults
// to high rather than risking under-classifying an exposed credential.
function mapSeverity(level: string): Severity {
  return (level || "").toLowerCase() === "error" ? "critical" : "high";
}

export function parseTrufflehogSarif(sarif: unknown, abs: string): Finding[] {
  const findings: Finding[] = [];
  for (const runObj of (sarif as { runs?: unknown[] }).runs ?? []) {
    for (const r of (runObj as { results?: unknown[] }).results ?? []) {
      const result = r as {
        ruleId?: string;
        level?: string;
        message?: { text?: string };
        locations?: {
          physicalLocation?: {
            artifactLocation?: { uri?: string };
            region?: { startLine?: number };
          };
        }[];
      };
      const ruleId = result.ruleId ?? "trufflehog";
      const loc = result.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri ?? "unknown";
      findings.push({
        engine: "trufflehog",
        ruleId,
        severity: mapSeverity(result.level ?? ""),
        // TruffleHog's SARIF message never includes the secret value itself
        // (it's a templated "Found <verified|unverified> result for detector
        // <name>." string), so no redaction step is needed before this text
        // reaches SARIF/the job summary.
        message: result.message?.text ?? ruleId,
        file: uri.replace(/^file:\/\//, "").replace(abs + "/", ""),
        line: loc?.region?.startLine ?? 0,
      });
    }
  }
  return findings;
}

async function ensureTrufflehog(): Promise<string | null> {
  const pinned = await findPinnedOnPath("trufflehog", TRUFFLEHOG.version, ["--version"], core);
  if (pinned) return pinned;
  core.info(`trufflehog v${TRUFFLEHOG.version} not found on PATH - downloading...`);
  try {
    return await cachedTool("trufflehog", TRUFFLEHOG.version, "trufflehog", async (directory) => {
      const archive = await downloadVerified(githubReleaseUrl(TRUFFLEHOG), TRUFFLEHOG.sha256);
      await tc.extractTar(archive, directory);
      fs.chmodSync(path.join(directory, "trufflehog"), 0o700);
    });
  } catch (err) {
    core.warning(`trufflehog download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export async function runTrufflehog(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);

  const bin = await ensureTrufflehog();
  if (!bin) {
    return { engine: "trufflehog", findings: [], status: "failed", note: "trufflehog not installed" };
  }

  const result = await run(bin, ["filesystem", "--sarif", "--no-update", "--log-level=-1", abs]);
  if (!result.stdout.trim()) {
    // Deliberately not including result.stderr here: this engine actively
    // verifies live credentials, and its stderr is not a structured,
    // redaction-guaranteed surface the way its SARIF output is — an exit
    // code is enough to diagnose a failure without risking a secret value
    // reaching the Actions log.
    return {
      engine: "trufflehog",
      findings: [],
      status: "failed",
      note: `trufflehog produced no output (exit ${result.exitCode})`,
    };
  }

  try {
    const sarif = JSON.parse(result.stdout);
    return { engine: "trufflehog", findings: parseTrufflehogSarif(sarif, abs), status: "success" };
  } catch (err) {
    return {
      engine: "trufflehog",
      findings: [],
      status: "failed",
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }
}
