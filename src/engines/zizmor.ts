// zizmor engine adapter — GitHub Actions workflow security (dangerous
// triggers, template-injection, unpinned actions, excessive permissions,
// credential persistence, ...).
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { findPinnedOnPath, run } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, TOOLS } from "../tool-versions";

const ZIZMOR = TOOLS.zizmor;

export function hasWorkflows(root: string): boolean {
  const workflowsDir = path.join(root, ".github", "workflows");
  try {
    return fs
      .readdirSync(workflowsDir, { withFileTypes: true })
      .some((entry) => entry.isFile() && /\.ya?ml$/i.test(entry.name));
  } catch {
    // Missing, not a directory, or unreadable — treat as "no workflows".
    return false;
  }
}

// Observed zizmor SARIF only emits error/warning; any other/missing level
// (e.g. "note") is treated as low, defensively, like hadolint's parser.
function mapSeverity(level: string): Severity {
  switch ((level || "").toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    default:
      return "low";
  }
}

export function parseZizmorSarif(sarif: unknown, abs: string): Finding[] {
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
            region?: { startLine?: number; startColumn?: number };
          };
        }[];
      };
      const ruleId = result.ruleId ?? "zizmor";
      const loc = result.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri ?? "unknown";
      findings.push({
        engine: "zizmor",
        ruleId,
        severity: mapSeverity(result.level ?? ""),
        message: result.message?.text ?? ruleId,
        // zizmor emits URIs relative to the scanned directory already; strip
        // a file:// scheme and the abs prefix defensively, like hadolint's parser.
        file: uri.replace(/^file:\/\//, "").replace(abs + "/", ""),
        line: loc?.region?.startLine ?? 0,
        column: loc?.region?.startColumn,
      });
    }
  }
  return findings;
}

async function ensureZizmor(): Promise<string | null> {
  const pinned = await findPinnedOnPath("zizmor", ZIZMOR.version, ["--version"], core);
  if (pinned) return pinned;
  core.info(`zizmor v${ZIZMOR.version} not found on PATH - downloading...`);
  try {
    return await cachedTool("zizmor", ZIZMOR.version, "zizmor", async (directory) => {
      const archive = await downloadVerified(githubReleaseUrl(ZIZMOR), ZIZMOR.sha256);
      await tc.extractTar(archive, directory);
      fs.chmodSync(path.join(directory, "zizmor"), 0o700);
    });
  } catch (err) {
    core.warning(`zizmor download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export async function runZizmor(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  if (!hasWorkflows(abs)) {
    return { engine: "zizmor", findings: [], status: "skipped", note: "no GitHub Actions workflows found" };
  }

  const bin = await ensureZizmor();
  if (!bin) {
    return { engine: "zizmor", findings: [], status: "failed", note: "zizmor not installed" };
  }

  // --offline skips audits that need to fetch remote repositories/actions,
  // keeping the scan deterministic and free of extra token requirements.
  const result = await run(bin, ["--format", "sarif", "--offline", abs]);
  if (!result.stdout.trim()) {
    return {
      engine: "zizmor",
      findings: [],
      status: "failed",
      note: result.stderr.slice(0, 200) || "zizmor produced no output",
    };
  }

  try {
    const sarif = JSON.parse(result.stdout);
    return { engine: "zizmor", findings: parseZizmorSarif(sarif, abs), status: "success" };
  } catch (err) {
    return {
      engine: "zizmor",
      findings: [],
      status: "failed",
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }
}
