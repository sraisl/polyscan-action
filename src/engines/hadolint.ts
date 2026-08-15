// hadolint engine adapter — Dockerfile linting (best practices + security-relevant checks).
// Downloads the pinned standalone binary and parses hadolint's native SARIF output.
import * as fs from "node:fs";
import * as path from "node:path";
import { getCore } from "../actions-core";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, TOOLS } from "../tool-versions";

const HADOLINT = TOOLS.hadolint;
const IGNORED_DIRECTORIES = new Set([".git", "node_modules", "vendor", "build", "dist", "target", ".gradle"]);

function isDockerfile(name: string): boolean {
  const lower = name.toLowerCase();
  return lower === "dockerfile" || lower.startsWith("dockerfile.") || lower.endsWith(".dockerfile");
}

export function findDockerfiles(root: string): string[] {
  const files: string[] = [];

  function walk(directory: string): void {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) walk(path.join(directory, entry.name));
      } else if (entry.isFile() && isDockerfile(entry.name)) {
        files.push(path.join(directory, entry.name));
      }
    }
  }

  walk(root);
  return files;
}

// hadolint SARIF only emits error/warning/note (info+style are packed into note); map to our severities.
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

export function parseHadolintSarif(sarif: unknown, abs: string): Finding[] {
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
      const ruleId = result.ruleId ?? "hadolint";
      const loc = result.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri ?? "unknown";
      findings.push({
        engine: "hadolint",
        ruleId,
        severity: mapSeverity(result.level ?? ""),
        message: result.message?.text ?? ruleId,
        file: uri.replace(/^file:\/\//, "").replace(abs + "/", ""),
        line: loc?.region?.startLine ?? 0,
        column: loc?.region?.startColumn,
      });
    }
  }
  return findings;
}

async function ensureHadolint(): Promise<string | null> {
  const core = await getCore();
  if (await which("hadolint")) return "hadolint";
  core.info(`hadolint not found — downloading v${HADOLINT.version}…`);
  try {
    return await cachedTool("hadolint", HADOLINT.version, "hadolint", async (directory) => {
      const downloaded = await downloadVerified(githubReleaseUrl(HADOLINT), HADOLINT.sha256);
      const executable = path.join(directory, "hadolint");
      fs.copyFileSync(downloaded, executable);
      fs.chmodSync(executable, 0o700);
    });
  } catch (err) {
    core.warning(`hadolint download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export async function runHadolint(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const dockerfiles = findDockerfiles(abs);
  if (dockerfiles.length === 0) {
    return { engine: "hadolint", findings: [], status: "skipped", note: "no Dockerfiles found" };
  }

  const bin = await ensureHadolint();
  if (!bin) {
    return { engine: "hadolint", findings: [], status: "failed", note: "hadolint not installed" };
  }

  const result = await run(bin, ["--no-fail", "--format", "sarif", ...dockerfiles]);
  if (!result.stdout.trim()) {
    return {
      engine: "hadolint",
      findings: [],
      status: "failed",
      note: result.stderr.slice(0, 200) || "hadolint produced no output",
    };
  }

  try {
    const sarif = JSON.parse(result.stdout);
    return { engine: "hadolint", findings: parseHadolintSarif(sarif, abs), status: "success" };
  } catch (err) {
    return {
      engine: "hadolint",
      findings: [],
      status: "failed",
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }
}
