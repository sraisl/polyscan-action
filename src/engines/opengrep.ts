// OpenGrep engine adapter — downloads a pinned standalone binary and parses
// Semgrep-compatible JSON output.
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as path from "node:path";
import { EngineResult, Finding } from "../schema";
import { resolveExecutable, resolvePinnedExecutable, run } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, TOOLS } from "../tool-versions";
import { parseSemgrepCompatibleJson } from "./semgrep-json";

const OPENGREP = TOOLS.opengrep;

export function parseOpengrepJson(stdout: string): Finding[] {
  return parseSemgrepCompatibleJson(stdout, "opengrep", "opengrep-rule", "OpenGrep finding");
}

async function ensureOpengrep(): Promise<string | null> {
  const existing = resolveExecutable("opengrep");
  if (existing) {
    const pinned = await resolvePinnedExecutable(
      "opengrep",
      OPENGREP.version,
      ["--version", "--disable-version-check"],
    );
    if (pinned) return pinned;
    core.warning(
      `Ignoring OpenGrep from PATH because it is not the pinned version ${OPENGREP.version}`,
    );
  }

  core.info(`OpenGrep ${OPENGREP.version} not found - downloading verified binary...`);
  try {
    return await cachedTool("opengrep", OPENGREP.version, "opengrep", async (directory) => {
      const downloaded = await downloadVerified(githubReleaseUrl(OPENGREP), OPENGREP.sha256);
      const executable = path.join(directory, "opengrep");
      fs.copyFileSync(downloaded, executable);
      fs.chmodSync(executable, 0o700);
    });
  } catch (err) {
    core.warning(`OpenGrep download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export function opengrepArgs(
  target: string,
  config: string,
  excludedRules: readonly string[] = [],
): string[] {
  return [
    "scan",
    "--config",
    config,
    ...excludedRules.flatMap((rule) => ["--exclude-rule", rule]),
    "--json",
    "--quiet",
    "--no-git-ignore",
    target,
  ];
}

export async function runOpengrep(
  target: string,
  config: string,
  excludedRules: readonly string[] = [],
): Promise<EngineResult> {
  const executable = await ensureOpengrep();
  if (!executable) {
    return { engine: "opengrep", findings: [], status: "failed", note: "opengrep not installed" };
  }

  const result = await run(executable, opengrepArgs(resolveTarget(target), config, excludedRules));
  if (result.exitCode !== 0) {
    return {
      engine: "opengrep",
      findings: [],
      status: "failed",
      note: result.stderr.slice(0, 300) || `opengrep exited ${result.exitCode}`,
    };
  }
  if (!result.stdout.trim()) {
    return {
      engine: "opengrep",
      findings: [],
      status: "failed",
      note: result.stderr.slice(0, 300) || "opengrep produced no output",
    };
  }

  try {
    return {
      engine: "opengrep",
      findings: parseOpengrepJson(result.stdout),
      status: "success",
    };
  } catch (err) {
    return {
      engine: "opengrep",
      findings: [],
      status: "failed",
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }
}
