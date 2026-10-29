// reviewdog integration — posts findings as inline PR review comments and as a
// GitHub check with annotations. Downloads a pinned reviewdog binary and feeds it
// the PolyScan SARIF on stdin. Never fails the action: problems become warnings.
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { EngineResult, Finding } from "./schema";
import { run } from "./exec";
import { toSarif } from "./sarif";
import { workspaceRoot } from "./target";
import { cachedTool, downloadVerified } from "./tools";
import { githubReleaseUrl, TOOLS } from "./tool-versions";

const REVIEWDOG = TOOLS.reviewdog;

export interface ReviewdogPass {
  reporter: "github-pr-review" | "github-check";
  filterMode: "added" | "nofilter";
  level?: "warning";
}

const PR_EVENTS: ReadonlySet<string> = new Set(["pull_request", "pull_request_target"]);

// On pull requests, comment inline on changed lines only, so pre-existing findings
// don't flood the review. Every run also gets a check with annotations for all
// findings; level=warning keeps that check neutral instead of failed, since the
// Quality Gate (not reviewdog) decides whether the job fails.
export function reviewdogPasses(eventName: string | undefined): ReviewdogPass[] {
  const passes: ReviewdogPass[] = [];
  if (eventName && PR_EVENTS.has(eventName)) {
    passes.push({ reporter: "github-pr-review", filterMode: "added" });
  }
  passes.push({ reporter: "github-check", filterMode: "nofilter", level: "warning" });
  return passes;
}

export function reviewdogArgs(pass: ReviewdogPass): string[] {
  return [
    "-f=sarif",
    "-name=PolyScan",
    `-reporter=${pass.reporter}`,
    `-filter-mode=${pass.filterMode}`,
    "-fail-level=none",
    ...(pass.level ? [`-level=${pass.level}`] : []),
  ];
}

// Container image findings have no source location, so reviewdog cannot place them.
export function reviewdogFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => !finding.source?.startsWith("image:"));
}

async function ensureReviewdog(): Promise<string> {
  core.info(`Downloading reviewdog v${REVIEWDOG.version}…`);
  return cachedTool("reviewdog", REVIEWDOG.version, "reviewdog", async (directory) => {
    const archive = await downloadVerified(githubReleaseUrl(REVIEWDOG), REVIEWDOG.sha256);
    await tc.extractTar(archive, directory);
    fs.chmodSync(path.join(directory, "reviewdog"), 0o700);
  });
}

export async function runReviewdog(
  findings: Finding[],
  engineResults: EngineResult[],
  token: string,
  eventName: string | undefined = process.env.GITHUB_EVENT_NAME,
): Promise<void> {
  if (!token) {
    core.warning("reviewdog=true but no github-token is available; skipping reviewdog.");
    return;
  }
  core.setSecret(token);

  let bin: string;
  try {
    bin = await ensureReviewdog();
  } catch (err) {
    core.warning(`reviewdog download failed: ${String(err).slice(0, 200)}`);
    return;
  }

  const located = reviewdogFindings(findings);
  const sarif = toSarif(located, engineResults);
  for (const pass of reviewdogPasses(eventName)) {
    const res = await run(bin, reviewdogArgs(pass), {
      cwd: workspaceRoot(),
      env: { REVIEWDOG_GITHUB_API_TOKEN: token },
      input: sarif,
    });
    if (res.exitCode === 0) {
      core.info(`reviewdog (${pass.reporter}) reported ${located.length} finding(s).`);
      continue;
    }
    core.warning(
      `reviewdog (${pass.reporter}) failed with exit code ${res.exitCode}: ` +
        `${(res.stderr || res.stdout).trim().slice(-300)} — the workflow needs ` +
        "'permissions: checks: write, pull-requests: write' (pull requests from forks " +
        "only get a read-only token).",
    );
  }
}
