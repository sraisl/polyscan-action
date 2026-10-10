// Detects whether the code in the workspace came from someone who cannot push
// to this repository.
//
// Anyone with a GitHub account can open a pull request from a fork, so on such
// a run every file in the workspace — including build scripts — is attacker
// controlled. Engines that execute repository-controlled code must therefore
// not run by default for these events (see RISKY_ENGINE_REASONS in engines.ts).
import * as fs from "node:fs";

export interface RunTrust {
  untrusted: boolean;
  // Human-readable rationale, surfaced in the log and the job summary.
  reason: string;
  // Set when the run is reported as trusted but the workflow may still have
  // placed untrusted code in the workspace; main.ts emits it as a warning.
  advisory?: string;
}

const PULL_REQUEST_TARGET_ADVISORY =
  "pull_request_target runs with the base repository's permissions and secrets, so PolyScan " +
  "treats it as trusted. This pull request comes from a fork: if this workflow checks out the " +
  "pull request head instead of the base ref, the workspace holds untrusted code and you should " +
  "not run engines that execute it.";

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function repoFullName(repo: Record<string, unknown> | undefined): string | undefined {
  return typeof repo?.full_name === "string" ? repo.full_name : undefined;
}

/**
 * Reads and parses the webhook payload GitHub writes for the current event.
 *
 * Returns `undefined` when `GITHUB_EVENT_PATH` is unset, unreadable or not
 * valid JSON. The payload is attacker-influenced data, so every field is
 * re-checked at the point of use rather than trusted to have a given shape.
 */
export function readEventPayload(env: NodeJS.ProcessEnv): unknown {
  const eventPath = env.GITHUB_EVENT_PATH;
  if (!eventPath) return undefined;
  try {
    return JSON.parse(fs.readFileSync(eventPath, "utf8"));
  } catch {
    return undefined;
  }
}

/**
 * Classifies the current run as trusted or untrusted.
 *
 * - Any event other than `pull_request` runs code that only someone with write
 *   access could have placed in the repository, so it is trusted. That includes
 *   local runs, where `GITHUB_EVENT_NAME` is unset, and `pull_request_target`,
 *   which checks out the base ref by default (see PULL_REQUEST_TARGET_ADVISORY).
 * - A `pull_request` is untrusted when its head repository is not its base
 *   repository. Comparing `full_name` is the reliable signal: `head.repo.fork`
 *   is also `true` for an internal pull request when the repository is itself a
 *   fork of something else, so it is only consulted as a fallback.
 * - A `pull_request` whose head repository cannot be identified — no payload,
 *   unparsable payload, or a deleted head repository — fails closed and is
 *   reported as untrusted.
 *
 * The event payload is read from disk when it is not supplied by the caller.
 */
export function isUntrustedRun(
  env: NodeJS.ProcessEnv = process.env,
  eventPayload: unknown = readEventPayload(env),
): RunTrust {
  const eventName = env.GITHUB_EVENT_NAME ?? "";
  if (eventName !== "pull_request") {
    const trusted: RunTrust = {
      untrusted: false,
      reason: `event "${eventName || "(none)"}" only runs code from the repository itself`,
    };
    if (eventName === "pull_request_target" && headIsForeign(eventPayload) === true) {
      trusted.advisory = PULL_REQUEST_TARGET_ADVISORY;
    }
    return trusted;
  }

  const foreign = headIsForeign(eventPayload);
  if (foreign === undefined) {
    return {
      untrusted: true,
      reason:
        "pull_request event whose head repository could not be identified — " +
        "assuming it is a fork",
    };
  }
  if (!foreign) {
    return { untrusted: false, reason: "pull request from a branch of this repository" };
  }
  return { untrusted: true, reason: "pull request from a forked repository" };
}

/**
 * Whether the pull request's head repository differs from its base repository.
 * Returns `undefined` when the payload does not let us tell.
 */
function headIsForeign(eventPayload: unknown): boolean | undefined {
  const pullRequest = asRecord(asRecord(eventPayload)?.pull_request);
  if (!pullRequest) return undefined;

  const headRepo = asRecord(asRecord(pullRequest.head)?.repo);
  const baseRepo = asRecord(asRecord(pullRequest.base)?.repo);

  const headName = repoFullName(headRepo);
  const baseName = repoFullName(baseRepo);
  if (headName !== undefined && baseName !== undefined) return headName !== baseName;

  // full_name is missing on at least one side — fall back to the fork flag.
  if (headRepo?.fork === true) return true;
  return undefined;
}
