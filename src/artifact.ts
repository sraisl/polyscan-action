// Workflow artifact naming. Artifact names must be unique per workflow run, so
// several PolyScan steps (matrix legs, separate jobs, a second step in the same
// job) would otherwise collide on the same name with a 409 Conflict.

import { randomBytes } from "node:crypto";

export const DEFAULT_ARTIFACT_NAME = "polyscan-reports";
// Matrix legs share GITHUB_JOB, so fallbacks past the job-qualified name carry a
// random suffix; a fixed counter would run out once enough legs had uploaded.
const RANDOM_NAME_ATTEMPTS = 3;
// Characters the artifact service rejects in names.
const INVALID_NAME_CHARS = /[":<>|*?\\/\r\n]/g;

function randomSuffix(): string {
  return randomBytes(4).toString("hex");
}

export function sanitizeArtifactName(name: string): string {
  return name.replace(INVALID_NAME_CHARS, "-").trim();
}

export function isArtifactNameConflict(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /\(409\)|already exists/i.test(message);
}

// Name to try for each upload attempt: the requested name first, then the same
// name qualified with the job id, then that qualified name with random suffixes.
export function artifactNameCandidates(
  base: string,
  job = process.env.GITHUB_JOB,
  suffix: () => string = randomSuffix,
): string[] {
  const name = sanitizeArtifactName(base) || DEFAULT_ARTIFACT_NAME;
  const qualified = job ? `${name}-${sanitizeArtifactName(job)}` : name;
  const candidates = [name];
  if (qualified !== name) candidates.push(qualified);
  for (let n = 0; n < RANDOM_NAME_ATTEMPTS; n++) {
    candidates.push(`${qualified}-${suffix()}`);
  }
  return candidates;
}

export async function uploadWithUniqueName(
  base: string,
  upload: (name: string) => Promise<void>,
  job = process.env.GITHUB_JOB,
  suffix: () => string = randomSuffix,
): Promise<string> {
  let lastError: unknown;
  for (const name of artifactNameCandidates(base, job, suffix)) {
    try {
      await upload(name);
      return name;
    } catch (err) {
      if (!isArtifactNameConflict(err)) throw err;
      lastError = err;
    }
  }
  throw lastError;
}
