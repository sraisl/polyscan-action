// Workflow artifact naming. Artifact names must be unique per workflow run, so
// several PolyScan steps (matrix legs, separate jobs, a second step in the same
// job) would otherwise collide on the same name with a 409 Conflict.

export const DEFAULT_ARTIFACT_NAME = "polyscan-reports";
const MAX_NAME_ATTEMPTS = 10;
// Characters the artifact service rejects in names.
const INVALID_NAME_CHARS = /["':<>|*?\\/\r\n]/g;

export function sanitizeArtifactName(name: string): string {
  return name.replace(INVALID_NAME_CHARS, "-").trim();
}

export function isArtifactNameConflict(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /\(409\)|already exists/i.test(message);
}

// Name to try for each upload attempt: the requested name first, then the same
// name qualified with the job id and a counter.
export function artifactNameCandidates(base: string, job = process.env.GITHUB_JOB): string[] {
  const name = sanitizeArtifactName(base) || DEFAULT_ARTIFACT_NAME;
  const qualified = job ? `${name}-${sanitizeArtifactName(job)}` : name;
  const candidates = [name];
  if (qualified !== name) candidates.push(qualified);
  for (let n = 2; candidates.length < MAX_NAME_ATTEMPTS; n++) {
    candidates.push(`${qualified}-${n}`);
  }
  return candidates;
}

export async function uploadWithUniqueName(
  base: string,
  upload: (name: string) => Promise<void>,
  job = process.env.GITHUB_JOB,
): Promise<string> {
  let lastError: unknown;
  for (const name of artifactNameCandidates(base, job)) {
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
