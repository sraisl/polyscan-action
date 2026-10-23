import test from "node:test";
import assert from "node:assert/strict";

import {
  artifactNameCandidates,
  isArtifactNameConflict,
  sanitizeArtifactName,
  uploadWithUniqueName,
} from "../src/artifact";

const CONFLICT = new Error(
  "Failed to CreateArtifact: Received non-retryable error: Failed request: (409) Conflict: " +
    "an artifact with this name already exists on the workflow run",
);

test("isArtifactNameConflict recognizes the artifact service 409 response", () => {
  assert.equal(isArtifactNameConflict(CONFLICT), true);
  assert.equal(isArtifactNameConflict(new Error("(500) Internal Server Error")), false);
});

function counter(): () => string {
  let n = 0;
  return () => `r${++n}`;
}

test("sanitizeArtifactName replaces characters the artifact service rejects", () => {
  assert.equal(sanitizeArtifactName("reports/linux:node 24"), "reports-linux-node 24");
});

test("sanitizeArtifactName keeps valid names unchanged", () => {
  assert.equal(sanitizeArtifactName("team's-reports (v2)"), "team's-reports (v2)");
});

test("artifactNameCandidates starts with the requested name and then qualifies it by job", () => {
  const candidates = artifactNameCandidates("polyscan-reports", "scan", counter());
  assert.deepEqual(candidates, [
    "polyscan-reports",
    "polyscan-reports-scan",
    "polyscan-reports-scan-r1",
    "polyscan-reports-scan-r2",
    "polyscan-reports-scan-r3",
  ]);
});

test("artifactNameCandidates uses random suffixes by default", () => {
  const [, , first, second] = artifactNameCandidates("polyscan-reports", "scan");
  assert.match(first, /^polyscan-reports-scan-[0-9a-f]{8}$/);
  assert.notEqual(first, second);
});

test("artifactNameCandidates falls back to the default name for an empty input", () => {
  assert.equal(artifactNameCandidates("  ", undefined)[0], "polyscan-reports");
});

test("uploadWithUniqueName retries with another name after a conflict", async () => {
  const taken = new Set(["polyscan-reports", "polyscan-reports-scan"]);
  const tried: string[] = [];
  const name = await uploadWithUniqueName(
    "polyscan-reports",
    async (candidate) => {
      tried.push(candidate);
      if (taken.has(candidate)) throw CONFLICT;
    },
    "scan",
    counter(),
  );
  assert.equal(name, "polyscan-reports-scan-r1");
  assert.deepEqual(tried, ["polyscan-reports", "polyscan-reports-scan", "polyscan-reports-scan-r1"]);
});

test("uploadWithUniqueName finds a name for more than ten matrix legs sharing a job id", async () => {
  const taken = new Set<string>();
  const upload = async (candidate: string): Promise<void> => {
    if (taken.has(candidate)) throw CONFLICT;
    taken.add(candidate);
  };
  for (let leg = 0; leg < 25; leg++) {
    await uploadWithUniqueName("polyscan-reports", upload, "scan");
  }
  assert.equal(taken.size, 25);
});

test("uploadWithUniqueName does not retry other upload errors", async () => {
  let calls = 0;
  await assert.rejects(
    uploadWithUniqueName(
      "polyscan-reports",
      async () => {
        calls++;
        throw new Error("network down");
      },
      "scan",
    ),
    /network down/,
  );
  assert.equal(calls, 1);
});
