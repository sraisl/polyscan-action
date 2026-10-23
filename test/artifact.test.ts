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

test("sanitizeArtifactName replaces characters the artifact service rejects", () => {
  assert.equal(sanitizeArtifactName("reports/linux:node 24"), "reports-linux-node 24");
});

test("artifactNameCandidates starts with the requested name and then qualifies it by job", () => {
  const candidates = artifactNameCandidates("polyscan-reports", "scan");
  assert.deepEqual(candidates.slice(0, 3), [
    "polyscan-reports",
    "polyscan-reports-scan",
    "polyscan-reports-scan-2",
  ]);
  assert.equal(new Set(candidates).size, candidates.length);
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
  );
  assert.equal(name, "polyscan-reports-scan-2");
  assert.deepEqual(tried, ["polyscan-reports", "polyscan-reports-scan", "polyscan-reports-scan-2"]);
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
