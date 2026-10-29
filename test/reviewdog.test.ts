import test from "node:test";
import assert from "node:assert/strict";

import { reviewdogArgs, reviewdogFindings, reviewdogPasses } from "../src/reviewdog";
import { Finding } from "../src/schema";

test("reviewdogPasses comments on PR lines and always adds a neutral check", () => {
  assert.deepEqual(
    reviewdogPasses("pull_request").map((pass) => pass.reporter),
    ["github-pr-review", "github-check"],
  );
  assert.deepEqual(
    reviewdogPasses("pull_request_target").map((pass) => pass.reporter),
    ["github-pr-review", "github-check"],
  );
  assert.deepEqual(reviewdogPasses("push").map((pass) => pass.reporter), ["github-check"]);
  assert.deepEqual(reviewdogPasses(undefined).map((pass) => pass.reporter), ["github-check"]);
});

test("reviewdogArgs never fails the job and keeps the check neutral", () => {
  const [review, check] = reviewdogPasses("pull_request").map(reviewdogArgs);
  assert.deepEqual(review, [
    "-f=sarif",
    "-name=PolyScan",
    "-reporter=github-pr-review",
    "-filter-mode=added",
    "-fail-level=none",
  ]);
  assert.deepEqual(check, [
    "-f=sarif",
    "-name=PolyScan",
    "-reporter=github-check",
    "-filter-mode=nofilter",
    "-fail-level=none",
    "-level=warning",
  ]);
});

test("reviewdogFindings drops container image findings, which have no source location", () => {
  const base = { engine: "trivy", ruleId: "CVE-1", severity: "high", message: "m", line: 0 } as const;
  const findings: Finding[] = [
    { ...base, file: "package-lock.json" },
    { ...base, file: "usr/lib/libssl.so", source: "image:app:latest" },
  ];
  assert.deepEqual(reviewdogFindings(findings).map((finding) => finding.file), ["package-lock.json"]);
});
