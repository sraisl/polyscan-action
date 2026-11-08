import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { pullRequestHeadSha, sourceBaseUrl, sourceUrl } from "../src/links";
import { Finding } from "../src/schema";

const SHA = "0123456789abcdef0123456789abcdef01234567";
const HEAD = "fedcba9876543210fedcba9876543210fedcba98";
const ENV = { GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "owner/repo", GITHUB_SHA: SHA };

function finding(overrides: Partial<Finding>): Finding {
  return { engine: "semgrep", ruleId: "r", severity: "high", message: "m", file: "src/a.ts", line: 3, ...overrides };
}

test("sourceBaseUrl builds a blob URL from the workflow environment", () => {
  assert.equal(sourceBaseUrl(ENV, undefined), `https://github.com/owner/repo/blob/${SHA}`);
});

test("sourceBaseUrl prefers the pull request head commit over GITHUB_SHA", () => {
  assert.equal(sourceBaseUrl(ENV, HEAD), `https://github.com/owner/repo/blob/${HEAD}`);
});

test("sourceBaseUrl returns undefined for missing or malformed parts", () => {
  assert.equal(sourceBaseUrl({}, undefined), undefined);
  assert.equal(sourceBaseUrl({ ...ENV, GITHUB_SERVER_URL: "javascript:alert(1)" }, undefined), undefined);
  assert.equal(sourceBaseUrl({ ...ENV, GITHUB_REPOSITORY: "owner/repo)evil" }, undefined), undefined);
  assert.equal(sourceBaseUrl({ ...ENV, GITHUB_SHA: "main" }, undefined), undefined);
});

test("pullRequestHeadSha reads the head SHA from the event payload", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-event-"));
  try {
    const eventPath = path.join(dir, "event.json");
    fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { head: { sha: HEAD } } }));
    assert.equal(pullRequestHeadSha({ GITHUB_EVENT_PATH: eventPath }), HEAD);
    fs.writeFileSync(eventPath, JSON.stringify({ ref: "refs/heads/main" }));
    assert.equal(pullRequestHeadSha({ GITHUB_EVENT_PATH: eventPath }), undefined);
    fs.writeFileSync(eventPath, "not json");
    assert.equal(pullRequestHeadSha({ GITHUB_EVENT_PATH: eventPath }), undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("sourceUrl links to the finding line and encodes path segments", () => {
  const base = `https://github.com/owner/repo/blob/${SHA}`;
  assert.equal(sourceUrl(finding({}), base), `${base}/src/a.ts#L3`);
  assert.equal(sourceUrl(finding({ file: "./my dir/a(1).ts", line: 0 }), base), `${base}/my%20dir/a(1).ts`);
  assert.equal(sourceUrl(finding({ file: "a>b.ts" }), base), `${base}/a%3Eb.ts#L3`);
});

test("sourceUrl refuses image findings and unsafe or unknown paths", () => {
  const base = `https://github.com/owner/repo/blob/${SHA}`;
  assert.equal(sourceUrl(finding({}), undefined), undefined);
  assert.equal(sourceUrl(finding({ source: "image:app:latest" }), base), undefined);
  assert.equal(sourceUrl(finding({ file: "/etc/passwd" }), base), undefined);
  assert.equal(sourceUrl(finding({ file: "../outside.ts" }), base), undefined);
  assert.equal(sourceUrl(finding({ file: "unknown" }), base), undefined);
});
