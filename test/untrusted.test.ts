import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { isUntrustedRun, readEventPayload } from "../src/untrusted";

function pullRequestPayload(headRepo: unknown, baseRepo: unknown = { full_name: "acme/app" }) {
  return { pull_request: { head: { repo: headRepo }, base: { repo: baseRepo } } };
}

const SAME_REPO = { full_name: "acme/app", fork: false };
const FORK_REPO = { full_name: "contributor/app", fork: true };

test("push events are trusted", () => {
  const trust = isUntrustedRun({ GITHUB_EVENT_NAME: "push" }, {});
  assert.equal(trust.untrusted, false);
  assert.match(trust.reason, /push/);
});

test("a run with no event name (local development) is trusted", () => {
  assert.equal(isUntrustedRun({}, undefined).untrusted, false);
});

test("a pull request from a branch of the same repository is trusted", () => {
  const trust = isUntrustedRun(
    { GITHUB_EVENT_NAME: "pull_request" },
    pullRequestPayload(SAME_REPO),
  );
  assert.equal(trust.untrusted, false);
});

test("a pull request from a fork is untrusted", () => {
  const trust = isUntrustedRun(
    { GITHUB_EVENT_NAME: "pull_request" },
    pullRequestPayload(FORK_REPO),
  );
  assert.equal(trust.untrusted, true);
  assert.match(trust.reason, /fork/);
});

// head.repo.fork is true for every pull request in a repository that is itself
// a fork, so the full_name comparison has to win over the flag.
test("an internal pull request in a forked repository is trusted", () => {
  const trust = isUntrustedRun(
    { GITHUB_EVENT_NAME: "pull_request" },
    pullRequestPayload({ full_name: "acme/app", fork: true }, { full_name: "acme/app", fork: true }),
  );
  assert.equal(trust.untrusted, false);
});

test("the fork flag decides when full_name is missing", () => {
  const trust = isUntrustedRun(
    { GITHUB_EVENT_NAME: "pull_request" },
    pullRequestPayload({ fork: true }, {}),
  );
  assert.equal(trust.untrusted, true);
});

test("pull_request_target is trusted", () => {
  const trust = isUntrustedRun(
    { GITHUB_EVENT_NAME: "pull_request_target" },
    pullRequestPayload(SAME_REPO),
  );
  assert.equal(trust.untrusted, false);
  assert.equal(trust.advisory, undefined);
});

test("pull_request_target from a fork is trusted but carries an advisory", () => {
  const trust = isUntrustedRun(
    { GITHUB_EVENT_NAME: "pull_request_target" },
    pullRequestPayload(FORK_REPO),
  );
  assert.equal(trust.untrusted, false);
  assert.match(String(trust.advisory), /checks out the pull request head/);
});

test("a pull_request with no payload fails closed", () => {
  const trust = isUntrustedRun({ GITHUB_EVENT_NAME: "pull_request" }, undefined);
  assert.equal(trust.untrusted, true);
});

test("a pull_request whose head repository was deleted fails closed", () => {
  const trust = isUntrustedRun(
    { GITHUB_EVENT_NAME: "pull_request" },
    pullRequestPayload(null),
  );
  assert.equal(trust.untrusted, true);
});

test("a pull_request payload of the wrong shape fails closed", () => {
  for (const payload of ["a string", 42, null, [], { pull_request: [] }, { pull_request: "x" }]) {
    assert.equal(
      isUntrustedRun({ GITHUB_EVENT_NAME: "pull_request" }, payload).untrusted,
      true,
      `expected fail-closed for ${JSON.stringify(payload)}`,
    );
  }
});

test("readEventPayload returns undefined without GITHUB_EVENT_PATH", () => {
  assert.equal(readEventPayload({}), undefined);
});

test("readEventPayload returns undefined for a missing or malformed file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-untrusted-"));
  try {
    assert.equal(readEventPayload({ GITHUB_EVENT_PATH: path.join(dir, "absent.json") }), undefined);

    const malformed = path.join(dir, "malformed.json");
    fs.writeFileSync(malformed, "{not json");
    assert.equal(readEventPayload({ GITHUB_EVENT_PATH: malformed }), undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("readEventPayload parses the event file and feeds the default argument", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-untrusted-"));
  try {
    const eventPath = path.join(dir, "event.json");
    fs.writeFileSync(eventPath, JSON.stringify(pullRequestPayload(FORK_REPO)));

    assert.deepEqual(
      readEventPayload({ GITHUB_EVENT_PATH: eventPath }),
      pullRequestPayload(FORK_REPO),
    );
    // Omitting the payload makes isUntrustedRun read it from GITHUB_EVENT_PATH.
    assert.equal(
      isUntrustedRun({ GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: eventPath }).untrusted,
      true,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
