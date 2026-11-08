import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { findDockerfiles, parseHadolintSarif } from "../src/engines/hadolint";

const ABS = "/repo";

function sarifWith(results: unknown[]): unknown {
  return { runs: [{ results }] };
}

function sarifResult(opts: {
  ruleId: string;
  level: string;
  message: string;
  uri: string;
  line: number;
  column?: number;
}): unknown {
  return {
    ruleId: opts.ruleId,
    level: opts.level,
    message: { text: opts.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: opts.uri },
          region: { startLine: opts.line, startColumn: opts.column },
        },
      },
    ],
  };
}

test("parseHadolintSarif: error level maps to high", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "DL3002", level: "error", message: "Last USER should not be root", uri: `${ABS}/Dockerfile`, line: 4, column: 1 }),
  ]);
  const [f] = parseHadolintSarif(sarif, ABS);
  assert.equal(f.engine, "hadolint");
  assert.equal(f.ruleId, "DL3002");
  assert.equal(f.severity, "high");
  assert.equal(f.message, "Last USER should not be root");
  assert.equal(f.file, "Dockerfile");
  assert.equal(f.line, 4);
  assert.equal(f.column, 1);
});

test("parseHadolintSarif: warning level maps to medium", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "DL3008", level: "warning", message: "Pin versions in apt get install", uri: `${ABS}/Dockerfile`, line: 2 }),
  ]);
  assert.equal(parseHadolintSarif(sarif, ABS)[0].severity, "medium");
});

test("parseHadolintSarif: note level maps to low", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "DL3015", level: "note", message: "Avoid additional packages", uri: `${ABS}/Dockerfile`, line: 2 }),
  ]);
  assert.equal(parseHadolintSarif(sarif, ABS)[0].severity, "low");
});

test("parseHadolintSarif: strips the target prefix and file:// scheme from the uri", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "DL3007", level: "warning", message: "Pin the version", uri: `file://${ABS}/services/api/Dockerfile`, line: 1 }),
  ]);
  assert.equal(parseHadolintSarif(sarif, ABS)[0].file, "services/api/Dockerfile");
});

test("parseHadolintSarif: shellcheck rule ids (RUN instructions) are preserved as-is", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "SC2086", level: "warning", message: "Double quote to prevent globbing", uri: `${ABS}/Dockerfile`, line: 3 }),
  ]);
  assert.equal(parseHadolintSarif(sarif, ABS)[0].ruleId, "SC2086");
});

test("parseHadolintSarif: multiple results all parsed", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "DL3007", level: "warning", message: "a", uri: `${ABS}/Dockerfile`, line: 1 }),
    sarifResult({ ruleId: "DL3015", level: "note", message: "b", uri: `${ABS}/Dockerfile`, line: 2 }),
    sarifResult({ ruleId: "DL3002", level: "error", message: "c", uri: `${ABS}/Dockerfile`, line: 4 }),
  ]);
  assert.equal(parseHadolintSarif(sarif, ABS).length, 3);
});

test("parseHadolintSarif: empty results returns empty array", () => {
  assert.deepEqual(parseHadolintSarif(sarifWith([]), ABS), []);
});

test("parseHadolintSarif: empty runs returns empty array", () => {
  assert.deepEqual(parseHadolintSarif({ runs: [] }, ABS), []);
});

test("findDockerfiles finds Dockerfile variants and ignores vendored copies", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-hadolint-test-"));
  try {
    const services = path.join(root, "services", "api");
    const vendor = path.join(root, "node_modules", "example");
    fs.mkdirSync(services, { recursive: true });
    fs.mkdirSync(vendor, { recursive: true });
    fs.writeFileSync(path.join(root, "Dockerfile"), "FROM scratch\n");
    fs.writeFileSync(path.join(services, "Dockerfile.prod"), "FROM scratch\n");
    fs.writeFileSync(path.join(services, "worker.dockerfile"), "FROM scratch\n");
    fs.writeFileSync(path.join(services, "README.md"), "not a dockerfile\n");
    fs.writeFileSync(path.join(services, "Dockerfile.dockerignore"), "*\n");
    fs.writeFileSync(path.join(vendor, "Dockerfile"), "FROM scratch\n");

    assert.deepEqual(
      findDockerfiles(root).sort(),
      [
        path.join(root, "Dockerfile"),
        path.join(services, "Dockerfile.prod"),
        path.join(services, "worker.dockerfile"),
      ].sort(),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("findDockerfiles returns an empty array when no Dockerfiles exist", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-hadolint-test-"));
  try {
    fs.writeFileSync(path.join(root, "README.md"), "nothing here\n");
    assert.deepEqual(findDockerfiles(root), []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
