import test from "node:test";
import assert from "node:assert/strict";

import { parseDetektSarif } from "../src/engines/detekt";

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
}): unknown {
  return {
    ruleId: opts.ruleId,
    level: opts.level,
    message: { text: opts.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: opts.uri },
          region: { startLine: opts.line },
        },
      },
    ],
  };
}

test("parseDetektSarif: security rule (matches regex) bumped to high regardless of level", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "detekt/HardcodedSecret", level: "warning", message: "Hardcoded secret", uri: `file://${ABS}/src/Config.kt`, line: 15 }),
  ]);
  const [f] = parseDetektSarif(sarif, ABS);
  assert.equal(f.engine, "detekt");
  assert.equal(f.ruleId, "HardcodedSecret");
  assert.equal(f.severity, "high");
  assert.equal(f.message, "Hardcoded secret");
  assert.equal(f.file, "src/Config.kt");
  assert.equal(f.line, 15);
});

test("parseDetektSarif: SQL injection rule (matches 'sql') bumped to high", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "detekt/SqlInjection", level: "note", message: "SQL injection risk", uri: `file://${ABS}/src/Dao.kt`, line: 8 }),
  ]);
  assert.equal(parseDetektSarif(sarif, ABS)[0].severity, "high");
});

test("parseDetektSarif: error level non-security rule maps to high", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "detekt/MaxLineLength", level: "error", message: "Line too long", uri: `file://${ABS}/src/Foo.kt`, line: 1 }),
  ]);
  assert.equal(parseDetektSarif(sarif, ABS)[0].severity, "high");
});

test("parseDetektSarif: warning level non-security rule maps to medium", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "detekt/MagicNumber", level: "warning", message: "Magic number", uri: `file://${ABS}/src/Foo.kt`, line: 2 }),
  ]);
  assert.equal(parseDetektSarif(sarif, ABS)[0].severity, "medium");
});

test("parseDetektSarif: note level non-security rule maps to low", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "detekt/TrailingWhitespace", level: "note", message: "Trailing whitespace", uri: `file://${ABS}/src/Foo.kt`, line: 3 }),
  ]);
  assert.equal(parseDetektSarif(sarif, ABS)[0].severity, "low");
});

test("parseDetektSarif: file:// prefix and abs path are stripped from file URI", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "detekt/MagicNumber", level: "warning", message: "x", uri: `file://${ABS}/src/deep/Bar.kt`, line: 5 }),
  ]);
  assert.equal(parseDetektSarif(sarif, ABS)[0].file, "src/deep/Bar.kt");
});

test("parseDetektSarif: ruleId uses last path segment", () => {
  const sarif = sarifWith([
    sarifResult({ ruleId: "detekt/style/MagicNumber", level: "warning", message: "x", uri: `file://${ABS}/src/Foo.kt`, line: 1 }),
  ]);
  assert.equal(parseDetektSarif(sarif, ABS)[0].ruleId, "MagicNumber");
});

test("parseDetektSarif: multiple runs and results all parsed", () => {
  const sarif = {
    runs: [
      { results: [sarifResult({ ruleId: "detekt/A", level: "error", message: "a", uri: `file://${ABS}/A.kt`, line: 1 })] },
      { results: [sarifResult({ ruleId: "detekt/B", level: "warning", message: "b", uri: `file://${ABS}/B.kt`, line: 2 })] },
    ],
  };
  assert.equal(parseDetektSarif(sarif, ABS).length, 2);
});

test("parseDetektSarif: empty runs returns empty array", () => {
  assert.deepEqual(parseDetektSarif({ runs: [] }, ABS), []);
});

test("parseDetektSarif: empty results returns empty array", () => {
  assert.deepEqual(parseDetektSarif(sarifWith([]), ABS), []);
});
