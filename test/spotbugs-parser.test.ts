import test from "node:test";
import assert from "node:assert/strict";

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { parseSpotbugsXml, findClassDirs, findModuleDirs, findWrapper } from "../src/engines/spotbugs";

function bugInstance(opts: {
  type: string;
  priority?: string;
  cweid?: string;
  sourcepath?: string;
  start?: string;
  message?: string;
}): string {
  const cweAttr = opts.cweid ? ` cweid="${opts.cweid}"` : "";
  return `
    <BugInstance type="${opts.type}" priority="${opts.priority ?? "2"}"${cweAttr}>
      <ShortMessage>${opts.message ?? opts.type}</ShortMessage>
      <SourceLine sourcepath="${opts.sourcepath ?? "com/example/Foo.java"}" start="${opts.start ?? "10"}" end="${opts.start ?? "10"}"/>
    </BugInstance>`;
}

const JAVA_FILES = ["/repo/src/main/java/com/example/Foo.java"];

test("parseSpotbugsXml: HIGH_PATTERNS type overrides priority to high", () => {
  const xml = `<BugCollection>${bugInstance({ type: "SQL_INJECTION_JDBC", priority: "2", cweid: "89" })}</BugCollection>`;
  const [f] = parseSpotbugsXml(xml, JAVA_FILES);
  assert.equal(f.engine, "spotbugs");
  assert.equal(f.ruleId, "SQL_INJECTION_JDBC");
  assert.equal(f.severity, "high");
  assert.equal(f.cwe, "CWE-89");
});

test("parseSpotbugsXml: COMMAND_INJECTION is a HIGH_PATTERN", () => {
  const xml = `<BugCollection>${bugInstance({ type: "COMMAND_INJECTION", priority: "3" })}</BugCollection>`;
  assert.equal(parseSpotbugsXml(xml, JAVA_FILES)[0].severity, "high");
});

test("parseSpotbugsXml: priority 1 maps to high for non-pattern types", () => {
  const xml = `<BugCollection>${bugInstance({ type: "NP_NULL_ON_SOME_PATH", priority: "1" })}</BugCollection>`;
  assert.equal(parseSpotbugsXml(xml, JAVA_FILES)[0].severity, "high");
});

test("parseSpotbugsXml: priority 2 maps to medium", () => {
  const xml = `<BugCollection>${bugInstance({ type: "NP_NULL_ON_SOME_PATH", priority: "2" })}</BugCollection>`;
  assert.equal(parseSpotbugsXml(xml, JAVA_FILES)[0].severity, "medium");
});

test("parseSpotbugsXml: priority 3 maps to low", () => {
  const xml = `<BugCollection>${bugInstance({ type: "NP_NULL_ON_SOME_PATH", priority: "3" })}</BugCollection>`;
  assert.equal(parseSpotbugsXml(xml, JAVA_FILES)[0].severity, "low");
});

test("parseSpotbugsXml: resolves file path from javaFiles list", () => {
  const xml = `<BugCollection>${bugInstance({ type: "SQL_INJECTION_JDBC", sourcepath: "com/example/Foo.java", start: "42" })}</BugCollection>`;
  const [f] = parseSpotbugsXml(xml, JAVA_FILES);
  assert.equal(f.file, JAVA_FILES[0]);
  assert.equal(f.line, 42);
});

test("parseSpotbugsXml: falls back to sourcepath when no match in javaFiles", () => {
  const xml = `<BugCollection>${bugInstance({ type: "SQL_INJECTION_JDBC", sourcepath: "com/other/Bar.java" })}</BugCollection>`;
  const [f] = parseSpotbugsXml(xml, JAVA_FILES);
  assert.equal(f.file, "com/other/Bar.java");
});

test("parseSpotbugsXml: ShortMessage used as finding message", () => {
  const xml = `<BugCollection>${bugInstance({ type: "SQL_INJECTION_JDBC", message: "SQL injection found" })}</BugCollection>`;
  assert.equal(parseSpotbugsXml(xml, JAVA_FILES)[0].message, "SQL injection found");
});

test("parseSpotbugsXml: multiple bugs all parsed", () => {
  const xml = `<BugCollection>
    ${bugInstance({ type: "SQL_INJECTION_JDBC", priority: "1" })}
    ${bugInstance({ type: "COMMAND_INJECTION", priority: "2" })}
    ${bugInstance({ type: "NP_NULL_ON_SOME_PATH", priority: "3" })}
  </BugCollection>`;
  assert.equal(parseSpotbugsXml(xml, JAVA_FILES).length, 3);
});

test("parseSpotbugsXml: empty XML returns empty array", () => {
  assert.deepEqual(parseSpotbugsXml("<BugCollection></BugCollection>", JAVA_FILES), []);
});

test("parseSpotbugsXml: no cweid attribute → cwe undefined", () => {
  const xml = `<BugCollection>${bugInstance({ type: "SQL_INJECTION_JDBC" })}</BugCollection>`;
  assert.equal(parseSpotbugsXml(xml, JAVA_FILES)[0].cwe, undefined);
});

test("monorepo module discovery, class dirs and wrapper lookup", () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-sb-")));
  const prev = process.env.GITHUB_WORKSPACE;
  process.env.GITHUB_WORKSPACE = root;
  try {
    const mod = path.join(root, "apps", "demo");
    fs.mkdirSync(path.join(mod, "target", "classes"), { recursive: true });
    fs.writeFileSync(path.join(mod, "target", "classes", "A.class"), "x");
    fs.mkdirSync(path.join(root, "node_modules", "x", "target", "classes"), { recursive: true });
    fs.writeFileSync(path.join(mod, "pom.xml"), "<project/>");
    fs.writeFileSync(path.join(root, "mvnw"), "#!/bin/sh");

    assert.deepEqual(findClassDirs(root), [path.join(mod, "target", "classes")]);
    assert.deepEqual(findModuleDirs(root), [mod]);
    assert.equal(findWrapper(mod, "mvnw"), path.join(root, "mvnw"));
    assert.equal(findWrapper(mod, "gradlew"), "");
  } finally {
    if (prev === undefined) delete process.env.GITHUB_WORKSPACE;
    else process.env.GITHUB_WORKSPACE = prev;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
