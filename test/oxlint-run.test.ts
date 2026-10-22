import test, { TestContext } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import * as tools from "../src/tools";
import * as execution from "../src/exec";
import { collectJsSources, hasJsSources, isOxlintLintable, oxlintBatches, runOxlint } from "../src/engines/oxlint";
import { normalizeFindingPath } from "../src/target";
import { TOOLS } from "../src/tool-versions";

function fixture(t: TestContext) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-oxlint-run-")));
  const workspace = path.join(root, "workspace");
  fs.mkdirSync(workspace);
  const previous = { ...process.env };
  process.env.GITHUB_WORKSPACE = workspace;
  t.after(() => {
    process.env = previous;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, workspace };
}

function binary(directory: string, version: string, exitCode = 0): string {
  const file = path.join(directory, "oxlint");
  fs.writeFileSync(file, `#!/bin/sh\nprintf '%s\\n' '${version}'\nexit ${exitCode}\n`);
  fs.chmodSync(file, 0o755);
  return file;
}

test("discovery ignores all symlinks and Git ignore rules, and sorts absolute paths", (t) => {
  const { root, workspace } = fixture(t);
  fs.writeFileSync(path.join(root, "outside.ts"), "eval(input);");
  fs.symlinkSync(path.join(root, "outside.ts"), path.join(workspace, "escape.ts"));
  fs.symlinkSync(root, path.join(workspace, "escape-dir"));
  fs.symlinkSync(workspace, path.join(workspace, "cycle"));
  assert.equal(hasJsSources(workspace), false);
  fs.writeFileSync(path.join(workspace, ".gitignore"), "*.ts\n");
  for (const name of ["z.ts", "a.TSX"]) fs.writeFileSync(path.join(workspace, name), "eval(input);");
  fs.symlinkSync(path.join(workspace, "z.ts"), path.join(workspace, "internal.ts"));
  assert.deepEqual(collectJsSources(workspace), ["a.TSX", "z.ts"].map((name) => path.join(workspace, name)));
});

for (const scenario of [
  { name: "matching", version: `Version: ${TOOLS.oxlint.version}`, exit: 0, accepted: true },
  { name: "mismatched", version: "Version: 0.0.1", exit: 0, accepted: false },
  { name: "malformed", version: "unknown", exit: 0, accepted: false },
  { name: "failed", version: `Version: ${TOOLS.oxlint.version}`, exit: 1, accepted: false },
]) {
  test(`provisioning handles ${scenario.name} PATH version`, async (t) => {
    const { root, workspace } = fixture(t);
    const executable = binary(root, scenario.version, scenario.exit);
    process.env.PATH = root;
    fs.writeFileSync(path.join(workspace, "app.ts"), "eval(input);");
    const fallback = path.join(root, "cached-oxlint");
    const cache = t.mock.method(tools, "cachedTool", async () => fallback);
    const realRun = execution.run;
    const runs: string[] = [];
    t.mock.method(execution, "run", async (command: string, args: string[]) => {
      if (args.includes("--version")) return realRun(command, args);
      runs.push(command);
      return { exitCode: 0, stdout: '{"diagnostics":[]}', stderr: "" };
    });
    assert.equal((await runOxlint(".")).status, "success");
    assert.deepEqual(runs, [scenario.accepted ? executable : fallback]);
    assert.equal(cache.mock.callCount(), scenario.accepted ? 0 : 1);
    if (!scenario.accepted) assert.deepEqual(cache.mock.calls[0].arguments.slice(0, 3), ["oxlint", TOOLS.oxlint.version, "oxlint"]);
  });
}

test("empty projects skip provisioning", async (t) => {
  fixture(t);
  const cache = t.mock.method(tools, "cachedTool", async () => { throw new Error("unexpected install"); });
  assert.equal((await runOxlint(".")).status, "skipped");
  assert.equal(cache.mock.callCount(), 0);
});

test("batches respect UTF-8 argument size and preserve every path", () => {
  const files = Array.from({ length: 400 }, (_, i) => `/workspace/${i}-${"ä".repeat(60)}.ts`);
  const flags = ["--config", "/tmp/config.json", "--"];
  const batches = oxlintBatches(files, flags);
  assert.ok(batches.length > 1);
  assert.deepEqual(batches.flat(), files);
  for (const batch of batches) assert.ok([...flags, ...batch].reduce((n, arg) => n + Buffer.byteLength(arg) + 1, 0) <= 32768);
  assert.throws(() => oxlintBatches(["x".repeat(32768)], flags), /argument budget/);
});

for (const failure of ["none", "process", "json"] as const) {
  test(`multi-batch scan: ${failure}`, async (t) => {
    const { workspace } = fixture(t);
    for (let i = 0; i < 300; i++) fs.writeFileSync(path.join(workspace, `${i}-${"x".repeat(120)}.ts`), "eval(input);");
    t.mock.method(execution, "resolvePinnedExecutable", async () => "/test/oxlint");
    const calls: string[][] = [];
    const configs: string[] = [];
    t.mock.method(execution, "run", async (_bin: string, args: string[], options: { cwd?: string }) => {
      assert.equal(options.cwd, path.dirname(args[1]));
      configs.push(args[1]);
      const files = args.slice(args.indexOf("--") + 1);
      calls.push(files);
      if (calls.length === 2 && failure !== "none") return {
        exitCode: failure === "process" ? 2 : 0, stdout: "invalid report", stderr: "",
      };
      return { exitCode: 1, stderr: "", stdout: JSON.stringify({ diagnostics: [
        { code: "eslint(no-eval)", filename: files[0] },
        { filename: "unparsed.ts", message: "Unexpected token" },
      ] }) };
    });
    const result = await runOxlint(".");
    assert.ok(calls.length > 1);
    if (failure === "none") {
      assert.equal(result.status, "success");
      assert.equal(result.findings.length, calls.length);
      assert.match(result.note!, /^1 file\(s\)/);
      assert.deepEqual(calls.flat(), collectJsSources(workspace));
    } else {
      assert.equal(result.status, "failed");
      assert.deepEqual(result.findings, []);
    }
    for (const config of configs) assert.equal(fs.existsSync(config), false);
  });
}

test("pinned oxlint scans tracked ignored sources without following escaping symlinks", {
  skip: !process.env.OXLINT_TEST_BINARY && "Set OXLINT_TEST_BINARY to the pinned oxlint executable",
}, async (t) => {
  const executable = fs.realpathSync(process.env.OXLINT_TEST_BINARY!);
  assert.match(execFileSync(executable, ["--version"], { encoding: "utf8" }), new RegExp(TOOLS.oxlint.version.replace(/\./g, "\\.")));
  const { root, workspace } = fixture(t);
  for (const name of ["tracked.ts", "space name.ts", "-leading.ts"]) fs.writeFileSync(path.join(workspace, name), "eval(input);\n");
  execFileSync("git", ["init", "--quiet", workspace]);
  execFileSync("git", ["-C", workspace, "add", "tracked.ts"]);
  fs.writeFileSync(path.join(workspace, ".gitignore"), "tracked.ts\n");
  fs.writeFileSync(path.join(root, "external.ts"), "eval(input);\n");
  fs.symlinkSync(path.join(root, "external.ts"), path.join(workspace, "escape.ts"));
  fs.symlinkSync(root, path.join(workspace, "escape-dir"));
  fs.symlinkSync(executable, path.join(root, "oxlint"));
  process.env.PATH = `${root}${path.delimiter}${process.env.PATH ?? ""}`;
  t.mock.method(tools, "cachedTool", async () => { throw new Error("pinned PATH binary must be reused"); });
  const result = await runOxlint(".");
  assert.equal(result.status, "success");
  assert.deepEqual(result.findings.map((finding) => normalizeFindingPath(finding.file, workspace)).sort(), ["-leading.ts", "space name.ts", "tracked.ts"]);
});

function mockScan(t: TestContext, diagnostics: (files: string[]) => unknown[]) {
  t.mock.method(execution, "resolvePinnedExecutable", async () => "/test/oxlint");
  const calls: { files: string[]; cwd?: string; config: string }[] = [];
  t.mock.method(execution, "run", async (_bin: string, args: string[], options: { cwd?: string }) => {
    const files = args.slice(args.indexOf("--") + 1);
    calls.push({ files, cwd: options.cwd, config: args[1] });
    return { exitCode: 1, stderr: "", stdout: JSON.stringify({ diagnostics: diagnostics(files) }) };
  });
  return calls;
}

test("oxlint runs from its private config directory, never the scanned target", async (t) => {
  const { workspace } = fixture(t);
  fs.writeFileSync(path.join(workspace, "app.ts"), "eval(input);");
  fs.writeFileSync(path.join(workspace, "oxlint-suppressions.json"), '{"app.ts":{"no-eval":{"count":1}}}');
  const calls = mockScan(t, () => []);
  assert.equal((await runOxlint(".")).status, "success");
  assert.equal(calls.length, 1);
  assert.notEqual(calls[0].cwd, workspace);
  assert.equal(calls[0].cwd, path.dirname(calls[0].config));
  assert.deepEqual(calls[0].files, [path.join(workspace, "app.ts")]);
});

test("isOxlintLintable mirrors oxlint's minified-name and case-sensitive extension filters", () => {
  for (const name of ["app.ts", "App.tsx", "admin.js", "minimal.mjs", "a.min-x.cjs"]) assert.equal(isOxlintLintable(name), true, name);
  for (const name of ["app.TSX", "App.Js", "lib.min.js", "auth-min.ts", "x_min.jsx"]) assert.equal(isOxlintLintable(name), false, name);
});

test("files oxlint would skip are not passed to it and are reported in the note", async (t) => {
  const { workspace } = fixture(t);
  for (const name of ["app.ts", "App.TSX", "auth-min.ts", "lib.min.js"]) fs.writeFileSync(path.join(workspace, name), "eval(input);");
  const calls = mockScan(t, () => []);
  const result = await runOxlint(".");
  assert.equal(result.status, "success");
  assert.deepEqual(calls.flatMap((call) => call.files), [path.join(workspace, "app.ts")]);
  assert.equal(result.note, "3 file(s) not supported by oxlint and not scanned: App.TSX, auth-min.ts, lib.min.js");
});

test("findings are sorted by location and rule regardless of oxlint's output order", async (t) => {
  const { workspace } = fixture(t);
  for (const name of ["a.ts", "b.ts"]) fs.writeFileSync(path.join(workspace, name), "eval(input);");
  const at = (file: string, line: number, column: number, code: string) => ({
    code, severity: "error", message: code, filename: path.join(workspace, file),
    labels: [{ span: { line, column } }],
  });
  mockScan(t, () => [
    at("b.ts", 1, 1, "eslint(no-eval)"),
    at("a.ts", 2, 1, "eslint(no-new-func)"),
    at("a.ts", 1, 5, "eslint(no-eval)"),
    at("a.ts", 1, 5, "eslint(no-script-url)"),
    at("a.ts", 1, 1, "eslint(no-script-url)"),
  ]);
  const result = await runOxlint(".");
  assert.deepEqual(
    result.findings.map((finding) => `${path.basename(finding.file)}:${finding.line}:${finding.column} ${finding.ruleId}`),
    ["a.ts:1:1 no-script-url", "a.ts:1:5 no-eval", "a.ts:1:5 no-script-url", "a.ts:2:1 no-new-func", "b.ts:1:1 no-eval"],
  );
});

test("pinned oxlint ignores target suppressions, keeps nested target paths and reports skipped files", {
  skip: !process.env.OXLINT_TEST_BINARY && "Set OXLINT_TEST_BINARY to the pinned oxlint executable",
}, async (t) => {
  const executable = fs.realpathSync(process.env.OXLINT_TEST_BINARY!);
  const { root, workspace } = fixture(t);
  const target = path.join(workspace, "src");
  fs.mkdirSync(path.join(target, "src"), { recursive: true });
  for (const file of ["src/app.ts", "auth-min.ts", "App.TSX"]) fs.writeFileSync(path.join(target, file), "eval(input);\n");
  fs.writeFileSync(
    path.join(target, "oxlint-suppressions.json"),
    JSON.stringify({ "src/app.ts": { "no-eval": { count: 1 } }, "auth-min.ts": { "no-eval": { count: 1 } } }),
  );
  fs.symlinkSync(executable, path.join(root, "oxlint"));
  process.env.PATH = `${root}${path.delimiter}${process.env.PATH ?? ""}`;
  t.mock.method(tools, "cachedTool", async () => { throw new Error("pinned PATH binary must be reused"); });
  const result = await runOxlint("src");
  assert.equal(result.status, "success");
  assert.deepEqual(result.findings.map((finding) => normalizeFindingPath(finding.file, target)), ["src/src/app.ts"]);
  assert.equal(result.note, "2 file(s) not supported by oxlint and not scanned: App.TSX, auth-min.ts");
});
