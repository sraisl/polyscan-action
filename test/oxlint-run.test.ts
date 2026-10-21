import test, { TestContext } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import * as tools from "../src/tools";
import * as execution from "../src/exec";
import { collectJsSources, hasJsSources, oxlintBatches, runOxlint } from "../src/engines/oxlint";
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
      assert.equal(options.cwd, workspace);
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
