import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  normalizeFindingPath,
  resolveOutputDir,
  resolveTarget,
  writeReportFile,
} from "../src/target";

function withWorkspace(run: (workspace: string) => void): void {
  const previous = process.env.GITHUB_WORKSPACE;
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-workspace-"));
  process.env.GITHUB_WORKSPACE = workspace;
  try {
    run(workspace);
  } finally {
    if (previous === undefined) delete process.env.GITHUB_WORKSPACE;
    else process.env.GITHUB_WORKSPACE = previous;
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}

test("resolveTarget accepts relative and absolute directories inside the workspace", () => {
  withWorkspace((workspace) => {
    const target = path.join(workspace, "services", "api");
    fs.mkdirSync(target, { recursive: true });
    assert.equal(resolveTarget("services/api"), fs.realpathSync(target));
    assert.equal(resolveTarget(target), fs.realpathSync(target));
  });
});

test("resolveTarget rejects missing targets and files", () => {
  withWorkspace((workspace) => {
    assert.throws(() => resolveTarget("missing"), /does not exist/);
    fs.writeFileSync(path.join(workspace, "file.txt"), "x");
    assert.throws(() => resolveTarget("file.txt"), /not a directory/);
  });
});

test("resolveTarget rejects lexical and symlink workspace escapes", () => {
  withWorkspace((workspace) => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-outside-"));
    try {
      assert.throws(() => resolveTarget(outside), /inside GITHUB_WORKSPACE/);
      fs.symlinkSync(outside, path.join(workspace, "escape"), "dir");
      assert.throws(() => resolveTarget("escape"), /inside GITHUB_WORKSPACE/);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

test("resolveOutputDir creates a workspace-contained directory", () => {
  withWorkspace((workspace) => {
    const output = resolveOutputDir("reports/security");
    assert.equal(output, path.join(fs.realpathSync(workspace), "reports", "security"));
    assert.equal(fs.statSync(output).isDirectory(), true);
    assert.throws(() => resolveOutputDir("../reports"), /inside GITHUB_WORKSPACE/);
  });
});

test("resolveOutputDir rejects symlink escapes before creating directories", () => {
  withWorkspace((workspace) => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-output-outside-"));
    try {
      fs.symlinkSync(outside, path.join(workspace, "reports"), "dir");
      assert.throws(() => resolveOutputDir("reports/security"), /inside GITHUB_WORKSPACE/);
      assert.equal(fs.existsSync(path.join(outside, "security")), false);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

test("normalizeFindingPath returns repository-relative POSIX paths", () => {
  withWorkspace((workspace) => {
    const target = path.join(workspace, "services", "api");
    const source = path.join(target, "src", "app.ts");
    fs.mkdirSync(path.dirname(source), { recursive: true });
    fs.writeFileSync(source, "eval('x')");

    assert.equal(normalizeFindingPath(source, target), "services/api/src/app.ts");
    assert.equal(normalizeFindingPath("src/app.ts", target), "services/api/src/app.ts");
    assert.equal(
      normalizeFindingPath(new URL(`file://${source}`).toString(), target),
      "services/api/src/app.ts",
    );
  });
});

test("normalizeFindingPath rejects paths outside the workspace", () => {
  withWorkspace((workspace) => {
    const target = path.join(workspace, "target");
    fs.mkdirSync(target);
    assert.throws(
      () => normalizeFindingPath(path.join(workspace, "..", "secret.txt"), target),
      /inside GITHUB_WORKSPACE/,
    );
    assert.throws(
      () => normalizeFindingPath("file://[invalid", target),
      /invalid finding file URI/,
    );
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-finding-outside-"));
    try {
      fs.symlinkSync(outside, path.join(target, "escape"), "dir");
      assert.throws(
        () => normalizeFindingPath("escape/missing.ts", target),
        /inside GITHUB_WORKSPACE/,
      );
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

test("writeReportFile creates and truncates regular report files", () => {
  withWorkspace((workspace) => {
    const report = path.join(workspace, "polyscan-report.json");
    writeReportFile(report, "first, longer content");
    writeReportFile(report, "second");
    assert.equal(fs.readFileSync(report, "utf8"), "second");
  });
});

test("writeReportFile refuses a report symlink and leaves its external target unchanged", () => {
  withWorkspace((workspace) => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-outside-"));
    try {
      const victim = path.join(outside, "victim.txt");
      fs.writeFileSync(victim, "original");
      const report = path.join(workspace, "polyscan-report.json");
      fs.symlinkSync(victim, report);

      assert.throws(() => writeReportFile(report, "overwritten"), /refusing to write report through symlink/);
      assert.equal(fs.readFileSync(victim, "utf8"), "original");
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});
