import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ensurePythonTool, resolveExecutable, resolvePinnedExecutable } from "../src/exec";

function recordingCore() {
  const info: string[] = [];
  const warning: string[] = [];
  return {
    info: (s: string) => info.push(s),
    warning: (s: string) => warning.push(s),
    messages: { info, warning },
  };
}

test("resolveExecutable returns an absolute executable from the supplied PATH", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-path-"));
  const executable = path.join(directory, "semgrep");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\n");
    fs.chmodSync(executable, 0o755);

    assert.equal(resolveExecutable("semgrep", directory), executable);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolveExecutable ignores tools outside the inherited PATH", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-path-"));
  const executable = path.join(directory, "semgrep");
  const inheritedPath = path.join(directory, "empty");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\n");
    fs.chmodSync(executable, 0o755);
    fs.mkdirSync(inheritedPath);

    assert.equal(resolveExecutable("semgrep", inheritedPath), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolveExecutable rejects non-executable files", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-path-"));
  const executable = path.join(directory, "semgrep");
  try {
    fs.writeFileSync(executable, "not executable");
    fs.chmodSync(executable, 0o644);

    assert.equal(resolveExecutable("semgrep", directory), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolvePinnedExecutable accepts only the expected tool version", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-version-"));
  const executable = path.join(directory, "opengrep");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\nprintf '1.26.0\\n'\n");
    fs.chmodSync(executable, 0o755);

    assert.equal(
      await resolvePinnedExecutable(
        "opengrep",
        "1.26.0",
        ["--version", "--disable-version-check"],
        directory,
      ),
      executable,
    );
    assert.equal(
      await resolvePinnedExecutable("opengrep", "1.25.0", ["--version"], directory),
      null,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolvePinnedExecutable rejects malformed output and failed version commands", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-version-"));
  const executable = path.join(directory, "opengrep");
  try {
    fs.writeFileSync(executable, "#!/bin/sh\nprintf 'unknown\\n'\n");
    fs.chmodSync(executable, 0o755);
    assert.equal(
      await resolvePinnedExecutable("opengrep", "1.26.0", ["--version"], directory),
      null,
    );

    fs.writeFileSync(executable, "#!/bin/sh\nexit 2\n");
    assert.equal(
      await resolvePinnedExecutable("opengrep", "1.26.0", ["--version"], directory),
      null,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("resolvePinnedExecutable accepts output prefixed with the tool name", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-version-"));
  const executable = path.join(directory, "bandit");
  try {
    fs.writeFileSync(
      executable,
      "#!/bin/sh\nprintf 'bandit 1.9.4\\n  python version = 3.13.0 (1.2.3)\\n'\n",
    );
    fs.chmodSync(executable, 0o755);

    assert.equal(
      await resolvePinnedExecutable("bandit", "1.9.4", ["--version"], directory),
      executable,
    );
    assert.equal(await resolvePinnedExecutable("bandit", "3.13.0", ["--version"], directory), null);
    assert.equal(await resolvePinnedExecutable("bandit", "1.9.3", ["--version"], directory), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("ensurePythonTool reuses a preinstalled tool that reports the pinned version", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-python-"));
  const executable = path.join(directory, "bandit");
  const originalPath = process.env.PATH;
  const core = recordingCore();
  try {
    fs.writeFileSync(executable, "#!/bin/sh\nprintf 'bandit 1.9.4\\n'\n");
    fs.chmodSync(executable, 0o755);
    process.env.PATH = directory;

    const prepared = await ensurePythonTool("bandit", "1.9.4", "bandit", core);

    assert.equal(prepared?.executable, executable);
    assert.deepEqual(core.messages.warning, []);
    prepared?.cleanup();
  } finally {
    process.env.PATH = originalPath;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("ensurePythonTool ignores a preinstalled tool with a different version", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-python-"));
  const executable = path.join(directory, "bandit");
  const originalPath = process.env.PATH;
  const core = recordingCore();
  try {
    fs.writeFileSync(executable, "#!/bin/sh\nprintf 'bandit 1.8.0\\n'\n");
    fs.chmodSync(executable, 0o755);
    // PATH holds the mismatched tool only, so the pinned install cannot find
    // python3 and fails instead of reaching the network.
    process.env.PATH = directory;

    const prepared = await ensurePythonTool("bandit", "1.9.4", "bandit", core);

    assert.equal(prepared, null);
    assert.ok(
      core.messages.warning.some((message) =>
        message.includes("not the pinned version 1.9.4"),
      ),
      `expected a pinned-version warning, got ${JSON.stringify(core.messages.warning)}`,
    );
  } finally {
    process.env.PATH = originalPath;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
