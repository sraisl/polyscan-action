import test from "node:test";
import assert from "node:assert/strict";

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  findClassDirs,
  findModuleDirs,
  findWrapper,
  tryProjectBuild,
  wrapperInvocation,
} from "../src/engines/spotbugs";

async function withWorkspace(run: (root: string) => void | Promise<void>): Promise<void> {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-spotbugs-")));
  const previous = process.env.GITHUB_WORKSPACE;
  process.env.GITHUB_WORKSPACE = root;
  try {
    await run(root);
  } finally {
    if (previous === undefined) delete process.env.GITHUB_WORKSPACE;
    else process.env.GITHUB_WORKSPACE = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function writeFile(file: string, content: string, mode?: number): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, mode === undefined ? undefined : { mode });
}

test("resource-only output directories do not suppress a module build", async () => {
  await withWorkspace(async (root) => {
    const module = path.join(root, "apps", "resources");
    const classes = path.join(module, "target", "classes");
    writeFile(path.join(module, "pom.xml"), "<project/>");
    writeFile(path.join(classes, "application.yml"), "config");
    writeFile(
      path.join(root, "mvnw"),
      "#!/bin/sh\nmkdir -p target/classes\nprintf bytecode > target/classes/Generated.class\n",
      0o755,
    );

    assert.deepEqual(findClassDirs(root), []);
    assert.deepEqual(await tryProjectBuild(root, [], true), [classes]);
  });
});

test("reusing build outputs skips only built modules and builds the others", async () => {
  await withWorkspace(async (root) => {
    const built = path.join(root, "apps", "built");
    const unbuilt = path.join(root, "apps", "unbuilt");
    writeFile(path.join(built, "pom.xml"), "<project/>");
    writeFile(path.join(built, "target", "classes", "Built.class"), "bytecode");
    writeFile(path.join(unbuilt, "pom.xml"), "<project/>");
    writeFile(
      path.join(root, "mvnw"),
      "#!/bin/sh\nmkdir -p target/classes\nprintf bytecode > target/classes/Unbuilt.class\n",
      0o755,
    );
    assert.equal(findWrapper(unbuilt, "mvnw"), path.join(root, "mvnw"));

    const notes: string[] = [];
    const classDirs = await tryProjectBuild(root, notes, true);

    assert.deepEqual(classDirs, [
      path.join(built, "target", "classes"),
      path.join(unbuilt, "target", "classes"),
    ]);
    assert.deepEqual(notes, []);
  });
});

test("existing outputs are rebuilt when reuse is not enabled", async () => {
  await withWorkspace(async (root) => {
    const module = path.join(root, "apps", "service");
    const calls = path.join(root, "wrapper-calls.txt");
    writeFile(path.join(module, "pom.xml"), "<project/>");
    writeFile(path.join(module, "target", "classes", "Existing.class"), "bytecode");
    writeFile(path.join(root, "mvnw"), `#!/bin/sh\nprintf '%s\\n' "$PWD" >> '${calls}'\n`, 0o755);

    await tryProjectBuild(root, []);

    assert.equal(fs.readFileSync(calls, "utf8").trim(), module);
  });
});

test("failed module build notes include the module path", async () => {
  await withWorkspace(async (root) => {
    const module = path.join(root, "apps", "broken");
    writeFile(path.join(module, "pom.xml"), "<project/>");
    writeFile(path.join(root, "mvnw"), "#!/bin/sh\nexit 1\n", 0o755);

    const notes: string[] = [];
    await tryProjectBuild(root, notes);

    assert.deepEqual(notes, ["mvn compile had errors in apps/broken"]);
  });
});

test("Gradle settings files identify the root build", async () => {
  await withWorkspace((root) => {
    writeFile(path.join(root, "settings.gradle.kts"), "include(\":app\")");
    writeFile(path.join(root, "app", "build.gradle.kts"), "plugins {}");

    assert.deepEqual(findModuleDirs(root), [root]);
  });
});

test("target build files take precedence and nested modules are discovered once", async () => {
  await withWorkspace((root) => {
    writeFile(path.join(root, "pom.xml"), "<project/>");
    writeFile(path.join(root, "modules", "parent", "pom.xml"), "<project/>");
    writeFile(path.join(root, "modules", "parent", "child", "pom.xml"), "<project/>");
    assert.deepEqual(findModuleDirs(root), [root]);

    fs.rmSync(path.join(root, "pom.xml"));
    assert.deepEqual(findModuleDirs(root), [path.join(root, "modules", "parent")]);
  });
});

test("wrapper lookup stops at the workspace boundary", async () => {
  const parent = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-spotbugs-parent-")));
  const root = path.join(parent, "workspace");
  fs.mkdirSync(root);
  const previous = process.env.GITHUB_WORKSPACE;
  process.env.GITHUB_WORKSPACE = root;
  try {
    const target = path.join(root, "repo");
    fs.mkdirSync(target);
    writeFile(path.join(parent, "mvnw"), "#!/bin/sh");

    assert.equal(findWrapper(target, "mvnw"), "");
  } finally {
    if (previous === undefined) delete process.env.GITHUB_WORKSPACE;
    else process.env.GITHUB_WORKSPACE = previous;
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("non-executable wrappers are launched through sh", async () => {
  await withWorkspace(async (root) => {
    const wrapper = path.join(root, "mvnw");
    const module = path.join(root, "service");
    const classes = path.join(module, "target", "classes");
    writeFile(path.join(module, "pom.xml"), "<project/>");
    writeFile(
      wrapper,
      "#!/bin/sh\nmkdir -p target/classes\nprintf bytecode > target/classes/Generated.class\n",
      0o644,
    );

    assert.deepEqual(wrapperInvocation(wrapper), { command: "sh", args: [wrapper] });
    assert.deepEqual(await tryProjectBuild(root, []), [classes]);
  });
});
