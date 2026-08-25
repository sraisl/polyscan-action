import test from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

import { TOOLS } from "../src/tool-versions";

const SCRIPT = path.resolve(__dirname, "../../scripts/engine-tools.mjs");

interface EngineToolModule {
  checksumFromText: (text: string, assetName: string) => string | undefined;
  xmlElementText: (xml: string, element: string) => string | undefined;
}

async function loadEngineTools(): Promise<EngineToolModule> {
  return import(pathToFileURL(SCRIPT).href) as Promise<EngineToolModule>;
}

function runCli(args: string[]) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: "utf8",
    env: process.env,
  });
}

test("engine tools list prints every locked tool", () => {
  const result = runCli(["list"]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^tool\tprovider\tversion/m);
  for (const [name, tool] of Object.entries(TOOLS)) {
    const escaped = tool.version.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
    assert.match(result.stdout, new RegExp(`^${name}\t${tool.provider}\t${escaped}$`, "m"));
  }
});

test("engine tools list rejects unknown tools", () => {
  const result = runCli(["list", "unknown"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unknown tool "unknown"/);
});

test("engine tools update rejects unsafe versions before network access", () => {
  const result = runCli(["update", "trivy", "../../bad", "--dry-run"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /invalid version/);
});

test("engine tools update rejects unknown options", () => {
  const result = runCli(["update", "trivy", "1.2.3", "--unsafe"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unknown option "--unsafe"/);
});

test("checksum parser supports GNU and BSD formats with escaped asset names", async () => {
  const { checksumFromText } = await loadEngineTools();
  const digest = "a".repeat(64);
  const asset = "scanner+cli(1.2).tar.gz";

  assert.equal(checksumFromText(`${digest}  ${asset}\n`, asset), digest);
  assert.equal(checksumFromText(`SHA256 (${asset}) = ${digest}\n`, asset), digest);
  assert.equal(checksumFromText(`${digest}  other.tar.gz\n`, asset), undefined);
});

test("XML element parser extracts trimmed values without regex backtracking", async () => {
  const { xmlElementText } = await loadEngineTools();

  assert.equal(xmlElementText("<metadata><release> 1.14.0 </release></metadata>", "release"), "1.14.0");
  assert.equal(xmlElementText("<metadata><release>1.14.0</metadata>", "release"), undefined);
  assert.equal(xmlElementText("<metadata></metadata>", "release"), undefined);
});
