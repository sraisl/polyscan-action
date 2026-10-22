import test from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

import { TOOLS } from "../src/tool-versions";

const SCRIPT = path.resolve(__dirname, "../../scripts/engine-tools.mjs");

interface GithubRelease {
  tag_name: string;
  assets?: Array<{ name: string; digest?: string; browser_download_url: string }>;
}

interface GithubTool {
  provider: "github";
  repository: string;
  tagTemplate: string;
  assetTemplate: string;
}

interface EngineToolModule {
  checksumFromText: (text: string, assetName: string) => string | undefined;
  xmlElementText: (xml: string, element: string) => string | undefined;
  githubAssetDigest: (
    release: GithubRelease,
    assetName: string,
  ) => Promise<{ sha256: string; verified: boolean }>;
  resolveGithubUpdate: (
    tool: GithubTool,
    version: string,
  ) => Promise<{ version: string; sha256: string }>;
  latestGithubVersion: (tool: GithubTool) => Promise<string>;
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

test("githubAssetDigest falls back to computing SHA-256 when a release has no published checksum", async () => {
  const { githubAssetDigest } = await loadEngineTools();
  const assetBody = Buffer.from("fake-release-asset-bytes");
  const expectedSha256 = createHash("sha256").update(assetBody).digest("hex");
  const release = {
    tag_name: "v1.2.3",
    assets: [{ name: "tool-1.2.3.tar.gz", browser_download_url: "https://example.invalid/tool-1.2.3.tar.gz" }],
  };

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => ({
    ok: true,
    status: 200,
    statusText: "OK",
    body: (async function* () {
      yield assetBody;
    })(),
  })) as unknown as typeof fetch;

  try {
    const result = await githubAssetDigest(release, "tool-1.2.3.tar.gz");
    assert.equal(result.sha256, expectedSha256);
    assert.equal(result.verified, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("resolveGithubUpdate skips the redundant re-download when the digest was computed, not cross-checked", async () => {
  const { resolveGithubUpdate } = await loadEngineTools();
  const assetBody = Buffer.from("another-fake-release-asset");
  const expectedSha256 = createHash("sha256").update(assetBody).digest("hex");
  const tool = {
    provider: "github" as const,
    repository: "example/tool",
    tagTemplate: "v{version}",
    assetTemplate: "tool-{version}.tar.gz",
  };
  let fetchCalls = 0;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL) => {
    fetchCalls++;
    if (String(url).includes("/releases/tags/")) {
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        json: async () => ({
          tag_name: "v1.2.3",
          assets: [{ name: "tool-1.2.3.tar.gz", browser_download_url: "https://example.invalid/tool-1.2.3.tar.gz" }],
        }),
      };
    }
    return {
      ok: true,
      status: 200,
      statusText: "OK",
      body: (async function* () {
        yield assetBody;
      })(),
    };
  }) as unknown as typeof fetch;

  try {
    const result = await resolveGithubUpdate(tool, "1.2.3");
    assert.equal(result.version, "1.2.3");
    assert.equal(result.sha256, expectedSha256);
    // one call for release metadata, one for the asset — no second download to cross-check
    // a digest that was itself computed from that same single download.
    assert.equal(fetchCalls, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function stubGithubReleases(latestTag: string, releases: Array<{ tag_name: string; draft?: boolean; prerelease?: boolean }>) {
  const requested: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL) => {
    requested.push(String(url));
    const json = String(url).endsWith("/releases/latest") ? { tag_name: latestTag } : releases;
    return { ok: true, status: 200, statusText: "OK", json: async () => json };
  }) as unknown as typeof fetch;
  return { requested, restore: () => (globalThis.fetch = originalFetch) };
}

const MONOREPO_TOOL = {
  provider: "github" as const,
  repository: "oxc-project/oxc",
  tagTemplate: "oxlint_v{version}",
  assetTemplate: "oxlint-x86_64-unknown-linux-gnu.tar.gz",
};

test("latestGithubVersion uses the repository latest release when its tag matches", async () => {
  const { latestGithubVersion } = await loadEngineTools();
  const stub = stubGithubReleases("oxlint_v1.89.0", []);
  try {
    assert.equal(await latestGithubVersion(MONOREPO_TOOL), "1.89.0");
    assert.equal(stub.requested.length, 1);
  } finally {
    stub.restore();
  }
});

test("latestGithubVersion skips other monorepo products, drafts and prereleases", async () => {
  const { latestGithubVersion } = await loadEngineTools();
  const stub = stubGithubReleases("oxfmt_v0.74.0", [
    { tag_name: "oxfmt_v0.74.0" },
    { tag_name: "crates_v0.155.0" },
    { tag_name: "oxlint_v1.90.0", draft: true },
    { tag_name: "oxlint_v1.90.0-beta.1", prerelease: true },
    { tag_name: "oxlint_v1.89.0" },
    { tag_name: "oxlint_v1.88.0" },
  ]);
  try {
    assert.equal(await latestGithubVersion(MONOREPO_TOOL), "1.89.0");
  } finally {
    stub.restore();
  }
});

test("latestGithubVersion fails when no release matches the tag template", async () => {
  const { latestGithubVersion } = await loadEngineTools();
  const stub = stubGithubReleases("oxfmt_v0.74.0", [{ tag_name: "oxfmt_v0.74.0" }]);
  try {
    await assert.rejects(latestGithubVersion(MONOREPO_TOOL), /no stable release of oxc-project\/oxc matches/);
  } finally {
    stub.restore();
  }
});
