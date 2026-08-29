import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultLockPath = resolve(repositoryRoot, "tools.lock.json");
const lockPath = process.env.POLYSCAN_TOOLS_LOCK
  ? resolve(process.env.POLYSCAN_TOOLS_LOCK)
  : defaultLockPath;

function expandVersion(template, version) {
  return template.replaceAll("{version}", version);
}

function githubTag(tool, version) {
  return expandVersion(tool.tagTemplate, version);
}

function githubAssetName(tool, version) {
  return expandVersion(tool.assetTemplate, version);
}

function mavenBaseUrl(tool, version) {
  const groupPath = tool.group.replaceAll(".", "/");
  const filename = `${tool.artifact}-${version}.${tool.extension}`;
  return `https://repo1.maven.org/maven2/${groupPath}/${tool.artifact}/${version}/${filename}`;
}

async function fetchResponse(url, accept = "*/*") {
  const response = await fetch(url, {
    headers: {
      Accept: accept,
      "User-Agent": "polyscan-engine-updater",
    },
    redirect: "follow",
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response;
}

async function fetchOptionalResponse(url, accept = "*/*") {
  const response = await fetch(url, {
    headers: {
      Accept: accept,
      "User-Agent": "polyscan-engine-updater",
    },
    redirect: "follow",
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response;
}

async function fetchJson(url) {
  return fetchResponse(url, "application/json").then((response) => response.json());
}

async function digestResponse(response, algorithms) {
  if (!response.body) throw new Error("download response has no body");
  const hashes = Object.fromEntries(algorithms.map((algorithm) => [algorithm, createHash(algorithm)]));
  for await (const chunk of response.body) {
    for (const hash of Object.values(hashes)) hash.update(chunk);
  }
  return Object.fromEntries(
    Object.entries(hashes).map(([algorithm, hash]) => [algorithm, hash.digest("hex")]),
  );
}

function extractVersion(template, value) {
  const marker = "{version}";
  const markerIndex = template.indexOf(marker);
  if (markerIndex < 0) throw new Error(`template is missing ${marker}`);
  const prefix = template.slice(0, markerIndex);
  const suffix = template.slice(markerIndex + marker.length);
  if (!value.startsWith(prefix) || !value.endsWith(suffix)) {
    throw new Error(`value "${value}" does not match template "${template}"`);
  }
  return value.slice(prefix.length, value.length - suffix.length || undefined);
}

export function checksumFromText(text, assetName) {
  const escapedName = assetName.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
  const common = new RegExp(
    String.raw`^([a-fA-F0-9]{64})\s+\*?${escapedName}$`,
    "m",
  ).exec(text);
  if (common) return common[1].toLowerCase();
  const bsd = new RegExp(
    String.raw`^SHA256\s*\(${escapedName}\)\s*=\s*([a-fA-F0-9]{64})$`,
    "mi",
  ).exec(text);
  return bsd?.[1]?.toLowerCase();
}

export function xmlElementText(xml, element) {
  const openingTag = `<${element}>`;
  const closingTag = `</${element}>`;
  const contentStart = xml.indexOf(openingTag);
  if (contentStart < 0) return undefined;
  const valueStart = contentStart + openingTag.length;
  const contentEnd = xml.indexOf(closingTag, valueStart);
  if (contentEnd < 0) return undefined;
  return xml.slice(valueStart, contentEnd).trim() || undefined;
}

async function githubRelease(tool, version) {
  const tag = githubTag(tool, version);
  const url = `https://api.github.com/repos/${tool.repository}/releases/tags/${encodeURIComponent(tag)}`;
  return fetchJson(url);
}

export async function githubAssetDigest(release, assetName) {
  const asset = release.assets?.find((candidate) => candidate.name === assetName);
  if (!asset) throw new Error(`release ${release.tag_name} has no asset ${assetName}`);

  const apiDigest = /^sha256:([a-f0-9]{64})$/i.exec(asset.digest ?? "");
  if (apiDigest) return { asset, sha256: apiDigest[1].toLowerCase(), verified: true };

  const checksumAssets = (release.assets ?? []).filter((candidate) =>
    /(?:checksums?|sha256)/i.test(candidate.name),
  );
  for (const checksumAsset of checksumAssets) {
    const text = await fetchResponse(checksumAsset.browser_download_url).then((response) =>
      response.text(),
    );
    const sha256 = checksumFromText(text, assetName);
    if (sha256) return { asset, sha256, verified: true };
  }
  // No checksum file found: download the asset and compute its SHA-256 directly. This is
  // trust-on-first-use, not independently verified — this initial download isn't checked
  // against any published digest, only against itself. It becomes repeatably verifiable
  // from here on because the computed digest is pinned into tools.lock.json and cross-checked
  // against a fresh download on every subsequent update.
  const downloaded = await digestResponse(await fetchResponse(asset.browser_download_url), [
    "sha256",
  ]);
  console.warn(
    `release asset ${assetName} has no published checksum; SHA-256 computed from download`,
  );
  return { asset, sha256: downloaded.sha256, verified: false };
}

async function latestVersion(tool) {
  switch (tool.provider) {
    case "github": {
      const release = await fetchJson(
        `https://api.github.com/repos/${tool.repository}/releases/latest`,
      );
      return extractVersion(tool.tagTemplate, release.tag_name);
    }
    case "pypi": {
      const metadata = await fetchJson(`https://pypi.org/pypi/${tool.package}/json`);
      return metadata.info.version;
    }
    case "npm": {
      const metadata = await fetchJson(`https://registry.npmjs.org/${tool.package}/latest`);
      return metadata.version;
    }
    case "maven": {
      const groupPath = tool.group.replaceAll(".", "/");
      const metadataUrl =
        `https://repo1.maven.org/maven2/${groupPath}/${tool.artifact}/maven-metadata.xml`;
      const metadata = await fetchResponse(metadataUrl).then((response) => response.text());
      const release = xmlElementText(metadata, "release");
      if (!release) throw new Error(`Maven metadata has no release version for ${tool.artifact}`);
      return release;
    }
    default:
      throw new Error(`unsupported provider ${tool.provider}`);
  }
}

export async function resolveGithubUpdate(tool, version) {
  const release = await githubRelease(tool, version);
  const assetName = githubAssetName(tool, version);
  const { asset, sha256, verified } = await githubAssetDigest(release, assetName);
  if (verified) {
    // sha256 came from a published checksum; re-download and confirm.
    const downloaded = await digestResponse(
      await fetchResponse(asset.browser_download_url),
      ["sha256"],
    );
    if (downloaded.sha256 !== sha256) {
      throw new Error(
        `downloaded SHA-256 ${downloaded.sha256} does not match release digest ${sha256}`,
      );
    }
  }
  return { version, sha256 };
}

async function resolvePypiUpdate(tool, version) {
  const metadata = await fetchJson(
    `https://pypi.org/pypi/${tool.package}/${encodeURIComponent(version)}/json`,
  );
  if (metadata.info.version !== version) throw new Error(`PyPI returned ${metadata.info.version}`);
  if (!metadata.urls?.some((file) => !file.yanked)) {
    throw new Error(`PyPI release ${tool.package}@${version} has no active distributions`);
  }
  return { version };
}

async function resolveNpmUpdate(tool, version) {
  const metadata = await fetchJson(
    `https://registry.npmjs.org/${tool.package}/${encodeURIComponent(version)}`,
  );
  if (metadata.version !== version) throw new Error(`npm returned ${metadata.version}`);
  if (!metadata.dist?.integrity) {
    throw new Error(`npm release ${tool.package}@${version} has no integrity digest`);
  }
  return { version };
}

async function resolveMavenUpdate(tool, version) {
  const artifactUrl = mavenBaseUrl(tool, version);
  const sha256Response = await fetchOptionalResponse(`${artifactUrl}.sha256`);
  if (sha256Response) {
    const checksumText = await sha256Response.text();
    const sha256 = /^[a-fA-F0-9]{64}/.exec(checksumText.trim())?.[0]?.toLowerCase();
    if (!sha256) throw new Error(`Maven artifact has no valid SHA-256 checksum`);
    const downloaded = await digestResponse(await fetchResponse(artifactUrl), ["sha256"]);
    if (downloaded.sha256 !== sha256) {
      throw new Error(
        `downloaded SHA-256 ${downloaded.sha256} does not match Maven digest ${sha256}`,
      );
    }
    return { version, sha256 };
  }

  const checksumResponse = await fetchResponse(`${artifactUrl}.sha1`);
  const checksumText = await checksumResponse.text();
  const sha1 = /^[a-fA-F0-9]{40}/.exec(checksumText.trim())?.[0]?.toLowerCase();
  if (!sha1) throw new Error(`Maven artifact has no valid SHA-1 checksum`);
  const downloaded = await digestResponse(await fetchResponse(artifactUrl), ["sha1", "sha256"]);
  if (downloaded.sha1 !== sha1) {
    throw new Error(`downloaded SHA-1 ${downloaded.sha1} does not match Maven digest ${sha1}`);
  }
  console.warn("Maven SHA-256 unavailable; artifact verified with repository SHA-1");
  return { version, sha256: downloaded.sha256 };
}

async function resolveUpdate(tool, version) {
  switch (tool.provider) {
    case "github":
      return resolveGithubUpdate(tool, version);
    case "pypi":
      return resolvePypiUpdate(tool, version);
    case "npm":
      return resolveNpmUpdate(tool, version);
    case "maven":
      return resolveMavenUpdate(tool, version);
    default:
      throw new Error(`unsupported provider ${tool.provider}`);
  }
}

function validateVersion(version) {
  if (!/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(version)) {
    throw new Error(`invalid version "${version}"`);
  }
}

async function readLock() {
  const lock = JSON.parse(await readFile(lockPath, "utf8"));
  if (lock.schemaVersion !== 1 || !lock.tools || typeof lock.tools !== "object") {
    throw new Error(`unsupported tool lock schema in ${lockPath}`);
  }
  return lock;
}

function selectTools(lock, names) {
  const selected = names.length > 0 ? names : Object.keys(lock.tools);
  for (const name of selected) {
    if (!lock.tools[name]) throw new Error(`unknown tool "${name}"`);
  }
  return selected;
}

function printList(lock, names) {
  console.log("tool\tprovider\tversion");
  for (const name of selectTools(lock, names)) {
    const tool = lock.tools[name];
    console.log(`${name}\t${tool.provider}\t${tool.version}`);
  }
}

async function checkTools(lock, names) {
  console.log("tool\tcurrent\tlatest\tstatus");
  let failed = false;
  for (const name of selectTools(lock, names)) {
    const tool = lock.tools[name];
    try {
      const latest = await latestVersion(tool);
      const status = latest === tool.version ? "current" : "update available";
      console.log(`${name}\t${tool.version}\t${latest}\t${status}`);
    } catch (error) {
      failed = true;
      console.error(`${name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (failed) process.exitCode = 1;
}

function runVerification() {
  const npmCli = process.env.npm_execpath;
  if (!npmCli || !isAbsolute(npmCli)) {
    throw new Error("npm_execpath must be an absolute path; run the updater through npm");
  }
  for (const args of [
    ["run", "typecheck"],
    ["test"],
    ["run", "build"],
  ]) {
    const result = spawnSync(process.execPath, [npmCli, ...args], {
      cwd: repositoryRoot,
      stdio: "inherit",
    });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`npm ${args.join(" ")} failed`);
  }
}

async function updateTool(lock, name, version, options) {
  const tool = lock.tools[name];
  if (!tool) throw new Error(`unknown tool "${name}"`);
  validateVersion(version);
  const update = await resolveUpdate(tool, version);
  const updatedLock = structuredClone(lock);
  Object.assign(updatedLock.tools[name], update);

  console.log(`${name}: ${tool.version} -> ${version}`);
  if (update.sha256) console.log(`sha256: ${update.sha256}`);
  if (options.dryRun) return;

  await writeFile(lockPath, `${JSON.stringify(updatedLock, null, 2)}\n`);
  if (!options.skipProjectChecks) runVerification();
}

function usage() {
  console.log(`Usage:
  npm run engines:list
  npm run engines:check -- [tool...]
  npm run engines:update -- <tool> <version> [--dry-run] [--skip-project-checks]`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const lock = await readLock();
  switch (command) {
    case "list":
      printList(lock, args);
      break;
    case "check":
      await checkTools(lock, args);
      break;
    case "update": {
      const supportedOptions = new Set(["--dry-run", "--skip-project-checks"]);
      const unknownOptions = args.filter(
        (arg) => arg.startsWith("--") && !supportedOptions.has(arg),
      );
      if (unknownOptions.length > 0) {
        throw new Error(`unknown option "${unknownOptions[0]}"`);
      }
      const dryRun = args.includes("--dry-run");
      const skipProjectChecks = args.includes("--skip-project-checks");
      const positional = args.filter((arg) => !arg.startsWith("--"));
      if (positional.length !== 2) throw new Error("update requires <tool> <version>");
      await updateTool(lock, positional[0], positional[1], { dryRun, skipProjectChecks });
      break;
    }
    default:
      usage();
      if (command) process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    await main();
  } catch (error) {
    console.error(`engine-tools: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
