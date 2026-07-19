// CycloneDX 1.5 SBOM generator.
// Reads exact dependency versions from lock files when available,
// falling back to manifest files for projects without lock files.
// Supported: package-lock.json (v1/v2/v3), Pipfile.lock, requirements.txt, package.json, pom.xml.
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

interface Component {
  type: string;
  name: string;
  version: string;
  purl: string;
}

// npm: prefer package-lock.json (exact transitive deps) over package.json.
function detectNpm(target: string, comps: Component[]): void {
  if (detectNpmLock(target, comps)) return;
  detectNpmManifest(target, comps);
}

function detectNpmLock(target: string, comps: Component[]): boolean {
  const lockPath = path.join(target, "package-lock.json");
  if (!fs.existsSync(lockPath)) return false;
  try {
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8")) as {
      lockfileVersion?: number;
      packages?: Record<string, { version?: string; link?: boolean }>;
      dependencies?: Record<string, { version?: string; dependencies?: Record<string, unknown> }>;
    };
    const seen = new Set<string>();
    if ((lock.lockfileVersion ?? 1) >= 2 && lock.packages) {
      // v2/v3: flat packages map, keys like "node_modules/foo" or "node_modules/x/node_modules/foo"
      for (const [key, pkg] of Object.entries(lock.packages)) {
        if (!key || pkg.link) continue; // skip root ("") and symlinks
        const lastIdx = key.lastIndexOf("node_modules/");
        const name = lastIdx >= 0 ? key.slice(lastIdx + "node_modules/".length) : key;
        const version = pkg.version ?? "unknown";
        const id = `${name}@${version}`;
        if (seen.has(id)) continue;
        seen.add(id);
        comps.push({ type: "library", name, version, purl: `pkg:npm/${name}@${version}` });
      }
    } else if (lock.dependencies) {
      // v1: nested dependencies object
      collectNpmV1Deps(lock.dependencies, comps, seen);
    }
    return true;
  } catch {
    return false;
  }
}

function collectNpmV1Deps(
  deps: Record<string, { version?: string; dependencies?: Record<string, unknown> }>,
  comps: Component[],
  seen: Set<string>,
): void {
  for (const [name, dep] of Object.entries(deps)) {
    const version = dep.version ?? "unknown";
    const id = `${name}@${version}`;
    if (!seen.has(id)) {
      seen.add(id);
      comps.push({ type: "library", name, version, purl: `pkg:npm/${name}@${version}` });
    }
    if (dep.dependencies) {
      collectNpmV1Deps(
        dep.dependencies as Record<string, { version?: string; dependencies?: Record<string, unknown> }>,
        comps,
        seen,
      );
    }
  }
}

function detectNpmManifest(target: string, comps: Component[]): void {
  const pkgPath = path.join(target, "package.json");
  if (!fs.existsSync(pkgPath)) return;
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    for (const [name, ver] of Object.entries(deps)) {
      const version = String(ver).replace(/[^0-9.]/g, "") || "0.0.0";
      comps.push({
        type: "library",
        name,
        version,
        purl: `pkg:npm/${name}@${version}`,
      });
    }
  } catch {
    /* ignore */
  }
}

// pip: prefer Pipfile.lock (exact transitive deps) over requirements.txt.
function detectPip(target: string, comps: Component[]): void {
  if (detectPipfileLock(target, comps)) return;
  detectPipRequirements(target, comps);
}

function detectPipfileLock(target: string, comps: Component[]): boolean {
  const lockPath = path.join(target, "Pipfile.lock");
  if (!fs.existsSync(lockPath)) return false;
  try {
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8")) as Record<
      string,
      Record<string, { version?: string }>
    >;
    const seen = new Set<string>();
    for (const section of ["default", "develop"]) {
      for (const [name, pkg] of Object.entries(lock[section] ?? {})) {
        const version = (pkg.version ?? "unknown").replace(/^==/, "");
        const id = `${name}@${version}`;
        if (seen.has(id)) continue;
        seen.add(id);
        comps.push({ type: "library", name, version, purl: `pkg:pypi/${name}@${version}` });
      }
    }
    return true;
  } catch {
    return false;
  }
}

function detectPipRequirements(target: string, comps: Component[]): void {
  const reqPath = path.join(target, "requirements.txt");
  if (!fs.existsSync(reqPath)) return;
  const lines = fs.readFileSync(reqPath, "utf-8").split("\n");
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=)?\s*([0-9][A-Za-z0-9.\-]*)?/.exec(line);
    if (!m) continue;
    const name = m[1];
    const version = m[2] ?? "unknown";
    comps.push({
      type: "library",
      name,
      version,
      purl: `pkg:pypi/${name}@${version}`,
    });
  }
}

function xmlText(block: string, tag: string): string | undefined {
  const match = new RegExp(`<${tag}>\\s*([^<]+?)\\s*</${tag}>`).exec(block);
  return match?.[1]?.trim();
}

function detectMaven(target: string, comps: Component[]): void {
  const pomPath = path.join(target, "pom.xml");
  if (!fs.existsSync(pomPath)) return;
  const pom = fs.readFileSync(pomPath, "utf-8");
  const depRe = /<dependency\b[^>]*>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = depRe.exec(pom)) !== null) {
    const block = m[1];
    const groupId = xmlText(block, "groupId");
    const artifactId = xmlText(block, "artifactId");
    const version = xmlText(block, "version") ?? "unknown";
    if (!groupId || !artifactId) continue;
    comps.push({
      type: "library",
      name: `${groupId}:${artifactId}`,
      version,
      purl: `pkg:maven/${groupId}/${artifactId}@${version}`,
    });
  }
}

export function toSbom(target: string): string {
  const abs = path.resolve(target);
  const comps: Component[] = [];
  detectNpm(abs, comps);
  detectPip(abs, comps);
  detectMaven(abs, comps);

  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "Stefan Raisl", name: "PolyScan", version: "1.0.0" }],
    },
    components: comps,
  };

  return JSON.stringify(bom, null, 2);
}
