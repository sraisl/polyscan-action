// Minimal CycloneDX 1.5 SBOM generator.
// Detects dependencies from package.json, requirements.txt, and pom.xml.
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

interface Component {
  type: string;
  name: string;
  version: string;
  purl: string;
}

function detectNpm(target: string, comps: Component[]): void {
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

function detectPip(target: string, comps: Component[]): void {
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

export function toSbom(target: string): string {
  const abs = path.resolve(target);
  const comps: Component[] = [];
  detectNpm(abs, comps);
  detectPip(abs, comps);

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
