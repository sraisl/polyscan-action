// gosec engine adapter for Go security analysis.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { getCore } from "../actions-core";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, TOOLS } from "../tool-versions";

const GOSEC = TOOLS.gosec;
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".gradle",
  "build",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);

interface SarifRule {
  id?: string;
  properties?: { tags?: unknown[] };
  relationships?: {
    target?: { id?: string; toolComponent?: { name?: string } };
  }[];
}

interface SarifResult {
  ruleId?: string;
  ruleIndex?: number;
  level?: string;
  message?: { text?: string };
  locations?: {
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number; startColumn?: number };
    };
  }[];
}

interface SarifRun {
  tool?: { driver?: { rules?: SarifRule[] } };
  results?: SarifResult[];
}

function severityFor(rule: SarifRule | undefined, level: string): Severity {
  const tags = rule?.properties?.tags ?? [];
  const gosecSeverity = tags.find(
    (tag): tag is string =>
      typeof tag === "string" && ["HIGH", "MEDIUM", "LOW"].includes(tag.toUpperCase()),
  );
  switch (gosecSeverity?.toUpperCase()) {
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      if (level === "error") return "high";
      if (level === "warning") return "medium";
      return "low";
  }
}

function cweFor(rule: SarifRule | undefined): string | undefined {
  const target = rule?.relationships?.find(
    (relationship) => relationship.target?.toolComponent?.name === "CWE",
  )?.target;
  const match = /^(?:CWE-)?(\d+)$/i.exec(target?.id ?? "");
  return match ? `CWE-${match[1]}` : undefined;
}

function findingPath(uri: string, basePath: string): string {
  const relative = uri.replace(/^file:\/\//, "");
  return basePath && relative !== "unknown" ? path.posix.join(basePath, relative) : relative;
}

export function parseGosecSarif(sarif: unknown, basePath = ""): Finding[] {
  const findings: Finding[] = [];
  for (const runObj of (sarif as { runs?: SarifRun[] }).runs ?? []) {
    const rules = runObj.tool?.driver?.rules ?? [];
    const rulesById = new Map(rules.map((rule) => [rule.id, rule]));
    for (const result of runObj.results ?? []) {
      const ruleId = result.ruleId ?? "gosec";
      const rule = rulesById.get(result.ruleId) ?? rules[result.ruleIndex ?? -1];
      const location = result.locations?.[0]?.physicalLocation;
      findings.push({
        engine: "gosec",
        ruleId,
        severity: severityFor(rule, result.level ?? ""),
        message: result.message?.text ?? ruleId,
        file: findingPath(location?.artifactLocation?.uri ?? "unknown", basePath),
        line: location?.region?.startLine ?? 0,
        column: location?.region?.startColumn,
        cwe: cweFor(rule),
      });
    }
  }
  return findings;
}

export function findGoScanRoots(root: string): string[] {
  const moduleRoots: string[] = [];
  let hasGoFiles = false;

  function walk(directory: string): void {
    const entries = fs.readdirSync(directory, { withFileTypes: true });
    if (entries.some((entry) => entry.isFile() && entry.name === "go.mod")) {
      moduleRoots.push(directory);
    }
    if (entries.some((entry) => entry.isFile() && entry.name.endsWith(".go"))) {
      hasGoFiles = true;
    }
    for (const entry of entries) {
      if (
        entry.isDirectory() &&
        !IGNORED_DIRECTORIES.has(entry.name)
      ) {
        walk(path.join(directory, entry.name));
      }
    }
  }

  walk(root);
  if (moduleRoots.length > 0) return moduleRoots;
  return hasGoFiles ? [root] : [];
}

async function ensureGosec(): Promise<string | null> {
  const core = await getCore();
  if (await which("gosec")) return "gosec";
  core.info(`gosec not found - downloading v${GOSEC.version}...`);
  try {
    return await cachedTool("gosec", GOSEC.version, "gosec", async (directory) => {
      const archive = await downloadVerified(githubReleaseUrl(GOSEC), GOSEC.sha256);
      await tc.extractTar(archive, directory);
      fs.chmodSync(path.join(directory, "gosec"), 0o700);
    });
  } catch (err) {
    core.warning(`gosec download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export async function runGosec(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const scanRoots = findGoScanRoots(abs);
  if (scanRoots.length === 0) {
    return { engine: "gosec", findings: [], status: "skipped", note: "no .go files found" };
  }
  if (!(await which("go"))) {
    return { engine: "gosec", findings: [], status: "failed", note: "go not available" };
  }

  const bin = await ensureGosec();
  if (!bin) {
    return { engine: "gosec", findings: [], status: "failed", note: "gosec not installed" };
  }

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-gosec-"));
  const findings: Finding[] = [];
  const failures: string[] = [];
  try {
    for (const [index, scanRoot] of scanRoots.entries()) {
      const sarifOut = path.join(workdir, `gosec-${index}.sarif`);
      const result = await run(
        bin,
        ["-fmt", "sarif", "-out", sarifOut, "-no-fail", "./..."],
        { cwd: scanRoot },
      );
      if (!fs.existsSync(sarifOut)) {
        failures.push(
          (result.stderr || result.stdout || `module exited ${result.exitCode}`).slice(0, 200),
        );
        continue;
      }
      try {
        const sarif = JSON.parse(fs.readFileSync(sarifOut, "utf-8"));
        const basePath = path.relative(abs, scanRoot).split(path.sep).join("/");
        findings.push(...parseGosecSarif(sarif, basePath));
        if (result.exitCode !== 0) {
          failures.push((result.stderr || `module exited ${result.exitCode}`).slice(0, 200));
        }
      } catch (err) {
        failures.push(`parse error: ${String(err).slice(0, 200)}`);
      }
    }
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }

  return failures.length > 0
    ? { engine: "gosec", findings, status: "failed", note: failures.join("; ").slice(0, 300) }
    : { engine: "gosec", findings, status: "success" };
}
