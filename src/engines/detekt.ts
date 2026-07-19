// detekt engine adapter — Kotlin-native static analysis (code security + quality).
// Runs the detekt CLI (downloaded on demand) with the SARIF report and parses it.
import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";

// Resolve the target path relative to the GitHub workspace (if set),
// not the action's own directory — otherwise '.' resolves to the wrong place.
function resolveTarget(target: string): string {
  const ws = process.env.GITHUB_WORKSPACE;
  if (ws && !path.isAbsolute(target)) {
    return path.resolve(ws, target);
  }
  return path.resolve(target);
}

const DETEKT_VERSION = "1.23.7";
const DETEKT_URL = `https://github.com/detekt/detekt/releases/download/v${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar`;

// detekt SARIF levels: error/warning/note → map to our severities.
function mapSeverity(level: string, ruleId: string): Severity {
  // Security-relevant rules bumped to high.
  const sec = /inject|sql|command|crypto|hardcod|secret|ssl|tls|trust|random|xxe|path|traversal/i;
  if (sec.test(ruleId)) return "high";
  switch ((level || "").toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    default:
      return "low";
  }
}

function findKotlinFiles(dir: string): boolean {
  const walk = (d: string): boolean => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (["node_modules", ".git", "target", "build"].includes(entry.name)) continue;
        if (walk(path.join(d, entry.name))) return true;
      } else if (entry.name.endsWith(".kt")) {
        return true;
      }
    }
    return false;
  };
  return walk(dir);
}

export function parseDetektSarif(sarif: unknown, abs: string): Finding[] {
  const findings: Finding[] = [];
  for (const runObj of (sarif as { runs?: unknown[] }).runs ?? []) {
    for (const r of (runObj as { results?: unknown[] }).results ?? []) {
      const result = r as {
        ruleId?: string;
        level?: string;
        message?: { text?: string };
        locations?: { physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number } } }[];
      };
      const ruleId = result.ruleId ?? "detekt";
      const loc = result.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri ?? "unknown";
      const line = loc?.region?.startLine ?? 0;
      findings.push({
        engine: "detekt",
        ruleId: String(ruleId).split("/").pop() || "detekt",
        severity: mapSeverity(result.level ?? "", ruleId),
        message: result.message?.text ?? ruleId,
        file: uri.replace(/^file:\/\//, "").replace(abs + "/", ""),
        line,
      });
    }
  }
  return findings;
}

export async function runDetekt(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  if (!findKotlinFiles(abs)) {
    return { engine: "detekt", findings: [], available: true, note: "no .kt files found" };
  }
  if (!(await which("java"))) {
    return { engine: "detekt", findings: [], available: false, note: "java not available" };
  }

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-detekt-"));
  const jar = path.join(workdir, "detekt-cli.jar");
  core.info(`Downloading detekt v${DETEKT_VERSION}…`);
  const dl = await run("bash", [
    "-lc",
    `curl -sSL -o "${jar}" "${DETEKT_URL}"`,
  ]);
  if (dl.exitCode !== 0 || !fs.existsSync(jar)) {
    return { engine: "detekt", findings: [], available: false, note: `detekt download failed: ${dl.stderr.slice(0, 200)}` };
  }

  const sarifOut = path.join(workdir, "detekt.sarif");
  // --build-upon-default-config keeps the default ruleset; --all-rules enables extra (incl. security-adjacent) rules.
  const res = await run("java", [
    "-jar",
    jar,
    "--input",
    abs,
    "--report",
    `sarif:${sarifOut}`,
    "--build-upon-default-config",
    "--all-rules",
  ]);

  if (!fs.existsSync(sarifOut)) {
    return { engine: "detekt", findings: [], available: false, note: `detekt produced no output: ${res.stdout.slice(0, 200)}` };
  }

  try {
    const sarif = JSON.parse(fs.readFileSync(sarifOut, "utf-8"));
    return { engine: "detekt", findings: parseDetektSarif(sarif, abs), available: true };
  } catch (err) {
    return { engine: "detekt", findings: [], available: true, note: `parse error: ${String(err).slice(0, 200)}` };
  }
}
