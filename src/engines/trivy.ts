// Trivy engine adapter — filesystem scan for vulnerable dependencies and
// misconfigurations (SCA + IaC), with optional container image scan.
// Installs the trivy binary on demand.
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

const TRIVY = TOOLS.trivy;
const TRIVY_VERSION = TRIVY.version;
const TRIVY_SHA256 = TRIVY.sha256;

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

async function ensureTrivy(): Promise<string | null> {
  const core = await getCore();
  if (await which("trivy")) return "trivy";
  core.info(`trivy not found — downloading v${TRIVY_VERSION}…`);
  try {
    return await cachedTool("trivy", TRIVY_VERSION, "trivy", async (directory) => {
      const archive = await downloadVerified(
        githubReleaseUrl(TRIVY),
        TRIVY_SHA256,
      );
      await tc.extractTar(archive, directory);
      fs.chmodSync(path.join(directory, "trivy"), 0o700);
    });
  } catch (err) {
    core.warning(`trivy download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export function parseTrivyData(data: unknown, imageRef?: string): Finding[] {
  const findings: Finding[] = [];
  for (const result of (data as { Results?: unknown[] }).Results ?? []) {
    const r = result as {
      Target?: string;
      Vulnerabilities?: unknown[];
      Misconfigurations?: unknown[];
    };
    const artifact = r.Target ?? "unknown";
    findings.push(
      ...parseVulnerabilities(r.Vulnerabilities ?? [], artifact, imageRef),
      ...parseMisconfigurations(r.Misconfigurations ?? [], artifact, imageRef),
    );
  }
  return findings;
}

function parseVulnerabilities(
  vulnerabilities: unknown[],
  artifact: string,
  imageRef?: string,
): Finding[] {
  return vulnerabilities.map((value) => {
    const vulnerability = value as {
      VulnerabilityID?: string;
      PkgName?: string;
      InstalledVersion?: string;
      FixedVersion?: string;
      Severity?: string;
      Title?: string;
      CweIDs?: string[];
      PrimaryURL?: string;
    };
    const fixed = vulnerability.FixedVersion ? ` (fixed in ${vulnerability.FixedVersion})` : "";
    return {
      engine: "trivy",
      ruleId: vulnerability.VulnerabilityID ?? "TRIVY-VULN",
      severity: mapSeverity(vulnerability.Severity ?? ""),
      message:
        `${vulnerability.PkgName}@${vulnerability.InstalledVersion}: ` +
        `${vulnerability.Title ?? vulnerability.VulnerabilityID}${fixed}`,
      file: artifact,
      line: 0,
      cwe: vulnerability.CweIDs?.[0],
      url: vulnerability.PrimaryURL,
      source: imageRef ? `image:${imageRef}` : undefined,
    };
  });
}

function parseMisconfigurations(
  misconfigurations: unknown[],
  artifact: string,
  imageRef?: string,
): Finding[] {
  return misconfigurations.map((value) => {
    const misconfiguration = value as {
      ID?: string;
      Title?: string;
      Message?: string;
      Severity?: string;
      CauseMetadata?: { StartLine?: number };
      PrimaryURL?: string;
    };
    return {
      engine: "trivy",
      ruleId: misconfiguration.ID ?? "TRIVY-MISCONF",
      severity: mapSeverity(misconfiguration.Severity ?? ""),
      message: `${misconfiguration.Title ?? misconfiguration.ID}: ${misconfiguration.Message ?? ""}`.trim(),
      file: artifact,
      line: misconfiguration.CauseMetadata?.StartLine ?? 0,
      url: misconfiguration.PrimaryURL,
      source: imageRef ? `image:${imageRef}` : undefined,
    };
  });
}

async function scanTrivy(
  bin: string,
  args: string[],
  output: string,
  label: string,
  imageRef?: string,
): Promise<{ findings: Finding[]; note?: string }> {
  const subject = args.at(-1);
  const options = args.slice(0, -1);
  const result = await run(bin, [
    ...options,
    "--format",
    "json",
    "--output",
    output,
    "--quiet",
    ...(subject ? [subject] : []),
  ]);
  const notes: string[] = [];
  if (result.exitCode !== 0) {
    notes.push(`${label} scan exited ${result.exitCode}: ${result.stderr.slice(0, 120)}`);
  }
  if (!fs.existsSync(output)) {
    notes.push(`${label} scan produced no output: ${result.stdout.slice(0, 150)}`);
    return { findings: [], note: notes.join("; ") };
  }
  try {
    return {
      findings: parseTrivyData(JSON.parse(fs.readFileSync(output, "utf-8")), imageRef),
      note: notes.length > 0 ? notes.join("; ") : undefined,
    };
  } catch (err) {
    notes.push(`${label} parse error: ${String(err).slice(0, 150)}`);
    return { findings: [], note: notes.join("; ") };
  }
}

export async function runTrivy(target: string, image?: string): Promise<EngineResult> {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-trivy-"));
  try {
    const core = await getCore();
    const bin = await ensureTrivy();
    if (!bin) {
      return { engine: "trivy", findings: [], status: "failed", note: "trivy not installed" };
    }

    const fsOut = path.join(workdir, "trivy-fs.json");
    const scans = [
      await scanTrivy(
        bin,
        ["fs", "--scanners", "vuln,misconfig", "--offline-scan", resolveTarget(target)],
        fsOut,
        "fs",
      ),
    ];
    if (image) {
      core.info(`trivy: scanning image "${image}"…`);
      const imgOut = path.join(workdir, "trivy-image.json");
      scans.push(
        await scanTrivy(bin, ["image", "--scanners", "vuln", image], imgOut, "image", image),
      );
    }

    const notes = scans.flatMap((scan) => (scan.note ? [scan.note] : []));
    return {
      engine: "trivy",
      findings: scans.flatMap((scan) => scan.findings),
      status: notes.length ? "failed" : "success",
      note: notes.length ? notes.join("; ") : undefined,
    };
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}
