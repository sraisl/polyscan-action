// PolyScan GitHub Action — entry point.
import * as fs from "node:fs";
import * as path from "node:path";
import { DefaultArtifactClient } from "@actions/artifact";

import { getCore, type ActionsCore } from "./actions-core";
import { Finding, EngineResult, countBySeverity } from "./schema";
import { runSemgrep } from "./engines/semgrep";
import { runOpengrep } from "./engines/opengrep";
import { runBandit } from "./engines/bandit";
import { runEslint } from "./engines/eslint";
import { runSpotbugs } from "./engines/spotbugs";
import { runTrivy } from "./engines/trivy";
import { runDetekt } from "./engines/detekt";
import { runGitleaks } from "./engines/gitleaks";
import { runGosec } from "./engines/gosec";
import { runHadolint } from "./engines/hadolint";
import { evaluateGate } from "./gate";
import { toSarif } from "./sarif";
import { toSbom } from "./sbom";
import { renderSummary } from "./summary";
import { resolveEngines, unknownEngines, SUPPORTED_ENGINES } from "./engines";
import { normalizeFindingPath, resolveOutputDir, resolveTarget } from "./target";
import { assertSupportedPlatform } from "./tools";
import { mapConcurrentWithBarriers, parseMaxConcurrency } from "./scheduler";

const DEFAULT_MAX_CONCURRENCY = 2;

function boolInput(core: ActionsCore, name: string, def: boolean): boolean {
  const raw = core.getInput(name);
  if (raw === "") return def;
  return raw.toLowerCase() === "true";
}

function intInput(core: ActionsCore, name: string, def: number): number {
  const raw = core.getInput(name);
  if (raw === "") return def;
  const n = Number.parseInt(raw, 10);
  return Number.isNaN(n) ? def : n;
}

interface ActionConfig {
  target: string;
  engines: string[];
  gateEnforced: boolean;
  failOnEngineError: boolean;
  wantSarif: boolean;
  wantSbom: boolean;
  uploadArtifacts: boolean;
  uploadSarif: boolean;
  maxConcurrency: number;
  outputDir: string;
  trivyImage?: string;
  opengrepConfig: string;
  gate: {
    maxCritical: number;
    maxHigh: number;
    maxMedium: number;
  };
}

async function readConfig(core: ActionsCore): Promise<ActionConfig> {
  const engines = resolveEngines(core.getInput("engines"));
  const unknown = unknownEngines(engines);
  if (unknown.length > 0) {
    throw new Error(
      `Unknown engine(s): ${unknown.join(", ")}. Valid engines: ${SUPPORTED_ENGINES.join(", ")}`,
    );
  }

  return {
    target: resolveTarget(core.getInput("target") || "."),
    engines,
    gateEnforced: boolInput(core, "gate", true),
    failOnEngineError: boolInput(core, "fail-on-engine-error", true),
    wantSarif: boolInput(core, "sarif", true),
    wantSbom: boolInput(core, "sbom", false),
    uploadArtifacts: boolInput(core, "upload-artifacts", true),
    uploadSarif: boolInput(core, "upload-sarif", false),
    maxConcurrency: parseMaxConcurrency(
      core.getInput("max-concurrency"),
      DEFAULT_MAX_CONCURRENCY,
      SUPPORTED_ENGINES.length,
    ),
    outputDir: resolveOutputDir(core.getInput("output-dir") || "."),
    trivyImage: core.getInput("trivy-image") || undefined,
    opengrepConfig: core.getInput("opengrep-config") || "auto",
    gate: {
      maxCritical: intInput(core, "max-critical", 0),
      maxHigh: intInput(core, "max-high", 0),
      maxMedium: intInput(core, "max-medium", 50),
    },
  };
}

async function runEngine(
  name: string,
  target: string,
  trivyImage: string | undefined,
  opengrepConfig: string,
): Promise<EngineResult> {
  try {
    switch (name) {
      case "semgrep":
        return await runSemgrep(target);
      case "opengrep":
        return await runOpengrep(target, opengrepConfig);
      case "bandit":
        return await runBandit(target);
      case "eslint":
        return await runEslint(target);
      case "spotbugs":
        return await runSpotbugs(target);
      case "trivy":
        return await runTrivy(target, trivyImage);
      case "detekt":
        return await runDetekt(target);
      case "gitleaks":
        return await runGitleaks(target);
      case "gosec":
        return await runGosec(target);
      case "hadolint":
        return await runHadolint(target);
      default:
        return { engine: name, findings: [], status: "failed", note: "unknown engine" };
    }
  } catch (err) {
    return {
      engine: name,
      findings: [],
      status: "failed",
      note: `engine crashed: ${String(err).slice(0, 200)}`,
    };
  }
}

function normalizeEngineFindings(result: EngineResult, target: string): void {
  try {
    result.findings = result.findings.map((finding) =>
      finding.source?.startsWith("image:")
        ? finding
        : { ...finding, file: normalizeFindingPath(finding.file, target) },
    );
  } catch (err) {
    result.findings = [];
    result.status = "failed";
    result.note = `invalid finding path: ${String(err).slice(0, 200)}`;
  }
}

async function runEngines(core: ActionsCore, config: ActionConfig): Promise<EngineResult[]> {
  core.info(
    `Engine concurrency: ${config.maxConcurrency} (spotbugs runs as a serial barrier)`,
  );
  return mapConcurrentWithBarriers(
    config.engines,
    config.maxConcurrency,
    (engine) => engine === "spotbugs",
    async (engine) => {
      core.info(`[${engine}] started`);
      const startedAt = Date.now();
      const result = await runEngine(
        engine,
        config.target,
        config.trivyImage,
        config.opengrepConfig,
      );
      normalizeEngineFindings(result, config.target);
      const elapsedSeconds = ((Date.now() - startedAt) / 1000).toFixed(1);
      core.info(
        `[${engine}] completed in ${elapsedSeconds}s: ${result.findings.length} findings ` +
          `(status=${result.status})`,
      );
      if (result.note) core.info(`[${engine}] note: ${result.note}`);
      return result;
    },
  );
}

function sortedFindings(engineResults: EngineResult[]): Finding[] {
  const findings = engineResults.flatMap((result) => result.findings);
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity] || a.engine.localeCompare(b.engine));
  return findings;
}

function writeReports(
  core: ActionsCore,
  config: ActionConfig,
  findings: Finding[],
  summary: string,
): { files: string[]; sarifPath: string } {
  const artifactFiles: string[] = [];
  let sarifPath = "";
  if (config.wantSarif) {
    sarifPath = path.join(config.outputDir, "polyscan.sarif");
    fs.writeFileSync(sarifPath, toSarif(findings));
    core.info(`Wrote SARIF: ${sarifPath}`);
    artifactFiles.push(sarifPath);
    core.setOutput("sarif-file", sarifPath);
  }

  if (config.wantSbom) {
    const sbomPath = path.join(config.outputDir, "polyscan.sbom.json");
    fs.writeFileSync(sbomPath, toSbom(config.target));
    core.info(`Wrote SBOM: ${sbomPath}`);
    artifactFiles.push(sbomPath);
    core.setOutput("sbom-file", sbomPath);
  }

  const summaryPath = path.join(config.outputDir, "polyscan-summary.md");
  fs.writeFileSync(summaryPath, summary);
  artifactFiles.push(summaryPath);
  return { files: artifactFiles, sarifPath };
}

async function publishSummary(core: ActionsCore, summary: string): Promise<void> {
  try {
    await core.summary.addRaw(summary).write();
  } catch (err) {
    core.warning(`could not write job summary: ${String(err).slice(0, 150)}`);
  }
}

async function uploadReports(core: ActionsCore, files: string[], outputDir: string): Promise<void> {
  try {
    const client = new DefaultArtifactClient();
    await client.uploadArtifact("polyscan-reports", files, outputDir, { retentionDays: 30 });
    core.info(`Uploaded ${files.length} report artifact(s).`);
  } catch (err) {
    core.warning(`artifact upload failed: ${String(err).slice(0, 200)}`);
  }
}

function setOutputs(
  core: ActionsCore,
  findings: Finding[],
  engineResults: EngineResult[],
  gatePassed: boolean,
): EngineResult[] {
  const counts = countBySeverity(findings);
  core.setOutput("total", String(counts.total));
  core.setOutput("critical", String(counts.critical));
  core.setOutput("high", String(counts.high));
  core.setOutput("medium", String(counts.medium));
  core.setOutput("low", String(counts.low));
  core.setOutput("info", String(counts.info));
  core.setOutput("gate-passed", String(gatePassed));
  const failedEngines = engineResults.filter((result) => result.status === "failed");
  core.setOutput("engines-passed", String(failedEngines.length === 0));
  core.setOutput("failed-engines", failedEngines.map((result) => result.engine).join(","));
  core.info(
    `Totals — critical:${counts.critical} high:${counts.high} medium:${counts.medium} low:${counts.low} total:${counts.total}`,
  );
  return failedEngines;
}

function enforceResults(
  core: ActionsCore,
  failedEngines: EngineResult[],
  failOnEngineError: boolean,
  gateEnforced: boolean,
  gate: ReturnType<typeof evaluateGate>,
): void {
  const failures: string[] = [];
  if (failOnEngineError && failedEngines.length > 0) {
    failures.push(`engines failed: ${failedEngines.map((result) => result.engine).join(", ")}`);
  } else if (failedEngines.length > 0) {
    core.warning(`Engine failures ignored: ${failedEngines.map((result) => result.engine).join(", ")}`);
  }
  if (gateEnforced && !gate.passed) {
    failures.push(`Quality Gate failed: ${gate.reasons.join(", ")}`);
  } else if (!gateEnforced && !gate.passed) {
    core.warning(`Quality Gate would have failed: ${gate.reasons.join(", ")} (not enforced)`);
  }

  if (failures.length > 0) {
    core.setFailed(failures.join("; "));
  } else {
    core.info("Quality Gate passed.");
  }
}

async function main(): Promise<void> {
  assertSupportedPlatform();
  const core = await getCore();
  const config = await readConfig(core);
  core.info(`PolyScan scanning "${config.target}" with engines: ${config.engines.join(", ")}`);

  const engineResults = await runEngines(core, config);
  const findings = sortedFindings(engineResults);
  const counts = countBySeverity(findings);
  const gate = evaluateGate(findings, config.gate);
  const summary = renderSummary(findings, counts, gate, config.gateEnforced, engineResults);

  await publishSummary(core, summary);
  const reports = writeReports(core, config, findings, summary);
  if (config.uploadArtifacts && reports.files.length > 0) {
    await uploadReports(core, reports.files, config.outputDir);
  }
  if (config.uploadSarif && reports.sarifPath) {
    core.info(
      "upload-sarif=true: use a follow-up 'github/codeql-action/upload-sarif' step " +
        `with sarif_file: ${reports.sarifPath} (needs security-events: write).`,
    );
  }

  const failedEngines = setOutputs(core, findings, engineResults, gate.passed);
  enforceResults(core, failedEngines, config.failOnEngineError, config.gateEnforced, gate);
}

main().catch(async (err) => {
  const core = await getCore();
  core.setFailed(`PolyScan crashed: ${err instanceof Error ? err.stack : String(err)}`);
});
