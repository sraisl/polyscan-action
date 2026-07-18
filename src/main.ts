// PolyScan GitHub Action — entry point.
import * as core from "@actions/core";
import * as fs from "fs";
import * as path from "path";
import { DefaultArtifactClient } from "@actions/artifact";

import { Finding, EngineResult, countBySeverity } from "./schema";
import { runSemgrep } from "./engines/semgrep";
import { runBandit } from "./engines/bandit";
import { runEslint } from "./engines/eslint";
import { runSpotbugs } from "./engines/spotbugs";
import { runTrivy } from "./engines/trivy";
import { evaluateGate } from "./gate";
import { toSarif } from "./sarif";
import { toSbom } from "./sbom";
import { renderSummary } from "./summary";

function boolInput(name: string, def: boolean): boolean {
  const raw = core.getInput(name);
  if (raw === "") return def;
  return raw.toLowerCase() === "true";
}

function intInput(name: string, def: number): number {
  const raw = core.getInput(name);
  if (raw === "") return def;
  const n = parseInt(raw, 10);
  return Number.isNaN(n) ? def : n;
}

async function runEngine(name: string, target: string): Promise<EngineResult> {
  try {
    switch (name) {
      case "semgrep":
        return await runSemgrep(target);
      case "bandit":
        return await runBandit(target);
      case "eslint":
        return await runEslint(target);
      case "spotbugs":
        return await runSpotbugs(target);
      case "trivy":
        return await runTrivy(target);
      default:
        return { engine: name, findings: [], available: false, note: "unknown engine" };
    }
  } catch (err) {
    return {
      engine: name,
      findings: [],
      available: false,
      note: `engine crashed: ${String(err).slice(0, 200)}`,
    };
  }
}

async function main(): Promise<void> {
  const target = core.getInput("target") || ".";
  const engines = (core.getInput("engines") || "semgrep,bandit,eslint")
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);

  const gateEnforced = boolInput("gate", true);
  const wantSarif = boolInput("sarif", true);
  const wantSbom = boolInput("sbom", false);
  const uploadArtifacts = boolInput("upload-artifacts", true);
  const uploadSarif = boolInput("upload-sarif", false);
  const outputDir = core.getInput("output-dir") || ".";

  const gateCfg = {
    maxCritical: intInput("max-critical", 0),
    maxHigh: intInput("max-high", 0),
    maxMedium: intInput("max-medium", 50),
  };

  core.info(`PolyScan scanning "${target}" with engines: ${engines.join(", ")}`);

  // Run engines sequentially (they install tools; parallel would race on pip/npm).
  const engineResults: EngineResult[] = [];
  for (const e of engines) {
    core.startGroup(`Engine: ${e}`);
    const res = await runEngine(e, target);
    core.info(`${e}: ${res.findings.length} findings (available=${res.available})`);
    if (res.note) core.info(`note: ${res.note}`);
    core.endGroup();
    engineResults.push(res);
  }

  const findings: Finding[] = engineResults.flatMap((r) => r.findings);
  // Sort by severity rank then engine.
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity] || a.engine.localeCompare(b.engine));

  const counts = countBySeverity(findings);
  const gate = evaluateGate(findings, gateCfg);

  fs.mkdirSync(path.resolve(outputDir), { recursive: true });
  const artifactFiles: string[] = [];

  // SARIF
  let sarifPath = "";
  if (wantSarif) {
    sarifPath = path.join(outputDir, "polyscan.sarif");
    fs.writeFileSync(sarifPath, toSarif(findings));
    core.info(`Wrote SARIF: ${sarifPath}`);
    artifactFiles.push(sarifPath);
    core.setOutput("sarif-file", sarifPath);
  }

  // SBOM
  let sbomPath = "";
  if (wantSbom) {
    sbomPath = path.join(outputDir, "polyscan.sbom.json");
    fs.writeFileSync(sbomPath, toSbom(target));
    core.info(`Wrote SBOM: ${sbomPath}`);
    artifactFiles.push(sbomPath);
    core.setOutput("sbom-file", sbomPath);
  }

  // Job summary
  const summaryMd = renderSummary(findings, counts, gate, gateEnforced, engineResults);
  try {
    await core.summary.addRaw(summaryMd).write();
  } catch (err) {
    core.warning(`could not write job summary: ${String(err).slice(0, 150)}`);
  }
  // Also emit a summary file for consumers who want it as an artifact.
  const summaryPath = path.join(outputDir, "polyscan-summary.md");
  fs.writeFileSync(summaryPath, summaryMd);
  artifactFiles.push(summaryPath);

  // Upload artifacts
  if (uploadArtifacts && artifactFiles.length > 0) {
    try {
      const client = new DefaultArtifactClient();
      await client.uploadArtifact("polyscan-reports", artifactFiles, outputDir, {
        retentionDays: 30,
      });
      core.info(`Uploaded ${artifactFiles.length} report artifact(s).`);
    } catch (err) {
      core.warning(`artifact upload failed: ${String(err).slice(0, 200)}`);
    }
  }

  // Upload SARIF to code scanning (delegated hint — actual upload via separate step
  // is recommended, but we support it if the CodeQL upload tool is present).
  if (uploadSarif && sarifPath) {
    core.info(
      "upload-sarif=true: use a follow-up 'github/codeql-action/upload-sarif' step " +
        `with sarif_file: ${sarifPath} (needs security-events: write).`,
    );
  }

  // Outputs
  core.setOutput("total", String(counts.total));
  core.setOutput("critical", String(counts.critical));
  core.setOutput("high", String(counts.high));
  core.setOutput("medium", String(counts.medium));
  core.setOutput("low", String(counts.low));
  core.setOutput("gate-passed", String(gate.passed));

  core.info(
    `Totals — critical:${counts.critical} high:${counts.high} medium:${counts.medium} low:${counts.low} total:${counts.total}`,
  );

  if (gateEnforced && !gate.passed) {
    core.setFailed(`Quality Gate failed: ${gate.reasons.join(", ")}`);
  } else if (!gateEnforced && !gate.passed) {
    core.warning(`Quality Gate would have failed: ${gate.reasons.join(", ")} (not enforced)`);
  } else {
    core.info("Quality Gate passed.");
  }
}

main().catch((err) => {
  core.setFailed(`PolyScan crashed: ${err instanceof Error ? err.stack : String(err)}`);
});
