// betterleaks engine adapter — secret / credential detection in git history + working tree.
// Downloads the betterleaks binary on demand and parses its JSON report.
//
// Unlike gitleaks, betterleaks' SARIF writer emits no per-result "level" at
// all (see report/sarif.go upstream — no Level field on Results), so there's
// no severity to read from SARIF. Its JSON report does carry a
// ValidationStatus per finding when a rule defines a `validate` block (an
// async check against the credential's own provider API, same idea as
// trufflehog's live verification), so JSON is used here and severity is
// derived from that field instead.
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";
import { resolveTarget } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, TOOLS } from "../tool-versions";

const BETTERLEAKS = TOOLS.betterleaks;

// A "valid" status means the secret was confirmed live against its own
// provider API — a confirmed active breach, so it maps to critical, the same
// treatment trufflehog gives a verified secret. "invalid"/"revoked" secrets
// are pattern matches known not to work, so they're downgraded to low rather
// than dropped outright. Everything else (no validation performed, or an
// indeterminate/errored validation attempt) defaults to high.
function mapSeverity(validationStatus: string): Severity {
  switch ((validationStatus || "").toLowerCase()) {
    case "valid":
      return "critical";
    case "invalid":
    case "revoked":
      return "low";
    default:
      return "high";
  }
}

interface BetterleaksFinding {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  ValidationStatus?: string;
}

export function parseBetterleaksJson(report: unknown, abs: string): Finding[] {
  const findings: Finding[] = [];
  for (const raw of (report as unknown[] | null) ?? []) {
    const f = raw as BetterleaksFinding;
    const ruleId = f.RuleID ?? "betterleaks";
    const file = f.File ?? "unknown";
    findings.push({
      engine: "betterleaks",
      ruleId,
      severity: mapSeverity(f.ValidationStatus ?? ""),
      message: f.Description ?? ruleId,
      file: file.replace(abs + "/", ""),
      line: f.StartLine ?? 0,
    });
  }
  return findings;
}

export async function runBetterleaks(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-betterleaks-"));
  try {
    const bin = await ensureBetterleaks();
    if (!bin) {
      return { engine: "betterleaks", findings: [], status: "failed", note: "betterleaks not installed" };
    }

    const reportOut = path.join(workdir, "betterleaks.json");
    const res = await run(
      bin,
      [
        "dir",
        abs,
        "--report-path",
        reportOut,
        "--report-format",
        "json",
        "--no-banner",
        "--redact",
      ],
      { cwd: abs },
    );

    if (!fs.existsSync(reportOut)) {
      return {
        engine: "betterleaks",
        findings: [],
        status: "failed",
        note: `betterleaks produced no report (exit ${res.exitCode})`,
      };
    }

    try {
      const report = JSON.parse(fs.readFileSync(reportOut, "utf-8"));
      return { engine: "betterleaks", findings: parseBetterleaksJson(report, abs), status: "success" };
    } catch (err) {
      return {
        engine: "betterleaks",
        findings: [],
        status: "failed",
        note: `parse error: ${String(err).slice(0, 200)}`,
      };
    }
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}

async function ensureBetterleaks(): Promise<string | null> {
  if (await which("betterleaks")) return "betterleaks";
  core.info(`betterleaks not found — downloading v${BETTERLEAKS.version}…`);
  try {
    return await cachedTool("betterleaks", BETTERLEAKS.version, "betterleaks", async (directory) => {
      const archive = await downloadVerified(githubReleaseUrl(BETTERLEAKS), BETTERLEAKS.sha256);
      await tc.extractTar(archive, directory);
      fs.chmodSync(path.join(directory, "betterleaks"), 0o700);
    });
  } catch (err) {
    core.warning(`betterleaks download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}
