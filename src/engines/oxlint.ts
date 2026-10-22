// oxlint engine adapter for JS/TS security-relevant rules.
// Downloads the pinned standalone binary, runs a minimal security rule set and parses
// oxlint's JSON report. Unlike the ESLint adapter it parses TypeScript/JSX natively.
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

const OXLINT = TOOLS.oxlint;
const IGNORED_DIRECTORIES = new Set([".git", "node_modules", "vendor", "build", "dist", "target", ".gradle"]);
const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);

// Every default category is switched off so only the explicit security rules run.
// react/jsx-no-script-url is left out on purpose: no-script-url already reports the same
// `javascript:` URL, and enabling both would count one issue twice in the Quality Gate.
const CONFIG = {
  plugins: ["react"],
  categories: {
    correctness: "off",
    suspicious: "off",
    pedantic: "off",
    perf: "off",
    style: "off",
    restriction: "off",
    nursery: "off",
  },
  rules: {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error",
    "react/no-danger": "warn",
  },
};

export function hasJsSources(root: string): boolean {
  function walk(directory: string): boolean {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name) && walk(path.join(directory, entry.name))) return true;
      } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  return walk(root);
}

// oxlint reports "error" / "warning" / "advice".
function mapSeverity(severity: string): Severity {
  switch ((severity || "").toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    default:
      return "low";
  }
}

// oxlint codes look like "eslint(no-eval)" or "react(no-danger)"; report them the way the
// rules are configured: core rules bare, plugin rules as "<plugin>/<rule>".
export function oxlintRuleId(code: string): string {
  const match = /^([^()]+)\((.+)\)$/.exec(code.trim());
  if (!match) return code.trim();
  const plugin = match[1].replace(/^eslint-plugin-/, "");
  return plugin === "eslint" ? match[2] : `${plugin}/${match[2]}`;
}

export interface OxlintReport {
  findings: Finding[];
  // Files oxlint could not parse. Their diagnostics carry no rule code.
  parseErrorFiles: string[];
}

export function parseOxlintJson(stdout: string): OxlintReport {
  const data = JSON.parse(stdout) as { diagnostics?: unknown };
  if (!Array.isArray(data.diagnostics)) throw new Error("oxlint report has no diagnostics array");

  const findings: Finding[] = [];
  const parseErrorFiles = new Set<string>();
  for (const d of data.diagnostics) {
    const diagnostic = d as {
      code?: string;
      severity?: string;
      message?: string;
      url?: string;
      filename?: string;
      labels?: { span?: { line?: number; column?: number } }[];
    };
    const file = diagnostic.filename ?? "unknown";
    if (!diagnostic.code) {
      parseErrorFiles.add(file);
      continue;
    }
    const ruleId = oxlintRuleId(diagnostic.code);
    const span = diagnostic.labels?.[0]?.span;
    findings.push({
      engine: "oxlint",
      ruleId,
      severity: mapSeverity(diagnostic.severity ?? ""),
      message: diagnostic.message ?? ruleId,
      file,
      line: span?.line ?? 0,
      column: span?.column,
      ...(diagnostic.url ? { url: diagnostic.url } : {}),
    });
  }
  return { findings, parseErrorFiles: [...parseErrorFiles].sort() };
}

async function ensureOxlint(): Promise<string | null> {
  if (await which("oxlint")) return "oxlint";
  core.info(`oxlint not found — downloading v${OXLINT.version}…`);
  try {
    return await cachedTool("oxlint", OXLINT.version, "oxlint", async (directory) => {
      const archive = await downloadVerified(githubReleaseUrl(OXLINT), OXLINT.sha256);
      await tc.extractTar(archive, directory);
      // The archive holds a single binary named like the asset, e.g. oxlint-x86_64-unknown-linux-gnu.
      const packaged = OXLINT.assetTemplate.replace(/\.tar\.gz$/, "");
      fs.renameSync(path.join(directory, packaged), path.join(directory, "oxlint"));
      fs.chmodSync(path.join(directory, "oxlint"), 0o700);
    });
  } catch (err) {
    core.warning(`oxlint download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

export async function runOxlint(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  if (!hasJsSources(abs)) {
    return { engine: "oxlint", findings: [], status: "skipped", note: "no JavaScript/TypeScript files found" };
  }

  const bin = await ensureOxlint();
  if (!bin) {
    return { engine: "oxlint", findings: [], status: "failed", note: "oxlint not installed" };
  }

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-oxlint-"));
  try {
    const configPath = path.join(workdir, "oxlintrc.json");
    fs.writeFileSync(configPath, JSON.stringify(CONFIG));

    // Nested project configs are disabled so a repository cannot switch the security rules off.
    const res = await run(
      bin,
      ["--config", configPath, "--disable-nested-config", "--no-ignore", "--format", "json", "."],
      { cwd: abs },
    );
    // oxlint exits 1 when it reports findings.
    if (res.exitCode > 1 || !res.stdout.trim()) {
      return {
        engine: "oxlint",
        findings: [],
        status: "failed",
        note: (res.stderr || res.stdout).slice(0, 200) || `oxlint exited ${res.exitCode}`,
      };
    }

    let report: OxlintReport;
    try {
      report = parseOxlintJson(res.stdout);
    } catch (err) {
      return {
        engine: "oxlint",
        findings: [],
        status: "failed",
        note: `parse error: ${String(err).slice(0, 200)}`,
      };
    }

    const unparsed = report.parseErrorFiles;
    return {
      engine: "oxlint",
      findings: report.findings,
      status: "success",
      ...(unparsed.length > 0
        ? {
            note: `${unparsed.length} file(s) could not be parsed and were not scanned: ${unparsed.slice(0, 5).join(", ")}`,
          }
        : {}),
    };
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}
