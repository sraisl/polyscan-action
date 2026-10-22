// oxlint engine adapter for JS/TS security-relevant rules.
// Downloads the pinned standalone binary, runs a minimal security rule set and parses
// oxlint's JSON report. Unlike the ESLint adapter it parses TypeScript/JSX natively.
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { run, resolvePinnedExecutable } from "../exec";
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

export function collectJsSources(root: string): string[] {
  const files: string[] = [];
  function walk(directory: string): void {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) walk(path.join(directory, entry.name));
      } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        files.push(path.resolve(directory, entry.name));
      }
    }
  }

  walk(root);
  return files.sort();
}

export function hasJsSources(root: string): boolean {
  return collectJsSources(root).length > 0;
}

// oxlint 1.89.0 silently drops explicit paths it does not consider lintable (apps/oxlint/src/walk.rs):
// names containing ".min.", "-min." or "_min.", and extensions that are not an exact lowercase match.
export function isOxlintLintable(file: string): boolean {
  const name = path.basename(file);
  if ([".min.", "-min.", "_min."].some((marker) => name.includes(marker))) return false;
  return SOURCE_EXTENSIONS.has(path.extname(name));
}

// oxlint's parallel workers emit diagnostics in completion order.
function compareFindings(a: Finding, b: Finding): number {
  return (
    a.file.localeCompare(b.file) ||
    a.line - b.line ||
    (a.column ?? 0) - (b.column ?? 0) ||
    a.ruleId.localeCompare(b.ruleId) ||
    a.message.localeCompare(b.message)
  );
}

function fileList(label: string, files: readonly string[], root: string): string {
  const shown = files.slice(0, 5).map((file) => path.relative(root, file).split(path.sep).join("/"));
  return `${files.length} file(s) ${label}: ${shown.join(", ")}${files.length > 5 ? ", …" : ""}`;
}

// Leave ample room for the inherited environment and argv pointers on runners.
export function oxlintBatches(files: readonly string[], flags: readonly string[]): string[][] {
  const limit = 32 * 1024;
  const base = flags.reduce((bytes, arg) => bytes + Buffer.byteLength(arg) + 1, 0);
  const batches: string[][] = [];
  let batch: string[] = [];
  let bytes = base;
  for (const file of files) {
    const size = Buffer.byteLength(file) + 1;
    if (base + size > limit) throw new Error("oxlint source path exceeds argument budget");
    if (bytes + size > limit) {
      batches.push(batch);
      batch = [];
      bytes = base;
    }
    batch.push(file);
    bytes += size;
  }
  if (batch.length) batches.push(batch);
  return batches;
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
  const pinned = await resolvePinnedExecutable("oxlint", OXLINT.version);
  if (pinned) return pinned;
  core.info(`oxlint v${OXLINT.version} not found on PATH — using verified cache/download…`);
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
  const files = collectJsSources(abs);
  if (files.length === 0) {
    return { engine: "oxlint", findings: [], status: "skipped", note: "no JavaScript/TypeScript files found" };
  }

  const bin = await ensureOxlint();
  if (!bin) {
    return { engine: "oxlint", findings: [], status: "failed", note: "oxlint not installed" };
  }

  const lintable = files.filter(isOxlintLintable);
  const unsupported = files.filter((file) => !isOxlintLintable(file));
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-oxlint-"));
  try {
    const configPath = path.join(workdir, "oxlintrc.json");
    fs.writeFileSync(configPath, JSON.stringify(CONFIG));

    // Nested project configs are disabled so a repository cannot switch the security rules off.
    // oxlint runs from the private workdir, never the target: it loads oxlint-suppressions.json
    // from its working directory, which would let a scanned repository hide findings. Running
    // elsewhere also makes it report absolute filenames, which normalizeFindingPath resolves
    // unambiguously (a target-relative "src/app.ts" under target "src" reads as workspace-relative).
    const flags = ["--config", configPath, "--disable-nested-config", "--no-ignore", "--format", "json", "--"];
    const findings: Finding[] = [];
    const parseErrorFiles = new Set<string>();
    for (const batch of oxlintBatches(lintable, flags)) {
      const res = await run(bin, [...flags, ...batch], { cwd: workdir });
      // oxlint exits 1 when it reports findings.
      if (![0, 1].includes(res.exitCode) || !res.stdout.trim()) {
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

      findings.push(...report.findings);
      for (const file of report.parseErrorFiles) parseErrorFiles.add(file);
    }
    const notes = [
      ...(parseErrorFiles.size > 0
        ? [fileList("could not be parsed and were not scanned", [...parseErrorFiles].sort(), abs)]
        : []),
      ...(unsupported.length > 0 ? [fileList("not supported by oxlint and not scanned", unsupported, abs)] : []),
    ];
    return {
      engine: "oxlint",
      findings: findings.sort(compareFindings),
      status: "success",
      ...(notes.length > 0 ? { note: notes.join("; ") } : {}),
    };
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}
