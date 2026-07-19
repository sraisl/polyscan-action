// ESLint engine adapter for JS/TS security-relevant rules.
// Uses a minimal flat config with no-eval / no-implied-eval and scans *.js/*.ts.
import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Finding, EngineResult, Severity } from "../schema";
import { run } from "../exec";

function mapSeverity(sev: number): Severity {
  // ESLint: 2 = error, 1 = warning
  return sev === 2 ? "high" : "medium";
}

const FLAT_CONFIG = `
module.exports = [
  {
    files: ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error"
    }
  }
];
`;

export function parseEslintJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  const data = JSON.parse(stdout);
  for (const file of data) {
    for (const m of file.messages ?? []) {
      if (!m.ruleId) continue; // parse errors etc.
      findings.push({
        engine: "eslint",
        ruleId: m.ruleId,
        severity: mapSeverity(m.severity),
        message: m.message,
        file: file.filePath,
        line: m.line ?? 0,
        column: m.column,
      });
    }
  }
  return findings;
}

export async function runEslint(target: string): Promise<EngineResult> {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-eslint-"));
  // Install eslint 8 locally (flat-config capable, no plugin resolution headaches).
  core.info("Installing eslint@8 …");
  const init = await run("npm", ["init", "-y"], { cwd: workdir });
  const install =
    init.exitCode === 0
      ? await run("npm", ["install", "--no-audit", "--no-fund", "--silent", "eslint@8"], {
          cwd: workdir,
        })
      : init;
  if (install.exitCode !== 0) {
    return {
      engine: "eslint",
      findings: [],
      available: false,
      note: `eslint install failed: ${install.stderr.slice(0, 200)}`,
    };
  }

  const configPath = path.join(workdir, "eslint.config.cjs");
  fs.writeFileSync(configPath, FLAT_CONFIG);

  const absTarget = path.resolve(target);
  const eslintBin = path.join(workdir, "node_modules", ".bin", "eslint");
  const res = await run(
    eslintBin,
    ["--config", configPath, "--no-ignore", "-f", "json", "."],
    { cwd: absTarget, env: { ESLINT_USE_FLAT_CONFIG: "true" } },
  );

  if (!res.stdout.trim()) {
    return { engine: "eslint", findings: [], available: true, note: res.stderr.slice(0, 200) };
  }

  let findings: Finding[];
  try {
    findings = parseEslintJson(res.stdout);
  } catch (err) {
    return {
      engine: "eslint",
      findings: [],
      available: true,
      note: `parse error: ${String(err).slice(0, 200)}`,
    };
  }

  return { engine: "eslint", findings, available: true };
}
