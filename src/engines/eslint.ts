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

export async function runEslint(target: string): Promise<EngineResult> {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-eslint-"));
  // Install eslint 8 locally (flat-config capable, no plugin resolution headaches).
  core.info("Installing eslint@8 …");
  const install = await run("bash", [
    "-lc",
    `cd ${workdir} && npm init -y >/dev/null 2>&1 && npm install --no-audit --no-fund --silent eslint@8 >/dev/null 2>&1`,
  ]);
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
  const res = await run("bash", [
    "-lc",
    `cd "${absTarget}" && ESLINT_USE_FLAT_CONFIG=true ${workdir}/node_modules/.bin/eslint --config ${configPath} --no-ignore -f json . || true`,
  ]);

  if (!res.stdout.trim()) {
    return { engine: "eslint", findings: [], available: true, note: res.stderr.slice(0, 200) };
  }

  const findings: Finding[] = [];
  try {
    const data = JSON.parse(res.stdout);
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
