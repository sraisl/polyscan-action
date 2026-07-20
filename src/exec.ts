// Shared helper to run an external command and capture stdout/stderr,
// tolerating non-zero exit codes (linters exit non-zero when they find issues).
import * as exec from "@actions/exec";

export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export async function run(
  command: string,
  args: string[],
  options: { cwd?: string; env?: { [key: string]: string } } = {},
): Promise<RunResult> {
  let stdout = "";
  let stderr = "";
  let exitCode = 0;
  const mergedEnv: { [key: string]: string } = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) mergedEnv[k] = v;
  }
  if (options.env) Object.assign(mergedEnv, options.env);
  try {
    exitCode = await exec.exec(command, args, {
      cwd: options.cwd,
      env: mergedEnv,
      ignoreReturnCode: true,
      silent: true,
      listeners: {
        stdout: (data: Buffer) => {
          stdout += data.toString();
        },
        stderr: (data: Buffer) => {
          stderr += data.toString();
        },
      },
    });
  } catch (err) {
    return { exitCode: 127, stdout, stderr: String(err) };
  }
  return { exitCode, stdout, stderr };
}

// Check whether a binary is available on PATH.
export async function which(tool: string): Promise<boolean> {
  const res = await run("bash", ["-lc", `command -v ${tool} >/dev/null 2>&1`]);
  return res.exitCode === 0;
}

// Install a Python CLI tool robustly on any runner.
//
// Newer distros (PEP 668) mark Python as "externally-managed", so a bare
// `pip install <tool>` fails with "error: externally-managed-environment".
// We try escalating fallbacks:
//   1. `pip install --user`                  (preferred, no system mutation)
//   2. `pip install --break-system-packages` (self-hosted runners, PEP 668)
//   3. a local venv in /tmp                   (last resort)
// Returns true if the tool ends up on PATH (also exports ~/.local/bin).
export async function ensurePythonTool(
  tool: string,
  label: string,
  core: { info: (s: string) => void; warning: (s: string) => void },
): Promise<boolean> {
  if (await which(tool)) return true;
  core.info(`${label} not found — installing via pip…`);
  const script = [
    "set -e",
    "PIP=$(command -v pip || command -v pip3 || true)",
    'if [ -z "$PIP" ]; then echo "no pip available"; exit 1; fi',
    'if [ -n "$VIRTUAL_ENV" ]; then "$PIP" install --quiet ' + tool + "; exit 0; fi",
    'if "$PIP" install --user --quiet ' + tool + " 2>/dev/null; then echo installed-user; exit 0; fi",
    'if "$PIP" install --break-system-packages --quiet ' + tool + " 2>/dev/null; then echo installed-break; exit 0; fi",
    "python3 -m venv /tmp/polyscan-pyvenv && /tmp/polyscan-pyvenv/bin/pip install --quiet " + tool,
  ].join("\n");
  const res = await run("bash", ["-lc", script]);
  if (res.exitCode !== 0) {
    core.warning(`${label} install failed: ${res.stderr.slice(0, 300)}`);
    return false;
  }
  // Ensure ~/.local/bin (used by --user installs) is on PATH for later steps.
  const home = process.env.HOME ?? "";
  if (home) process.env.PATH = `${home}/.local/bin:${process.env.PATH ?? ""}`;
  return which(tool);
}
