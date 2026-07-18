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
