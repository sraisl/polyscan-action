// Shared helper to run an external command and capture stdout/stderr,
// tolerating non-zero exit codes (linters exit non-zero when they find issues).
import * as childProcess from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

// Spawning a binary that another tool install has just written can fail with ETXTBSY
// while a concurrently forked child still holds the inherited write descriptor.
// The window closes within milliseconds, so the spawn is retried.
const SPAWN_RETRY_ATTEMPTS = 5;
const SPAWN_RETRY_DELAY_MS = 100;

function isTextBusy(err: unknown): boolean {
  return (err as NodeJS.ErrnoException | null)?.code === "ETXTBSY";
}

// child_process.spawn is used directly instead of @actions/exec: @actions/exec spawns
// inside an async Promise executor, so a synchronous spawn failure such as ETXTBSY
// becomes an unhandled rejection that crashes the action instead of reaching a caller.
function spawnOnce(
  command: string,
  args: string[],
  options: { cwd?: string; env: { [key: string]: string } },
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let child: childProcess.ChildProcess;
    try {
      child = childProcess.spawn(command, args, {
        cwd: options.cwd,
        env: options.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      reject(err);
      return;
    }
    child.stdout?.setEncoding("utf8").on("data", (data: string) => {
      stdout += data;
    });
    child.stderr?.setEncoding("utf8").on("data", (data: string) => {
      stderr += data;
    });
    child.once("error", reject);
    child.once("close", (code, signal) => {
      resolve({ exitCode: code ?? 128, stdout, stderr: signal ? `${stderr}killed by ${signal}` : stderr });
    });
  });
}

export async function run(
  command: string,
  args: string[],
  options: { cwd?: string; env?: { [key: string]: string } } = {},
): Promise<RunResult> {
  const mergedEnv: { [key: string]: string } = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) mergedEnv[k] = v;
  }
  if (options.env) Object.assign(mergedEnv, options.env);
  for (let attempt = 1; ; attempt++) {
    try {
      return await spawnOnce(command, args, { cwd: options.cwd, env: mergedEnv });
    } catch (err) {
      if (!isTextBusy(err) || attempt === SPAWN_RETRY_ATTEMPTS) {
        return { exitCode: 127, stdout: "", stderr: String(err) };
      }
      await new Promise((resolve) => setTimeout(resolve, SPAWN_RETRY_DELAY_MS * attempt));
    }
  }
}

// Resolve against the same PATH inherited by direct child processes. A login
// shell may source profile files and report tools that @actions/exec cannot see.
export function resolveExecutable(
  tool: string,
  searchPath: string = process.env.PATH ?? "",
): string | null {
  const candidates = tool.includes(path.sep)
    ? [path.resolve(tool)]
    : searchPath.split(path.delimiter).map((directory) => path.resolve(directory || ".", tool));

  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // Continue searching PATH.
    }
  }
  return null;
}

export async function resolvePinnedExecutable(
  tool: string,
  expectedVersion: string,
  versionArgs: string[] = ["--version"],
  searchPath: string = process.env.PATH ?? "",
): Promise<string | null> {
  const executable = resolveExecutable(tool, searchPath);
  if (!executable) return null;

  const result = await run(executable, versionArgs);
  if (result.exitCode !== 0) return null;
  // Tools report the version either bare ("1.180.0") or prefixed with their own
  // name ("bandit 1.9.4") or oxlint's "Version: 1.89.0" label. Allow at most one leading token on the first
  // line so a version number printed elsewhere in a banner cannot pass for the
  // pinned release.
  const firstLine = result.stdout.trim().split(/\r?\n/, 1)[0] ?? "";
  const match = /^(?:(?:[A-Za-z][\w.+-]*|Version:)\s+)?v?(\d+(?:\.\d+)+)(?:\s|$)/.exec(firstLine);
  return match?.[1] === expectedVersion ? executable : null;
}

// Check whether a binary is available to direct child processes.
export async function which(tool: string): Promise<boolean> {
  return resolveExecutable(tool) !== null;
}

export interface PreparedTool {
  executable: string;
  cleanup: () => void;
}

// Python virtual environments contain absolute shebangs and cannot be moved
// into the tool cache. Keep the isolated environment alive for exactly one scan.
export async function ensurePythonTool(
  tool: string,
  version: string,
  label: string,
  core: { info: (s: string) => void; warning: (s: string) => void },
): Promise<PreparedTool | null> {
  // A preinstalled binary is only reusable when it reports the version pinned in
  // tools.lock.json. Otherwise install the pinned release in an isolated
  // environment, keeping scanner behavior reproducible across runners.
  if (resolveExecutable(tool)) {
    const pinned = await resolvePinnedExecutable(tool, version);
    if (pinned) {
      return { executable: pinned, cleanup: () => undefined };
    }
    core.warning(`Ignoring ${label} from PATH because it is not the pinned version ${version}`);
  }

  core.info(`${label} not found — installing ${tool}==${version} in an isolated environment…`);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `polyscan-${tool}-`));
  try {
    const venv = path.join(directory, "venv");
    const create = await run("python3", ["-m", "venv", venv]);
    if (create.exitCode !== 0) throw new Error(create.stderr || "could not create Python venv");
    const install = await run(path.join(venv, "bin", "pip"), [
      "install",
      "--quiet",
      `${tool}==${version}`,
    ]);
    if (install.exitCode !== 0) throw new Error(install.stderr || "pip install failed");
    const executable = path.join(venv, "bin", tool);
    if (!fs.existsSync(executable)) throw new Error(`${tool} executable missing after install`);
    return {
      executable,
      cleanup: () => fs.rmSync(directory, { recursive: true, force: true }),
    };
  } catch (err) {
    fs.rmSync(directory, { recursive: true, force: true });
    core.warning(`${label} install failed: ${String(err).slice(0, 300)}`);
    return null;
  }
}
