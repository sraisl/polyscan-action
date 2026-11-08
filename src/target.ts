import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export function workspaceRoot(): string {
  return fs.realpathSync(process.env.GITHUB_WORKSPACE || process.cwd());
}

function assertInsideWorkspace(candidate: string, label: string): void {
  const workspace = workspaceRoot();
  const relative = path.relative(workspace, candidate);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${label} must be inside GITHUB_WORKSPACE`);
  }
}

function resolveFromExistingAncestor(candidate: string): string {
  const missingSegments: string[] = [];
  let ancestor = candidate;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) break;
    missingSegments.unshift(path.basename(ancestor));
    ancestor = parent;
  }
  return path.resolve(fs.realpathSync(ancestor), ...missingSegments);
}

export function resolveTarget(target: string): string {
  const candidate = path.resolve(workspaceRoot(), target);
  if (!fs.existsSync(candidate)) throw new Error(`target does not exist: ${target}`);
  if (!fs.statSync(candidate).isDirectory()) throw new Error(`target is not a directory: ${target}`);

  const resolved = fs.realpathSync(candidate);
  assertInsideWorkspace(resolved, "target");
  return resolved;
}

export function resolveOutputDir(outputDir: string): string {
  const candidate = path.resolve(workspaceRoot(), outputDir);
  assertInsideWorkspace(candidate, "output-dir");
  assertInsideWorkspace(resolveFromExistingAncestor(candidate), "output-dir");
  fs.mkdirSync(candidate, { recursive: true });

  const resolved = fs.realpathSync(candidate);
  assertInsideWorkspace(resolved, "output-dir");
  return resolved;
}

export function normalizeFindingPath(file: string, target: string): string {
  let raw = file.trim();
  if (raw.startsWith("file://")) {
    try {
      raw = fileURLToPath(raw);
    } catch (err) {
      throw new Error(`invalid finding file URI "${file}": ${String(err)}`);
    }
  }

  const workspace = workspaceRoot();
  const resolvedTarget = fs.realpathSync(target);
  const targetRelative = path.relative(workspace, resolvedTarget);
  let absolute: string;
  if (path.isAbsolute(raw)) {
    absolute = resolveFromExistingAncestor(path.resolve(raw));
  } else {
    const normalizedRaw = path.normalize(raw);
    const alreadyWorkspaceRelative =
      targetRelative === "" ||
      normalizedRaw === targetRelative ||
      normalizedRaw.startsWith(`${targetRelative}${path.sep}`);
    absolute = resolveFromExistingAncestor(
      path.resolve(alreadyWorkspaceRelative ? workspace : resolvedTarget, normalizedRaw),
    );
  }

  assertInsideWorkspace(absolute, "finding path");
  return path.relative(workspace, absolute).split(path.sep).join("/");
}

// Report files land in a directory a pull request can populate, so a checked-in
// symlink named like a report would otherwise redirect the write to its target,
// possibly outside the workspace. O_NOFOLLOW refuses a symlink as the final path
// component; resolveOutputDir has already validated the directories above it.
export function writeReportFile(file: string, content: string): void {
  let fd: number;
  try {
    fd = fs.openSync(
      file,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW,
      0o644,
    );
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error(`refusing to write report through symlink: ${file}`);
    }
    throw err;
  }
  try {
    fs.writeFileSync(fd, content);
  } finally {
    fs.closeSync(fd);
  }
}
