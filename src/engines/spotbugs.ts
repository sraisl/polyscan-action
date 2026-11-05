// SpotBugs + FindSecBugs engine adapter for Java/Kotlin.
// Compiles .java sources, downloads SpotBugs+FindSecBugs on demand, parses XML.
import * as core from "@actions/core";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";
import { resolveTarget, workspaceRoot } from "../target";
import { cachedTool, downloadVerified } from "../tools";
import { githubReleaseUrl, mavenArtifactUrl, TOOLS } from "../tool-versions";

const SPOTBUGS = TOOLS.spotbugs;
const FINDSECBUGS = TOOLS.findsecbugs;
const KOTLIN = TOOLS.kotlin;
const SPOTBUGS_VERSION = SPOTBUGS.version;
const SPOTBUGS_URL = githubReleaseUrl(SPOTBUGS);
const SPOTBUGS_SHA256 = SPOTBUGS.sha256;
const FINDSECBUGS_VERSION = FINDSECBUGS.version;
const FINDSECBUGS_URL = mavenArtifactUrl(FINDSECBUGS);
const FINDSECBUGS_SHA256 = FINDSECBUGS.sha256;
const KOTLIN_VERSION = KOTLIN.version;
const KOTLIN_SHA256 = KOTLIN.sha256;

// FindSecBugs bug patterns considered high severity (security-critical).
const HIGH_PATTERNS = new Set([
  "SQL_INJECTION_JDBC",
  "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE",
  "COMMAND_INJECTION",
  "PATH_TRAVERSAL_IN",
  "XXE_SAXPARSER",
  "LDAP_INJECTION",
  "XPATH_INJECTION",
]);

function mapSeverity(type: string, priority: string): Severity {
  if (HIGH_PATTERNS.has(type)) return "high";
  const p = Number.parseInt(priority, 10);
  if (p === 1) return "high";
  if (p === 2) return "medium";
  return "low";
}

function findSourceFiles(dir: string, ext: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "target" || entry.name === "build") continue;
        walk(full);
      } else if (entry.name.endsWith(ext)) {
        out.push(full);
      }
    }
  };
  walk(dir);
  return out;
}

function findJavaFiles(dir: string): string[] {
  return findSourceFiles(dir, ".java");
}

function findKotlinFiles(dir: string): string[] {
  return findSourceFiles(dir, ".kt");
}

const CLASS_DIR_CANDIDATES = [
  "target/classes", // Maven
  "build/classes/kotlin/main", // Gradle Kotlin
  "build/classes/java/main", // Gradle Java
  "out/production/classes", // IntelliJ
];
const SKIPPED_DIRS = new Set(["node_modules", ".git", "target", "build", "out"]);

function hasBuildFile(dir: string): boolean {
  return ["pom.xml", "build.gradle", "build.gradle.kts"].some((f) => fs.existsSync(path.join(dir, f)));
}

function listSubdirs(dir: string): string[] {
  try {
    return fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.isSymbolicLink() && e.name !== "node_modules" && e.name !== ".git")
      .map((e) => path.join(dir, e.name))
      .sort();
  } catch {
    return [];
  }
}

function classDirsOf(dir: string): string[] {
  const found: string[] = [];
  for (const c of CLASS_DIR_CANDIDATES) {
    const p = path.join(dir, c);
    try {
      if (fs.statSync(p).isDirectory() && fs.readdirSync(p).length > 0) found.push(p);
    } catch {
      // not present
    }
  }
  return found;
}

// Finds compiled class directories in dir and in any module directories below it.
export function findClassDirs(dir: string): string[] {
  const found: string[] = [];
  const walk = (d: string) => {
    found.push(...classDirsOf(d));
    for (const sub of listSubdirs(d)) {
      if (SKIPPED_DIRS.has(path.basename(sub))) continue;
      walk(sub);
    }
  };
  walk(dir);
  return found;
}

// Finds directories to build: the target itself, or the top-most module directories below it.
export function findModuleDirs(abs: string): string[] {
  if (hasBuildFile(abs)) return [abs];
  const modules: string[] = [];
  const walk = (d: string) => {
    for (const sub of listSubdirs(d)) {
      if (SKIPPED_DIRS.has(path.basename(sub))) continue;
      if (hasBuildFile(sub)) modules.push(sub);
      else walk(sub);
    }
  };
  walk(abs);
  return modules;
}

// Searches dir and its parents (up to the workspace root) for a wrapper script.
export function findWrapper(dir: string, name: string): string {
  const root = workspaceRoot();
  let cur = dir;
  for (;;) {
    const candidate = path.join(cur, name);
    if (fs.existsSync(candidate)) return candidate;
    if (cur === root || path.dirname(cur) === cur) return "";
    cur = path.dirname(cur);
    const rel = path.relative(root, cur);
    if (rel.startsWith("..") || path.isAbsolute(rel)) return "";
  }
}

async function tryProjectBuild(
  abs: string,
  noteParts: string[],
): Promise<string[]> {
  // Reuse already compiled classes (e.g. from a previous build step) before building.
  const existing = findClassDirs(abs);
  if (existing.length > 0) return existing;

  const classDirs: string[] = [];
  for (const moduleDir of findModuleDirs(abs)) {
    const mavenClasses = await tryMavenBuild(moduleDir, noteParts);
    classDirs.push(...(mavenClasses.length > 0 ? mavenClasses : await tryGradleBuild(moduleDir, noteParts)));
  }
  return classDirs;
}

async function mavenCommand(abs: string): Promise<string> {
  const mvnw = findWrapper(abs, "mvnw");
  if (mvnw) return mvnw;
  return (await which("mvn")) ? "mvn" : "";
}

async function tryMavenBuild(abs: string, noteParts: string[]): Promise<string[]> {
  if (!fs.existsSync(path.join(abs, "pom.xml"))) return [];
  const command = await mavenCommand(abs);
  if (!command) return [];
  core.info("Detected pom.xml — running 'mvn compile' for a full classpath…");
  const result = await run(command, ["-q", "-B", "-DskipTests", "compile"], { cwd: abs });
  if (result.exitCode !== 0) noteParts.push("mvn compile had errors");
  return findClassDirs(abs);
}

async function gradleCommand(abs: string): Promise<string> {
  const gradlew = findWrapper(abs, "gradlew");
  if (gradlew) return gradlew;
  return (await which("gradle")) ? "gradle" : "";
}

async function tryGradleBuild(abs: string, noteParts: string[]): Promise<string[]> {
  const hasGradle =
    fs.existsSync(path.join(abs, "build.gradle")) ||
    fs.existsSync(path.join(abs, "build.gradle.kts"));
  if (!hasGradle) return [];

  const command = await gradleCommand(abs);
  if (!command) return [];

  core.info("Detected Gradle build — running 'classes' task for a full classpath…");
  const result = await run(command, ["classes", "--console=plain", "-q"], { cwd: abs });
  if (result.exitCode !== 0) noteParts.push("gradle build had errors");
  return findClassDirs(abs);
}

async function ensureKotlinc(): Promise<string | null> {
  if (await which("kotlinc")) return "kotlinc";
  try {
    return await cachedTool(
      "kotlin-compiler",
      KOTLIN_VERSION,
      path.join("kotlinc", "bin", "kotlinc"),
      async (directory) => {
        const archive = await downloadVerified(
          githubReleaseUrl(KOTLIN),
          KOTLIN_SHA256,
        );
        await tc.extractZip(archive, directory);
      },
    );
  } catch (err) {
    core.warning(`kotlinc download failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

async function ensureSpotbugs(): Promise<string | null> {
  const cacheVersion = `${SPOTBUGS_VERSION}-findsecbugs-${FINDSECBUGS_VERSION}`;
  const executable = path.join(`spotbugs-${SPOTBUGS_VERSION}`, "bin", "spotbugs");
  try {
    return await cachedTool("spotbugs", cacheVersion, executable, async (directory) => {
      const archive = await downloadVerified(SPOTBUGS_URL, SPOTBUGS_SHA256);
      await tc.extractTar(archive, directory);

      const plugin = await downloadVerified(FINDSECBUGS_URL, FINDSECBUGS_SHA256);
      const pluginDir = path.join(directory, `spotbugs-${SPOTBUGS_VERSION}`, "plugin");
      fs.copyFileSync(plugin, path.join(pluginDir, "findsecbugs-plugin.jar"));
      fs.chmodSync(path.join(directory, executable), 0o700);
    });
  } catch (err) {
    core.warning(`spotbugs installation failed: ${String(err).slice(0, 200)}`);
    return null;
  }
}

async function compileJava(javaFiles: string[], classesDir: string, notes: string[]): Promise<void> {
  if (javaFiles.length === 0) return;
  const result = await run("javac", ["-d", classesDir, ...javaFiles]);
  if (result.exitCode !== 0) notes.push("javac had errors (missing deps?)");
}

async function compileKotlin(
  kotlinFiles: string[],
  classesDir: string,
  notes: string[],
): Promise<void> {
  if (kotlinFiles.length === 0) return;
  const command = await ensureKotlinc();
  if (!command) {
    notes.push("kotlinc unavailable");
    return;
  }
  const result = await run(command, [...kotlinFiles, "-d", classesDir]);
  if (result.exitCode !== 0) notes.push("kotlinc had errors (missing deps?)");
}

async function compileWithoutBuild(
  javaFiles: string[],
  kotlinFiles: string[],
  workdir: string,
  notes: string[],
): Promise<string[]> {
  if (!(await which("javac"))) {
    notes.push("javac not available");
    return [];
  }

  core.info("No build output found — falling back to direct javac/kotlinc compilation…");
  const classesDir = path.join(workdir, "classes");
  fs.mkdirSync(classesDir, { recursive: true });
  await compileJava(javaFiles, classesDir, notes);
  await compileKotlin(kotlinFiles, classesDir, notes);

  const hasClasses = fs.existsSync(classesDir) && fs.readdirSync(classesDir).length > 0;
  return hasClasses ? [classesDir] : [];
}

async function analyzeClasses(
  script: string,
  classDirs: string[],
  workdir: string,
  sources: string[],
): Promise<EngineResult> {
  const output = path.join(workdir, "spotbugs.xml");
  const result = await run(script, [
    "-textui",
    "-xml:withMessages",
    "-effort:max",
    "-low",
    "-output",
    output,
    ...classDirs,
  ]);
  if (!fs.existsSync(output)) {
    return {
      engine: "spotbugs",
      findings: [],
      status: "failed",
      note: `spotbugs run failed: ${result.stderr.slice(0, 200)}`,
    };
  }
  return {
    engine: "spotbugs",
    findings: parseSpotbugsXml(fs.readFileSync(output, "utf-8"), sources),
    status: "success",
  };
}

export async function runSpotbugs(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const javaFiles = findJavaFiles(abs);
  const kotlinFiles = findKotlinFiles(abs);
  const allSources = [...javaFiles, ...kotlinFiles];
  if (allSources.length === 0) {
    return { engine: "spotbugs", findings: [], status: "skipped", note: "no .java/.kt files found" };
  }

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-spotbugs-"));
  try {
    const noteParts: string[] = [];
    let classDirs = await tryProjectBuild(abs, noteParts);
    if (classDirs.length === 0) {
      classDirs = await compileWithoutBuild(javaFiles, kotlinFiles, workdir, noteParts);
    }

    if (classDirs.length === 0) {
      return {
        engine: "spotbugs",
        findings: [],
        status: "failed",
        note: `no .class files to analyze${noteParts.length ? " (" + noteParts.join("; ") + ")" : ""}`,
      };
    }

    const script = await ensureSpotbugs();
    if (!script) {
      return {
        engine: "spotbugs",
        findings: [],
        status: "failed",
        note: "spotbugs or FindSecBugs installation failed",
      };
    }

    const result = await analyzeClasses(script, classDirs, workdir, allSources);
    const notes = [...(result.note ? [result.note] : []), ...noteParts];
    result.note = notes.length > 0 ? notes.join("; ") : undefined;
    return result;
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}

// Lightweight XML parse (avoids a heavy XML dependency in the bundle).
export function parseSpotbugsXml(xml: string, javaFiles: string[]): Finding[] {
  const findings: Finding[] = [];
  const bugRe = /<BugInstance\b([^>]*)>([\s\S]*?)<\/BugInstance>/g;
  let m: RegExpExecArray | null;
  while ((m = bugRe.exec(xml)) !== null) {
    const attrs = m[1];
    const body = m[2];
    const type = /type="([^"]+)"/.exec(attrs)?.[1] ?? "SPOTBUGS";
    const priority = /priority="([^"]+)"/.exec(attrs)?.[1] ?? "2";
    const cweMatch = /cweid="([^"]+)"/.exec(attrs)?.[1];
    const sourceLine = /<SourceLine\b([^>]*)>/.exec(body)?.[1] ?? "";
    const sourcePath = /sourcepath="([^"]+)"/.exec(sourceLine)?.[1] ?? "";
    const start = /start="([^"]+)"/.exec(sourceLine)?.[1] ?? "0";
    const shortMsg = /<ShortMessage>([\s\S]*?)<\/ShortMessage>/.exec(body)?.[1]?.trim();
    // Resolve file path against the discovered java files when possible.
    const resolved =
      javaFiles.find((f) => f.endsWith(sourcePath)) ||
      javaFiles.find((f) => path.basename(f) === path.basename(sourcePath)) ||
      sourcePath ||
      "unknown";
    findings.push({
      engine: "spotbugs",
      ruleId: type,
      severity: mapSeverity(type, priority),
      message: shortMsg || type,
      file: resolved,
      line: Number.parseInt(start, 10) || 0,
      cwe: cweMatch ? `CWE-${cweMatch}` : undefined,
    });
  }
  return findings;
}
