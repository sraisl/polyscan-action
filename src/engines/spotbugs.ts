// SpotBugs + FindSecBugs engine adapter for Java/Kotlin.
// Compiles .java sources, downloads SpotBugs+FindSecBugs on demand, parses XML.
import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";

// Resolve the target path relative to the GitHub workspace (if set),
// not the action's own directory — otherwise '.' resolves to the wrong place.
function resolveTarget(target: string): string {
  const ws = process.env.GITHUB_WORKSPACE;
  if (ws && !path.isAbsolute(target)) {
    return path.resolve(ws, target);
  }
  return path.resolve(target);
}

const SPOTBUGS_VERSION = "4.8.6";
const SPOTBUGS_URL = `https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz`;
const FINDSECBUGS_VERSION = "1.13.0";
const FINDSECBUGS_URL = `https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar`;

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
  const p = parseInt(priority, 10);
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

function findClassDirs(dir: string): string[] {
  // Look for typical compiled-output directories.
  const candidates = [
    "target/classes", // Maven
    "build/classes/kotlin/main", // Gradle Kotlin
    "build/classes/java/main", // Gradle Java
    "out/production/classes", // IntelliJ
  ];
  const found: string[] = [];
  for (const c of candidates) {
    const p = path.join(dir, c);
    if (fs.existsSync(p) && fs.readdirSync(p).length > 0) found.push(p);
  }
  return found;
}

async function tryProjectBuild(
  abs: string,
  noteParts: string[],
): Promise<string[]> {
  // Maven
  if (fs.existsSync(path.join(abs, "pom.xml")) && (await which("mvn"))) {
    core.info("Detected pom.xml — running 'mvn compile' for a full classpath…");
    const res = await run("mvn", ["-q", "-B", "-DskipTests", "compile"], { cwd: abs });
    if (res.exitCode !== 0) noteParts.push("mvn compile had errors");
    const dirs = findClassDirs(abs);
    if (dirs.length) return dirs;
  }
  // Gradle
  const gradlew = path.join(abs, "gradlew");
  const hasGradle =
    fs.existsSync(path.join(abs, "build.gradle")) ||
    fs.existsSync(path.join(abs, "build.gradle.kts"));
  if (hasGradle) {
    const gradleCmd = fs.existsSync(gradlew) ? gradlew : (await which("gradle")) ? "gradle" : "";
    if (gradleCmd) {
      core.info("Detected Gradle build — running 'classes' task for a full classpath…");
      const res = await run(gradleCmd, ["classes", "--console=plain", "-q"], { cwd: abs });
      if (res.exitCode !== 0) noteParts.push("gradle build had errors");
      const dirs = findClassDirs(abs);
      if (dirs.length) return dirs;
    }
  }
  return [];
}

export async function runSpotbugs(target: string): Promise<EngineResult> {
  const abs = resolveTarget(target);
  const javaFiles = findJavaFiles(abs);
  const kotlinFiles = findKotlinFiles(abs);
  const allSources = [...javaFiles, ...kotlinFiles];
  if (allSources.length === 0) {
    return { engine: "spotbugs", findings: [], available: true, note: "no .java/.kt files found" };
  }

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-spotbugs-"));
  const noteParts: string[] = [];

  // Strategy 1 (preferred): use the project's own build so the full dependency
  // classpath is present — this is what makes SpotBugs reliable on real Java/Kotlin apps.
  let classDirs = await tryProjectBuild(abs, noteParts);

  // Strategy 2 (fallback): direct compilation without dependencies (best-effort;
  // only produces .class files for code that doesn't need third-party imports).
  if (classDirs.length === 0) {
    if (!(await which("javac"))) {
      return { engine: "spotbugs", findings: [], available: false, note: "no build tool succeeded and javac not available" };
    }
    core.info("No build output found — falling back to direct javac/kotlinc compilation…");
    const classesDir = path.join(workdir, "classes");
    fs.mkdirSync(classesDir, { recursive: true });

    if (javaFiles.length > 0) {
      const compile = await run("javac", ["-d", classesDir, ...javaFiles]);
      if (compile.exitCode !== 0) noteParts.push("javac had errors (missing deps?)");
    }

    if (kotlinFiles.length > 0) {
      if (!(await which("kotlinc"))) {
        core.info("kotlinc not found — downloading…");
        const kt = await run("bash", [
          "-lc",
          [
            "set -e",
            "KV=1.9.24",
            `cd ${workdir}`,
            'curl -sSL -o kotlin.zip "https://github.com/JetBrains/kotlin/releases/download/v${KV}/kotlin-compiler-${KV}.zip"',
            "unzip -q kotlin.zip",
          ].join("\n"),
        ]);
        if (kt.exitCode !== 0) noteParts.push("kotlinc unavailable");
      }
      const kotlincBin = (await which("kotlinc")) ? "kotlinc" : `${workdir}/kotlinc/bin/kotlinc`;
      if (fs.existsSync(kotlincBin) || (await which("kotlinc"))) {
        const ktc = await run(kotlincBin, [...kotlinFiles, "-d", classesDir]);
        if (ktc.exitCode !== 0) noteParts.push("kotlinc had errors (missing deps?)");
      }
    }

    if (fs.existsSync(classesDir) && fs.readdirSync(classesDir).length > 0) {
      classDirs = [classesDir];
    }
  }

  if (classDirs.length === 0) {
    return {
      engine: "spotbugs",
      findings: [],
      available: false,
      note: `no .class files to analyze${noteParts.length ? " (" + noteParts.join("; ") + ")" : ""}`,
    };
  }

  // Download + extract SpotBugs.
  let spotbugsHome: string;
  try {
    const tgz = await tc.downloadTool(SPOTBUGS_URL);
    const extracted = await tc.extractTar(tgz, path.join(workdir, "sb"));
    spotbugsHome = path.join(extracted, `spotbugs-${SPOTBUGS_VERSION}`);
  } catch (err) {
    return {
      engine: "spotbugs",
      findings: [],
      available: false,
      note: `spotbugs download failed: ${String(err).slice(0, 200)}`,
    };
  }

  // Download FindSecBugs plugin.
  const pluginDir = path.join(spotbugsHome, "plugin");
  try {
    const jar = await tc.downloadTool(FINDSECBUGS_URL);
    fs.copyFileSync(jar, path.join(pluginDir, "findsecbugs-plugin.jar"));
  } catch (err) {
    core.warning(`findsecbugs download failed (continuing with core spotbugs): ${String(err).slice(0, 150)}`);
  }

  const xmlOut = path.join(workdir, "spotbugs.xml");
  const sbScript = path.join(spotbugsHome, "bin", "spotbugs");
  fs.chmodSync(sbScript, 0o755);

  const res = await run(sbScript, [
    "-textui",
    "-xml:withMessages",
    "-effort:max",
    "-low",
    "-output",
    xmlOut,
    ...classDirs,
  ]);

  if (!fs.existsSync(xmlOut)) {
    return {
      engine: "spotbugs",
      findings: [],
      available: false,
      note: `spotbugs run failed: ${res.stderr.slice(0, 200)}`,
    };
  }

  const xml = fs.readFileSync(xmlOut, "utf-8");
  const findings = parseSpotbugsXml(xml, allSources);
  return {
    engine: "spotbugs",
    findings,
    available: true,
    note: noteParts.length ? noteParts.join("; ") : undefined,
  };
}

// Lightweight XML parse (avoids a heavy XML dependency in the bundle).
function parseSpotbugsXml(xml: string, javaFiles: string[]): Finding[] {
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
      line: parseInt(start, 10) || 0,
      cwe: cweMatch ? `CWE-${cweMatch}` : undefined,
    });
  }
  return findings;
}
