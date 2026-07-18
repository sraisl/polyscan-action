// SpotBugs + FindSecBugs engine adapter for Java/Kotlin.
// Compiles .java sources, downloads SpotBugs+FindSecBugs on demand, parses XML.
import * as core from "@actions/core";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as tc from "@actions/tool-cache";
import { Finding, EngineResult, Severity } from "../schema";
import { run, which } from "../exec";

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

export async function runSpotbugs(target: string): Promise<EngineResult> {
  const abs = path.resolve(target);
  const javaFiles = findJavaFiles(abs);
  const kotlinFiles = findKotlinFiles(abs);
  const allSources = [...javaFiles, ...kotlinFiles];
  if (allSources.length === 0) {
    return { engine: "spotbugs", findings: [], available: true, note: "no .java/.kt files found" };
  }

  if (!(await which("javac"))) {
    return { engine: "spotbugs", findings: [], available: false, note: "javac not available" };
  }

  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "polyscan-spotbugs-"));
  const classesDir = path.join(workdir, "classes");
  fs.mkdirSync(classesDir, { recursive: true });
  const noteParts: string[] = [];

  // Compile Java (best-effort; ignore missing deps by continuing).
  if (javaFiles.length > 0) {
    const compile = await run("bash", [
      "-lc",
      `javac -d ${classesDir} ${javaFiles.map((f) => `"${f}"`).join(" ")}`,
    ]);
    if (compile.exitCode !== 0) {
      core.warning(`javac reported issues (continuing): ${compile.stderr.slice(0, 200)}`);
      noteParts.push("javac had errors");
    }
  }

  // Compile Kotlin via kotlinc (install on demand). SpotBugs analyses the resulting .class files.
  if (kotlinFiles.length > 0) {
    const hasKotlinc = await which("kotlinc");
    if (!hasKotlinc) {
      core.info("kotlinc not found — installing via sdkman-less direct download…");
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
      if (kt.exitCode !== 0) {
        core.warning(`kotlinc install failed (continuing without Kotlin): ${kt.stderr.slice(0, 200)}`);
        noteParts.push("kotlinc unavailable");
      }
    }
    const kotlincBin = (await which("kotlinc")) ? "kotlinc" : `${workdir}/kotlinc/bin/kotlinc`;
    if (fs.existsSync(kotlincBin) || (await which("kotlinc"))) {
      const ktc = await run("bash", [
        "-lc",
        `"${kotlincBin}" ${kotlinFiles.map((f) => `"${f}"`).join(" ")} -d ${classesDir} 2>&1 || true`,
      ]);
      if (ktc.exitCode !== 0) {
        core.warning(`kotlinc reported issues (continuing): ${ktc.stderr.slice(0, 200)}`);
        noteParts.push("kotlinc had errors");
      }
    }
  }

  const compiled = fs.existsSync(classesDir) && fs.readdirSync(classesDir).length > 0;
  if (!compiled) {
    return {
      engine: "spotbugs",
      findings: [],
      available: false,
      note: `compilation produced no .class files${noteParts.length ? " (" + noteParts.join("; ") + ")" : ""}`,
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

  const res = await run("bash", [
    "-lc",
    `"${sbScript}" -textui -xml:withMessages -effort:max -low -output "${xmlOut}" "${classesDir}"`,
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
