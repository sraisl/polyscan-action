// Documentation links for findings (shared by the job summary and SARIF helpUri) and
// links to the source lines they point at (job summary).
import * as fs from "node:fs";
import { Finding } from "./schema";
import { EngineName } from "./engines";

// Keyed by EngineName (not a bare string) so a typo in an engine key fails to
// compile instead of silently never matching.
// Only link when a canonical URL can be derived with confidence: a fixed
// engine-doc naming convention. Engine-supplied URLs (Trivy, oxlint) and the
// CWE fallback are handled separately in findingUrl().
const ENGINE_RULE_URL: Partial<Record<EngineName, (ruleId: string) => string | undefined>> = {
  hadolint: (ruleId) => {
    if (/^DL\d+$/.test(ruleId)) return `https://github.com/hadolint/hadolint/wiki/${ruleId}`;
    if (/^SC\d+$/.test(ruleId)) return `https://www.shellcheck.net/wiki/${ruleId}`;
    return undefined;
  },
  gosec: (ruleId) => (/^G\d+$/.test(ruleId) ? `https://securego.io/docs/rules/${ruleId.toLowerCase()}.html` : undefined),
  eslint: (ruleId) => (ruleId.includes("/") ? undefined : `https://eslint.org/docs/latest/rules/${ruleId}`),
  zizmor: (ruleId) =>
    ruleId.startsWith("zizmor/") ? `https://docs.zizmor.sh/audits/#${ruleId.slice("zizmor/".length)}` : undefined,
};

// finding.url is engine-supplied (Trivy's PrimaryURL, oxlint's rule docs) and not
// type-enforced beyond "string" — reject anything that isn't a well-formed
// http(s) URL rather than rendering it as a link destination.
function isHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export function findingUrl(finding: Finding): string | undefined {
  if (finding.url && isHttpUrl(finding.url)) return finding.url;

  const specific = ENGINE_RULE_URL[finding.engine as EngineName]?.(finding.ruleId);
  if (specific) return specific;

  const cweMatch = finding.cwe ? /^CWE-(\d+)$/.exec(finding.cwe) : null;
  return cweMatch ? `https://cwe.mitre.org/data/definitions/${cweMatch[1]}.html` : undefined;
}

// Blob URL prefix ("https://github.com/owner/repo/blob/<sha>") for linking findings to
// their source lines. On pull requests GITHUB_SHA is the ephemeral merge commit, so the
// PR head commit is preferred. Returns undefined unless every part looks well-formed.
export function sourceBaseUrl(
  env: NodeJS.ProcessEnv = process.env,
  headSha: string | undefined = pullRequestHeadSha(env),
): string | undefined {
  const server = env.GITHUB_SERVER_URL;
  const repository = env.GITHUB_REPOSITORY;
  const sha = headSha || env.GITHUB_SHA;
  if (!server || !isHttpUrl(server)) return undefined;
  if (!repository || !/^[\w.-]+\/[\w.-]+$/.test(repository)) return undefined;
  if (!sha || !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i.test(sha)) return undefined;
  return `${server.replace(/\/+$/, "")}/${repository}/blob/${sha}`;
}

export function pullRequestHeadSha(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (!env.GITHUB_EVENT_PATH) return undefined;
  try {
    const event = JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, "utf-8")) as {
      pull_request?: { head?: { sha?: unknown } };
    };
    const sha = event.pull_request?.head?.sha;
    return typeof sha === "string" ? sha : undefined;
  } catch {
    return undefined;
  }
}

// Link to the finding's line, or undefined for findings without a safe, relative
// workspace path (container image layers, absolute paths, "..", "unknown").
export function sourceUrl(finding: Finding, baseUrl: string | undefined): string | undefined {
  if (!baseUrl || finding.source?.startsWith("image:")) return undefined;
  const file = finding.file.startsWith("./") ? finding.file.slice(2) : finding.file;
  const segments = file.split("/");
  if (!file || file === "unknown" || file.startsWith("/") || segments.includes("..")) return undefined;
  const anchor = finding.line > 0 ? `#L${finding.line}` : "";
  return `${baseUrl}/${segments.map(encodeURIComponent).join("/")}${anchor}`;
}
