// Documentation links for findings, shared by the job summary and SARIF helpUri.
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
