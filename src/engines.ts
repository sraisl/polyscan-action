export const DEFAULT_ENGINES = [
  "semgrep",
  "bandit",
  "eslint",
  "spotbugs",
  "trivy",
  "detekt",
  "gitleaks",
  "betterleaks",
  "gosec",
  "hadolint",
  "zizmor",
] as const;

export const SUPPORTED_ENGINES = [
  "semgrep",
  "opengrep",
  "bandit",
  "eslint",
  "spotbugs",
  "trivy",
  "detekt",
  "gitleaks",
  "betterleaks",
  "gosec",
  "hadolint",
  "zizmor",
  "trufflehog",
] as const;

export type EngineName = (typeof SUPPORTED_ENGINES)[number];

export function resolveEngines(input: string): string[] {
  const raw = input.trim();
  if (raw === "" || raw.toLowerCase() === "all") {
    return [...DEFAULT_ENGINES];
  }
  return raw
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);
}

export function unknownEngines(engines: string[]): string[] {
  return engines.filter((e) => !(SUPPORTED_ENGINES as readonly string[]).includes(e));
}
