export const ALL_ENGINES = [
  "semgrep",
  "bandit",
  "eslint",
  "spotbugs",
  "trivy",
  "detekt",
  "gitleaks",
] as const;

export type EngineName = (typeof ALL_ENGINES)[number];

export function resolveEngines(input: string): string[] {
  const raw = input.trim();
  if (raw === "" || raw.toLowerCase() === "all") {
    return [...ALL_ENGINES];
  }
  return raw
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);
}
