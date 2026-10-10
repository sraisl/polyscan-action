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

// Engines that are unsafe to point at code from someone without write access:
// they either execute repository-controlled code or send repository content off
// the runner. They are skipped on untrusted runs unless the workflow opts in
// with `allow-risky-engines: true` — see src/untrusted.ts.
//
// Keyed by EngineName (not a bare string) so a typo in an engine key fails to
// compile instead of silently never matching.
export const RISKY_ENGINE_REASONS: Partial<Record<EngineName, string>> = {
  spotbugs:
    "compiles the target using its own build files (mvn compile, gradle classes, ./gradlew), " +
    "which executes repository-controlled code on the runner",
  trufflehog:
    "verifies candidate credentials by making live outbound requests to third-party provider APIs",
};

export interface SkippedEngine {
  engine: string;
  reason: string;
}

export function riskyEngineReason(engine: string): string | undefined {
  return RISKY_ENGINE_REASONS[engine as EngineName];
}

export function isRiskyEngine(engine: string): boolean {
  return riskyEngineReason(engine) !== undefined;
}

/**
 * Splits the requested engines into the ones that may run and the ones safe
 * mode withholds. Engine order is preserved. Nothing is withheld on a trusted
 * run, or when the workflow has explicitly opted into risky engines.
 */
export function selectEnginesForRun(
  engines: string[],
  options: { untrusted: boolean; allowRisky: boolean },
): { engines: string[]; skipped: SkippedEngine[] } {
  if (!options.untrusted || options.allowRisky) {
    return { engines: [...engines], skipped: [] };
  }

  const selected: string[] = [];
  const skipped: SkippedEngine[] = [];
  for (const engine of engines) {
    const reason = riskyEngineReason(engine);
    if (reason === undefined) {
      selected.push(engine);
    } else {
      skipped.push({ engine, reason });
    }
  }
  return { engines: selected, skipped };
}
