export function parseExcludedRules(input: string): string[] {
  return [...new Set(input.split(",").map((rule) => rule.trim()).filter(Boolean))];
}
