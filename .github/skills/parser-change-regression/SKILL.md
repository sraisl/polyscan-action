---
name: parser-change-regression
description: "Use when changing scanner-output parsing, severity mapping, finding metadata, native output handling, or malformed-output behavior in a PolyScan engine parser."
argument-hint: "Name the parser or native output shape that needs support or correction."
user-invocable: true
---

# Parser Change Regression

Make focused parser changes while preserving the shared `Finding` contract and predictable behavior across scanner output shapes.

## Procedure

1. Identify the engine parser under `src/engines/` and its matching test file under `test/`.
2. Read `src/schema.ts` and `src/target.ts` to confirm required finding fields, severity values, source identity, and path normalization rules.
3. Capture the native output shape with a minimal fixture or inline test value. Do not require a globally installed scanner, credentials, network access, or a live repository.
4. Implement the smallest parser change that supports the requested output:
   - Preserve engine identity and stable finding fields.
   - Map native severities consistently with existing conventions.
   - Handle missing, empty, malformed, and unexpected optional fields safely.
   - Preserve CWE, rule, message, source, and location metadata where available.
   - Route filesystem paths through the central normalization helper when applicable.
5. Add tests for valid output, empty output, malformed output, missing fields, severity mapping, and path or metadata behavior relevant to the parser.
6. Run `npm run typecheck` and `npm test`. Review failures for contract regressions rather than weakening assertions.
7. Run `git diff --check`; if source or bundling inputs changed, run `npm run build` and verify committed runtime `dist/` files.

## Test Design

Prefer `node:test` and `node:assert/strict` with deterministic fixtures. Assert the complete meaningful finding shape, not only the finding count. Include a skipped/non-applicable case when the adapter owns applicability detection.

## Boundaries

Do not change shared severity semantics for one engine without checking all consumers. Do not silently discard malformed findings, emit absolute paths, depend on external tools in unit tests, or refactor unrelated parsers.
