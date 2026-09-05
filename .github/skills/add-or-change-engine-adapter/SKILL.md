---
name: add-or-change-engine-adapter
description: "Use when adding a scanner engine, changing an engine adapter, wiring a parser, or updating PolyScan engine registration, tool provisioning, public metadata, tests, and the bundled action."
argument-hint: "Describe the scanner engine or adapter behavior to add or change."
user-invocable: true
---

# Add Or Change Engine Adapter

Guide a complete engine change across implementation, provisioning, registration, tests, metadata, documentation, and the committed action bundle.

## Procedure

1. Inspect a nearby adapter with a similar provisioning model, such as `src/engines/hadolint.ts` for a pinned binary or `src/engines/spotbugs.ts` for build-aware behavior.
2. Define applicability first. A language-specific engine must perform a cheap file-presence or project check before downloading or installing tools.
3. Add or update the pinned tool entry through `npm run engines:update`, not by hand-editing `tools.lock.json`. Preserve provider metadata and SHA-256 verification.
4. Implement `run<Engine>()` under `src/engines/` using the shared `EngineResult` contract from `src/schema.ts`:
   - Return `success`, `skipped`, or `failed` deliberately.
   - Return `skipped` with a useful note when the engine is not applicable.
   - Do not let expected adapter errors escape `main.ts`'s engine boundary.
   - Normalize engine-native paths through `normalizeFindingPath` in `src/target.ts`.
   - Preserve stable severity, source, rule, CWE, and deterministic ordering metadata.
5. Register the engine in `src/engines.ts` and dispatch it from `src/main.ts`.
6. Add focused parser and adapter tests under `test/`, covering valid output, empty output, malformed or incomplete native fields, severity mapping, path normalization, and skip behavior.
7. Update `action.yml`, README engine tables, inputs, outputs, or user-facing behavior when the public contract changes.
8. Run `npm run typecheck`, `npm test`, and `npm run build`. Review the runtime `dist/` diff and never edit generated bundle files manually.

## Completion Checklist

- Applicability check occurs before provisioning.
- Tool versions and downloads are centrally pinned and verified.
- `EngineResult` status semantics are preserved.
- Findings use the shared schema and workspace-relative POSIX paths.
- Engine registration and dispatch are complete.
- Focused tests cover malformed output and non-applicable repositories.
- Public metadata and documentation match the implementation.
- Typecheck, tests, build, and bundle freshness checks pass.

## Boundaries

Do not refactor unrelated engines, weaken target containment, add unverified downloads, or change severity semantics merely to satisfy a test.
