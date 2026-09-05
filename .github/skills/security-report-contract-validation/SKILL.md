---
name: security-report-contract-validation
description: "Use when validating or fixing SARIF, CycloneDX SBOM, job-summary, finding-path, target-containment, report-ordering, or output-portability regressions in PolyScan."
argument-hint: "Describe the report contract, path issue, or output regression to validate."
user-invocable: true
---

# Security Report Contract Validation

Validate that findings and generated reports remain portable, deterministic, workspace-contained, and available when enforcement later fails.

## Procedure

1. Trace the behavior through `src/target.ts`, `src/sarif.ts`, `src/sbom.ts`, `src/summary.ts`, `src/schema.ts`, and `src/main.ts` before editing.
2. Confirm targets and output directories reject absolute paths or traversal outside the workspace, including symlink escape cases covered by existing tests.
3. Confirm engine-native finding paths pass through `normalizeFindingPath` and become POSIX, repository-relative paths. Preserve the special handling for image findings with `source: image:`.
4. Validate SARIF 2.1.0 output:
   - Artifact URIs are portable and do not contain host workspace prefixes.
   - Finding locations, rules, severity levels, and sources remain stable.
   - Empty findings and missing optional fields serialize safely.
5. Validate CycloneDX 1.5 output and summary behavior without exposing secrets or host-dependent paths.
6. Confirm `main.ts` writes reports, summaries, and outputs before quality-gate or `fail-on-engine-error` enforcement.
7. Add or update focused tests in `test/target.test.ts`, `test/sarif.test.ts`, `test/sbom.test.ts`, or `test/summary.test.ts` as appropriate.
8. Run `npm run typecheck` and `npm test`. For action-level behavior, inspect `.github/workflows/selftest.yml`, which asserts findings and repository-relative SARIF paths.
9. Run `git diff --check` and review generated report paths or fixtures for accidental secrets and absolute paths.

## Failure Modes to Check

- Workspace escape through `..`, absolute paths, or symlinks.
- Windows separators or host-specific absolute paths in SARIF.
- Image findings incorrectly forced into filesystem locations.
- Missing or malformed native fields causing report generation to throw.
- Gate or engine failure preventing diagnostic reports from being written.
- Nondeterministic finding order or report content.

## Boundaries

Do not weaken containment checks, omit findings, lower severities, suppress serialization errors, or use real credentials and external scanner installations in tests.
