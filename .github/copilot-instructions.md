# PolyScan Action — AI agent instructions

## What this is
A native TypeScript GitHub Action (`src/main.ts` entry) that orchestrates multiple SAST/SCA engines (Semgrep, OpenGrep, Bandit, ESLint, SpotBugs+FindSecBugs, Trivy, detekt, gitleaks, gosec, hadolint), normalizes all results into one `Finding` schema, enforces a Quality Gate, and emits SARIF/CycloneDX SBOM/job-summary outputs. Runs only on Linux x64 (`assertSupportedPlatform` in [src/tools.ts](../src/tools.ts)).

## Source of truth
- `src/` is the editable implementation; `src/main.ts` is the action entrypoint and owns orchestration and final failure behavior.
- `package-lock.json` is the dependency lockfile. Use `npm ci` for reproducible installs; use `npm install` only when intentionally changing dependencies or the lockfile.
- `tools.lock.json` is the source of truth for scanner and helper-tool versions, URLs, and checksums.
- `dist/` contains the committed GitHub Action runtime bundle. It is generated, must never be edited manually, and must be rebuilt after source or bundling changes.
- Keep changes focused on the requested behavior. Do not introduce new linting or formatting requirements unless the repository adds an enforced check for them.

## Architecture (src/)
- `main.ts` — reads action inputs, resolves config, runs engines, normalizes/sorts findings, writes reports, uploads artifacts, sets outputs.
- `engines/*.ts` — one adapter per tool. Each exports `run<Engine>(target, ...)` returning `EngineResult` (`schema.ts`). Adapters install/download their own tool on demand (pip venv via `exec.ts`, or a pinned+SHA-256-verified binary via `tools.ts`/`tools.lock.json`) and are responsible for parsing native output into `Finding[]`.
- `engines.ts` — `SUPPORTED_ENGINES`, `resolveEngines("all"|"a,b,c")`, `unknownEngines(...)`.
- `scheduler.ts` — bounded-concurrency runner. `mapConcurrentWithBarriers` runs engines with `max-concurrency` parallelism, except SpotBugs (`isBarrier`) which runs alone as a serial barrier (it may invoke `mvn`/`gradle` builds — see `engines/spotbugs.ts`).
- `gate.ts` — compares severity counts against `max-critical`/`max-high`/`max-medium` thresholds.
- `sarif.ts` / `sbom.ts` / `summary.ts` — output renderers from the normalized `Finding[]`.
- `target.ts` — resolves/validates the scan target and output dir stay workspace-contained, and normalizes finding paths to POSIX, repo-relative (required for SARIF portability — see the selftest workflow assertion).
- `tools.ts` / `tool-versions.ts` — shared download/cache/checksum-verify helpers and the `tools.lock.json` reader used by every binary-based engine.
- `exec.ts` — subprocess/`which` helpers, and pip-venv provisioning (`python3 -m venv`) used by Python-based engines.

## Conventions
- Every engine adapter must return `EngineResult` (`status: success|skipped|failed`) and never throw past `main.ts`'s `runEngine` try/catch; use `status: "skipped"` with a `note` when a language/tool isn't applicable (keeps `engines: "all"` cheap on repos that don't use that language).
- Language-specific adapters should perform their cheap applicability check before downloading or installing a tool. Preserve the distinction between `success`, `skipped`, and `failed` because aggregate engine status and outputs depend on it.
- `Finding.file` must end up POSIX, relative to the scan target/workspace — always route engine-native paths through `normalizeFindingPath` (`target.ts`), except image findings (`source: "image:..."`).
- Targets and output directories must remain inside the workspace. Do not weaken `target.ts` containment checks or emit host-dependent absolute paths in reports.
- Preserve stable `Finding` fields, severity mapping, source metadata, and deterministic finding ordering when changing parsers or normalizers.
- New/updated scanner or helper tool versions are pinned centrally in [tools.lock.json](../tools.lock.json) — never hardcode a version/URL in an engine file. Use `npm run engines:check` / `engines:update` ([scripts/engine-tools.mjs](../scripts/engine-tools.mjs)) to change them; update validates against the real provider (GitHub Releases/PyPI/npm/Maven Central) and verifies SHA-256 before writing the lock file.
- Downloaded binaries are always SHA-256 verified (`verifySha256`/`downloadVerified` in `tools.ts`) — don't add a download path that skips this.
- Reports and action outputs must remain available even when the quality gate or `fail-on-engine-error` later fails the job. Preserve the existing ordering in `main.ts` when changing final enforcement.

## Build & test workflow
- Requires Node 24 (`.nvmrc`, `package.json engines.node`); `scripts/require-node24.cjs` enforces this as a `prebuild` step.
- For a clean checkout, run `npm ci` before validation. The full CI checks are `npm run typecheck`, `npm test`, `npm audit --audit-level=moderate`, and `npm run build`.
- `npm run typecheck` — `tsc --noEmit`.
- `npm run build` — bundles `src/main.ts` → `dist/index.js` with `@vercel/ncc`, then `scripts/check-bundle.cjs` asserts no broken CRC64 loader in the bundle. **`dist/` is committed** — CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) fails if runtime `dist/` files differ after a fresh build. Source maps are excluded from that comparison because they are not deterministic.
- `npm test` — compiles tests via `tsc -p tsconfig.test.json` to `dist-test/`, then runs with Node's built-in `node --test`. Tests live in `test/*.test.ts`, mirror one file per engine/module, and use `node:test` + `node:assert/strict` (no external test framework).
- `npm run all` = typecheck + build. CI also runs `npm audit --audit-level=moderate`.
- A devcontainer ([.devcontainer/devcontainer.json](../.devcontainer/devcontainer.json)) provides Node 24 + Python + Java(Maven/Gradle) + Go so the actual engines can be exercised locally, not just the TS build.

## Testing expectations
- Add or update focused tests with every behavior change. Parser tests should cover valid output, missing or malformed native fields, severity mapping, path normalization, and non-applicable/skip behavior where relevant.
- Test scheduler changes for bounded concurrency, serial SpotBugs barriers, failure propagation, and deterministic result ordering.
- Filesystem and tool-provisioning tests should use temporary directories and clean them up. Do not make tests depend on a developer's globally installed scanner or credentials.
- Use existing `node:test` and `node:assert/strict` patterns. Avoid adding a test framework or broad integration fixtures unless the behavior cannot be covered locally.
- When changing public inputs, outputs, engine names, or user-visible behavior, update `action.yml`, [README.md](../README.md), and the relevant tests together.

## When adding/changing an engine adapter
1. Add the tool's pinned version/checksum to `tools.lock.json` (via `engines:update`, not by hand).
2. Implement `run<Engine>()` in `src/engines/<name>.ts` following the existing adapters' shape (see `hadolint.ts` for a simple binary-based example, `spotbugs.ts` for a build-aware one).
3. Wire it into `SUPPORTED_ENGINES`/`resolveEngines` (`engines.ts`) and the `switch` in `main.ts`'s `runEngine`.
4. Add a parser test in `test/<name>-parser.test.ts` and update `action.yml`/README's engine table + inputs description.
5. Run `npm run typecheck && npm test && npm run build`, commit `dist/`.

## Release and generated files
- Pull requests that change `src/` or bundling inputs must regenerate and commit the runtime files in `dist/`; never patch the bundle by hand.
- The release workflow ([.github/workflows/release.yml](workflows/release.yml)) verifies the bundle from the current `main` and pushes only a release tag. It is not a mechanism for committing generated files back to `main`.
- Do not commit generated reports, `dist-test/`, temporary tool environments, or unrelated build output.
