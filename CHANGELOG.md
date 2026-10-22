# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) starting at `v16.0.0`.

Releases before `v16.0.0` (`v1` through `v15`) predate this changelog and used plain
incrementing integer tags rather than semver — see the repository's
[tag list](../../tags) and [compare view](../../compare) for that history. The new scheme
starts at `v16` (not `v1`/`v2`/…) precisely because all of `v1`…`v15` already exist as legacy
tags and must not be reused or moved.

## [Unreleased]

## [v17.0.0] - 2026-10-22

### Added

- New `oxlint` engine for JavaScript/TypeScript (including JSX/TSX). It runs `no-eval`,
  `no-implied-eval`, `no-new-func`, `no-script-url` and `react/no-danger` from a pinned,
  SHA-256-verified standalone binary, is skipped when no JS/TS files are present, and reports
  files it cannot parse or does not lint (minified names, non-lowercase extensions) in the engine
  note instead of dropping them silently. It runs outside the scanned target, so a repository's
  `oxlint-suppressions.json` cannot hide findings.

### Changed

- `engines: "all"` now runs `oxlint` instead of `eslint`. ESLint stays available as an opt-in
  engine (`engines: "eslint,..."`) but its default parser cannot read TypeScript syntax, so it
  never reported findings in `.ts`/`.tsx` files. Findings now carry `oxlint/<rule>` rule IDs, so
  existing code scanning alerts from `eslint/<rule>` close and reopen under the new IDs.
- `npm run engines:check` finds the latest release of a tool in a monorepo that publishes several
  products (such as `oxc-project/oxc`) by matching the tool's tag template.

### Fixed

- Bandit and Semgrep reuse a preinstalled executable only when it reports the version pinned in
  `tools.lock.json`. A runner with a different version installed now gets the pinned release in an
  isolated environment instead, so scan results stay reproducible.
- The SARIF driver and the CycloneDX SBOM tool entry report the release version (`17.0.0`)
  instead of the placeholder `1.0.0` from `package.json`.

## [v16.1.0] - 2026-09-25

### Added

- Optional `semgrep-exclude-rules` and `opengrep-exclude-rules` inputs suppress individual
  scanner rules while the remaining rules continue to scan the same files.

### Changed

- Semgrep and OpenGrep findings retain their full rule IDs in the job summary and SARIF,
  so IDs can be copied directly into the new exclusion inputs.
- Updated the pinned ESLint, OpenGrep, Semgrep, trufflehog, and zizmor versions.

## [v16.0.3] - 2026-09-09

### Fixed

- Rebuilt the committed Action bundle to match the source.

## [v16.0.2] - 2026-09-05

### Added

- **betterleaks** engine: secret / credential detection in the current working tree via the
  betterleaks CLI (maintained by the original gitleaks author). Live-validated credentials are
  reported as `critical` (confirmed active) or `low` (confirmed dead); everything else defaults
  to `high`.

### Fixed

- `parseBetterleaksJson` no longer mis-strips file paths that don't start with the scan target
  prefix exactly.
- Corrected the "betterleaks unavailable" error note and the README's coverage claim: betterleaks
  scans the working tree only, not git history.

## [v16.0.1] - 2026-08-30

### Changed

- Renamed the Marketplace listing to PolyScan SAST Security Scanner.

## [v16.0.0] - 2026-08-30

### Changed

- Adopted semantic versioning (`vX.Y.Z`) with a floating major tag (`vX`) that tracks the
  latest release in that major line, replacing the previous plain-integer tag scheme
  (`v1`…`v15`). New usage should pin `@v16` (or an exact `@vX.Y.Z`) instead of `@v1`.
