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
