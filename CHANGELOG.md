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

### Changed

- Adopted semantic versioning (`vX.Y.Z`) with a floating major tag (`vX`) that tracks the
  latest release in that major line, replacing the previous plain-integer tag scheme
  (`v1`…`v15`). New usage should pin `@v16` (or an exact `@vX.Y.Z`) instead of `@v1`.
