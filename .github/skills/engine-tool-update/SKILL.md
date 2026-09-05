---
name: engine-tool-update
description: "Use when updating, checking, or validating scanner and helper-tool versions in tools.lock.json, including Semgrep, OpenGrep, Trivy, gosec, gitleaks, detekt, hadolint, SpotBugs, Bandit, and ESLint."
argument-hint: "Name the tool and requested version, or ask to check available updates."
user-invocable: true
---

# Engine Tool Update

Safely update PolyScan's pinned scanner and helper-tool versions without bypassing provider or checksum validation.

## When to Use

- Update a scanner or helper tool.
- Check current provider versions.
- Refresh `tools.lock.json`.
- Validate a proposed version or checksum.
- Diagnose an engine-tools update failure.

## Procedure

1. Read `tools.lock.json` and confirm the exact tool name, provider, version template, and artifact metadata.
2. Check the current lock state with `npm run engines:list` or `npm run engines:check -- <tool>`.
3. Use the repository CLI, never manual lockfile editing:
   - `npm run engines:update -- <tool> <version>` for a real update.
   - Add `--dry-run` when only validating.
   - Use `--skip-project-checks` only when explicitly requested; provider and artifact verification must still run.
4. Confirm the provider matches the lock entry: GitHub Releases, PyPI, npm, or Maven Central.
5. Confirm release assets and SHA-256 digests are verified before accepting the update. Never add an unverified binary path.
6. Review the resulting `tools.lock.json` diff for minimality and expected fields.
7. Run `npm run typecheck`, `npm test`, and `npm run build`. Confirm generated runtime `dist/` files are current and never patch them manually.
8. Update README or other public documentation only when the tool change affects documented behavior, support, or requirements.

## Guardrails

- Do not hardcode versions or URLs in engine adapters.
- Do not weaken checksum verification or accept a missing provider digest.
- Do not replace `npm ci` with an uncontrolled dependency installation.
- Do not commit generated reports, `dist-test/`, or unrelated build output.
- Report network/provider checks that could not run because external services were unavailable.

## Output

Report the tool and version changed, lockfile/checksum result, validation commands, generated bundle status, and any unresolved provider or compatibility risk.
