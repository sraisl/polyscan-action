# PolyScan Action

**Multi-language SAST as a native GitHub Action.** One step runs all configured security engines — Semgrep, OpenGrep, Bandit, ESLint, SpotBugs, detekt, gosec, Trivy, gitleaks, hadolint and zizmor — normalizes every result into a single schema, enforces a configurable **Quality Gate**, and emits **SARIF**, a **CycloneDX SBOM** and a rich **job summary** — plus optional artifact upload.

Written in TypeScript, bundled with `@vercel/ncc`, runs as a native GitHub Action on the `node24` runtime.

## Requirements

- **Linux x64 runners only** (GitHub-hosted `ubuntu-latest` or self-hosted) — PolyScan fails fast on other OS/architecture combinations.

## Usage

```yaml
name: PolyScan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # only needed for upload-sarif

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: sraisl/polyscan-action@v16
        with:
          target: "."
          engines: "semgrep,bandit,eslint,spotbugs"
          max-critical: "0"
          max-high: "0"
          max-medium: "50"
          gate: "true"
          fail-on-engine-error: "true"
          sarif: "true"
          sbom: "true"
          upload-artifacts: "true"

      # optional: push SARIF into GitHub Code Scanning
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: polyscan.sarif
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `target` | `.` | Workspace-contained directory to scan |
| `engines` | `all` | `all` or comma-separated engines: `semgrep,opengrep,bandit,eslint,spotbugs,trivy,detekt,gitleaks,gosec,hadolint,zizmor,trufflehog`. OpenGrep and trufflehog are opt-in and are not included by `all`. |
| `opengrep-config` | `auto` | OpenGrep rules config: `auto`, a local path, URL, or registry ID |
| `max-concurrency` | `2` | Maximum concurrent read-only engines (`1`-`10`); SpotBugs runs as a serial barrier |
| `max-critical` | `0` | Max critical findings before the gate fails |
| `max-high` | `0` | Max high findings before the gate fails |
| `max-medium` | `50` | Max medium findings before the gate fails |
| `gate` | `true` | Enforce the Quality Gate (fail the job) |
| `fail-on-engine-error` | `true` | Fail after reports are written if a requested engine cannot complete |
| `sarif` | `true` | Write `polyscan.sarif` (SARIF 2.1.0) |
| `sbom` | `false` | Write `polyscan.sbom.json` (CycloneDX 1.5) |
| `upload-artifacts` | `true` | Upload SARIF + SBOM + summary as a workflow artifact |
| `upload-sarif` | `false` | Emit a hint to upload SARIF to code scanning (use the CodeQL step) |
| `trivy-image` | _(empty)_ | Docker image to scan with `trivy image` (e.g. `myapp:latest`). Image must be available in the local Docker daemon. Runs in addition to the filesystem scan. |
| `output-dir` | `.` | Workspace-contained directory for generated reports |

## Outputs

| Output | Description |
|---|---|
| `total` | Total findings |
| `critical` / `high` / `medium` / `low` / `info` | Counts per severity |
| `gate-passed` | `'true'` / `'false'` |
| `engines-passed` | `'true'` when every requested engine completed or was not applicable |
| `failed-engines` | Comma-separated engines that failed |
| `sarif-file` | Path to the SARIF file |
| `sbom-file` | Path to the SBOM file |

## Engines

| Engine | Languages | Notes |
|---|---|---|
| **Semgrep** | many | `--config auto` |
| **OpenGrep** | many | opt-in; standalone, pinned Linux x64 binary; configurable via `opengrep-config` |
| **Bandit** | Python | installed via pip on demand |
| **ESLint** | JS/TS | `no-eval` / `no-implied-eval` / `no-new-func` |
| **SpotBugs + FindSecBugs** | Java + Kotlin | **build-aware**: runs `mvn compile` / `gradle classes` when a build file is present (full dependency classpath), else falls back to direct `javac`/`kotlinc` |
| **Trivy** | deps + IaC | SCA (vulnerable dependencies / CVEs) + misconfig; binary downloaded on demand |
| **detekt** | Kotlin | Kotlin-native static analysis (incl. security rules) via detekt CLI; SARIF parsed |
| **gitleaks** | git history + working tree | Secret / credential detection (API keys, tokens, passwords) via gitleaks CLI; SARIF parsed |
| **gosec** | Go | Go-native security analysis; scans each detected Go module and preserves native severity and CWE data from SARIF |
| **hadolint** | Dockerfiles | Dockerfile linter (incl. embedded shell via ShellCheck); standalone Linux x64 binary; SARIF parsed natively |
| **zizmor** | GitHub Actions workflows | Workflow security (dangerous triggers, template-injection, unpinned actions, excessive permissions, credential persistence); standalone Linux x64 binary; runs `--offline`; SARIF parsed natively |
| **trufflehog** | any file | opt-in; secret detection with **live verification** — confirms a found credential actually works against its own provider API (AWS, GitHub, Slack, ...) instead of only pattern-matching; verified secrets are reported as `critical`, unverified as `high` |

Python engines are installed into isolated, version-pinned environments. OpenGrep does not require Python: PolyScan uses the exact pinned executable from `PATH` when available, otherwise it downloads and caches a SHA-256-verified standalone binary. Other downloaded tools are also cached and verified with SHA-256. SpotBugs is **build-aware** — for real Java/Kotlin projects it invokes the project's own build (Maven/Gradle) so the full dependency classpath is available, which is required to detect data-flow bugs (SQLi, command injection) on **Java** (FindSecBugs does not target Kotlin bytecode). For **Kotlin** code-security use **detekt**, which analyzes Kotlin source natively. gosec is downloaded only when Go files are present and requires the Go toolchain available on the runner. Trivy runs `--offline-scan` to avoid Maven Central rate limits.

**Default: `engines: "all"` expands to** `semgrep,bandit,eslint,spotbugs,trivy,detekt,gitleaks,gosec,hadolint,zizmor`. Each language-specific engine (gosec, detekt, hadolint, zizmor, …) runs a quick file-presence check and is skipped with no findings and no download when its file type isn't present, so `all` stays cheap on repositories that don't use that language. OpenGrep and trufflehog are explicit opt-ins and can be selected with `engines: "opengrep,trufflehog"` or combined with other engines.

`opengrep-config: "auto"` loads OpenGrep's automatic rules configuration and can require network access. Use a repository-local rule file, for example `opengrep-config: ".opengrep/rules.yml"`, for deterministic and offline-friendly scans.

trufflehog is opt-in because, unlike every other engine, its verification step makes live network calls to each credential's own provider API to confirm it actually works — a deliberately different (and non-deterministic, network-dependent) posture than the rest of PolyScan's offline scans. No extra token or permission is required: verification authenticates using the discovered credential itself, not a token supplied by PolyScan.

Read-only engines run with bounded concurrency (`max-concurrency`, default `2`). SpotBugs may invoke a project build and therefore runs as a serial barrier: all earlier engines finish before it starts, and later engines start only after it completes.

## Updating scanner tools

Scanner and helper-tool versions are pinned centrally in `tools.lock.json`.

```bash
npm run engines:list
npm run engines:check
npm run engines:check -- trivy semgrep opengrep
npm run engines:update -- trivy 0.73.0
npm run engines:update -- opengrep 1.26.0
npm run engines:update -- gosec 2.28.0
```

`engines:check` only reads official provider metadata. `engines:update` requires an explicit version, validates it against GitHub Releases, PyPI, npm, or Maven Central, verifies downloaded binary artifacts against provider checksums, updates the lock file, then runs the typecheck, tests, and production bundle build. Use `--dry-run` to verify an update without writing files. `--skip-project-checks` skips only the local typecheck, tests, and build; provider and artifact verification always remain enabled.

## Development

```bash
nvm use
npm install
npm run typecheck
npm run build      # bundles src/main.ts -> dist/index.js (must be committed)
```

> The `dist/` folder is committed on purpose — GitHub runs the bundled `dist/index.js` directly.

## Third-party tools & licenses

PolyScan itself is MIT-licensed, and its bundled `dist/index.js` only pulls in permissively
licensed npm dependencies — see the full, generated inventory in `dist/licenses.txt` (currently
MIT, Apache-2.0, ISC, BSD-3-Clause, BlueOak-1.0.0, 0BSD, and CC0; that file, not this README, is
the authoritative list). The scan engines below are **not** bundled or vendored: PolyScan installs
each one from its official distribution channel at scan time and invokes it as a separate
subprocess — PolyScan never links against or redistributes their code. Binary/archive downloads
(detekt, gitleaks, gosec, hadolint, the Kotlin compiler, opengrep, SpotBugs/FindSecBugs, Trivy,
trufflehog, zizmor) are SHA-256-verified against `tools.lock.json`; Semgrep and Bandit are
installed via `pip install <tool>==<version>` and ESLint via `npm install eslint@<version>`,
pinned to an exact version but relying on PyPI/npm registry integrity rather than PolyScan's own
checksum verification.

| Engine | License |
|---|---|
| ESLint, gitleaks, zizmor | MIT |
| Bandit, gosec, detekt, Kotlin compiler, Trivy | Apache-2.0 |
| Semgrep, OpenGrep, SpotBugs | LGPL-2.1 |
| FindSecBugs | LGPL-3.0 |
| hadolint | GPL-3.0 |
| trufflehog | AGPL-3.0 (opt-in only) |

**Semgrep's default rules — read this if you use PolyScan commercially.** Semgrep is scanned
with `--config auto`, which pulls Semgrep's own registry rules. Since late 2024 those rules are
licensed under the [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license/), which
restricts use to internal, non-SaaS, non-competing contexts — the Semgrep *engine* stays LGPL-2.1,
but its *default ruleset* does not. If you run PolyScan as part of a commercial SaaS offering or a
product that competes with Semgrep, select `opengrep` instead (`engines: "opengrep,..."`), which
maintains its own unrestricted rule set for exactly this reason.

## Versioning

Releases are tagged as semver (`vX.Y.Z`) with a floating major tag (e.g. `v16`) that always points at the latest `v16.x.y` — pin `@v16` for automatic minor/patch updates, or pin an exact `@vX.Y.Z`. Tags `v1` through `v15` predate this scheme (plain incrementing integers, not semver) and are kept as-is for existing consumers; the new scheme starts at `v16` precisely to avoid colliding with any of them. New usage should pin `@v16` or later. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT © Stefan Raisl
