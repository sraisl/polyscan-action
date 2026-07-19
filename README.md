# PolyScan Action

**Multi-language SAST as a native GitHub Action.** One step runs all configured security engines — Semgrep, Bandit, ESLint, SpotBugs, detekt and Trivy — normalizes every result into a single schema, enforces a configurable **Quality Gate**, and emits **SARIF**, a **CycloneDX SBOM** and a rich **job summary** — plus optional artifact upload.

Written in TypeScript, bundled with `@vercel/ncc`, runs as a native GitHub Action on the `node24` runtime.

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
      - uses: actions/checkout@v4

      - uses: sraisl/polyscan-action@v1
        with:
          target: "."
          engines: "semgrep,bandit,eslint,spotbugs"
          max-critical: "0"
          max-high: "0"
          max-medium: "50"
          gate: "true"
          sarif: "true"
          sbom: "true"
          upload-artifacts: "true"

      # optional: push SARIF into GitHub Code Scanning
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: polyscan.sarif
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `target` | `.` | Path to scan |
| `engines` | `semgrep,bandit,eslint` | Comma-separated: `semgrep,bandit,eslint,spotbugs` |
| `max-critical` | `0` | Max critical findings before the gate fails |
| `max-high` | `0` | Max high findings before the gate fails |
| `max-medium` | `50` | Max medium findings before the gate fails |
| `gate` | `true` | Enforce the Quality Gate (fail the job) |
| `sarif` | `true` | Write `polyscan.sarif` (SARIF 2.1.0) |
| `sbom` | `false` | Write `polyscan.sbom.json` (CycloneDX 1.5) |
| `upload-artifacts` | `true` | Upload SARIF + SBOM + summary as a workflow artifact |
| `upload-sarif` | `false` | Hint to upload SARIF to code scanning (use the CodeQL step) |
| `output-dir` | `.` | Directory for generated reports |

## Outputs

| Output | Description |
|---|---|
| `total` | Total findings |
| `critical` / `high` / `medium` / `low` | Counts per severity |
| `gate-passed` | `'true'` / `'false'` |
| `sarif-file` | Path to the SARIF file |
| `sbom-file` | Path to the SBOM file |

## Engines

| Engine | Languages | Notes |
|---|---|---|
| **Semgrep** | many | `--config auto` |
| **Bandit** | Python | installed via pip on demand |
| **ESLint** | JS/TS | `no-eval` / `no-implied-eval` / `no-new-func` |
| **SpotBugs + FindSecBugs** | Java + Kotlin | **build-aware**: runs `mvn compile` / `gradle classes` when a build file is present (full dependency classpath), else falls back to direct `javac`/`kotlinc` |
| **Trivy** | deps + IaC | SCA (vulnerable dependencies / CVEs) + misconfig; binary downloaded on demand |
| **detekt** | Kotlin | Kotlin-native static analysis (incl. security rules) via detekt CLI; SARIF parsed |

Python engines are auto-installed via `pip`; SpotBugs, Trivy and detekt are downloaded on demand. SpotBugs is **build-aware** — for real Java/Kotlin projects it invokes the project's own build (Maven/Gradle) so the full dependency classpath is available, which is required to detect data-flow bugs (SQLi, command injection) on **Java** (FindSecBugs does not target Kotlin bytecode). For **Kotlin** code-security use **detekt**, which analyzes Kotlin source natively. Trivy runs `--offline-scan` to avoid Maven Central rate limits.

**Default: all engines run** (`semgrep,bandit,eslint,spotbugs,trivy,detekt`). Restrict via the `engines` input, e.g. `engines: "spotbugs,trivy,detekt"`.

## Development

```bash
npm install
npm run typecheck
npm run build      # bundles src/main.ts -> dist/index.js (must be committed)
```

> The `dist/` folder is committed on purpose — GitHub runs the bundled `dist/index.js` directly.

## License

MIT © Stefan Raisl
