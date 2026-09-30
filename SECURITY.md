# Security Policy

## Running PolyScan on untrusted code

Anyone with a GitHub account can open a pull request from a fork, so on such a run every file in
the workspace — including build files — is contributor-controlled.

PolyScan classifies a run as **untrusted** when the event is `pull_request` and the head repository
is not the base repository, and then skips the engines that would act on that code:

- **`spotbugs`** compiles the target with its own `mvn` / `gradle` build files, which executes
  contributor-controlled code on the runner.
- **`trufflehog`** makes live outbound requests to third-party provider APIs to verify candidate
  credentials found in the repository.

A `pull_request` whose head repository cannot be identified (missing, unparsable, or incomplete
event payload) fails closed and is treated as untrusted. Setting `allow-risky-engines: true`
disables this protection; only use it for workflows that do not scan contributor-supplied code.

`pull_request_target` is treated as trusted because it checks out the base ref by default. A
workflow that overrides the checkout to the pull request head combines untrusted code with the
base repository's secrets; PolyScan cannot detect that from the event, so it logs a warning
instead. Prefer `pull_request` for scanning contributor code.

## Supported Versions

Only the [latest release](../../releases/latest) is actively supported. Please upgrade before
reporting an issue if you're on an older release or a legacy (`v1`–`v15`) tag.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report it privately via [GitHub Security Advisories](../../security/advisories/new)
for this repository, or email stefan.raisl@gmail.com with a description of the issue, steps
to reproduce, and its potential impact.

You should expect an initial response within a few business days. Once a fix is available,
a new release will be published and the advisory disclosed.
