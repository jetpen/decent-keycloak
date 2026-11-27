## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues for `jetpen/decent-keycloak`.
Before working with tickets, read `docs/agents/issue-tracker.md`.

### Triage labels

Use the five default triage labels.
Before triaging issues, read `docs/agents/triage-labels.md`.

### Domain docs

Use a single-context layout: root `GLOSSARY.md` and `docs/adr/`.
Before exploring the codebase, read `docs/agents/domain.md`.

## Development lifecycle

Before opening any PR whose CI runs project acceptance, complete the local lifecycle first: use a deterministic CLI and supporting scripts to preflight local prerequisites (including a Java 21-compatible runtime, Maven, rootless Podman, and project-specific dependencies), build from source, run and verify unit tests, and complete the local acceptance checks. CI should be independent verification rather than the first meaningful test run.

A PR that closes its owning issue must also satisfy that issue's required remote lifecycle before publication: tag and publish or transfer the exact image artifact for remote execution, perform one-time remote-host setup, preflight remote readiness, deploy disposable test instances, run and verify integration tests, tear those instances down, and provide ownership-scoped cleanup after the PR merges. Keep these phases explicit and reproducible, verify each phase's outputs before advancing, and preserve pre-existing or otherwise unowned remote resources.

A non-closing PR, including a partial checkpoint that references an issue without closing it, requires the local lifecycle only; remote transfer, remote-host setup, readiness preflight, deployment, integration tests, and remote teardown are not prerequisites to opening it. Keep the issue open and describe the remaining remote acceptance gates without implying that local evidence completes them. Remote operations remain subject to the issue's authorization requirements.
