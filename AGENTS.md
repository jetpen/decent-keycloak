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

Before opening a PR whose CI runs project acceptance, the development lifecycle must be deterministic and controllable through a CLI and supporting scripts, with local checks completed first so CI is independent verification rather than the first meaningful test run. The lifecycle must preflight local prerequisites (including a Java 21-compatible runtime, Maven, rootless Podman, and project-specific dependencies), build from source, run and verify unit tests, tag and publish or transfer the exact image artifact for remote execution, perform one-time remote-host setup, preflight remote readiness, deploy disposable test instances, run and verify integration tests, tear those instances down, and provide ownership-scoped cleanup after the PR merges. Keep these phases explicit and reproducible, verify each phase's outputs before advancing, and preserve pre-existing or otherwise unowned remote resources.
