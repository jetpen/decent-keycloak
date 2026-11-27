# Issue #74 lifecycle migration status: offline/local/CI

This is a bounded offline/local/CI slice, not completion of Issue #74. Local instructions and PR workflow invoke the same `keycloakctl acceptance --profile offline` profile. It performs local preflight, repository suites, provider and test-RP image build/smokes, source-bound sanitized receipt, and whitespace checks; offline acceptance retains built images and records cleanup as `not_run`. The RP smoke executes its configured image entrypoint with network access disabled, starts a loopback listener on an ephemeral port, checks a fixed safe response, and shuts down without issuer access. This is startup evidence only, not RP browser/Keycloak or live qualification. Remote lifecycle, qualification, manual evidence, and publication are deferred. Legacy `--allow-live` is not owner approval. No live or remote operation was run. Keep all 10 Issue #74 acceptance criteria open until their specific gates are verified.

The crosswalk below distinguishes changed command entry points from phase ownership; a row marked **open** is not claimed migrated.

| Legacy capability/stage | Current keycloakctl route / public assertion | Status |
|---|---|---|
| profiles | `./keycloakctl acceptance --profile offline`; local docs and PR CI use the same profile | Local/CI selection unified. Live profiles remain separate. |
| preflight | Acceptance invokes local preflight before repository/build work | Local prerequisites and selected local engine checked; remote topology/readiness remains open. |
| java-tests | `keycloakctl acceptance` invokes `mvn --batch-mode --no-transfer-progress package` before Surefire validation | Keycloakctl sequences and receipts the Maven test/package step; deliberately omits `clean` to preserve run state under `target/`. |
| verify-surefire | Keycloakctl acceptance validates Surefire reports after Maven | Keycloakctl parses all produced XML suites, requires positive test totals, zero failures/errors/skips, and receipts the outcome. |
| python-tests | Executed directly by keycloakctl acceptance | Canonical 21-module selection, pinned resolver/dependency preparation, isolated paths, and stage receipt are shared; broader lifecycle/profile parity remains open. |
| python-compile | Executed directly by keycloakctl acceptance | Owned local stage and durable receipt. |
| verify-provider | Keycloakctl acceptance validates provider service registration in the production JAR after Surefire | Keycloakctl directly checks the exact AuthenticatorFactory service descriptor and receipts the result; the legacy lifecycle implementation remains for its other callers. |
| diff-check | Executed directly by keycloakctl acceptance | Checks the GitHub Actions PR base-to-HEAD diff when `PR_BASE_SHA` is set, then checks staged/unstaged changes and every nonignored untracked file; failures are recorded in the durable receipt. |
| resolver sources/dependencies | Direct keycloakctl build materializes pinned resolver sources and locked artifacts | Invoked by acceptance build; dedicated resolver-provenance receipt remains open. |
| provider-image build | `keycloakctl build` within acceptance builds provider image and records immutable identity | Included in the local acceptance run. Actual engine execution is reported only when the full command succeeds. |
| image-smoke | `keycloakctl test` within acceptance smokes provider image | Included in the local acceptance run; no production/runtime qualification implied. |
| RP fixture image build/smoke | Build/test stages include the test-only RP fixture image | Included; smoke executes the fixture entrypoint offline, binds loopback, verifies a fixed response, and closes. No browser/Keycloak flow. |
| offline/CI profile and receipt | Local docs and PR CI use `keycloakctl acceptance --profile offline` | Unified profile records executed gate outcomes and cleanup as `not_run`; built images remain available until explicit image cleanup; receipt does not close Issue #74. |
| wallet-login-qualification | Preserved on `scripts/lifecycle.py` behind `--allow-live` | Open; not invoked. |
| remote-test-host | Preserved on `scripts/lifecycle.py` behind `--allow-live` | Open; not invoked. |
| image-fingerprints | `./keycloakctl image-fingerprints --target ... --field ...` | Public CLI migrated; `scripts/lifecycle.py` no longer exposes this command, while keycloakctl reuses its fingerprint computation helper. |
| image retention | `./keycloakctl images cleanup|pin|unpin|extend` | Public CLI, options, and dispatch are keycloakctl-owned; safety routines remain in the shared `scripts/image_lifecycle.py` module. No engine operation was run in this slice. |
| promote | Existing separately authorized publication flow remains gated | Open; not invoked. |

## Evidence limits

Offline tests exercise the CLI and sanitized receipt plus stage/cleanup failure handling; workflow tests assert the same named profile. A successful local acceptance run requires real local image builds/smokes and ownership readback. Synthetic fixture checks are not a substitute for that run. Live qualification, remote host operations, transfer, readiness, and publication are not run. No issue criterion is closed by this document.
