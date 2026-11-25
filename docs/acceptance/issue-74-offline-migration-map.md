# Issue #74 lifecycle migration status: offline/local/CI

This is a partial caller and phase migration, not completion of Issue #74. Local instructions and the PR workflow invoke `keycloakctl acceptance --profile offline|ci`; keycloakctl directly sequences Maven `package`, Surefire validation, provider service registration, Python tests, Python compilation, and whitespace checking. The Surefire and provider-registration checks are implemented directly in keycloakctl. The PR workflow change deliberately narrows the prior `scripts/lifecycle.py run ci` behavior: the current PR job no longer runs legacy image build/smoke or lifecycle cleanup gates. Those gates are deferred and remain open; a green keycloakctl PR job does not establish parity with the former full offline CI profile. Preflight, dedicated resolver-input receipts, image build/smoke, and teardown remain open. No live/engine qualification was run in this implementation slice. Keep all 10 Issue #74 acceptance criteria open until their specific gates are verified.

The legacy crosswalk in the implementation notes enumerates 16 capabilities. Status below distinguishes changed command entry points from phase ownership; a row marked **open** is not claimed migrated.

| Legacy capability/stage | Current keycloakctl route / public assertion | Status |
|---|---|---|
| profiles | `./keycloakctl acceptance --profile offline|ci`; public CLI limits profiles to offline/ci | Caller selection preserved. Complete profile-plan parity remains open. |
| preflight | Legacy offline runner still performs preflight and writes its lifecycle receipt | Open: not a keycloakctl-owned phase receipt. |
| java-tests | `keycloakctl acceptance` invokes `mvn --batch-mode --no-transfer-progress package` before Surefire validation | Keycloakctl sequences and receipts the Maven test/package step; deliberately omits `clean` to preserve run state under `target/`. |
| verify-surefire | Keycloakctl acceptance validates Surefire reports after Maven | Keycloakctl parses all produced XML suites, requires positive test totals, zero failures/errors/skips, and receipts the outcome. |
| python-tests | Executed directly by keycloakctl acceptance | Canonical 21-module selection, pinned resolver/dependency preparation, isolated paths, and stage receipt are shared; broader lifecycle/profile parity remains open. |
| python-compile | Executed directly by keycloakctl acceptance | Owned local stage and durable receipt. |
| verify-provider | Keycloakctl acceptance validates provider service registration in the production JAR after Surefire | Keycloakctl directly checks the exact AuthenticatorFactory service descriptor and receipts the result; the legacy lifecycle implementation remains for its other callers. |
| diff-check | Executed directly by keycloakctl acceptance | Checks the GitHub Actions PR base-to-HEAD diff when `PR_BASE_SHA` is set, then checks staged/unstaged changes and every nonignored untracked file; failures are recorded in the durable receipt. |
| resolver sources/dependencies | Legacy lifecycle materializes pinned resolver sources and locked artifacts | Open: keycloakctl-owned phase, provenance receipt, and cleanup assertions remain. |
| provider-image build | Legacy lifecycle builds and records immutable image identity | Open: no keycloakctl-owned build receipt; intentionally not run here. |
| image-smoke | Legacy lifecycle performs runtime image smoke | Open: engine-backed qualification intentionally not run. |
| RP fixture image build/smoke | Legacy lifecycle has the optional fixture path | Open: remains outside this caller migration and not run. |
| offline/CI profile and receipt | Local docs and PR CI use `keycloakctl acceptance` with their respective named profiles | The keycloakctl-owned receipt records Maven package, Surefire validation, provider-registration, Python-test, Python-compile, and diff-check outcomes; remaining parity, detailed provenance, and cleanup assertions remain open. |
| wallet-login-qualification | Preserved on `scripts/lifecycle.py` behind `--allow-live` | Open; not invoked. |
| remote-test-host | Preserved on `scripts/lifecycle.py` behind `--allow-live` | Open; not invoked. |
| image-fingerprints | Existing legacy image-fingerprint command remains | Open; no change in this slice. |
| promote | Existing separately authorized publication flow remains gated | Open; not invoked. |

## Evidence limits

The focused public CLI regressions verify the ordered Maven/Surefire/provider-registration/Python stages and durable receipts on success/failure; workflow tests assert the named CI profile and local-only workflow configuration. Surefire parsing and provider-JAR inspection are keycloakctl-owned. These checks do not prove that each legacy stage is now implemented by keycloakctl, nor do they qualify build/runtime/cleanup behavior. Live qualification, remote host operations, image builds/smokes, and publication are explicitly not run. No issue criterion is closed by this document.
