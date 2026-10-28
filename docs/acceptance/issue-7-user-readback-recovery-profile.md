# Issue #7: post-create UserProvider readback recovery profile

**Overall Issue #7 qualification:** PR #46 merged at `287584c079e2d1eddb5d982300dee964089bbfd3`; the seven-profile one-node matrix passes. Corrected-gate live reruns for empty, throwing, and over-cap readback preserved each original failed-ceremony subject through recovery signup, callback, and PKCE; consume-loss recovery did the same. See the [renewed campaign ledger](issue-7-renewed-qualification.md) for exact receipts and provenance. Faults are wrapper-mediated application-path evidence, not arbitrary provider-originated fault qualification. The accepted one-node scope is complete; multi-node/HA/distributed behavior remains unqualified.

## Status and scope

This file documents only the UserProvider readback profile; it does not by itself cover consume-loss or post-consume receipt-publication failure. Those gates were separately exercised in the passing one-node matrix with wrapper-mediated fault injection and are documented in the [renewed campaign ledger](issue-7-renewed-qualification.md). The in-memory handler tests linked below remain supporting characterization only, not standalone provider/runtime evidence.

The injected fault is test-only and **wrapper-mediated application-path evidence**: `Issue7FaultInjectingDatastoreProviderFactory` registers a `DatastoreProviderFactory` whose returned provider subclasses Keycloak's `DefaultDatastoreProvider`, preserving the concrete type required by `UserStorageManager`; its `userLocalStorage()` wraps the local `UserProvider` and injects one later query for the created model's `decent_identity_id` attribute. The fault helper supports `empty`, `throw`, and `over-cap`. The wrapper preserves the `UserCredentialStore` interface and never removes the created account. For `over-cap`, the 65 synthetic `UserModel` delegates expose distinct synthetic IDs; repeated rows with the created user's real ID would be de-duplicated by Keycloak 26.8's `UserStorageManager` before the mapping cap can see them. These synthetic candidates are not persisted users.

Three diagnostic-only Keycloak runs on the previous `UserProviderFactory` image `bb6fde2b87809750a3823e9215ec22f65290ef3d72dc1b49662e2d050997eae4` / `sha256:429604c2b52410c5887dfa5b9c203287d34cf848bed0896750a641e5070ad9f4` each created and read back a synthetic user successfully, but recorded zero test-factory and mode markers. The third run with `DefaultKeycloakSessionFactory` debug enabled showed the `user` SPI default resolving to `issue7-user-readback-fault` while that `UserProviderFactory` was not invoked. These were diagnostics, not Issue #7 profile attempts.

The first datastore-wrapper image `353209e0700572b720e2104ee819f9bd5cc6b0fe48dd38a1ce9ec767fd1944a6` / `sha256:5a73e7df47a89d16556b382db7cc1dca3bdd646bdaaa4be3924191cf391d44d7` was started once; discovery timed out before token or synthetic-user operations. That version of the probe collected logs only after successful operations, so marker counts for that run are unavailable, not zero. The probe was then updated with a sanitized startup/error summary and four offline classifier tests. It was run once against the post-`postInit`-fix image below, before the database-build-config correction; discovery again timed out, reporting `keycloak_started=false`, 3 error lines, and 3 exception lines. It ran no token or synthetic-user operation; the raw lines were not retained, so the startup cause is still unknown. These were diagnostic-only runs, not profile attempts. After the second run, cleanup was verified: no regular/external containers remained, port 18887 was free, and `wallet-login-test-net` retained ID `d9d58c11d12fdde5a31365af53b802a2cbb8ada10250712f0dead73ba5936a73` with no members.

Offline Keycloak 26.8 bytecode inspection established that `DefaultDatastoreProviderFactory.postInit()` registers the factory and `UserStorageEventListener` and wires their unregistration on close. The test factory had overridden it with a no-op. A regression failed with zero listener registrations before the fix; the factory now calls `super.postInit(factory)`, and the regression passes. This lifecycle defect is confirmed, but it is **not established as the cause** of the discovery timeout. The diagnostic image `ee809653ef82dd16786c332c42b28da00fd282e3d94474040cec3eb34ed7dfee` / `sha256:1819f61594b9df433fa80887b1f4c5f33ae6cf57f4b004223a29f34862bf6c57` was built after the lifecycle fix and started once; discovery still timed out. Its build emitted a warning about the production-profile DB default. Offline comparison found that the test target's second `kc.sh build` specified only the datastore SPI, unlike the runtime target's explicit `--db=dev-file`, `--cache=local`, and `infinispan` settings. A focused Dockerfile regression failed before the correction and passes after; the test target now repeats those settings with the datastore default. This is a plausible configuration cause, not a proven explanation for the timeout. The corrected image `82042abb87f89c7d493d85b685504554f21bf0acbe9df7624351670dfe8f0196` / `sha256:f25ce294ce9e55e438c5c7f710ac764995e5765ea1e7bb761ae369a6dd3b4b92` was then built with the explicit test DB/cache/SingleUseObject/datastore settings, and a first authorized diagnostic-only run was performed against that immutable ID. Startup timed out before discovery; the sanitized summary reported `keycloak_started=false`, 3 error lines, 3 exception lines, and zero factory/mode/operation/fault/outcome markers. No token or synthetic-user operation occurred. A second authorized diagnostic-only run used the same exact image after extending the offline sanitizer with bounded exception-class and approved-package stack-frame extraction. It also timed out before discovery with 3 error lines and 3 exception lines; the sanitizer extracted no exception classes or stack frames, and again no provider/fault/operation/outcome markers or user operation occurred. A third authorized startup-only diagnostic used `start --optimized --hostname=localhost --http-enabled=true` against the same image and reached OIDC discovery (`keycloak_started=true`, zero errors/exceptions). It performed no token or synthetic-user operation, so zero provider markers are expected and do not establish provider selection. The difference supports the startup-mode mismatch as a plausible cause of the earlier timeouts, not a proven root cause; the [Keycloak 26.8 configuration guide](https://www.keycloak.org/docs/26.8.0/server/configuration) recommends `start --optimized` for a prebuilt image. Cleanup after all three runs was verified: no regular or external containers or volumes remained, port 18887 was free, and `wallet-login-test-net` retained its original ID with no members. No Issue #7 profile was retried. Any further runtime probe or profile requires fresh authorization. Offline tests do not qualify runtime provider selection, local-JPA behavior, HTTP/browser behavior, callback/receipt state, or recovery. The expanded scratch sanitizer suite passes 4 tests. No multi-node or distributed guarantee is claimed.

## Profile selectors and image separation

`WALLET_IT_PROFILE` accepts:

- `issue7-user-readback-empty` — the exact post-create read returns empty;
- `issue7-user-readback-throw` — that read throws;
- `issue7-user-readback-overcap` — the read returns 65 distinct synthetic candidate IDs.

All three require `WALLET_IT_USER_READBACK_IMAGE`. Missing configuration and unknown selectors fail before image inspection or external setup. The selected image is inspected and the harness continues with the resolved immutable image ID. The image is isolated from production:

- normal production target: `runtime`;
- test-only target: `issue7-user-readback-test-runtime`;
- test SPI provider JAR: `target/issue7-user-readback-provider.jar`;
- build-time datastore provider selection in the test target: `--spi-datastore--provider-default=issue7-user-readback-fault`;
- runtime environment supplied to the detached Keycloak container: `ISSUE7_USER_READBACK_FAULT_MODE=<empty|throw|over-cap>`.

Prepare the artifact/image only when appropriate for the authorized test environment:

```bash
JAVA_HOME=/usr/lib/jvm/java-21-openjdk PATH=/usr/lib/jvm/java-21-openjdk/bin:$PATH \
  MAVEN_OPTS='-Xmx2g' mvn -o clean package
python3 scripts/build_issue7_user_readback_provider.py
podman build --no-cache --pull=never --network=none \
  --file container/Dockerfile --target issue7-user-readback-test-runtime \
  --tag decent-keycloak-issue7-test:local .
```

Then explicitly select the chosen mode and the separately built test image:

```bash
WALLET_IT_PROFILE=issue7-user-readback-empty \
WALLET_IT_USER_READBACK_IMAGE=decent-keycloak-issue7-test:local \
python3 scripts/wallet_login_live_e2e.py
```

The harness resolves the tag to an immutable image ID/digest before startup. The command above is documentation only; running it is not authorized by this implementation task.

## Required runtime path and evidence

For each selected mode, the production entry point must dispatch to the dedicated coordinator. The coordinator performs:

1. one explicit signup transaction with a fresh valid proof/current Identity lookup and the selected one-shot post-create readback fault;
2. assertion of an empty 503 with no newly followed redirect, callback, or code;
3. a pending status read using the initiating browser's cookie jar, with no callback/code fields;
4. an Admin readback showing exactly one enabled local user with the exact Identity mapping, retained after the failed request;
5. bounded startup evidence for the test factory and effective mode, plus a per-run log window beginning at a UTC cursor immediately before the proof; the sanitizer requires one fault marker and a request-correlated `IdentityMappingUnavailableException` mapping failure, and serializes only allowlisted booleans, mode enums and counts;
6. a wait longer than the production two-second identity-lookup admission cooldown;
7. a fresh explicit signup transaction, requiring the same retained local subject, exactly one enabled exact mapping, callback, and PKCE token exchange.

The retry uses a fresh browser client. The profile records the fault origin as `wrapper-mediated-application-path`, not as a production JPA/provider-originated fault. Checkpoints retain the last setup/flow stage and bounded evidence; raw logs, identifiers, transaction handles, proof material, callback URLs, tokens and exception messages are not serialized. The final `issue7_single_node_signup_recovery` object is passed through the normal checkpoint sanitizer.

## Offline verification and historical attempts

The focused Python module exercises selectors, image guards, dispatcher/coordinator ordering through the production entry point, setup-stage and final sanitized checkpoints, redirect/code predicates, bounded log collection, request correlation, cooldown synchronization, and the test-provider packaging helper. An all-mode offline regression dispatches through `main()` and the production profile table, executes the real readback coordinator and real `signup_wallet_flow` for both failed and fresh signup ceremonies, and scripts browser/wallet HTTP plus exact Admin readbacks for `empty`, `throw`, and `over-cap`. It verifies empty 503/no followed redirect or callback/code, pending browser status, retained single enabled exact account, correlated fault evidence, fresh transaction/handle and cooldown, successful callback/replay/state/PKCE, same-subject recovery, and sanitized checkpoints without raw identity, subject, locator, code, challenge or token. Only external setup/network boundaries are mocked; the entrypoint, coordinator and signup flow are not. This is scripted offline characterization, not an actual UserProvider/JPA/runtime execution. The ordinary signup-success entrypoint test also drives the real `signup_wallet_flow` through scripted HTTP and external setup mocks, including callback/replay and PKCE. The flow returns `local_subject_matches_expected` only when an existing subject is being checked, and both Issue #7 recovery consumers use that boolean instead of requiring a raw subject field; regression assertions verify ordinary signup does not manufacture a subject-match result and returned flow objects contain no raw subject. Focused Java tests exercise empty/throw/over-cap injection, retained-account behavior and credential-store delegation, including distinct synthetic IDs for the over-cap stream. `WalletLoginTransportHandlerTest.wrapperReadbackFaultsLeaveSignupPendingAndFreshExplicitSignupRecoversRetainedAccount` additionally composes the actual test `UserProvider` wrapper factory, actual `WalletLoginAccountMapping` methods, an in-memory transaction store, and public `WalletLoginTransportHandler.submitProof` for both `empty` and `throw`. Each first explicit signup returns an empty 503 while remaining pending without an accepted receipt or callback gate; one exact enabled account is retained and never removed. A distinct fresh root-session binding then starts a fresh explicit signup with a new challenge-bound proof and returns 202 by exact enabled-account lookup, without a second `addUser`; the first failed transaction remains pending/unaccepted. Because the retry uses a different root-session binding, this test does not exercise identity-lookup cooldown expiry; the focused Python coordinator tests cover its wait logic separately. This is test-wrapper-mediated, in-memory, single-process handler/application-path characterization only. The delegate is a mock, not Keycloak JPA. The all-mode Python test scripts HTTP/browser status, callback, replay, code, token and recovery; it does not invoke a running Keycloak server or actual UserProvider/JPA. No Registry or runtime qualification is exercised by these offline tests.

Historical 2026-10-27 attempts: the original empty run exited 1 without retained detailed evidence; throw and over-cap exited 1 at the proof-status gate before recovery. Those attempts remain unchanged as failed/incomplete records. The corrected-gate reruns later passed and are recorded in the [renewed qualification ledger](issue-7-renewed-qualification.md); this history does not describe current qualification status.
