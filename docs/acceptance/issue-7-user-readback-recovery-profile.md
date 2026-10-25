# Issue #7: post-create UserProvider readback recovery profile

## Status and scope

This isolated harness slice implements a runnable single-node profile for failures in the exact local-account readback that follows `UserProvider.addUser`. It does **not** implement or qualify every Issue #7 acceptance boundary. Pending-consume-loss and post-consume receipt-publication failure remain outside this image profile; separate offline handler-level fake tests cover those safe-retry boundaries in [`issue-7-safe-retry-boundary.md`](issue-7-safe-retry-boundary.md), without qualifying real provider/runtime behavior. Issue #7 remains open.

The injected fault is test-only and **wrapper-mediated application-path evidence**: `Issue7FaultInjectingUserProviderFactory` delegates to Keycloak's `jpa` `UserProvider`, records the created model after `addUser`, then injects exactly one later query for that model's `decent_identity_id` attribute. It supports `empty`, `throw`, and `over-cap`. The wrapper preserves the `UserCredentialStore` interface and never removes the created account. For `over-cap`, the 65 synthetic `UserModel` delegates expose distinct synthetic IDs; repeated rows with the created user's real ID would be de-duplicated by Keycloak 26.8's `UserStorageManager` before the mapping cap can see them. These synthetic candidates are not persisted users.

No Podman/Docker, Keycloak, Registry, or profile invocation was performed while preparing this slice. A live run needs fresh explicit authorization. Offline tests do not qualify local-JPA behavior, a running provider, HTTP/browser behavior, callback/receipt state, or runtime recovery. No multi-node or distributed guarantee is claimed.

## Profile selectors and image separation

`WALLET_IT_PROFILE` accepts:

- `issue7-user-readback-empty` — the exact post-create read returns empty;
- `issue7-user-readback-throw` — that read throws;
- `issue7-user-readback-overcap` — the read returns 65 distinct synthetic candidate IDs.

All three require `WALLET_IT_USER_READBACK_IMAGE`. Missing configuration and unknown selectors fail before image inspection or external setup. The selected image is inspected and the harness continues with the resolved immutable image ID. The image is isolated from production:

- normal production target: `runtime`;
- test-only target: `issue7-user-readback-test-runtime`;
- test SPI provider JAR: `target/issue7-user-readback-provider.jar`;
- build-time provider selection in the test target: `--spi-user--provider-default=issue7-user-readback-fault`;
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

## Offline verification and remaining gates

The focused Python module exercises selectors, image guards, dispatcher/coordinator ordering through the production entry point, setup-stage and final sanitized checkpoints, redirect/code predicates, bounded log collection, request correlation, cooldown synchronization, and the test-provider packaging helper. Its coordinator tests still stub `signup_wallet_flow`; they do not drive this readback fault and retry through the production entry point/coordinator using the real `signup_wallet_flow` with scripted HTTP. Focused Java tests exercise empty/throw/over-cap injection, retained-account behavior and credential-store delegation, including distinct synthetic IDs for the over-cap stream. `WalletLoginTransportHandlerTest.wrapperReadbackFaultsLeaveSignupPendingAndFreshExplicitSignupRecoversRetainedAccount` additionally composes the actual test `UserProvider` wrapper factory, actual `WalletLoginAccountMapping` methods, an in-memory transaction store, and public `WalletLoginTransportHandler.submitProof` for both `empty` and `throw`. Each first explicit signup returns an empty 503 while remaining pending without an accepted receipt or callback gate; one exact enabled account is retained and never removed. A distinct fresh root-session binding then starts a fresh explicit signup with a new challenge-bound proof and returns 202 by exact enabled-account lookup, without a second `addUser`; the first failed transaction remains pending/unaccepted. Because the retry uses a different root-session binding, this test does not exercise identity-lookup cooldown expiry; the focused Python coordinator tests cover its wait logic separately. This is test-wrapper-mediated, in-memory, single-process handler/application-path characterization only. The delegate is a mock, not Keycloak JPA; no Keycloak server, real provider, HTTP/browser, Registry, callback/code, or runtime recovery is exercised.

The profile itself remains **not run**. Separate offline handler tests cover consume-loss and receipt-publication failure using in-memory fakes (see [`issue-7-safe-retry-boundary.md`](issue-7-safe-retry-boundary.md)), but they do not qualify real provider/store semantics, callbacks, code, or recovery. The following are unqualified: live Keycloak 26.8 provider selection and local JPA behavior; actual HTTP/browser/status/callback/code/receipt behavior; live retry and same-subject recovery; pending-consume loss after provisioning; receipt-publication failure after consume; full Issue #7 acceptance; multi-node/distributed behavior (out of scope). Do not close Issue #7 or describe this offline slice as runtime qualification.
