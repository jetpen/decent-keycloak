# Issue #6 — post-consume runtime fault-injection profile

## Status and scope

This is an opt-in, one-node runtime profile for the post-consume accepted-receipt failure boundary. It is deliberately test-image-only. The test-scope `SingleUseObjectProviderFactory` delegates to Keycloak's `infinispan` provider, commits the accepted-receipt `replace`, then throws once. It does not alter the production provider JAR or the production Docker target.

The profile checks that the proof request fails closed with an empty HTTP 503 and no redirect, the identical proof retry and initiating-browser status poll return empty 404 responses, and neither callback nor authorization code is exposed. It requires exactly one request-correlated production-handler failure marker and one fixed test-decorator commit-then-throw marker. A fresh login then exercises callback replay denial and Code+PKCE recovery; those later gates are reported separately and must pass for the profile to qualify.

This is not evidence about an unmodified Keycloak/Infinispan provider committing and throwing. It is also not multi-node or distributed evidence, and it does not close Issue #6. The test image and provider selector are test-only; the production provider JAR and production image remain separate. Further live invocation requires explicit authorization outside this document.

## Current interpretation after the replay-parser fix

**Final disposition:** both same-browser recovery profiles now pass strict replay and Code+PKCE after narrowly retiring the bound terminal-failure authentication child. The [final matrix](issue-6-qualification.md) contains immutable image IDs, durable receipts and unrelated-tab safety-test scope. The following failed-run notes are historical, not current blockers. Faults remain test-decorator-injected after real delegate writes; they are not provider-originated exceptions. Final independent review is pending.

Both decorator profiles have now been rerun on the parser-fixed harness. Their injected fault and fail-closed HTTP/status checks passed, but same-browser fresh recovery still failed at strict callback replay. A diagnostic receipt rerun recorded one new `expired_code` login error, not `already_logged_in`. See the [current qualification matrix](issue-6-qualification.md) for exact receipts and source/image identities. This supersedes the earlier statement that no decorator rerun occurred.

The latest production auth-only run passed replay/PKCE after correcting `error_description` handling in the harness (see README current result). This does not retroactively qualify these decorator runs: their direct login-actions redirects were a distinct observed outcome, and neither recovery profile was rerun with the fix. Complete decorator recovery remains open. Historical production `state absent`/origin-mismatch conclusions were derived by the faulty parser, not independent wire-level evidence.

## Historical bounded live attempt (2026-10-24)

The authorized one-node receipt-failure profile used image ID `2227fccc6d39746d419fe7ad51b9c5c0eefdf3e06e0c2b6edb09189ce8ed17ea`, digest `sha256:becdf59e0dddfd3ae8948e352f2f14b7a8b68bc40cab301cf703d4d36cb47d43`, and harness SHA-256 `0f171cfce3860a24791f0c8d19d16013c2039bc9c962fdb3eab3a7a2eaebe3ff`. It reported Keycloak 26.8.0 and one node. Effective `dev-file` DB was independently read; effective cache and the masked configured provider selector remained unavailable. The request-correlated test-provider witness identified the expected receipt decorator for the pending transaction; provider availability alone was not used as selection proof.

The decorator committed the accepted-receipt write and threw once. The proof response was empty HTTP 503 with no redirect; the identical retry and status poll were empty HTTP 404; no callback or OIDC code was exposed. The fixed fault marker was correlated exactly once. After the harness waited beyond the two-second shared identity-lookup cooldown, a fresh recovery proof succeeded and the first callback returned an authorization code. The replay request was captured without following redirects and returned HTTP 302 to `/auth/realms/wallet-e2e/login-actions/authenticate` with query names `client_data`, `client_id`, and `tab_id`; the response contained no `state`, `error`, or `code` parameter. This is not the registered RP redirect or the documented safe Keycloak error-page case, so replay qualification failed and Code+PKCE recovery did not run. The live wrapper-mediated receipt-failure/retry/status behavior is evidenced; complete recovery and production-provider behavior remain unqualified. After teardown there were no containers, volumes, or listeners on the checked test ports; the two pre-existing Podman networks remained.

## Current candidate rerun (2026-10-24; auth-only, no expiry)

The receipt-decorator and callback-gate profiles used source fingerprint `7ee5cf91725b99d43bb1324a1d19dcda39c2d8f69d1617b2d9642429f79047f4`, harness SHA-256 `87aab8cba94410e01fe15a5286579264eae3ff162c3263e26c7cbdc423c5edb6`, and Keycloak 26.8.0 on one node. Effective DB/cache were `dev-file`/local; the selected SPI path remained unavailable.

- Receipt image `6aaf7667e9954789829b7298515a2686a588e7126979ccee2a3c80fa222d4f76`, digest `sha256:faeca4359745df0c8d97199497df3880c4802cee3c6a2790e855154bb5754d0f`: request-correlated commit-then-throw count 1, empty proof 503, empty retry/status 404, no redirect/callback/code. The fresh recovery attempt ended in `RuntimeError` before a recovery checkpoint; do not infer whether replay or a later recovery step caused it. Receipt: `/home/ben/.hermes/cache/scratch/issue6-live-receipt-issue6-postconsume-receipt-failure-e22d01be6d9741679624c44053299dad.json`.
- Callback-gate image `66fba72c20f871f85eb3a022ab357b281c9bb793dae20e3de21823d89ff2dbc7`, digest `sha256:e2d43a4b9ce54bd7fa01639606138126ee6ce53a2410bf96c0a1600cb367aff7`: provider ID was advertised and configured as the command input, but selected path remained unavailable. The sanitized checkpoint stayed at `preflight` with `RuntimeError`; no injection/recovery was established. Receipt: `/home/ben/.hermes/cache/scratch/issue6-live-receipt-issue6-postconsume-callback-gate-failure-a4932335431640f0b7cda1535d1db8c8.json`.

The production `issue6-auth-flow` run on the same candidate still failed strict replay and stopped before PKCE. It did not invoke the 301-second expiry runner. Post-run container/network/volume/listener/CID inventories matched their baselines, with no credential env files or retained CID files. These are partial live results; Issue #6 remains open and not PR-ready. See the README's current-candidate table for full image/harness provenance.

## Replay root-cause investigation and candidate fix (not live-qualified)

The pinned Keycloak 26.8.0 `SessionCodeChecks` implementation handles an invalid action code whose execution still matches the current execution by setting the forwarded `expiredAction` message and redirecting to the latest flow path ([source](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/services/resources/SessionCodeChecks.java)). The follow-up request has no action code and enters `LoginActionsService.authenticate()`, which calls `AuthenticationProcessor.authenticate()` rather than dispatching the original authenticator `action()`. `DefaultAuthenticationFlow.isProcessed()` skips executions in `SUCCESS`, so a completion guard inside `WalletChallengeAuthenticator.authenticate()` is not sufficient if the callback execution remains successful. This source path explains the same-realm, code-less flow recovery, but does not alone explain the recorded replay destination/error fields.

The earlier completion-marker candidate marked the authentication session after the receipt was consumed and attempted `LoginProtocol.sendError` only if the authenticator was re-entered. The current offline candidate also registers the wallet authenticator as a Keycloak flow callback: after top-flow success it restores the wallet execution as `CHALLENGED` and records it as the current execution, so the code-less stale-action recovery can re-enter `authenticate()` and reach the existing protocol-denial guard. An offline regression drives the Keycloak 26.8.0 `DefaultAuthenticationFlow`: it starts with the wallet execution successful, verifies top-flow callback re-arming, then runs the code-less flow again and verifies `sendError` is invoked. This proves the framework seam and call path only; the test stubs the protocol response and does not verify its actual `Location`, stored RP redirect/state, or the live destination. The recorded live image predates this re-arm change and failed the strict destination/state gate (`redirect_origin_mismatch`). Whether the new candidate resolves that exact live failure remains unproven; do not count this offline test as replay, PKCE, expiry, or production-provider qualification.

## Offline checks

Run with Java 21:

```bash
mvn -q -o -Dtest=Issue6PostConsumeReceiptFailureProviderFactoryTest test
python3.11 -m unittest scripts.test_wallet_login_transport_e2e -v
mvn -q -o -DskipTests test-compile
python3.11 scripts/build_issue6_postconsume_provider.py
```

The provider-builder packages only the test-compiled decorator class and its test-scope service registration. The production runtime image continues to select `infinispan`; the separate `issue6-postconsume-test-runtime` target selects the decorator at Keycloak build time.

## Reproduction commands (further runtime requires fresh authorization)

The test-image target and the receipt-failure profile have already been run once. To rebuild the image and, after a separately authorized attempt, select it explicitly:

```bash
mvn -q -o -DskipTests test-compile
python3.11 scripts/build_issue6_postconsume_provider.py
IMAGE_SOURCE_SHA256="$(python3.11 scripts/lifecycle.py image-fingerprints --target issue6-postconsume-test-runtime --field image_source_sha256)"
IMAGE_ARTIFACTS_SHA256="$(python3.11 scripts/lifecycle.py image-fingerprints --target issue6-postconsume-test-runtime --field image_artifacts_sha256)"
podman build --target issue6-postconsume-test-runtime \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg IMAGE_SOURCE_SHA256="$IMAGE_SOURCE_SHA256" \
  --build-arg IMAGE_ARTIFACTS_SHA256="$IMAGE_ARTIFACTS_SHA256" \
  -f container/Dockerfile -t localhost/decent-keycloak/wallet-provider-issue6-postconsume-test:local .
WALLET_IT_PROFILE=issue6-postconsume-receipt-failure \
WALLET_IT_TEST_IMAGE=localhost/decent-keycloak/wallet-provider-issue6-postconsume-test:local \
python3.11 scripts/wallet_login_live_e2e.py
```

The profile refuses to run without `WALLET_IT_TEST_IMAGE`; it does not fall back to the regular runtime image. Successful output is projected through the existing bounded evidence sanitizer. It does not retain the transaction locator, proof, callback URL, authorization code, request handle, or raw logs.

## Qualification gaps

Current evidence includes the prior bounded attempts and candidate `7ee5cf...` reruns. On the current receipt-decorator image, the correlated commit-then-throw and fail-closed proof/retry/status outcomes passed, but fresh recovery exited with `RuntimeError` before recovery fields were checkpointed; the precise cause/outcome is unavailable. On the current callback-gate image, Keycloak reached 26.8.0/one node and advertised/configured the decorator ID, but the sanitized checkpoint remained at `preflight` with `RuntimeError`, so injection and recovery were not established. Effective DB/cache were `dev-file`/local, while selected provider path remained unavailable. Production-provider post-consume behavior, callback-gate injection/recovery, complete receipt recovery, strict replay/PKCE, changed-signature replay, and live expiry remain open. Do not treat the test decorator or its unit tests as production-provider qualification.

## Rebuild the isolated callback-gate test image

After a successful Java 21 offline Maven package, build the fault-injector JAR and compute the target-specific fingerprints before the image build:

```bash
mvn -q -o clean package
python3.11 scripts/build_issue6_callback_gate_provider.py
IMAGE_SOURCE_SHA256="$(python3.11 scripts/lifecycle.py image-fingerprints --target issue6-callback-gate-test-runtime --field image_source_sha256)"
IMAGE_ARTIFACTS_SHA256="$(python3.11 scripts/lifecycle.py image-fingerprints --target issue6-callback-gate-test-runtime --field image_artifacts_sha256)"
podman build --no-cache --pull=never --network=none \\
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \\
  --build-arg IMAGE_SOURCE_SHA256="$IMAGE_SOURCE_SHA256" \\
  --build-arg IMAGE_ARTIFACTS_SHA256="$IMAGE_ARTIFACTS_SHA256" \\
  --file container/Dockerfile --target issue6-callback-gate-test-runtime \\
  --tag localhost/decent-keycloak/wallet-provider-issue6-callback-gate-test:local .
```

The build is local and does not publish. Select the resulting image by immutable ID in the separate live-profile command only after the required runtime authorization.

## Callback-gate `putIfAbsent` commit-then-throw (offline implementation; live profile stopped at preflight)

The sibling profile is `issue6-postconsume-callback-gate-failure`; it uses a separate test-only provider factory, selector, builder JAR, Dockerfile target and sanitized evidence keys. The wrapper delegates the exact `decent-wallet-login-v1:callback:` `putIfAbsent` to Keycloak's `infinispan` provider, then throws once only after a successful commit. It leaves the accepted-receipt `replace` provider/profile unchanged. The callback-gate injector factory, its anonymous delegate implementation class, and service registration are packaged from `target/test-classes` only in the distinct test image target; the production application JAR and production Docker target remain unchanged. The receipt and callback-gate test-provider builders both package the outer factory and all matching nested/anonymous class files.

The offline orchestration regression enters `run_issue6_postconsume_callback_gate_failure_profile`, exercises the login/challenge/proof/retry/status endpoint sequence through the flow, verifies empty 503 proof failure, empty 404 retry/status, no redirect/callback/code, correlates the neutral request-scoped production failure marker with the fixed decorator marker, then runs the recovery orchestration and validates callback replay denial and PKCE status in final sanitized evidence. Backend/runtime dependencies are controlled test doubles; this is not evidence that an unmodified provider commits and throws or that live provider selection works.

Focused checks:

```bash
MAVEN_SKIP_RC=1 TMPDIR=/home/ben/.hermes/cache/scratch mise exec java@21.0.2 -- mvn -o -q -Dtest=Issue6PostConsumeCallbackGateFailureProviderFactoryTest test
python3.11 -m unittest scripts.test_wallet_login_transport_e2e.Issue6PostConsumeRuntimeProfileTest -v
```

**TDD record:** the first attempted pre-implementation dispatch probe raised the unsupported-profile `ValueError`, so it was not counted as RED. After implementation, the dedicated selector-diagnostic assertion was replayed against the isolated clean `HEAD` source and failed as expected because the callback-gate selector was absent from its allowlist message; the same assertion passes on this worktree. This is explicitly retroactive baseline sensitivity, not a claim of strict assertion-level RED chronology.

The authorized 2026-10-24 callback-gate live profile used source fingerprint `e722fee94c09c76c8f363183345738d9f6cdbe03285f6acdbd98be9bf951e7a1`, image ID `e8bf8aaacaaa6b3ae94837454bb72d55384416776ccc4cbd3b45b876ca52f1bf`, and digest `sha256:f108683e2d2f0bd25bd9ab97928a91e85629d882b277019338a80dd609b83cce`. Keycloak reported 26.8.0 and one node and advertised the test-provider ID, but the selected path was unavailable; the sanitized result remained at `preflight` with failure type `RuntimeError`. No callback-gate injection or recovery outcome was established, and the sanitized checkpoint does not identify the cause. Further live attempts require fresh explicit authorization. Production-provider and live callback-gate behavior remain unqualified; Issue #6 remains open.

## Latest checkpointed decorator reruns (2026-10-24)

The latest receipt-failure and callback-gate decorator runs used the source-input fingerprint and immutable image IDs/digests documented in the README's latest rerun table. Both reached recovery checkpoints rather than stopping before any recovery evidence. The receipt decorator produced one correlated commit-then-throw, empty proof 503 and retry/status 404; recovery passed login/challenge/proof/identical retry/changed retry/status and the first callback, then failed at `fresh_replay` with sanitized `runtime_error`. The callback-gate decorator likewise produced one correlated commit-then-throw and the empty 503/404 denial, then reached `fresh_replay` and failed there. Both replay responses were 302s to Keycloak's login-actions authenticate path with query names `client_data`, `client_id`, and `tab_id`, and no OIDC state, error, or code. The replay GETs disabled redirect following, so these are the direct first-response Locations. Guard-log reads succeeded, but no guard marker was observed; neither reached PKCE. This supports that the custom guard did not produce the observed replay response, but does not prove the precise Keycloak internal branch.

The earlier callback-gate preflight failure is now explained by Keycloak rejecting the synthetic user's email because the harness reused the deliberately invalid `.invalid` Identity ID as its email. The harness now assigns `wallet-owner@example.com` as the separate reserved synthetic email while keeping the Identity ID in its custom mapping attribute. The rerun reached the injected callback-gate failure and recovery path. The selected SPI provider path remains unavailable; provider advertisement/configuration is not selection evidence. These are test-decorator runs only, not production-provider fault qualification. No expiry attempt was made; production behavior, strict replay, PKCE, expiry, selected provider, and complete recovery remain unqualified. Issue #6 stays open.
