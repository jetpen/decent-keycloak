# Issue #7: Offline safe-retry boundary characterization

**Status:** Offline unit/application-path evidence only. This is not a live Keycloak qualification and does not close Issue #7.

## What the tests exercise

The tests in `WalletLoginTransportHandlerTest` characterize concurrent-submission admission and three failure boundaries using in-memory test doubles:

1. **Concurrent submissions for one handle.** The first handler acquires the transaction's identity-lookup slot and pauses in the resolver. A second simultaneous submission of the same handle receives 429 before provisioning or consume. The first request completes signup once, consumes the pending transaction, and publishes one accepted receipt and callback gate; a subsequent identical proof is handled as an accepted retry without another account provision. This is single-process handler behavior with an in-memory store, not a Keycloak backend or distributed guarantee.
2. **Pending consume lost after account provisioning.** During `ensureEnabledUser`, the test marks the exact identity as provisioned and removes the pending transaction from the in-memory `SingleUseObjectProvider` fake. The handler then attempts its normal consume operation, receives no transaction, and returns its handler-level 409 result. The fake retains the enabled identity; the old transaction has no accepted receipt or callback gate. A new explicit `SIGNUP` transaction using the same identity succeeds without another provisioning call and has its own accepted receipt and callback gate.
3. **Accepted-receipt publication fails after consume.** The handler provisions the identity and consumes the pending transaction. The fake then fails exactly once when the accepted receipt is replaced, after the callback gate has been published. The store's failure path removes that gate; the handler returns its handler-level 503 result, the old pending transaction is not restored, and no accepted receipt or callback gate remains for it. A fresh explicit `SIGNUP` transaction subsequently succeeds using the retained identity without another provisioning call.
4. **Consume storage throws after removal.** The fake removes the pending transaction and then throws from the provider operation. The handler returns 503 without publishing an accepted receipt or callback gate; a fresh explicit signup reuses the retained exact account.

The concurrent-submission case is a handler-level admission test: the second same-handle request is rate-limited before it can attempt consume. The separate consume-loss test injects a competing consume outcome at the account-provisioning boundary; it does **not** run two handler callers concurrently through consume. The concurrent-submission and injected consume-loss tests are characterization of existing behavior. The consume-store-exception regression was RED before adding handler-level exception handling and GREEN afterward. All account resolver and transaction provider behavior remains in-memory test evidence, not live Keycloak qualification.

## Residual state and recovery

After consume loss, receipt-publication failure, or consume-store exception, treat the old transaction as unusable: do not retry its proof or restore its consumed pending gate. The possibly visible enabled account is intentionally retained; do not delete it as compensation. Start a new wallet flow with explicit signup intent. The tests use a fresh session binding for that transaction and verify that the retained exact identity is reused; this setup avoids the test's per-session identity-lookup cooldown and does not establish a browser-session requirement for live deployments.

If a fresh explicit signup still cannot resolve the retained exact account, leave the account and consumed transaction unchanged and investigate the normal account-mapping/readback path. These tests do not establish what a user sees through HTTP or prove absence of an OIDC code or browser callback in a running Keycloak process; those remain live acceptance gates.

## Evidence boundary

Verified locally with `MAVEN_OPTS='-Xmx2g' mvn -q -o -Dtest=WalletLoginTransportHandlerTest test` and `MAVEN_OPTS='-Xmx2g' mvn -q -o clean package`. This is deterministic single-process application behavior using in-memory fakes. It is not evidence for Keycloak provider initialization, JPA behavior, the real Keycloak transaction store, HTTP status/callback/code behavior, production operation, or multi-node/distributed atomicity. Multi-node and distributed signup/replay guarantees remain out of scope.
