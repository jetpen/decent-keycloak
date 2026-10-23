# Issue #6 — post-consume accepted-state publication failure

## Scope

This slice covers the post-consume boundary for one Keycloak node: publishing the callback gate and accepted receipt after the pending transaction has been consumed. A storage provider can commit a write and then throw, leaving the caller unable to tell whether state became visible.

The transaction store acquires an in-process publication gate before the first provider write, so same-node readers cannot observe partially published state. It treats either callback-gate or receipt publication exceptions as ambiguous, retains the handle in a process-local failed state, attempts best-effort removal of both records without masking the original exception, and rethrows. The gate is released only after successful receipt publication. The handler returns an empty HTTP 503 and logs only a fixed failure category with the opaque request-correlation ID. Polling, identical-proof retry, and callback consumption fail closed while publication is in progress or failed. A separate fresh transaction can succeed.

## Offline verification

`WalletLoginTransportHandlerTest` injects both callback-gate and accepted-receipt providers that commit their `replace` and then throw. A latch-based case holds the accepted-receipt write after commit and proves that concurrent same-node status, retry, polling, and callback access remain unavailable until publication completes and the injected throw is handled. Tests assert empty 503/no `Location`, no accepted receipt or callback gate remains in the provider, status/retry return 404, no callback can be consumed, and a separate fresh transaction succeeds after either receipt or callback-gate failure. Existing false-return publication-failure tests remain in place.

Run the focused tests with Java 21:

```bash
mvn -q '-Dtest=WalletLoginTransportHandlerTest#committedReceiptFollowedByProviderExceptionFailsClosed+acceptedReceiptIsHiddenWhileProviderPublicationCanStillFail+callbackRedemptionStartedBeforePublicationCannotConsumeAmbiguousReceipt+callbackGateCommitThenProviderExceptionFailsClosed+receiptPublicationFailureReturnsUnavailableAndCannotBePolledAsAccepted+callbackGatePublicationFailureReturnsUnavailableWithoutReceiptOrCallback' test
```

## Limits and open gates

This is controlled offline provider-double evidence only. It does not establish how an unmodified Keycloak/Infinispan provider behaves after a commit-then-throw, and it is not browser/OIDC Code+PKCE runtime evidence. The in-process gate preserves same-node fail-closed behavior during publication and after an exception; if best-effort cleanup also fails, a process restart loses that in-memory quarantine while provider-side state may remain, so restart recovery from double failure is not guaranteed. Cross-node failure semantics are not qualified. The separate test-image-only runtime fault-injection profile is documented in [`issue-6-postconsume-runtime.md`](issue-6-postconsume-runtime.md); it has not been run and is not production-provider evidence. Issue #6 expiry, changed-signature replay, live callback recovery, production-provider failure behavior, independent review, and remaining acceptance gates remain open.
