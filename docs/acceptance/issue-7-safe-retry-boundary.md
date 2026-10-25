# Issue #7 single-node safe-retry boundary (offline evidence)

## Ambiguous pending-consume outcome

`WalletLoginTransportHandlerTest.consumeThrowsAfterRemovingPendingFailsClosedAndFreshSignupRecovers` uses an in-memory `SingleUseObjectProvider` fake that removes the pending transaction and then throws. It asserts a 503 response, no accepted receipt or callback gate for the old handle, an unpollable old handle, and retention of the exact enabled account. A new explicit signup transaction for the same identity succeeds without a second provisioning call. This is handler-level evidence with a stubbed identity-key resolver; it does not exercise real Registry proof/currentness checks, Keycloak HTTP callbacks, or code issuance.

## Receipt-publication failure

The existing `WalletLoginTransportHandlerTest.acceptedReceiptWriteFailureLeavesCreatedAccountBeforePendingConsume` test uses an in-memory fake that rejects accepted-receipt publication after consume. It asserts no accepted receipt/callback gate or old-transaction recovery is exposed and that a fresh explicit signup reuses the retained account. This also does not qualify provider persistence or real callback/code behavior.

## Residual state and recovery

After an ambiguous consume that removed the pending key, the original transaction has no accepted receipt and is unusable; after consume succeeds but receipt publication fails, the consumed transaction likewise cannot be replayed or restored. The account is intentionally retained because deleting it could remove a concurrent winner. The intended runtime recovery is a fresh, explicitly authorized signup that repeats proof and Registry checks before resolving the exact enabled account rather than provisioning again; the unit tests stub the key resolver and do not establish those Registry checks. Empty, unavailable, or over-cap account readback must fail closed without deleting a possibly visible account. Operators should investigate retained account/store state; do not manually restore an old transaction or remove an account without establishing ownership.

These are Java unit tests against fakes, not Keycloak runtime, JPA/provider, Registry, browser, HTTP, or live-profile evidence. They do not establish persistence semantics or distributed atomicity. Multi-node, HA, and distributed guarantees remain out of scope for Issue #7.