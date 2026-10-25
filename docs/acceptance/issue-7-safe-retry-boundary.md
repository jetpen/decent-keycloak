# Issue #7 single-node safe-retry boundary (offline evidence)

## Ambiguous pending-consume outcome

`WalletLoginTransportHandlerTest.consumeThrowsAfterRemovingPendingFailsClosedAndFreshSignupRecovers` uses an in-memory `SingleUseObjectProvider` fake that removes the pending transaction and then throws. It asserts a 503 response, no accepted receipt or callback gate for the old handle, an unpollable old handle, and retention of the exact enabled account. A new explicit signup transaction for the same identity succeeds without a second provisioning call. This is handler-level evidence with a stubbed identity-key resolver; it does not exercise real Registry proof/currentness checks, Keycloak HTTP callbacks, or code issuance.

## Distinct-transaction local account/consume interleaving

`WalletLoginTransportHandlerTest.distinctSignupTransactionsPreserveConcurrentAccountWinnerWhenOneConsumeLoses`
runs two explicit signup transactions with different handles and root sessions for the same exact
identity through the public handler. Both pass three synchronized pre-create lookups and reach the
production account-mapping path. The test delegates to the actual `WalletLoginAccountMapping`
methods, while a domain-keyed in-memory `UserProvider` models one deterministic-username winner;
only the production setters configure that account, and the losing create reads it back after it is
exactly mapped and enabled. A `SingleUseObjectProvider` fake removes the selected pending key only
when its production atomic-remove boundary is reached, after the other transaction has published
its accepted receipt.

The test asserts one exact enabled account, one accepted winner, no receipt/callback/status or
response data/Location for the consume loser, no account deletion, and a fresh explicit signup
that reuses the exact winner without another create. The consume-loss is injected at the local
store boundary; this is not a second Keycloak request consuming that distinct transaction. This
is single-process application characterization only: the in-memory providers do not qualify
Keycloak runtime, JPA/provider persistence or atomicity, Registry/HTTP/browser callbacks, or OIDC
code issuance. The empty handler response establishes only that this code path exposes no code.

## Receipt-publication failure

The existing `WalletLoginTransportHandlerTest.acceptedReceiptWriteFailureLeavesCreatedAccountBeforePendingConsume` test uses an in-memory fake that rejects accepted-receipt publication after consume. It asserts no accepted receipt/callback gate or old-transaction recovery is exposed and that a fresh explicit signup reuses the retained account. This also does not qualify provider persistence or real callback/code behavior.

## Residual state and recovery

After an ambiguous consume that removed the pending key, the original transaction has no accepted receipt and is unusable; after consume succeeds but receipt publication fails, the consumed transaction likewise cannot be replayed or restored. The account is intentionally retained because deleting it could remove a concurrent winner. The intended runtime recovery is a fresh, explicitly authorized signup that repeats proof and Registry checks before resolving the exact enabled account rather than provisioning again; the unit tests stub the key resolver and do not establish those Registry checks. Empty, unavailable, or over-cap account readback must fail closed without deleting a possibly visible account. Operators should investigate retained account/store state; do not manually restore an old transaction or remove an account without establishing ownership.

These are Java unit tests against fakes, not Keycloak runtime, JPA/provider, Registry, browser, HTTP, or live-profile evidence. They do not establish persistence semantics or distributed atomicity. Multi-node, HA, and distributed guarantees remain out of scope for Issue #7.