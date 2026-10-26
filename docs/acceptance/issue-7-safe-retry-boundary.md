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

## Ordinary signup selected-provider witness (offline preparation)

The ordinary `issue7-signup-success` profile now requires a request-correlated
`Wallet proof transaction consumed` log event containing the selected SingleUseObjectProvider ID.
The production event is emitted only after the pending transaction was removed and validated; it
uses the request-correlation helper and the provider identity observed from the concrete provider
instance used by the transaction store. The harness reads a bounded per-run log window and accepts
exactly one marker for that request with a recognized provider ID. Missing, unknown, duplicate,
conflicting, or unrelated-only markers fail closed. The final checkpoint projects the provider ID
only for a completed success profile and omits the request ID and raw log contents.

Offline tests cover the production handler log, parser correlation/allowlisting, final checkpoint
projection, and the production entrypoint with scripted HTTP plus external setup mocked. This describes
that original offline preparation slice, not later runtime attempts. The combined success
checkpoint must still satisfy exact account, callback/replay, state, and PKCE assertions; the
consume marker alone does not establish accepted receipt publication or code issuance.

## Later ordinary signup runtime attempt

The separate authorized `issue7-signup-success` attempt on source
`24f36d843774997193faee6cfe8f1ab9902ff93c` was consumed once and failed at `account_readback`
after signup intent HTTP 200, before proof, consume, callback/replay, PKCE or selected-provider
witness. Offline tracing found `main()` reused the realm-preprovisioned Identity for fresh signup;
the corrected isolated candidate now gives this profile a distinct Identity but has not been
live-verified. The exact harness/image provenance and cleanup reconciliation are recorded in
[`issue-7-store-recovery.md`](issue-7-store-recovery.md). Issue #7 remains OPEN; do not retry
without fresh explicit authorization.

## Receipt-publication failure

The existing `WalletLoginTransportHandlerTest.acceptedReceiptWriteFailureLeavesCreatedAccountBeforePendingConsume` test uses an in-memory fake that rejects accepted-receipt publication after consume. It asserts no accepted receipt/callback gate or old-transaction recovery is exposed and that a fresh explicit signup reuses the retained account. This also does not qualify provider persistence or real callback/code behavior.

## Residual state and recovery

After an ambiguous consume that removed the pending key, the original transaction has no accepted receipt and is unusable; after consume succeeds but receipt publication fails, the consumed transaction likewise cannot be replayed or restored. The account is intentionally retained because deleting it could remove a concurrent winner. The intended runtime recovery is a fresh, explicitly authorized signup that repeats proof and Registry checks before resolving the exact enabled account rather than provisioning again; the unit tests stub the key resolver and do not establish those Registry checks. Empty, unavailable, or over-cap account readback must fail closed without deleting a possibly visible account. Operators should investigate retained account/store state; do not manually restore an old transaction or remove an account without establishing ownership.

These are Java unit tests against fakes, not Keycloak runtime, JPA/provider, Registry, browser, HTTP, or live-profile evidence. They do not establish persistence semantics or distributed atomicity. Multi-node, HA, and distributed guarantees remain out of scope for Issue #7.