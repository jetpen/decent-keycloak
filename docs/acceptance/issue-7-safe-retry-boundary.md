# Issue #7 single-node safe-retry boundary

**Current qualification:** the seven-profile one-node matrix passes, including corrected original-subject continuity reruns for all three readback modes and consume-loss. The four recovery runs preserved the original subject through recovery signup, callback, and PKCE; receipts and exact provenance are in the [renewed campaign ledger](issue-7-renewed-qualification.md). Faults remain test-decorator-mediated; this does not qualify distributed behavior. Issue #7 remains open; no PR or closure was authorized.

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

## PR #43 correction and later ordinary signup runtime attempt

PR #43 merged at `c203a028804882c088718b3add6ebbd7e8ad9b3d` from source head
`8c2c83488060c684ee8506485c47d9e4059b6b1c`. Its authorized push run `40393741461` and
pull_request run `40393878849` both succeeded and included “Build and check the immutable-base
provider image”. That CI step built a Docker image and ran the Keycloak 26.8.0 `kc.sh --version`
smoke only; it did not run signup or qualify Registry behavior. This post-publication CI evidence
is distinct from local offline implementation and does not qualify the signup profile.

The first two `issue7-signup-success` attempts are distinct and consumed. The first used source `24f36d843774997193faee6cfe8f1ab9902ff93c` and failed at `account_readback` after signup intent HTTP 200, before proof, consume, callback/replay, PKCE or selected-provider witness. Offline tracing found `main()` reused the realm-preprovisioned Identity for fresh signup. PR #43 changed only the ordinary success profile to use a distinct fresh Identity after realm setup; the latest run exercised this wiring through its signup and PKCE checks.

The second attempt used source `5310a2dc8944bd8c7cef8964e924ea4b07fb3ed0`, harness SHA-256 `03ff2e3b7adac4a26471c0ba5065d9567e42b8b1ad1b8240416bd8b10e2067e2`, image ID `918defd28421a226c8d11b0b39445d99d7f805714e098c1dd68e332b30d43992`, and digest `sha256:79b4ec91b1482009a7f900c1d86336ff5e25702a6b826c87132a9a008f9c6aae`. Its wrapper window was `2026-10-27T00:00:50Z`–`2026-10-27T00:01:50Z`; the sanitized receipt records exit code 1 and not timed out, with no `signup_case` evidence or request-correlated selected-provider witness. Its exact failure gate/cause is unavailable; raw output was not retained.

The third attempt used source HEAD `7d308304b9516c51566710376fa096e026c86e7c`, worktree diff SHA-256 `230bd45d918d15e55ad3a8784d916cdb02b5b0ffa71ee6548942dbf0f7b01e22`, harness SHA-256 `03ff2e3b7adac4a26471c0ba5065d9567e42b8b1ad1b8240416bd8b10e2067e2`, image `b357506d52c3aa95f67d17d48a4b8a7dca09fdbfe439a72a430f32bdde4f80a1` / digest `sha256:249cd3d63121976afaf92b742e762f3d942e9a9c7f38152385d35964036bb8d8`, and Registry commit `628120989703d146da50af97b4602f1f4aa3a068`. It exited 1 (not timed out). The bounded receipt records signup intent 200, proof 202, one exact account, callback 302, replay denial, preserved state, and PKCE token 200. Harness control flow places the failure after the signup flow returned, at the enclosing profile's request-correlated selected-provider witness requirement. The runtime selected provider/path remained unavailable; `infinispan` was only advertised as available. The successful transaction substeps are partial live evidence, not a complete Issue #7 pass. Cleanup was verified: no containers/external containers or volumes remained, the pre-existing test network was unchanged and empty, the fixed Keycloak port was unbound, and no run credential env file or CID directory remained. This run consumed the fresh authorization; any further runtime attempt requires fresh explicit authorization. Issue #7 remains OPEN. Exact evidence is recorded in [`issue-7-store-recovery.md`](issue-7-store-recovery.md).

## Receipt-publication failure

The existing `WalletLoginTransportHandlerTest.acceptedReceiptWriteFailureLeavesCreatedAccountBeforePendingConsume` test uses an in-memory fake that rejects accepted-receipt publication after consume. It asserts no accepted receipt/callback gate or old-transaction recovery is exposed and that a fresh explicit signup reuses the retained account. This also does not qualify provider persistence or real callback/code behavior.

## Residual state and recovery

After an ambiguous consume that removed the pending key, the original transaction has no accepted receipt and is unusable; after consume succeeds but receipt publication fails, the consumed transaction likewise cannot be replayed or restored. The account is intentionally retained because deleting it could remove a concurrent winner. The intended runtime recovery is a fresh, explicitly authorized signup that repeats proof and Registry checks before resolving the exact enabled account rather than provisioning again; the unit tests stub the key resolver and do not establish those Registry checks. Empty, unavailable, or over-cap account readback must fail closed without deleting a possibly visible account. Operators should investigate retained account/store state; do not manually restore an old transaction or remove an account without establishing ownership.

These are Java unit tests against fakes, not Keycloak runtime, JPA/provider, Registry, browser, HTTP, or live-profile evidence. They do not establish persistence semantics or distributed atomicity. Multi-node, HA, and distributed guarantees remain out of scope for Issue #7.