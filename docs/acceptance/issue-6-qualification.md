# Issue #6 qualification matrix

## Disposition

**Prior review blocker remediated; fresh review pending.** Security review of snapshot `0e1bbdfd39573f37f56b07d5cbd0341fd8f01382a4d9ee24d8d23d3a2b7c87d9` found that Keycloak 26.8's `RootAuthenticationSessionAdapter.removeAuthenticationSessionByTabId` removes the root when its final child is removed. Immediate retirement was replaced by deferred marking/pruning with a retained fresh child. Real pinned adapter/provider/changelog merge-task tests reproduce the old root-removal effect and cover the new behavior. All three deferred-cleanup live profiles passed. This is not yet a passing independent-review verdict; do not merge until the fresh reviews finish.

All requested one-node runtime acceptance scenarios passed on the candidate below. Final independent review is pending; this is not a merge recommendation, issue closure, production deployment qualification or a third-party audit. The issue remains open. No commit or push was performed.

One Keycloak 26.8.0 node only. No clustering, cross-node replication, high availability, signup recovery, Registry-negative/rotation, real-wallet/TLS, or deployment claims. Fault scenarios are explicitly test-decorator-injected failures after real delegate writes, not provider-originated exceptions.

## Candidate and reproducible invocation

- Source-input fingerprint: `cc74e27a505df393e60fc9d3705f7cab99fe1247e617b86600af13e7a6b35d9f` (88 sorted tracked/untracked non-document, non-generated inputs; path + NUL + decimal permission mode + NUL + 8-byte big-endian content length + bytes).
- Host harness SHA-256: `f861cefbaeb82e552a33e8473355753ce455c9d300d59a2e305082580b7c1958`.
- Base HEAD: `b928f0a5d57f2100a5318035b595db1fdb84002d`; uncommitted worktree, not a pinned committed release.
- Runtime manifest/lock and exact source dependencies are retained in each sanitized receipt.

| Profile | Immutable image ID | Image digest | Evidence |
|---|---|---|---|
| `issue6-single-node` | `ffb57e2b79c5485ed1069b4bfd676af26a6ba6df4209b14e3af6742ef1aefbc8` | `sha256:994c096991b920fd5f9e29dbfbd49f9d1a680a8d60c4ba13ee288389c8e1ca52` | [production](issue6-evidence/production.json) |
| `issue6-postconsume-receipt-failure` | `9573cc35e2506640fdb3be8f60f7e803d8cdf3b253de0dea83fce1b92b1b0dd9` | `sha256:2e725d4644d7ae60f52dfe0ceb15fd14ddbc2da7f9846ac9bf42978e490cd69d` | [receipt failure/recovery](issue6-evidence/receipt-failure.json) |
| `issue6-postconsume-callback-gate-failure` | `f0d98e97cf6796f1cfc01ce4dc7fadeb8de55e5b5bcb2f1b44b9ba2f5e6478ff` | `sha256:0d46a758db0c8554d3a318218009de74a5bda5a246c1573f681bc85fcff70fb1` | [callback-gate failure/recovery](issue6-evidence/callback-gate-failure.json) |

For an explicitly authorized rerun, use the exact immutable image above:

```bash
WALLET_IT_IMAGE="$PRODUCTION_IMAGE_ID" WALLET_IT_PROFILE=issue6-single-node \
  TMPDIR="$PRIVATE_SCRATCH" python3.11 scripts/wallet_login_live_e2e.py
WALLET_IT_TEST_IMAGE="$RECEIPT_TEST_IMAGE_ID" WALLET_IT_PROFILE=issue6-postconsume-receipt-failure \
  TMPDIR="$PRIVATE_SCRATCH" python3.11 scripts/wallet_login_live_e2e.py
WALLET_IT_TEST_IMAGE="$CALLBACK_TEST_IMAGE_ID" WALLET_IT_PROFILE=issue6-postconsume-callback-gate-failure \
  TMPDIR="$PRIVATE_SCRATCH" python3.11 scripts/wallet_login_live_e2e.py
```

The combined profile includes a 305-second wait for the unchanged 300-second production TTL. Source fingerprint belongs to the live-run candidate; subsequent evidence-only edits do not retroactively change that source identity.

## Acceptance matrix

| Criterion | Status | Observation |
|---|---|---|
| Pinned node and actual store configuration | Passed | Keycloak 26.8.0; one node; effective DB `dev-file`; cache `local`. Request-correlated production expiry denial identified the actual `SingleUseObjectProvider` implementation as `infinispan`. Masked configured selector remains unavailable; advertised factories were not used as selection proof. |
| Pending transaction, valid signed proof, accepted status, first callback | Passed | Proof 202; status 200/accepted; callback 302 with exact registered redirect, original state and one code. |
| Identical retry / changed signature | Passed | Identical retry 202; changed signature over unchanged signed claims 409; no additional callback issuance. |
| Callback one-use / consumed status / PKCE | Passed | Replay 302 to exact RP URI with original state, error and no code; status-after-callback 404; PKCE endpoint 200. |
| Expiry / fresh login | Passed | Actual TTL 300 seconds, wait 305 seconds; expired valid proof and status both 404; no accepted receipt, callback, code or redirect exposure; correlated denial; distinct fresh challenge 200. |
| Post-consume receipt-store failure | Passed, decorator scope | One correlated commit-then-throw; empty proof 503; retry/status 404; no callback/code. Fresh transaction in the same browser completed callback, strict replay and PKCE 200. |
| Post-consume callback-gate-store failure | Passed, decorator scope | Same failure/no-exposure checks and successful same-browser fresh-login/replay/PKCE recovery. |
| Cleanup and provenance | Passed | Each run exit 0; complete fixed-schema receipt; exact pre/post container/network/volume/test-listener/credential/CID inventories matched; no containers, credentials, CID files or test listener remained. |
| Independent review | Pending | Review must cover this final implementation and evidence; no merge-ready claim until complete. |

The auth-phase subobject retains provider `unavailable` measured before expiry. Final `resolver_runtime` and `expiry_case` contain the later `infinispan` witness; these are separate observation times, not conflicting selections. Decorator runtime config selection remains unavailable in the generic runtime subobject; each fault profile checks its request-correlated selection marker and fault before allowing recovery. Dedicated test images delegate to real `infinispan`; production JAR/image exclude test injectors.

## Same-browser recovery fix and safety

Both fault profiles originally left the failed authentication child session unfinished. Keycloak can retain that child/root and restart cookie after a different tab succeeds, then redirect replay into its internal authenticate path before the custom guard. The diagnostic receipt profile recorded `expired_code`; the precise restart branch was not independently traced, so the causal claim is bounded to the intervention and resulting live behavior.

The user explicitly selected preserving strict same-browser replay and narrowly retiring the bound terminal-failure child. `WalletTerminalAuthenticationSession.retire` validates realm, client, root, tab, wallet handle, origin and redirect from server-side binding/auth notes, then stores a length-framed marker bound to those values. It never removes a tab on the fault request. On a later fresh `authenticate`, `pruneOnFreshAuthenticate` revalidates marked children while retaining the new current child, before that child receives a challenge handle. Only validated marked failures are removed. Arbitrary siblings are not guards, completed/replacement sessions are untouched, and no root restart or shared-cookie mutation occurs. The handler marks only when publication fails after successful pending consume; pre-consume errors and successful publication do not mark. Marking exceptions retain the empty fail-closed 503.

Regression evidence includes observed red assertions before implementation, then nine helper tests using the actual pinned Keycloak 26.8 root adapter, authentication-session provider, transaction log and merge tasks. They reproduce singleton removal scheduling root REMOVE, prove terminal marking does not schedule removal, and exercise guarded deferred pruning, binding/replacement/completed-session rejection, authenticator-to-challenge wiring, and preservation of concurrent sibling edits/additions during merge. Cache transport is mocked: these are real provider/task semantics, not distributed-cache commit or browser-wide guarantees. The real transport-handler commit-then-throw regression also asserts exact marked handle/binding. Live same-browser recovery reaches Keycloak's state-bound RP error (`already_logged_in`) and PKCE without custom authenticator replay entry. Strict replay with arbitrary other unfinished browser tabs remains outside the measured scenarios.

## Verification and historical evidence

Offline candidate checks: Java 21 offline `mvn clean package`: 205 tests, zero failures/errors/skips. Exact documented Python acceptance command: 258 tests passed. Source compilation, resolver-input verification and whitespace checks are run separately. The new safety tests do not replace live provider evidence.

Earlier combined production receipt: `/home/ben/.hermes/cache/scratch/issue6-qualification-issue6-single-node-214329.json`. Failed pre-retirement fault receipts: `/home/ben/.hermes/cache/scratch/issue6-qualification-issue6-postconsume-receipt-failure-214734.json`, `/home/ben/.hermes/cache/scratch/issue6-qualification-issue6-postconsume-callback-gate-failure-214906.json`; diagnostic receipt: `/home/ben/.hermes/cache/scratch/issue6-qualification-issue6-postconsume-receipt-failure-215322.json`. They remain historical failures, not relabeled passes. Final passing fixed-schema receipts are copied beside this document so they do not depend on scratch retention.

An initial combined deferred-cleanup production attempt was interrupted by the tool's 420-second call limit after two fault profiles had run in that same call. Its checkpoint reached `transaction_created` in the expiry wait, so it was incomplete. Only exact CID-verified owned containers were removed and their absence read back; private signing fixtures were deleted. A renewed explicitly authorized, separate production run then completed at 22:59:02 UTC; its passing receipt is the final production evidence above.
