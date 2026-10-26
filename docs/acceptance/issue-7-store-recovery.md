# Issue #7 store recovery: scoped current-main candidate

Refs #7: https://github.com/jetpen/decent-keycloak/issues/7

**Disposition: scoped offline implementation candidate for human review; Issue #7 remains OPEN. This does not close the issue or qualify runtime behavior.**
No live/container/Registry invocation or image build was performed for this slice.
Real Keycloak HTTP, selected runtime SPI, wallet/browser and production-provider recovery
remain unqualified. Neither passing scripted HTTP tests nor an SPI JAR proves runtime qualification.
Multi-node integration and distributed provisioning/replay guarantees are out of scope.

## Ordinary signup attempt and correction boundary

Exactly one authorized `issue7-signup-success` runtime attempt was consumed on 2026-10-26. It
used source `24f36d843774997193faee6cfe8f1ab9902ff93c`, harness SHA-256
`baa747716f0e050e2a18e4089b701dccc7a9acf9b84ce99776eb8cbdeebea0ed`, image ID
`fc83bfb91d11555f6be59f7aa4700ba4d0617137c7287fb1d3f111dfea5aacd2`, image digest
`sha256:d6d184ad6ad6daa37e32ef0d5eb50202d2050e50c0ff958f672ce7ad146e3669`, and one
Keycloak 26.8.0 node (dev-file/local cache). It exited 1 at `account_readback`, with
`stage=intent`, `failure_stage=account_readback`, `failure_gate=account_readback`,
`failure_category=assertion_failed`, and provider operation witness unavailable. The signup
intent POST returned HTTP 200. This failed before proof POST, accepted transaction/consume,
callback, replay, or PKCE; no selected-provider witness was reached and no pass is claimed.

Offline source tracing attributes this attempt's account-readback failure to profile wiring, not
an established production-path defect: `main()` used the first Identity both to provision the
realm through `configure_realm` and to dispatch the success profile, while the real
`signup_wallet_flow` requires no exact mapped account before fresh signup proof. This candidate
keeps the first Identity for realm setup and other profiles, then publishes and passes a distinct
fresh Identity only for `issue7-signup-success`. It is corrected harness wiring, not a live-verified
fix; it does not change production Java behavior or acceptance criteria. The failure belongs to
the source snapshot above and remains a failed, consumed attempt. Cleanup was verified against
pre/post inventories: run-owned containers/networks/volumes/listeners/CID dirs/temp dirs were
reconciled, run-owned containers and the image were absent afterward, and no run CID or
credential scratch file remained. Do not retry without fresh explicit authorization.

## Preserved ordering and residual states

Failure-checkpoint diagnostics now preserve `last_confirmed_phase` separately from the coordinator's `faulted_signup` stage. The three store profiles and three UserProvider readback profiles project `fixture_factory_witness`, `fixture_operation_witness`, and `fixture_mutation_outcome` only from exact markers in the bounded per-run Keycloak log window. The factory-create witness records only run-scoped factory creation; it is never a selection claim. Both store and UserProvider request-level operation, fault, and outcome markers include the allowlisted wrapper ID, exact operation, and same handle-derived request ID. Readback correlation is bridged to the synchronous interception seam through a nested-restoring request-scoped context cleared/restored on scope close. A unique exact operation witness is required for attribution; delegate identity is not claimed. Provider registration/enumeration and factory creation alone never prove a particular transaction used the fixture. Missing/unreadable, duplicate, malformed, wrong-request, wrong-provider, wrong-operation, conflicting, or unknown markers fail closed for the request-level witness. No raw log, request ID, locator, identity, subject, exception, proof, token, or secret is serialized. This remains fixture-backed offline orchestration/parser evidence—not runtime provider qualification; Issue #7 remains OPEN.

Current `main` already implements server-bound explicit signup intent, fresh signed proof and current Registry verification, exact enabled local-account create/readback, then pending consume. This slice adds a bounded request-scoped correlation bridge for exact UserProvider readback diagnostics and scripted offline coverage; it does not alter provider selection policy, account/store outcomes, or acceptance gates. A regression invokes production `main()` through the `issue7-signup-success` dispatcher and the real `signup_wallet_flow` using scripted browser/wallet HTTP and mocked external setup boundaries. The scripted intent POST returns HTTP 200, then a deterministic transaction-binding validation fails; the final sanitized checkpoint preserves `stage=intent`, action status 200, and the exact `signup_intent`/`transaction_binding`/`assertion_failed` context while excluding raw error/identifier/token/request text, callbacks/codes/provider IDs, unrelated HTTP status fields, and false completion. Known request/decode/parser boundaries receive allowlisted phase/gate context; genuinely unknown failures remain unclassified, and checkpoint-writer failure preserves the primary exception. A separate production-main assertion-failure regression scripts proof HTTP 202 where the failure flow expects 503; the existing outer signup catch retains the bounded diagnostics through the final sanitized checkpoint, and no recovery starts. This is characterization of current behavior, not a production-code fix. A second production-entrypoint regression drives the real flow through proof HTTP 202 and a later status-poll HTTP 503. Immediately after transaction binding is validated, the request ID is passed only through in-memory progress and is never checkpointed. On failure, only the bounded per-run log window is inspected, and the existing strict production-marker parser is reused. The checkpoint records `transaction_consume_witness=observed` with an allowlisted `transaction_consume_provider_id` only for exactly one marker correlated to that request ID; missing, unreadable, duplicate, unrelated, or unknown markers preserve `provider_operation_witness=unavailable`. The marker establishes successful consume for that request/provider only; it does not establish the later failure's cause or accepted-receipt persistence. This is fixture-backed offline application-path evidence only, not runtime/provider qualification. On successful flows, provider selection still requires a unique allowlisted production marker correlated to that exact flow request ID. Runtime/provider/JPA/browser/Registry/PKCE qualification remains open.

## Historical six-profile provenance and cleanup reconciliation

The bounded run report saved at `2026-10-25T07:21:33Z` (report-save time; execution time unknown) records source branch/HEAD `main` / `3ecb945adb9d1d82dbb75222292d8e3e54df1a44` (`origin/main`) and harness SHA-256 `de95be7c8ef8114269743f154d4aa00d18bb0860d5970661bf9ac81c888a4054`. The three store-recovery profiles used image ID `e74486d3e17d76309934530170e8a10209b904614af04682a9b1e11f874dc390` / digest `sha256:15b6c122a44cc0eb20ba520c89b6778cfa061a3efcbabe0c6a1e95e3f739480d`; the three UserProvider readback profiles used image ID `1b586f8d8b3060cc24ff67ea6c629afd44029af1a759f71ce48b1a6e280e046c` / digest `sha256:3315527849bdde27b20969f65d29fbfdfe4c22b5aef01430683ab707bcae1737`. Both images were built from that source HEAD. Each of the six profiles was invoked once with its assigned immutable image ID; each exited 1 with `stage=faulted_signup` and generic `runtime_error`. Provider IDs were available in the store runtime view, but active provider selection and intended fault reach remained unavailable. These receipts do not establish a failure cause or a passing acceptance outcome.

The same report records pre/post cleanup comparison: no containers before/after, unchanged existing network and listener inventories, no volumes, and no remaining credential env files. Nine pre-existing CID files were inspected by exact full ID and classified absent; none were removed. Two empty run-CID directories with pre-existing timestamps were preserved. The worktree remained clean. This reconciles the historical run's recorded provenance and cleanup; any future runtime attempt still requires fresh explicit authorization, a new preflight inventory/cleanup baseline, and the current source/harness/image identity. Do not infer a precise execution timestamp from the report-save time.

## Profile mapping

| Opt-in `WALLET_IT_PROFILE` | One-shot test wrapper operation | Recovery |
|---|---|---|
| `issue7-consume-loss-recovery` | Remove pending transaction through the delegate, then throw | Fresh explicit SIGNUP resolves the retained exact enabled account; two signup transactions |
| `issue7-accepted-receipt-write-recovery` | Replace accepted receipt through the delegate, then throw | Fresh LOGIN for the same retained subject; one signup plus one login |
| `issue7-accepted-receipt-write-false-recovery` | Reject accepted receipt replacement before delegation/commit | Fresh LOGIN for the same retained subject; one signup plus one login |

All three require the faulted proof to return empty 503, then browser status and old identical
proof retry to return empty 404. Each response must have no case-insensitive Location header
and no newly followed redirect. The account must remain one exact enabled local subject.
A per-request UTC log cursor bounds the log read. The helper requires exactly one fixture
fault marker plus the matching handle-hash production `consume-unavailable` or `not_accepted`
signal. Evidence contains allowlisted counts/booleans/statuses only, never raw logs, subjects,
locators, proofs, signatures or callback/code values.

The old gate is never restored and old proof is never replayed to recover. The ordinary fresh
login helper verifies a distinct transaction, proof/retry/status, callback state/code/replay,
PKCE exchange and signed retained subject. Consume-loss uses the existing explicit signup
callback/PKCE path and verifies the same subject. Recovery waits beyond main's two-second
identity-admission cooldown. Invalid failure evidence prevents recovery; invalid recovery
never emits a complete checkpoint. Failed-signup facts are checkpointed before recovery.

Account creation and gate/receipt publication are not a compound atomic transaction. A
retained account after failure is expected; do not delete it or a possibly concurrent winner.
Users start the indicated fresh ceremony; operators inspect exact enabled mappings without
resetting consumed gates. Empty/unavailable/over-cap readback profiles already on main remain
separate and unchanged. The offline Java suite now includes a local handler characterization of
two distinct signup transactions racing to create the same account, followed by a store-level
consume-loser interleaving after the other transaction publishes its accepted receipt and a
fresh-signup reuse (see `issue-7-safe-retry-boundary.md`). It does not qualify restart persistence,
actual Keycloak/JPA/provider winner or consume-loss behavior, real provider atomicity, or
distributed guarantees. Unsupported live loser/concurrent modes fail closed before external
setup; they are not aliases.

## Test-only artifact and invocation (not executed here)

First run Java 21 offline `mvn -o clean package`, then:

```bash
python3.11 scripts/build_issue7_fault_provider.py
podman build --no-cache --pull=never --network=none \
  --file container/Dockerfile --target issue7-store-recovery-test-runtime \
  --tag decent-keycloak:issue7-store-recovery .
IMAGE_ID=$(podman image inspect --format '{{.Id}}' decent-keycloak:issue7-store-recovery)
WALLET_IT_PROFILE=issue7-consume-loss-recovery \
  WALLET_IT_STORE_RECOVERY_IMAGE="$IMAGE_ID" \
  python3.11 scripts/wallet_login_live_e2e.py
```

Each profile requires an explicit `WALLET_IT_STORE_RECOVERY_IMAGE` before image/container
resolution. Use a new isolated container per profile. The fault marker lives in that
container's `/tmp` and prevents repeated injection even if the factory is recreated.
The dedicated image persists `--spi-single-use-object--provider-default=issue7-fault-injection`
at `kc.sh build`; the launcher passes only an allowlisted fault-mode environment variable,
not an overriding runtime SPI selector. Production `runtime` does not include the fixture.
The JAR builder includes the outer factory and `$*.class` delegates and generates its own
service registration; tests and unrelated test SPI classes stay out. No shared test service
descriptor was added, so existing test providers' registrations are not replaced.
Provider enumeration is only availability evidence; actual fixture/production markers are
still required. An immutable image build and selected-SPI smoke start require separate
runtime authorization before these commands may be executed.

## Source and verification limits

This candidate is based on the current integration base after PR #41 at `72c61f4cbfe11d9bcda8f1da9ae0349d00d709c1`. It adds bounded fixture-witness parsing/checkpoint wiring for the three store and three readback failure profiles, a production-main proof-status assertion-failure regression, the shared confirmed-phase vocabulary, and offline evidence/docs updates. Test-only SPI log markers distinguish run-scoped factory creation from request-scoped operation/fault/outcome; both store and readback markers require the exact allowlisted wrapper ID, operation, and same handle-derived request ID. Readback correlation uses a nested-restoring synchronous request context. No delegate identity is claimed. These are fixture-backed offline orchestration/parser signals only, not runtime provider qualification; Issue #7 remains OPEN.


The Python store-recovery module now includes an all-mode production-entrypoint regression: the production `main()` with external setup mocked selects each configured store profile, executes the real `issue7_store_recovery.run`, and calls the real `signup_wallet_flow` plus either a fresh real signup (consume-loss) or real `auth_flow` (both receipt-write modes) using scripted browser/wallet HTTP and Admin readbacks. It checks scripted browser/wallet request ordering (explicit signup intent, challenge, proof, status and retry); empty 503 and old pending/retry 404 without redirect/callback/code; exact retained enabled-user readback from fixed Admin responses; and serialized evidence from a hand-authored request-correlated log fixture; cooldown; distinct recovery transaction; correct ceremony and accurate transaction counts; same local subject; callback/replay/state/code/PKCE; and final checkpoint/stdout sanitization. The test does not observe current Registry verification, actual local-account creation/readback, pending-store consumption, or provider-emitted fault logs. Those Issue #7 gates remain runtime/provider qualifications. The core flow and coordinator are not mocked. All secrets, private subject/identity, locators, challenges, proof material, codes, tokens and raw logs are excluded from serialized evidence. Factory-create markers may repeat across Keycloak sessions in the bounded profile log window and are run-scoped presence only; only the exact unique request-correlated operation+provider marker establishes that the test provider was used for that operation. This is scripted offline application-path evidence only; external setup is mocked and no container, Registry, Keycloak server/provider or live profile was run. Java tests continue to exercise one-shot decorator mutation ordering and delegation. None of this qualifies actual Keycloak acceptance, JPA/provider persistence/atomicity, real Registry/wallet behavior, or runtime/browser/provider selection. The added scenario passed against the unchanged production flow and is characterization of the previously untested orchestration; no product defect or runtime pass is claimed.
