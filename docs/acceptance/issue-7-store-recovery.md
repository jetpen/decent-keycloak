# Issue #7 store recovery: scoped current-main candidate

Refs #7: https://github.com/jetpen/decent-keycloak/issues/7

**Disposition: scoped offline implementation candidate for human review; Issue #7 remains OPEN. This does not close the issue or qualify runtime behavior.**
No live/container/Registry invocation or image build was performed for this slice.
Real Keycloak HTTP, selected runtime SPI, wallet/browser and production-provider recovery
remain unqualified. Neither passing scripted HTTP tests nor an SPI JAR proves runtime qualification.
Multi-node integration and distributed provisioning/replay guarantees are out of scope.

## Preserved ordering and residual states

Failure-checkpoint diagnostics now preserve `last_confirmed_phase` separately from the coordinator's `faulted_signup` stage. The three store profiles and three UserProvider readback profiles project `fixture_factory_witness`, `fixture_operation_witness`, and `fixture_mutation_outcome` only from exact markers in the bounded per-run Keycloak log window. The factory-create witness records only a run-scoped factory creation marker; it is not transaction-level provider selection and cannot support a selection claim. Request-scoped store operation/fault markers must match the request ID derived from that transaction's locator; only that exact operation marker supports the associated operation/provider attribution. Provider registration/enumeration and factory creation alone never prove a particular transaction used the fixture. The readback fixture's operation marker is not transaction-scoped and is accepted only as an exact unique marker in its bounded per-run window. Missing/unreadable, duplicate, malformed, unrelated, or unknown markers fail closed as `unavailable`; a factory-create marker alone can report only run-scoped factory creation while operation and outcome remain unavailable. The witness describes fixture selection/reach/outcome only and does not diagnose any historical `runtime_error` cause. No raw log, request ID, locator, identity, subject, exception, proof, token, or secret is serialized. This is offline fixture-backed application-path evidence only; runtime/provider behavior remains unqualified.

Current `main` already implements server-bound explicit signup intent, fresh signed proof and current Registry verification, exact enabled local-account create/readback, then pending consume. This slice adds bounded failure diagnostics to the ordinary signup success coordinator plus scripted offline coverage; it does not change production Java/provider behavior or acceptance gates. A regression invokes production `main()` through the `issue7-signup-success` dispatcher and the real `signup_wallet_flow` using scripted browser/wallet HTTP and mocked external setup boundaries. The scripted intent POST returns HTTP 200, then a deterministic transaction-binding validation fails; the final sanitized checkpoint preserves `stage=intent`, action status 200, and the exact `signup_intent`/`transaction_binding`/`assertion_failed` context while excluding raw error/identifier/token/request text, callbacks/codes/provider IDs, unrelated HTTP status fields, and false completion. Known request/decode/parser boundaries receive allowlisted phase/gate context; genuinely unknown failures remain unclassified, and checkpoint-writer failure preserves the primary exception. A separate production-main assertion-failure regression scripts proof HTTP 202 where the failure flow expects 503; the existing outer signup catch retains the bounded diagnostics through the final sanitized checkpoint, and no recovery starts. This is characterization of current behavior, not a production-code fix. A second production-entrypoint regression drives the real flow through proof HTTP 202 and a later status-poll HTTP 503. Immediately after transaction binding is validated, the request ID is passed only through in-memory progress and is never checkpointed. On failure, only the bounded per-run log window is inspected, and the existing strict production-marker parser is reused. The checkpoint records `transaction_consume_witness=observed` with an allowlisted `transaction_consume_provider_id` only for exactly one marker correlated to that request ID; missing, unreadable, duplicate, unrelated, or unknown markers preserve `provider_operation_witness=unavailable`. The marker establishes successful consume for that request/provider only; it does not establish the later failure's cause or accepted-receipt persistence. This is fixture-backed offline application-path evidence only, not runtime/provider qualification. On successful flows, provider selection still requires a unique allowlisted production marker correlated to that exact flow request ID. Runtime/provider/JPA/browser/Registry/PKCE qualification remains open.

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

This candidate is based on current `main` after PR #40 at `fcbff939de49b775969c71c78cc5b0e53087e7fa`. It adds bounded fixture-witness parsing/checkpoint wiring for the three store and three readback failure profiles, a production-main proof-status assertion-failure regression, the shared confirmed-phase vocabulary, and offline evidence/docs updates. Test-only SPI log markers distinguish factory creation from operation/fault/outcome; store operation/fault evidence is request-correlated, while factory creation and readback operations remain run-scoped. No production account/store Java or test-image packaging changes are included. None of the fixtures proves runtime provider selection, actual provider behavior, cause of the historical generic errors, or receipt persistence.


The Python store-recovery module now includes an all-mode production-entrypoint regression: the production `main()` with external setup mocked selects each configured store profile, executes the real `issue7_store_recovery.run`, and calls the real `signup_wallet_flow` plus either a fresh real signup (consume-loss) or real `auth_flow` (both receipt-write modes) using scripted browser/wallet HTTP and Admin readbacks. It checks scripted browser/wallet request ordering (explicit signup intent, challenge, proof, status and retry); empty 503 and old pending/retry 404 without redirect/callback/code; exact retained enabled-user readback from fixed Admin responses; and serialized evidence from a hand-authored request-correlated log fixture; cooldown; distinct recovery transaction; correct ceremony and accurate transaction counts; same local subject; callback/replay/state/code/PKCE; and final checkpoint/stdout sanitization. The test does not observe current Registry verification, actual local-account creation/readback, pending-store consumption, or provider-emitted fault logs. Those Issue #7 gates remain runtime/provider qualifications. The core flow and coordinator are not mocked. All secrets, private subject/identity, locators, challenges, proof material, codes, tokens and raw logs are excluded from serialized evidence. This is scripted offline application-path evidence only; external setup is mocked and no container, Registry, Keycloak server/provider or live profile was run. Java tests continue to exercise one-shot decorator mutation ordering and delegation. None of this qualifies actual Keycloak acceptance, JPA/provider persistence/atomicity, real Registry/wallet behavior, or runtime/browser/provider selection. The added scenario passed against the unchanged production flow and is characterization of the previously untested orchestration; no product defect or runtime pass is claimed.
