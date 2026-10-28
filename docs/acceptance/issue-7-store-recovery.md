# Issue #7 store recovery: merged implementation and evidence status

**Current qualification:** the seven-profile one-node matrix passes, including separately evidenced corrected-gate reruns for empty, throwing, and over-cap readback plus consume-loss. Each corrected run preserved the original failed-ceremony subject through fresh signup, callback, and PKCE, with cleanup verified. See the [renewed campaign ledger](issue-7-renewed-qualification.md) for immutable images, harness/source provenance, and receipts. Faults are test-decorator-mediated; no distributed or backend-originated-fault guarantee is claimed. Issue #7 remains open; no PR or closure was authorized.

Refs #7: https://github.com/jetpen/decent-keycloak/issues/7

**Disposition: PR #43 merged at `c203a028804882c088718b3add6ebbd7e8ad9b3d` (source head `8c2c83488060c684ee8506485c47d9e4059b6b1c`); Issue #7 remains OPEN.** The merged implementation does not establish live signup, provider, or Registry qualification.

## Registry fix uptake (offline candidate)

The resolver build pins decent-registry commit `628120989703d146da50af97b4602f1f4aa3a068` (the merge commit for Registry PR #126, the Registry #124 stale/request-only referral fix) and decent-identity commit `2caec24de52c2dbe241e72fe317281c051d03f89` by HTTPS Git URLs and full commit IDs in the lock. The updated CI workflow is configured to materialize temporary shallow checkouts and verify the locked commit markers before the image build; no Identity or Registry source archives are checked in. The dependency closure remains on the previously qualified `libp2p==0.7.0`; this intentionally does not include the separate py-libp2p 0.8.1 upgrade from Registry PR #127.

The no-cache `resolver-builder` image build passed, including 11 pinned DHT outcome tests and 7 pinned Registry lookup-outcome tests. The full `runtime` image build also passed. Candidate image ID `b357506d52c3aa95f67d17d48a4b8a7dca09fdbfe439a72a430f32bdde4f80a1`, digest `sha256:249cd3d63121976afaf92b742e762f3d942e9a9c7f38152385d35964036bb8d8`. No Keycloak server, Registry node, or Issue #7 live profile was started as part of that image-build checkpoint. It verifies build-time uptake and offline resolver tests only; the later exact-image live profile results are summarized at the top of this ledger and fully recorded in the renewed qualification report. This recorded checkpoint predates the current temporary-Git-clone redesign and used the source archive input that has since been removed; it does not verify the redesigned materializer or Docker named contexts.

The authorized PR #43 push run `40393741461` and pull_request run `40393878849` both succeeded. Each included “Build and check the immutable-base provider image”, which built the Docker image and ran the Keycloak 26.8.0 `kc.sh --version` smoke only—not the signup profile or Registry qualification. The CI image-build and Keycloak 26.8.0 version smoke do not qualify profiles by themselves. Separate local exact-image evidence now passes the seven-profile one-node Issue #7 matrix as wrapper-mediated application-path behavior (see the current qualification summary above). The generic active SingleUseObjectProvider path, arbitrary provider-originated failures, real TLS/browser-native-wallet interoperability, and distributed behavior remain unqualified; neither scripted HTTP tests nor an SPI JAR establishes those claims.
Multi-node integration and distributed provisioning/replay guarantees are out of scope.

## Ordinary signup attempt and correction boundary

Three distinct `issue7-signup-success` runtime attempts have now been consumed; keep their evidence separate. The latest was the user-authorized next run after the offline Registry fix uptake. Its authorization is consumed; another runtime attempt requires fresh explicit authorization.

The earlier attempt (2026-10-26) used source `24f36d843774997193faee6cfe8f1ab9902ff93c`, harness SHA-256
`baa747716f0e050e2a18e4089b701dccc7a9acf9b84ce99776eb8cbdeebea0ed`, image ID
`fc83bfb91d11555f6be59f7aa4700ba4d0617137c7287fb1d3f111dfea5aacd2`, image digest
`sha256:d6d184ad6ad6daa37e32ef0d5eb50202d2050e50c0ff958f672ce7ad146e3669`, and one
Keycloak 26.8.0 node (dev-file/local cache). It exited 1 at `account_readback`, with
`stage=intent`, `failure_stage=account_readback`, `failure_gate=account_readback`,
`failure_category=assertion_failed`, and provider operation witness unavailable. The signup
intent POST returned HTTP 200. This failed before proof POST, accepted transaction/consume,
callback, replay, or PKCE; no selected-provider witness was reached and no pass is claimed.

The second attempt ran on source `5310a2dc8944bd8c7cef8964e924ea4b07fb3ed0` in the wrapper window
`2026-10-27T00:00:50Z`–`2026-10-27T00:01:50Z`. Its sanitized receipt records profile `issue7-signup-success`, exit code 1, and not timed out. The source used harness SHA-256
`03ff2e3b7adac4a26471c0ba5065d9567e42b8b1ad1b8240416bd8b10e2067e2`, image ID
`918defd28421a226c8d11b0b39445d99d7f805714e098c1dd68e332b30d43992`, and image digest
`sha256:79b4ec91b1482009a7f900c1d86336ff5e25702a6b826c87132a9a008f9c6aae`. Its receipt contains no `signup_case` evidence or request-correlated selected-provider witness; the exact failure gate/cause is unavailable. Raw runner output was not retained. Do not attribute this attempt to `account_readback` or infer a cause.

**Historical prior-campaign evidence (three ordinary-signup attempts, before the current seven-profile campaign):**

The third attempt used source HEAD `7d308304b9516c51566710376fa096e026c86e7c` with worktree diff SHA-256 `230bd45d918d15e55ad3a8784d916cdb02b5b0ffa71ee6548942dbf0f7b01e22`, harness SHA-256 `03ff2e3b7adac4a26471c0ba5065d9567e42b8b1ad1b8240416bd8b10e2067e2`, and the exact candidate runtime image ID `b357506d52c3aa95f67d17d48a4b8a7dca09fdbfe439a72a430f32bdde4f80a1` / digest `sha256:249cd3d63121976afaf92b742e762f3d942e9a9c7f38152385d35964036bb8d8`. The run exited 1 (not timed out). Its sanitized partial checkpoint records Keycloak 26.8.0 on one node, DB `dev-file`, cache `local`, Registry commit `628120989703d146da50af97b4602f1f4aa3a068`, signup intent HTTP 200, proof HTTP 202, one exact mapped account, callback HTTP 302, callback replay denied, OIDC state preserved, and PKCE token HTTP 200. The flow returns only after checking token subject and wallet Identity claims; then the enclosing profile failed its final request-correlated selected-provider witness requirement. No provider ID was established for that request. Runtime provider configuration/path remains unavailable (`show_config_fields_missing`); `infinispan` was advertised as available, not proven selected. Thus the ordinary signup transaction reached its application and PKCE checks, but this profile did not produce its required complete evidence or a passing qualification receipt. The sanitized output reports only `runtime_error`; attribution to the post-flow witness gate is from the harness control flow, not a raw exception or runtime diagnostic.

Cleanup was verified after the third prior-campaign attempt: no containers or external containers remained, no volumes remained, the pre-existing `wallet-login-test-net` retained its same ID and empty membership, the Keycloak port was unbound, no admin credential env file remained, and the run-scoped CID directory was removed. Issue #7 remains OPEN. The prior campaign's attempts are consumed; a new explicitly approved campaign followed separately.

Offline source tracing of the first failure attributes its account-readback failure to profile wiring, not an established production-path defect. PR #43 corrected the ordinary success profile to use a distinct fresh Identity after realm setup; the third prior-campaign attempt exercised that wiring through the successful proof/account/callback/replay/PKCE path. That attempt still did not establish the request-correlated selected-provider witness, so the correction was exercised but the full ordinary-signup acceptance gate remains unqualified. Cleanup for the first two attempts is documented separately above; cleanup for the third attempt was verified by pre/post resource checks. A separate one-attempt campaign followed on 2026-10-27; that checkpoint's outcomes are preserved below, and the later corrected-gate matrix is summarized at the top and in the renewed ledger.
Offline follow-up attributes the prior exit to the harness's final provider-witness gate, not to proof/signup behavior: the flow returned only after its account, callback, replay, state, and PKCE checks. The old success path performed a non-strict log read and treated an unreadable log window the same as a missing marker; on witness failure it also raised outside the failure-checkpoint path, losing the exact gate and completed signup evidence. The offline fix uses a strict bounded log read, classifies only allowlisted witness outcomes (`marker_missing`, `request_mismatch`, `provider_unknown`, ambiguity/malformed, or `log_output_unavailable`), and checkpoints the final gate plus prior completed stages. It remains fail-closed and does not infer provider selection from advertised providers. The original raw log window was not retained, so its specific witness outcome cannot be recovered. In that 2026-10-27 campaign, the signup runner exited 0 but detailed evidence was not retained; the exact provider witness for that run cannot be asserted from the available record.

## Historical 2026-10-27 seven-profile campaign checkpoint (superseded by the current matrix)

At this historical checkpoint, four profile names had been invoked: ordinary signup and the three readback modes. Throw and over-cap had stopped before injected-fault recovery; consume-loss and the two receipt-write profiles had not yet run at that point. The campaign stopped at the missing fixture witness. The later receipt-write passes and four corrected-gate continuity reruns are recorded in the [renewed qualification ledger](issue-7-renewed-qualification.md); this paragraph does not describe current status.

`issue7-user-readback-throw` was invoked once after the recovery-Identity correction against image ID `d0b21c3a43dc5d94891d64e914b318dbd0ab0c5cdbb51056285d70cda4cb0ed9` / digest `sha256:2b0348b643274a1128835da4fa8cee98a928dc0804ff7c5cb48ba9280b6657bb`. Source HEAD `7d308304b9516c51566710376fa096e026c86e7c`, pre-run diff SHA-256 `634b5f8cb7c41a2d0546359944025d0713bef2f6df281ca97bcb8d55a88f62d3`, harness SHA-256 `02f09d24520e0955c254ca3691038793a37ea1afa7a682e0d24e025f649b353c`, Registry commit `628120989703d146da50af97b4602f1f4aa3a068`; the sanitized local receipt SHA-256 is `1ff2cbba979f3e555713fba6bd15ba4ded68063f6e8bb1697709acbc2a7772a9`. Runner exit 1; the partial checkpoint has `failure_gate=proof_http_status`, intent HTTP 200, proof HTTP 202 rather than expected injected-fault 503, and factory/operation/mutation-outcome witnesses all unavailable; recovery did not run. Cause is unknown. The exact image history contains `kc.sh build --spi-user--provider-default=issue7-user-readback-fault`; the test JAR contains its expected service registration, but those are build/package facts, not runtime selection or operation evidence. Cleanup was verified: no containers or external containers, volumes, run CID files, or admin credential env files; the full listener set matched pre-run; `wallet-login-test-net` retained ID `d9d58c11d12fdde5a31365af53b802a2cbb8ada10250712f0dead73ba5936a73` and empty membership. This particular 2026-10-27 throw attempt remains failed/consumed; the profile's corrected-gate rerun passed as recorded in the current ledger. The one-attempt statement here describes only that historical campaign. `issue7-user-readback-overcap` ran once on image ID `6377d31530d3cda4fb2da57d5deb6dd9e8ffec9a88e46d59484c65a3511eedf5` / digest `sha256:91d6b13377dcddd92ac63748a3e9625f0e1d61746c98de4d0e81aabea9fe88b1`, source HEAD `7d308304b9516c51566710376fa096e026c86e7c`, pre-run diff SHA-256 `3ba84235d57e5ce547efecaf9a269d72498606bd3ee89aaef8cde04729624c96`, harness SHA-256 `1ec799d44dbb84bba9453820786cbdcff9efba3f2fdb56fe9fb2581ec203c038`; sanitized receipt SHA-256 `b44785204292c886f68282a44fc95f3153c850a3702b7c0d82ed9294ee31e199`. It exited 1 at `proof_http_status`, intent 200/proof 202 instead of injected-fault 503; startup factory marker absent (`user_readback_factory_selected=false`), request-correlated fixture witnesses unavailable, and recovery did not run. Cause is unknown. Cleanup readback showed no containers, external containers, volumes, run CID directories, or admin env files; port 18886 was not listening; preserved `wallet-login-test-net` ID and empty membership. At this historical checkpoint, three store profiles were still unattempted; the later receipt-write passes and corrected consume-loss pass are documented in the current ledger. The campaign had stopped after the missing witness at that time. Issue #7 remains open for human disposition.

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

Earlier offline fixture-witness parsing/checkpoint work was delivered in PR #42, merged at `24f36d843774997193faee6cfe8f1ab9902ff93c`. It covers the three store and three readback failure profiles, a production-main proof-status assertion-failure regression, shared confirmed-phase vocabulary, and offline evidence/docs updates. Test-only SPI log markers distinguish run-scoped factory creation from request-scoped operation/fault/outcome; both store and readback markers require the exact allowlisted wrapper ID, operation, and same handle-derived request ID. Readback correlation uses a nested-restoring synchronous request context. No delegate identity is claimed. These are fixture-backed offline orchestration/parser signals only, not runtime provider qualification; Issue #7 remains OPEN. PR #43 adds only the distinct fresh Identity wiring for the ordinary success profile after realm setup, as recorded above; it changes no production Java behavior and remains unverified by a live profile.


The Python store-recovery module now includes an all-mode production-entrypoint regression: the production `main()` with external setup mocked selects each configured store profile, executes the real `issue7_store_recovery.run`, and calls the real `signup_wallet_flow` plus either a fresh real signup (consume-loss) or real `auth_flow` (both receipt-write modes) using scripted browser/wallet HTTP and Admin readbacks. It checks scripted browser/wallet request ordering (explicit signup intent, challenge, proof, status and retry); empty 503 and old pending/retry 404 without redirect/callback/code; exact retained enabled-user readback from fixed Admin responses; and serialized evidence from a hand-authored request-correlated log fixture; cooldown; distinct recovery transaction; correct ceremony and accurate transaction counts; same local subject; callback/replay/state/code/PKCE; and final checkpoint/stdout sanitization. The test does not observe current Registry verification, actual local-account creation/readback, pending-store consumption, or provider-emitted fault logs. Those Issue #7 gates remain runtime/provider qualifications. The core flow and coordinator are not mocked. All secrets, private subject/identity, locators, challenges, proof material, codes, tokens and raw logs are excluded from serialized evidence. Factory-create markers may repeat across Keycloak sessions in the bounded profile log window and are run-scoped presence only; only the exact unique request-correlated operation+provider marker establishes that the test provider was used for that operation. This is scripted offline application-path evidence only; external setup is mocked and no container, Registry, Keycloak server/provider or live profile was run. Java tests continue to exercise one-shot decorator mutation ordering and delegation. None of this qualifies actual Keycloak acceptance, JPA/provider persistence/atomicity, real Registry/wallet behavior, or runtime/browser/provider selection. The added scenario passed against the unchanged production flow and is characterization of the previously untested orchestration; no product defect or runtime pass is claimed.
