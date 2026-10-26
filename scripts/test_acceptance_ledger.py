"""Current Keycloak wallet-login qualification ledger, evidence and limits."""

from __future__ import annotations

from pathlib import Path
import unittest

README = Path(__file__).parents[1] / "README.md"
SECURITY_REVIEW = Path(__file__).parents[1] / "docs/security-review.md"

class AcceptanceLedgerTest(unittest.TestCase):
  def test_issue7_store_recovery_candidate_is_offline_and_ceremonies_are_distinct(self):
    readme = README.read_text()
    doc = (README.parent / 'docs/acceptance/issue-7-store-recovery.md').read_text()
    self.assertIn('docs/acceptance/issue-7-store-recovery.md', readme)
    self.assertIn('candidate for human review', doc)
    self.assertIn('Issue #7 remains OPEN', doc)
    self.assertIn('the real `issue7_store_recovery.run`', doc)
    self.assertIn('all-mode production-entrypoint regression', doc)
    self.assertIn('scripted offline application-path evidence only', doc)
    self.assertIn('hand-authored request-correlated log fixture', doc)
    self.assertIn('does not observe current Registry verification', doc)
    self.assertIn('exactly one marker correlated to that request ID', doc)
    self.assertIn('This is fixture-backed offline application-path evidence only, not runtime/provider qualification.', doc)
    self.assertIn('These diagnostics are fixture-backed offline application-path evidence only; fixtures do not establish actual provider behavior.', readme)
    self.assertIn('transaction_consume_witness=observed', readme)
    self.assertIn('The marker establishes only successful consume for that request/provider', readme)
    self.assertIn('actual Keycloak/UserProvider/JPA runtime behavior remains unqualified', readme)
    self.assertIn('bounded last-confirmed signup progress', readme)
    self.assertIn('status alone never selects a gate', readme)
    self.assertIn('Failure checkpoints may include a transaction-consume provider ID only when one production-format consume marker in the scripted log fixture is exactly correlated to the request ID', readme)
    self.assertIn('only one exact correlated production-format consume marker in the scripted log fixture permits', readme)
    self.assertIn('339 Python tests', readme)
    self.assertIn('browser status-poll `proof_status` failures use generic `failure_http_status`', readme)
    self.assertIn('exact proof-POST `proof_http_status` gate', readme)

  def test_issue_six_expiry_profile_is_documented_as_offline_only(self):
    text = README.read_text()
    self.assertIn("Issue #6 expiry-profile implementation chronology (2026-10-21)", text)
    self.assertIn("WALLET_IT_PROFILE=expiry", text)
    self.assertIn("configured real `SingleUseObjectProvider`", text)
    self.assertIn("No containers or profiles were run for this change", text)
    self.assertIn("Fresh combined-profile expiry execution, changed-signature live replay, and post-consume accepted-receipt failure/fresh-login recovery remain unqualified", text)
    self.assertEqual(2, text.count("historical replay 409 changed JSON whitespace only"))
    self.assertIn("This branch adds an offline changed-signature characterization", text)
    self.assertIn("The changed-signature variant has not been live-run; the historical live 409 changed JSON whitespace only.", text)
    self.assertIn("same-browser recovery login", text)
    self.assertIn("documented Python suite ran 151 tests (134 other tests, 14 ledger, 3 workflow guard tests", text)

  def test_issue_six_profile_sequences_auth_then_expiry_with_sanitized_checkpoint(self):
    text = README.read_text()
    security_review = SECURITY_REVIEW.read_text()
    harness = (README.parent / "scripts/wallet_login_live_e2e.py").read_text()
    regression = (README.parent / "scripts/test_wallet_login_transport_e2e.py").read_text()
    self.assertIn("`WALLET_IT_PROFILE=issue6-auth-flow` path runs only the bounded one-node authentication phase", text)
    self.assertIn("`WALLET_IT_PROFILE=issue6-single-node` runs the combined two-phase profile", text)
    self.assertIn("then `expiry_acceptance_flow`", text)
    self.assertIn("same running Keycloak node", text)
    self.assertIn("A sanitized checkpoint is written after the successful auth phase before expiry begins", text)
    self.assertIn("auth-before-expiry ordering", text)
    self.assertIn("issue6_single_node_case", harness)
    self.assertIn("checkpoint=lambda snapshot", harness)
    self.assertIn("test_single_node_profile_runs_auth_then_expiry_with_bounded_checkpoint", regression)
    self.assertIn("The auth-only profile did not invoke expiry", security_review)
    self.assertIn("phase_order", regression)

  def test_issue_six_receipt_commit_then_throw_evidence_is_scoped(self):
    readme = README.read_text()
    security_review = SECURITY_REVIEW.read_text()
    self.assertIn("Issue #6 ordinary-login receipt commit-then-throw regression", readme)
    self.assertIn("The offline ordinary-LOGIN regression drives the real", readme)
    self.assertIn("runtime version must exactly match the `keycloak.version` property in `pom.xml`", readme)
    self.assertIn("effective SingleUseObjectProvider remains unqualified", readme)
    self.assertIn("Effective DB/cache were `dev-file`/local, but selected production provider path remained unavailable", security_review)
    self.assertIn("not a production-provider fault or complete recovery qualification", readme)
    self.assertIn("fresh-login replay failed the documented error/state/destination gate before Code+PKCE", readme)
    self.assertIn("complete post-consume recovery: **not qualified**", security_review)
    self.assertIn("this remains wrapper-mediated, not production-provider evidence", security_review)
    self.assertIn("Final offline verification on this implementer snapshot: the exact CI Python acceptance command passed 223 tests", readme)
    self.assertIn("MAVEN_SKIP_RC=1 TMPDIR=/home/ben/.hermes/cache/scratch mise exec java@21.0.2 -- mvn -o clean package", readme)
    self.assertIn("first Maven attempt used `MAVEN_SKIP_RC=true` and failed", readme)
    self.assertIn("production provider JAR contains no test classes", readme)
    self.assertIn("mvn -o clean package` passed 190 tests across 14 suites with zero failures/errors/skips", readme)
    self.assertIn("The live run on source fingerprint `7ee5cf91725b99d43bb1324a1d19dcda39c2d8f69d1617b2d9642429f79047f4` observed production proof/retry/callback at 202/202/409/302", security_review)
    self.assertNotIn("On the current candidate fingerprint `7ee5cf91725b99d43bb1324a1d19dcda39c2d8f69d1617b2d9642429f79047f4`", security_review)
    self.assertIn("Changed-signature replay, strict replay, PKCE, expiry, selected-provider provenance, and complete post-consume recovery remain open.", security_review)
    self.assertIn("Effective DB/cache were `dev-file`/local, but selected production provider path remained unavailable", security_review)

  def test_excluded_multi_node_topology_is_not_reported_as_an_open_acceptance_gate(self):
    readme = README.read_text()
    security_review = SECURITY_REVIEW.read_text()
    self.assertNotIn("two-node replay", readme)
    self.assertNotIn("multi-node shared-store replay", readme)
    self.assertNotIn("two-node shared-store consume/status/callback one-winner proof", security_review)
    self.assertIn("multi-node behavior is explicitly out of scope", readme)
    self.assertIn("Multi-node behavior is explicitly out of scope for current acceptance.", security_review)

  def test_acceptance_ledger_reports_current_verification_layers_and_remaining_gates(self):
    text = README.read_text()
    self.assertIn("The checks failed against the synthetic merge revision", text)
    self.assertIn("The failure-specific probe also assumed the Hermes scratch directory exists", text)
    self.assertIn("147 tests (133 other tests, 11 ledger, 3 workflow guard tests", text)
    self.assertIn("Current cleanup-interrupt candidate offline checks:** Python 168 tests (150 other tests, 15 ledger, 3 workflow guard tests", text)
    self.assertIn("missing Registry configuration returns unavailable (503), not absence (401)", text)
    self.assertIn("a Registry miss accompanied by a dial warning is unavailable", text)
    self.assertIn("Current isolated offline branch: Java 21 Maven 179 tests and Python acceptance 185 tests pass", text)
    self.assertIn("pass 11 peer-outcome and 7 Registry propagation cases", text)
    self.assertIn("CI runs the image-build/runtime-version check; exact-image direct resolver qualification is recorded below.", text)
    self.assertIn("Pre-live offline verification on this source fingerprint (2026-10-24;", text)
    self.assertIn("Python acceptance command passed 245 tests", text)
    self.assertIn("`e722fee94c09c76c8f363183345738d9f6cdbe03285f6acdbd98be9bf951e7a1`", text)
    self.assertIn("Java 21 `mvn -o clean package` passed 195 tests across 15 suites", text)
    self.assertIn("Earlier offline candidate verification on an intermediate source snapshot (2026-10-24)", text)
    self.assertIn("the exact documented Python acceptance command passed 247 tests", text)
    self.assertIn("passed 196 tests with zero failures, errors, or skips", text)
    self.assertIn("Both test-only SPI JAR helpers were rebuilt after `clean package`", text)
    self.assertIn("No new Keycloak/Podman runtime attempt or expiry wait was made", text)
    self.assertIn("This image predates the later flow-callback re-arm candidate; the post-run offline framework-seam regression does not replace live evidence.", text)
    self.assertIn("A new offline Keycloak 26.8 `DefaultAuthenticationFlow` regression verifies that top-flow re-arming causes the code-less flow to invoke the wallet authenticator and call the protocol-denial path; the latest auth-only live run included this re-arm candidate but still failed the strict destination/state gate, so Code+PKCE was not reached.", text)
    self.assertIn("The protocol response and actual RP `Location`/state are mocked", text)
    self.assertIn("Latest bounded production live profile (2026-10-24; prior source snapshot)", text)
    self.assertIn("run-source snapshot fingerprint `8cbc830787e2cbb0ddbfe343bebd2141555175e8e8fef7c2217adc8848182321`", text)
    self.assertIn("show_config_fields_missing", text)
    self.assertIn("omitted cache", text)
    self.assertIn("destination failed the origin check (`redirect_origin_mismatch`)", text)
    self.assertIn("Strict gate failed at `callback_replay`; Code+PKCE and the authorized 301-second expiry phase were not reached.", text)
    self.assertIn("full live acceptance and merge readiness are not established", text)
    self.assertIn("Latest authorized Issue #6 live profile attempts (2026-10-24)", text)
    self.assertIn("callback-gate injection was not reached", text)
    postconsume = (README.parent / "docs/acceptance/issue-6-postconsume-runtime.md").read_text()
    self.assertIn("The authorized 2026-10-24 callback-gate live profile used source fingerprint", postconsume)
    self.assertIn("harness SHA-256 `0f171cfce3860a24791f0c8d19d16013c2039bc9c962fdb3eab3a7a2eaebe3ff`", postconsume)
    self.assertIn("On the current receipt-decorator image, the correlated commit-then-throw and fail-closed proof/retry/status outcomes passed", postconsume)
    self.assertIn("/auth/realms/wallet-e2e/login-actions/authenticate", postconsume)
    self.assertIn("the response contained no `state`, `error`, or `code` parameter", postconsume)
    issue6_profile = (README.parent / "docs/acceptance/issue-6-single-node.md").read_text()
    self.assertIn("The latest authorized auth-only production run used source fingerprint `7ee5cf91725b99d43bb1324a1d19dcda39c2d8f69d1617b2d9642429f79047f4`", issue6_profile)
    self.assertIn("again failed the strict replay destination/state gate", issue6_profile)
    self.assertIn("the separately documented safe same-issuer error page", issue6_profile)
    self.assertIn("Current Issue #6 live qualification on candidate 7ee5cf9", text)
    self.assertIn("`issue6-auth-flow`", text)
    self.assertIn("Callback replay returned 302 with error, without state or code", text)
    self.assertIn("Fresh recovery ended with `RuntimeError` before recovery evidence was checkpointed", text)
    self.assertIn("Sanitized checkpoint remained at `preflight` with `RuntimeError`", text)
    self.assertIn("renewed explicit authorization is required before another expiry wait", text)
    self.assertIn("candidate `7ee5cf...` reruns", postconsume)
    self.assertIn("e22d01be6d9741679624c44053299dad.json", postconsume)
    self.assertIn("This callback-gate implementation and orchestration passed offline checks. The current-candidate live callback-gate profile did run on image `66fba72c20f871f85eb3a022ab357b281c9bb793dae20e3de21823d89ff2dbc7`, but its sanitized receipt remained at `preflight` with `RuntimeError`; injection and recovery were not established.", text)
    self.assertNotIn("No Keycloak runtime, Podman command, container/image build, or network runtime attempt was performed.", text)
    self.assertIn("Selected production-provider provenance, strict replay/PKCE recovery, live expiry, callback-gate runtime recovery, changed-signature replay, and final independent review remain unqualified", text)
    self.assertIn("Latest bounded Issue #6 non-expiry reruns (2026-10-24)", text)
    self.assertIn("a7272daa03879a644d25e5bcc3bdb9de693135687a1b672992f5e3c20e79151f", text)
    self.assertIn("total, unavailable, and other guard-marker counts were all zero", text)
    self.assertIn("fresh_replay", text)
    self.assertIn("The prior `provision_identity` setup failure was traced", text)
    self.assertIn("sanitized CLI failure reporting", text)
    self.assertIn("Current Issue #6 result — auth-only replay/PKCE passed", text)
    self.assertIn("435600c226968435e34eb707d74f2a06b8b64ef78782a712ec6cd86390529948", text)
    self.assertIn("standard OAuth `error_description` response parameter", text)
    self.assertIn("The strict gate was not relaxed", text)
    self.assertIn("Decorator recovery profiles were not rerun with this fix", text)
    self.assertIn("Current disposition — replay/PKCE passed, full qualification open", issue6_profile)
    self.assertIn("Effective DB/cache were observed as `dev-file`/local in the current candidate runs; selected production-provider provenance remains unavailable.", text)
    self.assertNotIn("Effective cache and production provider selection", text)
    self.assertEqual(2, text.count("| Slice | Status | Verified so far | Still open |"))
    self.assertNotIn("uncommitted/unmerged", text)

  def test_previous_current_worktree_image_records_fail_closed_gate(self):
    text = README.read_text()
    self.assertIn("Previous #4 run from the current worktree based on `d700281409a876b74ee025f6d27ff50b40b0fca5`", text)
    self.assertIn("image ID `92cc5d4c06fd4a65dd1e2fbbb5472f70fd901201536b88019706bff48c14ce13`", text)
    self.assertIn("digest `sha256:b4120b6aa22de7bf036250a9f66b701245e6f4fd8082cbeaf71f96d832cfd58b`", text)
    self.assertIn("harness SHA `e220a7920c211b5d995a0b389b4665107565bf8c40da0b43d8cc4c9d2afd8d61`", text)
    self.assertIn("All six fresh successor reads (three configured-port, three ephemeral) were unavailable with balanced JSON", text)
    self.assertIn("two configured-port samples had peer-handshake diagnostics", text)
    self.assertIn("Harness exited 1 at the successor-read gate", text)
    self.assertIn("no stale/current-key proofs or provider `not_found` case ran", text)
    self.assertIn("Prior #4 run (image predates d700)", text)
    self.assertIn("A prior pre-wheelhouse no-cache image was built from the #4 worktree based on `d700281409a876b74ee025f6d27ff50b40b0fca5`", text)
    self.assertIn("provider JAR inside that image has SHA-256 `4a2d1364180350fffc671a7f61812ecbea5e68f04c90df95f95c0b669d4fbbcd`", text)
    self.assertIn("current Maven target JAR SHA-256 is `c0f84827366911b7714f8590c2055c956fdd47d87cbcb01462f88ee8f5ac05c5`", text)
    self.assertIn("all 46 ZIP entry names and uncompressed contents match", text)
    self.assertIn("downloaded hash-locked dependency artifacts", text)
    self.assertIn("That historical no-cache image build downloaded hash-locked dependency artifacts and was not network-isolated", text)

  def test_exact_image_resolver_qualification_is_recorded(self):
    text = README.read_text()
    self.assertIn("Prior provider-level loopback probe on offline-built runtime from staging fingerprint `a1b8f561ac91d1bde332675658195b06e000c8d84bc6290f8f26d54484edad6a`", text)
    self.assertIn("wheelhouse `container/resolver-wheelhouse.tar.gz` (67 files, 32,102,893 bytes", text)
    self.assertIn("SHA-256 `3859a6a17d27837713d1626a09a988d562455306eb79dc055564c3568e3e3587`", text)
    self.assertIn("The no-cache build used `--pull=never --network=none` and succeeded", text)
    self.assertIn("runtime image ID `b142c93da454437ef8e74dc5ab57e8b5149c632ebb1ba73c412c95247d489157`", text)
    self.assertIn("runner SHA `606e86f9335ef568c0dbec91008c7a987151d8dc6d41fcaabd238af84d260e8e`", text)
    self.assertIn("On this `a1b8f561ac91d1bde332675658195b06e000c8d84bc6290f8f26d54484edad6a` snapshot, the documented Python suite passed 150 tests", text)
    self.assertIn("the full Python suite passed 151 tests on the documentation/test-only follow-up", text)
    self.assertIn("Current #4 direct exact-image resolver qualification (isolated runs): qualification source fingerprint `7e2ff4291bf1e8e0a59deba92f6739d98c6e9f3b01201342ff74de639db4a2fc`; image ID `3a1eabb3cebadc77baf2bcbc0fac55b7bd5b5e3d60afb080a5a2b683214ec487`; digest `sha256:b9a45b0214a80008549bdefb001c2b9ab2c41c80d24feb909e6736e7ea8b7fb3`; production harness SHA `a24a1634b1b346ef9323415577cb799298433d1878c180f5db577db98f10ceb6`; exact resolver runner SHA `15eabbae4f1b25ca2035fed524d0e45f01980b071d7f9d0534c221afdc85d0c3`; fresh-Registry miss runner SHA `f28bfd1138dcbfcb20ded9c4dd8998bfb87db6bb51d912266a6b9aecf55a1099`.", text)
    self.assertIn("Results: `resolved` exact Identity ID/current owner key; `not_found` exact requested key with `get_value` and `remote_identity` each 1/1 clean-empty; `unavailable` from a stopped Registry.", text)
    self.assertIn("The three outcomes were established across isolated runs, not one combined run.", text)
    self.assertIn("The combined attempt's missing query after resolved-record traffic returned `unavailable` with one incomplete `get_value` referral; it is retained as a separate diagnostic.", text)
    self.assertIn("Multi-node/cross-node qualification is not an acceptance requirement under parent Issue #1.", text)
    self.assertNotIn("multi-node shared-store replay", text)
    self.assertNotIn("has not yet been qualified across nodes", text)
    self.assertIn("no actionable standards/security findings", text)
    self.assertNotIn("network-isolated image build remains unshown", text)

  def test_prior_provider_level_issue4_not_found_attempt_remains_unqualified(self):
    text = README.read_text()
    self.assertIn("The legacy selector `issue4-not-found` is now named `provider-not-found-diagnostic`: it starts a Keycloak HTTP flow separate from Issue #4’s direct resolver gate and was not run for this resolver-only qualification.", text)
    self.assertIn("Prior provider-level `issue4-not-found` diagnostic probe: image ID `a74499a0980391206b961260fe04e9e02b931d8c4fe36b61195318820d7874fe`", text)
    self.assertIn("digest `sha256:76d8083b7f2af1587d737ad82add075cf718f8814af891e06acf3a053c95512e`", text)
    self.assertIn("harness SHA `ccfda7f7d1ad4c7d634902ac1e067e409ce4411f50082e17385d589a85345b14`", text)
    self.assertIn("repeated `dial_warning` made resolution `unavailable`; provider returned 503/unavailable", text)
    self.assertIn("Status stayed 200/pending, redirects were safe, and no acceptance/callback evidence was present", text)
    self.assertIn("Eight fresh-client reads for an exact missing ID: one returned `not_found`", text)
    self.assertIn("seven returned `unavailable` with dial warnings", text)
    self.assertIn("Does not qualify clean CLI or provider `not_found`", text)

  def test_separate_registry_matrix_run_is_not_conflated_with_issue_four(self):
    text = README.read_text()
    self.assertIn("Separate #5 matrix attempt (not the #4 loopback run)", text)
    self.assertIn("harness SHA `3743c2b44e2f40f9f4ad3179d1d9a9767b0797661ce6dd9d6fc8729d1a13a7a6`", text)
    self.assertIn("provider_registry_inconsistent", text)
    self.assertIn("pending with no receipt or callback", text)
    self.assertIn("second missing-Identity attempt stopped at owner-key generation", text)
    self.assertIn("per-attempt key-filename fix was added afterward and was not live-verified", text)








  def test_earlier_loopback_is_distinguished_from_precommit_run(self):
    text = README.read_text()
    self.assertIn("Earlier #4 run: image ID", text)
    self.assertNotIn("Latest loopback from the current code state", text)
    self.assertIn("Prior #4 run (image predates d700)", text)

  def test_disposable_probe_documents_immutable_image_invocation(self):
    text = README.read_text()
    self.assertIn("podman build --no-cache --pull=never --target resolver-builder", text)
    self.assertIn("podman build --no-cache --pull=never --target runtime", text)
    self.assertIn("podman image inspect --format '{{.Id}}'", text)
    self.assertIn('WALLET_IT_IMAGE="$IMAGE_ID" python3 scripts/wallet_login_live_e2e.py', text)

  def test_runtime_configuration_documents_bundled_executable_default(self):
    text = README.read_text()
    self.assertIn("decent.wallet.identity.executable", text)
    self.assertIn("defaults to `/opt/decent-resolver/bin/decent-identity`", text)

  def test_failure_receipt_sanitizes_live_resolver_categories_before_cleanup(self):
    source = (README.parent / "scripts/wallet_login_live_e2e.py").read_text()
    self.assertIn("latest_resolver_diagnostics", source)
    self.assertIn("record_resolver_diagnostics(container)", source)
    self.assertIn("capture_live_resolver_diagnostics(\n            container, result, checkpoint)", source)
    start = source.index('def record_resolver_diagnostics(')
    end = source.index('def classify_oidc_action_error(', start)
    capture = source[start:end]
    self.assertIn("return sanitized_resolver_diagnostic_lines(logs.stdout)", capture)
    self.assertIn("categories = safe_resolver_diagnostic_snapshot(container)", capture)
    self.assertIn("marker = '[WALLET-RESOLVER-DIAG]'", source)
    self.assertNotIn("timestamp/logger-prefixed output", README.read_text())

  def test_stale_acceptance_wording_was_removed(self):
    text = README.read_text()
    self.assertNotIn("The latest run's three fresh resolver reads were unavailable", text)
    self.assertNotIn("This attribution fix is source-tested but has not yet been rebuilt into an immutable image and rerun", text)

  def test_provider_401_is_not_inferred_as_registry_miss(self):
    harness = (README.parent / "scripts/wallet_login_live_e2e.py").read_text()
    start = harness.index('def classify_provider_identity_outcome(')
    end = harness.index('\n\ndef missing_identity_flow(', start)
    classifier = harness[start:end]
    self.assertIn("if provider_http == 401:", classifier)
    self.assertIn("return 'provider_denied_unclassified'", classifier)
    self.assertNotIn('not_found', classifier)

  def test_registry_listener_is_loopback_only(self):
    harness = (README.parent / "scripts/wallet_login_live_e2e.py").read_text()
    start = harness.split("def start_registry(temp, image, run_seconds=300):", 1)[1].split("def start_resolver_tools(", 1)[0]
    self.assertIn("host: 127.0.0.1", start)
    self.assertNotIn("host: 0.0.0.0", start)

  def test_authenticator_preserves_keycloaks_execution_tracking_on_wallet_challenge(self):
    source = (README.parents[0] / "src/main/java/org/decentwallet/keycloak/wallet/WalletChallengeAuthenticator.java").read_text()
    challenge_start = source.index("public void authenticate(AuthenticationFlowContext context)")
    action_start = source.index("public void action(AuthenticationFlowContext context)", challenge_start)
    body = source[challenge_start:action_start]
    body = body[body.index("String accessCode = context.generateAccessCode();"):]
    self.assertNotIn("CURRENT_AUTHENTICATION_EXECUTION", body)
    self.assertNotIn("LAST_PROCESSED_EXECUTION", body)
    self.assertIn("context.getActionUrl(accessCode)", body)
