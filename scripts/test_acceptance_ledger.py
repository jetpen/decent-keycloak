"""Current Keycloak wallet-login qualification ledger, evidence and limits."""

from __future__ import annotations

from pathlib import Path
import unittest

README = Path(__file__).parents[1] / "README.md"

class AcceptanceLedgerTest(unittest.TestCase):
  def test_acceptance_ledger_reports_current_verification_layers_and_remaining_gates(self):
    text = README.read_text()
    self.assertIn("The checks failed against the synthetic merge revision", text)
    self.assertIn("The failure-specific probe also assumed the Hermes scratch directory exists", text)
    self.assertIn("146 tests (141 non-ledger, 11 ledger, 2 workflow guard tests", text)
    self.assertIn("missing Registry configuration returns unavailable (503), not absence (401)", text)
    self.assertIn("a Registry miss accompanied by a dial warning is unavailable", text)
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

  def test_latest_offline_build_and_live_probe_keep_missing_id_gate_open(self):
    text = README.read_text()
    self.assertIn("Latest #4 live probe on offline-built runtime from staging fingerprint `a1b8f561ac91d1bde332675658195b06e000c8d84bc6290f8f26d54484edad6a`", text)
    self.assertIn("wheelhouse `container/resolver-wheelhouse.tar.gz` (67 files, 32,102,893 bytes", text)
    self.assertIn("SHA-256 `3859a6a17d27837713d1626a09a988d562455306eb79dc055564c3568e3e3587`", text)
    self.assertIn("The no-cache build used `--pull=never --network=none` and succeeded", text)
    self.assertIn("runtime image ID `b142c93da454437ef8e74dc5ab57e8b5149c632ebb1ba73c412c95247d489157`", text)
    self.assertIn("runner SHA `606e86f9335ef568c0dbec91008c7a987151d8dc6d41fcaabd238af84d260e8e`", text)
    self.assertIn("On this `a1b8f561ac91d1bde332675658195b06e000c8d84bc6290f8f26d54484edad6a` snapshot, the documented Python suite passed 150 tests", text)
    self.assertIn("the full Python suite passed 151 tests on the documentation/test-only follow-up", text)
    self.assertIn("A separate stopped-Registry lookup classified `unavailable`", text)
    self.assertIn("Missing Identity produced Registry miss + terminal `not found` with repeated `dial_warning`, so classifier returned `unavailable`", text)
    self.assertIn("latest issue4-not-found run is recorded below", text)
    self.assertIn("clean provider-level terminal `not_found` for a missing Identity without disqualifying dial-warning diagnostics", text)
    self.assertIn("Multi-node/cross-node qualification is not an acceptance requirement under parent Issue #1.", text)
    self.assertNotIn("multi-node shared-store replay", text)
    self.assertNotIn("has not yet been qualified across nodes", text)
    self.assertIn("no actionable standards/security findings", text)
    self.assertNotIn("network-isolated image build remains unshown", text)

  def test_current_branch_issue4_not_found_attempt_remains_unqualified(self):
    text = README.read_text()
    self.assertIn("Python 189 tests pass on this worktree.", text)
    self.assertIn("Current #4 `issue4-not-found` run: image ID `a74499a0980391206b961260fe04e9e02b931d8c4fe36b61195318820d7874fe`", text)
    self.assertIn("Repeat #4 `issue4-not-found` attempt (report saved 2026-10-22 CDT / 2026-10-23 UTC; same immutable image/harness pair)", text)
    self.assertIn("CLI exited 1 as `unavailable` with `dial_warning`, `registry_miss` and terminal `not found`; provider returned HTTP 503/unavailable", text)
    self.assertIn("The harness reported cleanup `inconclusive`; post-run Podman events and exact full-ID inspections confirmed all three run-owned containers absent", text)
    self.assertIn("The offline cleanup readback correction is unit-tested but has not been live-rerun.", text)
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
