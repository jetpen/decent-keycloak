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

  def test_latest_image_from_current_worktree_records_fail_closed_gate(self):
    text = README.read_text()
    self.assertIn("Latest #4 run from the current worktree based on `d700281409a876b74ee025f6d27ff50b40b0fca5`", text)
    self.assertIn("image ID `92cc5d4c06fd4a65dd1e2fbbb5472f70fd901201536b88019706bff48c14ce13`", text)
    self.assertIn("digest `sha256:b4120b6aa22de7bf036250a9f66b701245e6f4fd8082cbeaf71f96d832cfd58b`", text)
    self.assertIn("harness SHA `e220a7920c211b5d995a0b389b4665107565bf8c40da0b43d8cc4c9d2afd8d61`", text)
    self.assertIn("All six fresh successor reads (three configured-port, three ephemeral) were unavailable with balanced JSON", text)
    self.assertIn("two configured-port samples had peer-handshake diagnostics", text)
    self.assertIn("Harness exited 1 at the successor-read gate", text)
    self.assertIn("no stale/current-key proofs or provider `not_found` case ran", text)
    self.assertIn("Prior #4 run (image predates d700)", text)
    self.assertIn("latest no-cache image was built from the current #4 worktree", text)
    self.assertIn("provider JAR inside that image has SHA-256 `4a2d1364180350fffc671a7f61812ecbea5e68f04c90df95f95c0b669d4fbbcd`", text)
    self.assertIn("current Maven target JAR SHA-256 is `c0f84827366911b7714f8590c2055c956fdd47d87cbcb01462f88ee8f5ac05c5`", text)
    self.assertIn("all 46 ZIP entry names and uncompressed contents match", text)
    self.assertIn("downloaded hash-locked dependency artifacts", text)
    self.assertIn("network-isolated image build remains unshown", text)

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
    start = harness.split("def start_registry(temp, image):", 1)[1].split("def start_resolver_tools(", 1)[0]
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
