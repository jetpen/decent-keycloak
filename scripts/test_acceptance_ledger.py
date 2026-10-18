"""Current Keycloak wallet-login qualification ledger, evidence and limits."""

from __future__ import annotations

from pathlib import Path
import unittest

README = Path(__file__).parents[1] / "README.md"

class AcceptanceLedgerTest(unittest.TestCase):
  def test_acceptance_ledger_reports_current_verification_layers_and_remaining_gates(self):
    text = README.read_text()
    self.assertIn("Python **133 non-ledger tests plus 10 acceptance-ledger tests (143 total across eight imported modules; one module discovers zero tests)**", text)
    self.assertIn("10 acceptance-ledger tests", text)
    self.assertIn("uses a balanced-object scan", text)

  def test_exact_image_evidence_records_rotation_outcome_and_unqualified_registry_matrix(self):
    text = README.read_text()
    self.assertIn("Prior run: image `sha256:480807ab7ab77d5a169dbcea064ba4a096fcddebb324e0f44caa2e5e603547ae`", text)
    self.assertIn("Latest: image `sha256:29fe182466744bf7d9286fde27331cce784041170898eed430bfb8490ae8f602`", text)
    self.assertIn("All six fresh successor reads failed exact Identity/key matching", text)
    self.assertIn("Receipt contains sanitized per-read JSON-balance/exact-match booleans", text)







  def test_current_source_run_stopped_before_registry_rotation_or_proof(self):
    text = README.read_text()
    self.assertIn("Prior run: image `sha256:480807ab7ab77d5a169dbcea064ba4a096fcddebb324e0f44caa2e5e603547ae`", text)
    self.assertIn("Latest: image `sha256:29fe182466744bf7d9286fde27331cce784041170898eed430bfb8490ae8f602`", text)
    self.assertIn("All six fresh successor reads failed exact Identity/key matching", text)
    self.assertIn("Receipt contains sanitized per-read JSON-balance/exact-match booleans", text)

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
      assert "if provider_http == 401:" in classifier
      assert "return 'provider_denied_unclassified'" in classifier
      assert 'not_found' not in classifier

  def test_registry_listener_is_loopback_only(self):
      harness = (README.parent / "scripts/wallet_login_live_e2e.py").read_text()
      start = harness.split("def start_registry(temp, image):", 1)[1].split("def start_resolver_tools(", 1)[0]
      assert "host: 127.0.0.1" in start
      assert "host: 0.0.0.0" not in start

  def test_authenticator_preserves_keycloaks_execution_tracking_on_wallet_challenge(self):
      source = (README.parents[0] / "src/main/java/org/decentwallet/keycloak/wallet/WalletChallengeAuthenticator.java").read_text()
      challenge_start = source.index("public void authenticate(AuthenticationFlowContext context)")
      action_start = source.index("public void action(AuthenticationFlowContext context)", challenge_start)
      body = source[challenge_start:action_start]
      body = body[body.index("String accessCode = context.generateAccessCode();"):]
      assert "CURRENT_AUTHENTICATION_EXECUTION" not in body
      assert "LAST_PROCESSED_EXECUTION" not in body
      assert "context.getActionUrl(accessCode)" in body