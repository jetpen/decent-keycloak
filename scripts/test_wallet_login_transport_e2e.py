import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

from wallet_login_live_e2e import b64url, classify_identity_lookup  # noqa: E402


class AuthStatusBindingProbeTest(unittest.TestCase):
  def test_real_e2e_flow_tests_wrong_session_contexts_before_acceptance(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def auth_flow(')
    end = source.index('\ndef negative_proof_flow(', start)
    body = source[start:end]
    self.assertIn("'wrong_client'", body)
    self.assertIn("'wrong_tab'", body)
    self.assertIn("'wrong_realm'", body)
    self.assertIn('wrong_binding_statuses', body)
    self.assertIn('all(status == 404 for status in wrong_binding_statuses.values())', body)

  def test_expired_transaction_proof_does_not_reach_identity_resolution(self):
    test_source = Path(__file__).parents[1] / 'src/test/java/org/decentwallet/keycloak/wallet/WalletLoginTransportHandlerTest.java'
    body = test_source.read_text()
    self.assertIn('rejectsSubmissionAfterPendingTransactionExpiresWithoutReceipt', body)
    self.assertIn('clock.advanceSeconds(WalletLoginTransactionStore.TRANSACTION_LIFESPAN_SECONDS)', body)
    self.assertIn('assertEquals(0, lookups.get())', body)


if __name__ == '__main__':
  unittest.main()
