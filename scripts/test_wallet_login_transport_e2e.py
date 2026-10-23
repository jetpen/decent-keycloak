import os
import sys
import tempfile
import unittest
from unittest.mock import patch
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


class Issue6PostConsumeRuntimeProfileTest(unittest.TestCase):
  def test_postconsume_runtime_profile_dispatches_to_issue6_runner(self):
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue6-postconsume-receipt-failure'}):
      with patch.object(probe, 'run_issue6_postconsume_receipt_failure_profile',
          return_value='selected', create=True) as runner:
        self.assertEqual('selected', probe.main())
    runner.assert_called_once_with()

  def test_postconsume_profile_invalid_value_lists_the_new_selector(self):
    import wallet_login_live_e2e as probe
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'unknown-profile'}):
      with self.assertRaisesRegex(ValueError, 'issue6-postconsume-receipt-failure'):
        probe.main()

  def test_postconsume_profile_requires_registered_test_provider(self):
    import wallet_login_live_e2e as probe
    self.assertTrue(probe.issue6_postconsume_provider_is_registered({
        'single_use_object_provider_ids': ['infinispan', 'issue6-postconsume-receipt-failure']}))
    self.assertFalse(probe.issue6_postconsume_provider_is_registered({
        'single_use_object_provider_ids': ['infinispan']}))
    self.assertFalse(probe.issue6_postconsume_provider_is_registered({
        'single_use_object_provider_ids': 'issue6-postconsume-receipt-failure'}))

  def test_postconsume_evidence_keeps_only_bounded_runtime_fields(self):
    from wallet_login_live_e2e import sanitize_live_checkpoint

    candidate = {
        'issue6_postconsume_receipt_failure_case': {
            'stage': 'failed_then_denied', 'proof_http': 503, 'retry_http': 404,
            'status_http': 404, 'proof_body_empty': True, 'proof_location_present': False,
            'proof_redirect_followed': False, 'status_body_empty': True,
            'status_location_present': False, 'status_redirect_followed': False,
            'callback_exposed': False, 'oidc_code_exposed': False,
            'fault_signal_correlated': True, 'delegate_commit_then_throw': True,
            'retry_redirect_followed': False, 'fault_signal_count': 1,
            'request_id': 'private', 'locator': 'https://private.example/path',
            'proof': 'secret', 'raw_logs': 'private diagnostic',
        },
        'issue6_postconsume_receipt_recovery': {
            'fresh_login_http': 200, 'fresh_login_transaction_available': True,
            'callback_http': 302, 'callback_code': True,
            'callback_replay_denied': True, 'pkce_token_http': 200,
            'authorization_code': 'secret', 'callback_url': 'https://private.example/cb',
        },
    }
    safe = sanitize_live_checkpoint(candidate)
    self.assertEqual({
        'issue6_postconsume_receipt_failure_case': {
            'stage': 'failed_then_denied', 'proof_http': 503, 'retry_http': 404,
            'status_http': 404, 'proof_body_empty': True, 'proof_location_present': False,
            'proof_redirect_followed': False, 'status_body_empty': True,
            'status_location_present': False, 'status_redirect_followed': False,
            'callback_exposed': False, 'oidc_code_exposed': False,
            'fault_signal_correlated': True, 'delegate_commit_then_throw': True,
            'retry_redirect_followed': False, 'fault_signal_count': 1,
        },
        'issue6_postconsume_receipt_recovery': {
            'fresh_login_http': 200, 'fresh_login_transaction_available': True,
            'callback_http': 302, 'callback_code': True,
            'callback_replay_denied': True, 'pkce_token_http': 200,
        },
    }, safe)

  def test_postconsume_failure_flow_checks_consumption_status_and_correlated_fault(self):
    import hashlib
    import json
    import subprocess
    import wallet_login_live_e2e as probe

    handle = 'H' * 43
    locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
        f'/decent-wallet-login/v1/transactions/{handle}')
    status_url = (f'/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/'
        f'{handle}/status')
    csrf = 'C' * 43
    login_page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const csrfToken = "{csrf}"; const statusUrl = "{status_url}";</script>').encode()

    class FakeClient:
      def __init__(self):
        self.redirects = []
        self.calls = []
      def request(self, method, path, data=None, headers=None, timeout=10):
        self.calls.append((method, path, data, headers))
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          return 200, {}, login_page
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge', 'csrf_token': csrf}).encode()
        if method == 'POST' and path == locator:
          posts = sum(call[0] == 'POST' for call in self.calls)
          return (503, {}, b'') if posts == 1 else (404, {}, b'')
        if method == 'GET' and path == status_url:
          return 404, {}, b''
        raise AssertionError('unexpected request boundary')

    clients = []
    def client_factory():
      client = FakeClient()
      clients.append(client)
      return client

    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    def fake_run(argv, **kwargs):
      self.assertEqual(argv[:3], ['podman', 'logs', '--since'])
      self.assertIn('--timestamps', argv)
      logs = (f'Wallet accepted receipt publication unavailable (request={request_id}, '
          'cause=post_consume_receipt_failure)\\n'
          'ISSUE6_TEST_FAULT: accepted receipt delegate write committed; test decorator threw\\n')
      return subprocess.CompletedProcess(argv, 0, logs, '')

    browser_state = {}
    with patch('wallet_login_live_e2e.run', side_effect=fake_run):
      evidence = probe.postconsume_receipt_failure_flow(None, 'fixture-identity', 'container',
          browser_state=browser_state, client_factory=client_factory,
          signer=lambda envelope, identity: 'A' * 86)
    self.assertIs(browser_state['browser'], clients[0])
    self.assertEqual('failed_then_denied', evidence['stage'])
    self.assertEqual(503, evidence['proof_http'])
    self.assertEqual(404, evidence['retry_http'])
    self.assertEqual(404, evidence['status_http'])
    self.assertFalse(evidence['callback_exposed'])
    self.assertTrue(evidence['fault_signal_correlated'])
    self.assertTrue(evidence['delegate_commit_then_throw'])

  def test_test_provider_is_test_image_only_and_selected_at_image_build(self):
    root = Path(__file__).parents[1]
    dockerfile = (root / 'container/Dockerfile').read_text()
    harness = (root / 'scripts/wallet_login_live_e2e.py').read_text()
    builder = (root / 'scripts/build_issue6_postconsume_provider.py').read_text()
    test_source = (root / 'src/test/java/org/decentwallet/keycloak/issue6test/'
        'Issue6PostConsumeReceiptFailureProviderFactory.java').read_text()
    main_sources = [path.read_text() for path in (root / 'src/main').rglob('*') if path.is_file()]

    self.assertIn('AS issue6-postconsume-test-runtime', dockerfile)
    self.assertIn('target/issue6-postconsume-receipt-failure-provider.jar', dockerfile)
    self.assertIn('--spi-single-use-object--provider=issue6-postconsume-receipt-failure', dockerfile)
    self.assertIn('--db=dev-file', dockerfile)
    self.assertIn('--spi-single-use-object--provider=infinispan', dockerfile)
    startup = harness.split('def start_keycloak(', 1)[1].split('def admin_token', 1)[0]
    self.assertIn("'--cache=local'", startup)
    self.assertNotIn('--spi-single-use-object--provider=', startup)
    self.assertNotIn("'show-config', '--all'", harness)
    self.assertNotIn('Issue6PostConsumeReceiptFailureProviderFactory', '\\n'.join(main_sources))
    self.assertIn('target/test-classes', builder)
    self.assertIn("os.environ.get('WALLET_IT_TEST_IMAGE')", harness)
    self.assertIn('issue6_postconsume_provider_is_registered(runtime_provenance)', harness)
    self.assertNotIn('--spi-single-use-object-provider-provider=', harness)
    self.assertIn('session.getProvider(SingleUseObjectProvider.class, "infinispan")', test_source)

  def test_postconsume_profile_requires_explicit_test_image_before_preflight(self):
    import wallet_login_live_e2e as probe
    with patch.dict(os.environ, {'WALLET_IT_TEST_IMAGE': ''}):
      with patch.object(probe, 'resolve_immutable_image') as resolve:
        with self.assertRaisesRegex(RuntimeError, 'WALLET_IT_TEST_IMAGE'):
          probe.run_issue6_postconsume_receipt_failure_profile()
    resolve.assert_not_called()

  def test_postconsume_profile_runs_fault_then_recovery_and_sanitizes_evidence(self):
    import hashlib
    import io
    import json
    import subprocess
    from contextlib import ExitStack, redirect_stdout
    from types import SimpleNamespace
    import wallet_login_live_e2e as probe

    handle = 'H' * 43
    locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
        f'/decent-wallet-login/v1/transactions/{handle}')
    status_url = (f'/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/'
        f'{handle}/status')
    csrf = 'C' * 43
    login_page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const csrfToken = "{csrf}"; const statusUrl = "{status_url}";</script>').encode()

    class FakeClient:
      def __init__(self, role):
        self.role = role
        self.redirects = []
        self.posts = 0
      def request(self, method, path, data=None, headers=None, timeout=10):
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          return 200, {}, login_page
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge', 'csrf_token': csrf}).encode()
        if method == 'POST' and path == locator and self.role == 'wallet':
          self.posts += 1
          return (503, {}, b'') if self.posts == 1 else (404, {}, b'')
        if method == 'GET' and path == status_url and self.role == 'browser':
          return 404, {}, b''
        raise AssertionError('unexpected profile request boundary')

    clients = []
    def client_factory():
      role = 'browser' if not clients else 'wallet'
      client = FakeClient(role)
      clients.append(client)
      return client

    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    def fake_run(argv, **kwargs):
      logs = (f'Wallet accepted receipt publication unavailable (request={request_id}, '
          'cause=post_consume_receipt_failure)\n'
          'ISSUE6_TEST_FAULT: accepted receipt delegate write committed; test decorator threw\n')
      return subprocess.CompletedProcess(argv, 0, logs, '')

    def fake_openssl(argv, **kwargs):
      output = b'X' * 44 if argv[1] == 'pkey' else b'S' * 64
      return subprocess.CompletedProcess(argv, 0, output, b'')

    runtime = {
        'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
        'single_use_object_provider_path': 'unavailable',
        'single_use_object_provider_ids': ['issue6-postconsume-receipt-failure'],
        'runtime_qualification_status': 'open_runtime_facts_unavailable',
    }
    keycloak = SimpleNamespace(wallet_container_id='a' * 64)
    recovery = {
        'login_page_http': 200, 'fresh_locator_distinct': True,
        'initial_status_accepted': True, 'callback_http': 302,
        'callback_code_returned': True, 'callback_replay_error_returned': True,
        'callback_replay_code_returned': False, 'pkce_token_http': 200,
    }
    with tempfile.TemporaryDirectory() as scratch:
      output = io.StringIO()
      with ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
        stack.enter_context(patch.object(probe, 'IMAGE', 'mutable-tag'))
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
        stack.enter_context(patch.dict(os.environ,
            {'WALLET_IT_TEST_IMAGE': 'isolated-test-image'}))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('immutable-test-image', 'sha256:' + 'b' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='resolver-tools'))
        registry = object()
        stack.enter_context(patch.object(probe, 'start_registry',
            return_value=(registry, 'bootstrap', 12345)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=12346))
        key = Path(scratch) / 'identity.pem'
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=(key, SimpleNamespace(name='wrapper'), 'identity-id')))
        stack.enter_context(patch.object(probe, 'start_keycloak', return_value=keycloak))
        stack.enter_context(patch.object(probe, 'admin_token', return_value='admin-token'))
        stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=runtime))
        stack.enter_context(patch.object(probe, 'configure_realm'))
        stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
        stack.enter_context(patch.object(probe, 'provision_identity_attribute'))
        selected_recovery = stack.enter_context(patch.object(probe, 'auth_flow', return_value=recovery))
        cleanup = stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=0))
        stack.enter_context(patch.object(probe, 'Client', side_effect=client_factory))
        stack.enter_context(patch.object(probe, 'run', side_effect=fake_run))
        stack.enter_context(patch.object(probe.subprocess, 'run', side_effect=fake_openssl))
        stack.enter_context(patch.object(probe, 'write_private_signing_input'))
        with redirect_stdout(output):
          probe.run_issue6_postconsume_receipt_failure_profile()

      selected_recovery.assert_called_once()
      self.assertIs(selected_recovery.call_args.args[0], clients[0])
      self.assertEqual(key, selected_recovery.call_args.args[1])
      self.assertEqual('identity-id', selected_recovery.call_args.args[2])
      self.assertEqual('a' * 64, selected_recovery.call_args.args[3])
      self.assertEqual(locator, selected_recovery.call_args.kwargs['prior_locator'])
      self.assertEqual('immutable-test-image', selected_recovery.call_args.args[4])
      cleanup.assert_called_once_with(registry, 'resolver-tools')
      prefix = 'issue6_postconsume_receipt_failure_evidence='
      rendered = next(line[len(prefix):] for line in output.getvalue().splitlines()
          if line.startswith(prefix))
      evidence = json.loads(rendered)
      self.assertEqual(503, evidence['issue6_postconsume_receipt_failure_case']['proof_http'])
      self.assertEqual(404, evidence['issue6_postconsume_receipt_failure_case']['retry_http'])
      self.assertTrue(evidence['issue6_postconsume_receipt_recovery']['fresh_login_transaction_available'])
      self.assertTrue(evidence['issue6_postconsume_receipt_recovery']['callback_replay_denied'])
      self.assertEqual(200, evidence['issue6_postconsume_receipt_recovery']['pkce_token_http'])
      self.assertNotIn(locator, rendered)
      self.assertNotIn(handle, rendered)


if __name__ == '__main__':
  unittest.main()
