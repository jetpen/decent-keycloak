"""Focused Issue #6 acceptance-profile regressions."""

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from unittest.mock import patch

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

import wallet_login_live_e2e as probe  # noqa: E402


class Issue6SingleNodeProfileTest(unittest.TestCase):
  def test_forwarded_port_matches_external_keycloak_origin(self):
    self.assertEqual(str(probe.KC_PORT), probe.Client().forward_headers['X-Forwarded-Port'])

  def test_callback_replay_capture_does_not_follow_error_redirect(self):
    class Handler(BaseHTTPRequestHandler):
      def do_GET(self):
        if self.path == '/callback':
          self.send_response(302)
          self.send_header('Location',
              f'https://idp.example:{cast(ThreadingHTTPServer, self.server).server_port}'
              '/auth/realms/test/error'
              '?state=state-1&error=access_denied')
          self.end_headers()
          return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Keycloak error page')

      def log_message(self, format, *args):
        return

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      with patch.object(probe, 'KC_PORT', cast(ThreadingHTTPServer, server).server_port):
        client = probe.Client()
        status, headers, _ = client.request('GET', '/callback', follow_redirects=False)
        self.assertEqual(302, status)
        self.assertIn('state=state-1', headers['Location'])
        followed_status, _, _ = client.request('GET', '/callback')
        self.assertEqual(200, followed_status)
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=2)

  def test_profile_dispatch_is_separate_from_broad_e2e_matrix(self):
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue6-single-node'}):
      with patch.object(probe, 'resolve_immutable_image',
          side_effect=AssertionError('broad E2E path selected')):
        with patch.object(probe, 'run_issue6_single_node_profile', create=True) as selected:
          probe.main()
    selected.assert_called_once_with()

    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue6-auth-flow'}):
      with patch.object(probe, 'resolve_immutable_image',
          side_effect=AssertionError('broad E2E path selected')):
        with patch.object(probe, 'run_issue6_single_node_profile', create=True) as selected:
          probe.main()
    selected.assert_called_once_with(run_expiry=False)

  def test_changed_signature_preserves_all_proof_claims(self):
    proof = json.dumps({
        'profile': 'decent-wallet-login-v1',
        'challenge': 'challenge-value',
        'identity_id': 'identity-value',
        'signature': 'original-signature',
    }, separators=(',', ':')).encode()

    changed = json.loads(probe.changed_signed_proof(proof, b'a' * 64))

    self.assertEqual({
        'profile': 'decent-wallet-login-v1',
        'challenge': 'challenge-value',
        'identity_id': 'identity-value',
    }, {key: value for key, value in changed.items() if key != 'signature'})
    self.assertNotEqual('original-signature', changed['signature'])

  def test_oidc_error_description_does_not_change_registered_redirect_identity(self):
    redirect = 'https://rp.example/callback?tenant=one'
    error_url = (redirect + '&state=state-1&error=temporarily_unavailable'
        '&error_description=Authentication+expired&iss=https%3A%2F%2Fidp.example')
    outcome = probe.callback_replay_outcome(302, error_url, 'state-1', redirect)
    self.assertTrue(outcome['redirect_uri_matches'])
    self.assertTrue(outcome['state_preserved'])
    self.assertTrue(outcome['replay_denied_safely'])
    for invalid in (
        error_url.replace('tenant=one', 'tenant=two'),
        error_url.replace('rp.example', 'attacker.example'),
        error_url.replace('state=state-1', 'state=wrong'),
        error_url + '&code=',
        error_url + '&state=state-1',
        error_url + '&unexpected=value',
    ):
      with self.subTest(invalid=invalid):
        self.assertFalse(probe.callback_replay_outcome(
            302, invalid, 'state-1', redirect)['replay_denied_safely'])

  def test_callback_replay_requires_safe_denial_without_code(self):
    valid = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=access_denied',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertEqual({
        'redirect_http': 302,
        'redirect_uri_matches': True,
        'state_preserved': True,
        'error_returned': True,
        'authorization_code_returned': False,
        'internal_error_page': False,
        'internal_error_reason': 'callback_url_unavailable',
        'internal_error_hostname_matches': False,
        'internal_error_port_matches': False,
        'replay_denied_safely': True,
    }, valid)

    keycloak_error = probe.callback_replay_outcome(
        302,
        'https://idp.example/auth/realms/wallet/login-actions/error?error=access_denied',
        'state-1',
        'https://rp.example/callback',
        'https://idp.example/auth/realms/wallet/broker/wallet/endpoint',
    )
    self.assertFalse(keycloak_error['redirect_uri_matches'])
    self.assertFalse(keycloak_error['state_preserved'])
    self.assertTrue(keycloak_error['internal_error_page'])
    self.assertEqual('same_origin_error_without_code', keycloak_error['internal_error_reason'])
    self.assertTrue(keycloak_error['internal_error_hostname_matches'])
    self.assertTrue(keycloak_error['internal_error_port_matches'])
    self.assertTrue(keycloak_error['replay_denied_safely'])

    keycloak_http_error = probe.callback_replay_outcome(
        302,
        'http://idp.example:18886/auth/realms/wallet/login-actions/error?error=access_denied',
        'state-1',
        'https://rp.example/callback',
        'http://idp.example:18886/auth/realms/wallet/broker/wallet/endpoint',
    )
    self.assertFalse(keycloak_http_error['redirect_uri_matches'])
    self.assertTrue(keycloak_http_error['error_returned'])
    self.assertFalse(keycloak_http_error['authorization_code_returned'])
    self.assertTrue(keycloak_http_error['internal_error_page'])
    self.assertEqual('same_origin_error_without_code', keycloak_http_error['internal_error_reason'])
    self.assertTrue(keycloak_http_error['internal_error_hostname_matches'])
    self.assertTrue(keycloak_http_error['internal_error_port_matches'])
    self.assertTrue(keycloak_http_error['replay_denied_safely'])

    keycloak_loopback_error = probe.callback_replay_outcome(
        302,
        'http://127.0.0.1:18886/auth/realms/wallet/login-actions/error?error=access_denied',
        'state-1',
        'https://rp.example/callback',
        'https://idp.example:18886/auth/realms/wallet/broker/wallet/endpoint',
    )
    self.assertTrue(keycloak_loopback_error['internal_error_page'])
    self.assertEqual('loopback_keycloak_error_without_code',
        keycloak_loopback_error['internal_error_reason'])
    self.assertFalse(keycloak_loopback_error['internal_error_hostname_matches'])
    self.assertTrue(keycloak_loopback_error['internal_error_port_matches'])
    self.assertTrue(keycloak_loopback_error['replay_denied_safely'])

    wrong_target = probe.callback_replay_outcome(
        302,
        'https://attacker.example/callback?state=state-1&error=access_denied',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertFalse(wrong_target['redirect_uri_matches'])
    self.assertFalse(wrong_target['state_preserved'])
    self.assertFalse(wrong_target['replay_denied_safely'])

    keycloak_wrong_origin = probe.callback_replay_outcome(
        302,
        'https://attacker.example/auth/error?error=access_denied',
        'state-1',
        'https://rp.example/callback',
        'https://idp.example/auth/realms/wallet/broker/wallet/endpoint',
    )
    self.assertFalse(keycloak_wrong_origin['internal_error_page'])
    self.assertEqual('redirect_origin_mismatch', keycloak_wrong_origin['internal_error_reason'])
    self.assertFalse(keycloak_wrong_origin['internal_error_hostname_matches'])
    self.assertTrue(keycloak_wrong_origin['internal_error_port_matches'])
    self.assertFalse(keycloak_wrong_origin['replay_denied_safely'])

    keycloak_scheme_mismatch = probe.callback_replay_outcome(
        302,
        'http://idp.example/auth/error?error=access_denied',
        'state-1',
        'https://rp.example/callback',
        'https://idp.example/auth/realms/wallet/broker/wallet/endpoint',
    )
    self.assertFalse(keycloak_scheme_mismatch['internal_error_page'])
    self.assertEqual('redirect_scheme_mismatch', keycloak_scheme_mismatch['internal_error_reason'])
    self.assertTrue(keycloak_scheme_mismatch['internal_error_hostname_matches'])
    self.assertTrue(keycloak_scheme_mismatch['internal_error_port_matches'])
    self.assertFalse(keycloak_scheme_mismatch['replay_denied_safely'])

    code_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&code=reused',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertTrue(code_replay['authorization_code_returned'])
    self.assertFalse(code_replay['error_returned'])
    self.assertFalse(code_replay['replay_denied_safely'])

    empty_error_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=&code=',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertFalse(empty_error_replay['error_returned'])
    self.assertTrue(empty_error_replay['authorization_code_returned'])
    self.assertFalse(empty_error_replay['replay_denied_safely'])

    duplicate_error_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=first&error=second',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertFalse(duplicate_error_replay['error_returned'])
    self.assertFalse(duplicate_error_replay['replay_denied_safely'])

    empty_code_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=access_denied&code=',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertTrue(empty_code_replay['authorization_code_returned'])
    self.assertFalse(empty_code_replay['replay_denied_safely'])

    duplicate_code_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=access_denied&code=one&code=two',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertTrue(duplicate_code_replay['authorization_code_returned'])
    self.assertFalse(duplicate_code_replay['replay_denied_safely'])

  def test_initial_callback_validates_static_query_state_and_single_code(self):
    valid = probe.callback_redirect_outcome(
        'https://rp.example/callback?tenant=one&state=state-1&code=code-1',
        'state-1',
        'https://rp.example/callback?tenant=one',
    )
    self.assertTrue(valid['redirect_uri_matches'])
    self.assertTrue(valid['state_preserved'])
    self.assertTrue(valid['authorization_code_returned'])

    empty_error = probe.callback_redirect_outcome(
        'https://rp.example/callback?tenant=one&state=state-1&code=code-1&error=',
        'state-1',
        'https://rp.example/callback?tenant=one',
    )
    self.assertTrue(empty_error['error_parameter_present'])
    self.assertFalse(empty_error['error_returned'])

    duplicate_error = probe.callback_redirect_outcome(
        'https://rp.example/callback?tenant=one&state=state-1&code=code-1&error=one&error=two',
        'state-1',
        'https://rp.example/callback?tenant=one',
    )
    self.assertTrue(duplicate_error['error_parameter_present'])

    unexpected_query = probe.callback_redirect_outcome(
        'https://rp.example/callback?tenant=one&extra=unexpected&state=state-1&code=code-1',
        'state-1',
        'https://rp.example/callback?tenant=one',
    )
    self.assertFalse(unexpected_query['redirect_uri_matches'])
    self.assertFalse(unexpected_query['state_preserved'])

    duplicate_code = probe.callback_redirect_outcome(
        'https://rp.example/callback?tenant=one&state=state-1&code=one&code=two',
        'state-1',
        'https://rp.example/callback?tenant=one',
    )
    self.assertTrue(duplicate_code['authorization_code_returned'])
    self.assertFalse(duplicate_code['single_authorization_code_returned'])

  def test_initial_status_requires_accepted_receipt_and_callback(self):
    accepted = b'{"status":"accepted","callback":"https://idp.example/callback"}'
    self.assertTrue(probe.accepted_status_payload(200, accepted))
    self.assertFalse(probe.accepted_status_payload(200, b'{"status":"pending"}'))
    self.assertFalse(probe.accepted_status_payload(503, accepted))

  def test_callback_replay_guard_log_parser_requires_unique_request_correlation(self):
    request_id = 'a' * 32
    expected = (f'Wallet callback replay guard entered (request={request_id}, '
        'state_present=true, redirect_uri_present=true, redirect_uri_registered=true, '
        'protocol_openid_connect=true)')
    matched = probe.callback_replay_guard_log_outcome(expected, request_id)
    self.assertEqual({'marker_count': 1, 'unavailable_marker_count': 0,
        'other_marker_count': 0, 'reached': True, 'state_present': True,
        'redirect_uri_present': True, 'redirect_uri_registered': True,
        'protocol_openid_connect': True}, matched)

    unavailable = probe.callback_replay_guard_log_outcome(
        expected.replace(request_id, 'unavailable'), request_id)
    self.assertEqual(1, unavailable['unavailable_marker_count'])
    self.assertFalse(unavailable['reached'])

    other_id = 'b' * 32
    unmatched = probe.callback_replay_guard_log_outcome(
        expected.replace(request_id, other_id), request_id)
    self.assertEqual(1, unmatched['other_marker_count'])
    self.assertFalse(unmatched['reached'])
    mixed = probe.callback_replay_guard_log_outcome(
        expected + '\n' + expected.replace(request_id, other_id), request_id)
    self.assertEqual(2, mixed['marker_count'])
    self.assertFalse(mixed['reached'])
    self.assertNotIn(request_id, str(mixed))

  def test_login_error_event_delta_uses_only_safe_new_error_categories(self):
    previous = [{'type': 'LOGIN_ERROR', 'error': 'expired_code',
        'detail_names': ['code_id']}]
    current = previous + [
        {'type': 'LOGIN_ERROR', 'error': 'invalid_code',
         'detail_names': ['code_id', 'redirect_uri']},
        {'type': 'LOGIN_ERROR', 'error': 'secret-bearing-unknown',
         'detail_names': ['username']},
    ]
    outcome = probe.login_error_event_delta(previous, current)
    self.assertEqual({'read': True, 'count': 2, 'category': 'multiple'}, outcome)
    self.assertNotIn('secret-bearing-unknown', str(outcome))
    self.assertEqual({'read': False, 'count': 0, 'category': 'unavailable'},
        probe.login_error_event_delta(None, current))

  def test_callback_authenticator_lifecycle_parser_separates_rearm_and_reentry(self):
    request_id = 'a' * 32
    other_id = 'b' * 32
    logs = '\n'.join((
        'Wallet challenge authenticator entered (request=unavailable, callback_completed=false)',
        f'Wallet callback execution rearmed (request={request_id}, execution_id_present=true)',
        f'Wallet challenge authenticator entered (request={request_id}, callback_completed=true)',
        f'Wallet callback execution rearmed (request={other_id}, execution_id_present=true)',
    ))
    outcome = probe.callback_authenticator_lifecycle_log_outcome(logs, request_id)
    self.assertEqual(2, outcome['authenticator_entry_marker_count'])
    self.assertEqual(1, outcome['authenticator_entry_unavailable_marker_count'])
    self.assertEqual(0, outcome['authenticator_entry_other_marker_count'])
    self.assertEqual(1, outcome['authenticator_entry_callback_completed_true_marker_count'])
    self.assertEqual(1, outcome['authenticator_entry_callback_completed_false_marker_count'])
    self.assertTrue(outcome['authenticator_entry_reached'])
    self.assertTrue(outcome['authenticator_entry_completed_marker_present'])
    self.assertEqual(2, outcome['callback_flow_rearm_marker_count'])
    self.assertEqual(1, outcome['callback_flow_rearm_other_marker_count'])
    self.assertTrue(outcome['callback_flow_rearmed'])
    self.assertTrue(outcome['callback_flow_rearm_execution_id_present'])
    self.assertNotIn(request_id, str(outcome))

    unavailable = probe.callback_authenticator_lifecycle_log_outcome(
        'Wallet challenge authenticator entered (request=unavailable, callback_completed=true)',
        request_id)
    self.assertEqual(1, unavailable['authenticator_entry_unavailable_marker_count'])
    self.assertEqual(1, unavailable['authenticator_entry_callback_completed_true_marker_count'])
    self.assertEqual(0, unavailable['authenticator_entry_callback_completed_false_marker_count'])
    self.assertFalse(unavailable['authenticator_entry_reached'])
    self.assertFalse(unavailable['callback_flow_rearmed'])

    duplicate = probe.callback_authenticator_lifecycle_log_outcome(
        f'Wallet challenge authenticator entered (request={request_id}, callback_completed=true)\n'
        f'Wallet challenge authenticator entered (request={request_id}, callback_completed=true)',
        request_id)
    self.assertTrue(duplicate['authenticator_entry_reached'])
    self.assertEqual(2, duplicate['authenticator_entry_marker_count'])

  def test_postconsume_stage_checkpoints_keep_granular_safe_outcomes(self):
    projected = probe.sanitize_live_checkpoint({
        'issue6_postconsume_callback_gate_failure_case': {
            'stage': 'provider_registration_verified', 'provider_id': 'secret-provider-id'},
        'issue6_postconsume_receipt_recovery': {
            'stage': 'fresh_replay', 'fresh_login_http': 400,
            'callback_replay_guard_log_read': True,
            'callback_replay_guard_reached': False,
            'callback_replay_guard_marker_count': 1,
            'callback_replay_guard_unavailable_marker_count': 1,
            'callback_replay_guard_other_marker_count': 0,
            'failure_category': 'runtime_error',
            'callback_url': 'https://secret.example/callback?code=secret',
            'raw_error': 'secret diagnostic'},
      })

    self.assertEqual({'stage': 'provider_registration_verified'},
        projected['issue6_postconsume_callback_gate_failure_case'])
    self.assertEqual({'stage': 'fresh_replay', 'fresh_login_http': 400,
        'callback_replay_guard_log_read': True,
        'callback_replay_guard_reached': False,
        'callback_replay_guard_marker_count': 1,
        'callback_replay_guard_unavailable_marker_count': 1,
        'callback_replay_guard_other_marker_count': 0,
        'failure_category': 'runtime_error'},
        projected['issue6_postconsume_receipt_recovery'])
    self.assertNotIn('provider_id', str(projected))
    self.assertNotIn('callback_url', str(projected))
    self.assertNotIn('raw_error', str(projected))

  def test_checkpointed_setup_step_records_safe_stage_and_category(self):
    events = []

    def mark_stage(stage, **facts):
      events.append((stage, facts))

    with self.assertRaisesRegex(RuntimeError, 'not retained'):
      probe.run_checkpointed_step(mark_stage, 'configure_realm', 'realm_configured',
          lambda: (_ for _ in ()).throw(RuntimeError('not retained')))

    self.assertEqual([
        ('configure_realm', {}),
        ('configure_realm', {'failure_category': 'runtime_error'}),
    ], events)
    projected = probe.sanitize_live_checkpoint({
        'issue6_postconsume_callback_gate_failure_case': {
            'stage': events[-1][0], **events[-1][1]},
    })
    self.assertEqual({'stage': 'configure_realm', 'failure_category': 'runtime_error'},
        projected['issue6_postconsume_callback_gate_failure_case'])

  def test_checkpointed_setup_step_records_completion(self):
    events = []
    result = probe.run_checkpointed_step(
        lambda stage, **facts: events.append((stage, facts)),
        'enable_login_events', 'login_events_enabled', lambda: 'done')
    self.assertEqual('done', result)
    self.assertEqual([('enable_login_events', {}), ('login_events_enabled', {})], events)

  def test_cli_failure_reports_safe_category_without_exception_text_or_traceback(self):
    env = dict(os.environ, WALLET_IT_PROFILE='unsupported-test-profile')
    env.pop('WALLET_IT_IMAGE', None)
    completed = subprocess.run([sys.executable,
        str(Path(probe.__file__).resolve())], env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=10, check=False)
    self.assertEqual(1, completed.returncode)
    self.assertIn('harness_status=failed; failure_category=value_error', completed.stdout)
    self.assertNotIn('Traceback', completed.stdout + completed.stderr)
    self.assertNotIn('WALLET_IT_PROFILE must be', completed.stdout + completed.stderr)

  def test_auth_flow_checkpoint_records_login_page_status_before_assertion(self):
    class FailedLoginClient:
      def request(self, *_args, **_kwargs):
        return 400, {}, b'body contains a secret and is intentionally discarded'

    progress = []
    with self.assertRaises(RuntimeError):
      probe.auth_flow(FailedLoginClient(), Path('/unused'), 'fixture-id',
          'fixture-container', 'fixture-image',
          progress_callback=lambda stage, fields: progress.append((stage, fields)))

    self.assertEqual([('fresh_login_page', {'fresh_login_http': 400})], progress)

  def test_callback_gate_profile_checkpoints_setup_failure_boundary(self):
    from contextlib import ExitStack, redirect_stdout
    from types import SimpleNamespace

    with tempfile.TemporaryDirectory() as scratch:
      registry_node = object()
      output = io.StringIO()
      with ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
        stack.enter_context(patch.object(probe, 'IMAGE', 'mutable-tag'))
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
        stack.enter_context(patch.dict(os.environ,
            {'WALLET_IT_TEST_IMAGE': 'test-image'}, clear=False))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('immutable-image', 'sha256:' + 'a' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools',
            return_value='resolver-tools-id'))
        stack.enter_context(patch.object(probe, 'start_registry',
            return_value=(registry_node, 'bootstrap', 12345)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=12346))
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=(Path(scratch) / 'identity.pem', SimpleNamespace(name='wrapper'), 'identity-id')))
        stack.enter_context(patch.object(probe, 'start_keycloak',
            side_effect=RuntimeError('do not serialize this diagnostic')))
        stack.enter_context(patch.object(probe, 'cleanup_after_failure', return_value=0))
        stack.enter_context(redirect_stdout(output))

        with self.assertRaises(RuntimeError):
          probe.run_issue6_postconsume_callback_gate_failure_profile()

      partial_lines = [line.removeprefix('partial_evidence=')
          for line in output.getvalue().splitlines()
          if line.startswith('partial_evidence=')]
      self.assertGreaterEqual(len(partial_lines), 1)
      for partial in partial_lines:
        receipt = json.loads(partial)
        self.assertEqual('identity_setup',
            receipt['issue6_postconsume_callback_gate_failure_case']['stage'])
      self.assertNotIn('do not serialize this diagnostic', output.getvalue())

  def test_receipt_failure_recovery_checkpoint_retains_last_http_result(self):
    from contextlib import ExitStack, redirect_stdout
    from types import SimpleNamespace

    with tempfile.TemporaryDirectory() as scratch:
      output = io.StringIO()
      events = []
      client = SimpleNamespace(wallet_container_id='a' * 64)
      runtime = {
          'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
          'single_use_object_provider_ids': ['issue6-postconsume-receipt-failure'],
          'single_use_object_provider_path': 'issue6-postconsume-receipt-failure',
      }

      def failed_receipt_case(*_args, browser_state, **_kwargs):
        browser_state.update({'browser': object(), 'initial_locator': 'prior-locator'})
        return {'stage': 'failed_then_denied', 'proof_http': 503,
            'retry_http': 404, 'status_http': 404, 'proof_body_empty': True,
            'proof_location_present': False, 'proof_redirect_followed': False,
            'status_body_empty': True, 'status_location_present': False,
            'status_redirect_followed': False, 'callback_exposed': False,
            'oidc_code_exposed': False, 'fault_signal_correlated': True,
            'delegate_commit_then_throw': True, 'retry_redirect_followed': False,
            'fault_signal_count': 1}

      def fail_recovery(*_args, progress_callback=None, **_kwargs):
        events.append('auth_flow')
        if progress_callback is None:
          raise AssertionError('recovery progress callback is required')
        progress_callback('fresh_login_page', {'fresh_login_http': 400})
        raise RuntimeError('sensitive response details must not be recorded')

      with ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
        stack.enter_context(patch.object(probe, 'IMAGE', 'mutable-tag'))
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
        stack.enter_context(patch.dict(os.environ,
            {'WALLET_IT_TEST_IMAGE': 'test-image'}, clear=False))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('immutable-image', 'sha256:' + 'b' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='tools-id'))
        stack.enter_context(patch.object(probe, 'start_registry',
            return_value=(object(), 'bootstrap', 12345)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=12346))
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=(Path(scratch) / 'identity.pem', SimpleNamespace(name='wrapper'), 'identity-id')))
        stack.enter_context(patch.object(probe, 'start_keycloak', return_value=client))
        stack.enter_context(patch.object(probe, 'admin_token', return_value='admin-token'))
        stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=runtime))
        stack.enter_context(patch.object(probe, 'runtime_baseline_is_verified', return_value=True))
        stack.enter_context(patch.object(probe, 'issue6_postconsume_provider_is_registered', return_value=True))
        stack.enter_context(patch.object(probe, 'configure_realm'))
        stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
        stack.enter_context(patch.object(probe, 'provision_identity_attribute'))
        stack.enter_context(patch.object(probe, 'postconsume_receipt_failure_flow',
            side_effect=failed_receipt_case))
        stack.enter_context(patch.object(probe, 'wait_for_identity_lookup_cooldown',
            side_effect=lambda: events.append('cooldown')))
        stack.enter_context(patch.object(probe, 'auth_flow', side_effect=fail_recovery))
        stack.enter_context(patch.object(probe, 'cleanup_after_failure', return_value=0))
        stack.enter_context(redirect_stdout(output))

        with self.assertRaises(RuntimeError):
          probe.run_issue6_postconsume_receipt_failure_profile()

      self.assertEqual(['cooldown', 'auth_flow'], events)
      partial_lines = [line.removeprefix('partial_evidence=')
          for line in output.getvalue().splitlines()
          if line.startswith('partial_evidence=')]
      self.assertGreaterEqual(len(partial_lines), 1)
      for partial in partial_lines:
        receipt = json.loads(partial)
        self.assertEqual({'stage': 'fresh_login_page', 'fresh_login_http': 400,
            'failure_category': 'runtime_error'},
            receipt['issue6_postconsume_receipt_recovery'])
      self.assertNotIn('sensitive response details', output.getvalue())

  def test_auth_flow_failure_checkpoints_allowlisted_status_without_error_text(self):
    result = {'issue6_single_node': {'stage': 'auth_flow', 'node_count': 1}}
    checkpoints = []
    attempt = probe.AuthFlowAttempt()
    attempt.record('proof_post_http', 202)
    attempt.record('callback_replay_internal_error_page', False)
    attempt.record('callback_replay_internal_error_reason', 'redirect_origin_mismatch')
    attempt.record('callback_replay_internal_error_hostname_matches', False)
    attempt.record('callback_replay_internal_error_port_matches', True)
    attempt.record('callback_replay_guard_log_read', True)
    attempt.record('callback_replay_guard_reached', False)
    attempt.record('callback_replay_login_error_log_read', True)
    attempt.record('callback_replay_login_error_count', 1)
    attempt.record('callback_replay_login_error_category', 'invalid_code')
    attempt.record('callback_replay_guard_marker_count', 0)
    attempt.record('callback_replay_authenticator_entry_reached', False)
    attempt.record('callback_replay_authenticator_entry_completed', False)
    attempt.record('callback_replay_authenticator_entry_marker_count', 1)
    attempt.record('callback_replay_authenticator_entry_unavailable_marker_count', 1)
    attempt.record('callback_replay_authenticator_entry_other_marker_count', 0)
    attempt.record('callback_top_flow_rearm_reached', True)
    attempt.record('callback_top_flow_rearm_execution_id_present', True)
    attempt.record('callback_top_flow_rearm_marker_count', 1)
    attempt.record('callback_top_flow_rearm_unavailable_marker_count', 0)
    attempt.record('callback_top_flow_rearm_other_marker_count', 0)

    with self.assertRaises(probe.AuthFlowFailure) as raised:
      probe.run_issue6_auth_flow(
          result,
          attempt,
          lambda: (_ for _ in ()).throw(RuntimeError('raw secret-bearing failure')),
          lambda: checkpoints.append(probe.sanitize_live_checkpoint(result)),
      )

    self.assertEqual(1, len(checkpoints))
    self.assertEqual(202, checkpoints[0]['issue6_single_node']['proof_post_http'])
    self.assertFalse(checkpoints[0]['issue6_single_node']['callback_replay_internal_error_page'])
    self.assertEqual('redirect_origin_mismatch',
        checkpoints[0]['issue6_single_node']['callback_replay_internal_error_reason'])
    self.assertFalse(checkpoints[0]['issue6_single_node'][
        'callback_replay_internal_error_hostname_matches'])
    self.assertTrue(checkpoints[0]['issue6_single_node'][
        'callback_replay_internal_error_port_matches'])
    self.assertTrue(checkpoints[0]['issue6_single_node']['callback_replay_guard_log_read'])
    self.assertTrue(checkpoints[0]['issue6_single_node'][
        'callback_replay_login_error_log_read'])
    self.assertEqual(1, checkpoints[0]['issue6_single_node'][
        'callback_replay_login_error_count'])
    self.assertEqual('invalid_code', checkpoints[0]['issue6_single_node'][
        'callback_replay_login_error_category'])
    self.assertFalse(checkpoints[0]['issue6_single_node']['callback_replay_guard_reached'])
    self.assertEqual(0, checkpoints[0]['issue6_single_node']['callback_replay_guard_marker_count'])
    self.assertFalse(checkpoints[0]['issue6_single_node'][
        'callback_replay_authenticator_entry_reached'])
    self.assertEqual(1, checkpoints[0]['issue6_single_node'][
        'callback_replay_authenticator_entry_unavailable_marker_count'])
    self.assertTrue(checkpoints[0]['issue6_single_node']['callback_top_flow_rearm_reached'])
    self.assertTrue(checkpoints[0]['issue6_single_node'][
        'callback_top_flow_rearm_execution_id_present'])
    self.assertEqual(1, checkpoints[0]['issue6_single_node'][
        'callback_top_flow_rearm_marker_count'])
    self.assertNotIn('raw secret-bearing failure', str(raised.exception))

  def test_profile_checkpoint_keeps_only_bounded_single_node_evidence(self):
    projected = probe.sanitize_live_checkpoint({'issue6_single_node': {
        'stage': 'auth_flow_failed', 'node_count': 1,
        'keycloak_version': '26.8.0', 'proof_post_http': 202,
        'callback_replay_http': 302, 'callback_replay_redirect_uri_matches': True,
        'callback_replay_state_preserved': True, 'callback_replay_error_returned': True,
        'callback_replay_code_returned': False, 'callback_replay_denied_safely': True,
        'callback_replay_internal_error_page': False,
        'callback_replay_internal_error_reason': 'redirect_origin_mismatch',
        'callback_replay_internal_error_hostname_matches': False,
        'callback_replay_internal_error_port_matches': True,
        'callback_replay_guard_log_read': True,
        'callback_replay_guard_reached': False,
        'callback_replay_login_error_log_read': True,
        'callback_replay_login_error_count': 1,
        'callback_replay_login_error_category': 'invalid_code',
        'callback_replay_guard_marker_count': 0,
        'callback_replay_authenticator_entry_reached': True,
        'callback_replay_authenticator_entry_completed': True,
        'callback_replay_authenticator_entry_marker_count': 2,
        'callback_replay_authenticator_entry_unavailable_marker_count': 1,
        'callback_replay_authenticator_entry_other_marker_count': 0,
        'callback_top_flow_rearm_reached': True,
        'callback_top_flow_rearm_execution_id_present': True,
        'callback_top_flow_rearm_marker_count': 1,
        'callback_top_flow_rearm_unavailable_marker_count': 0,
        'callback_top_flow_rearm_other_marker_count': 0,
        'failure_gate': 'pkce',
        'callback_url': 'https://secret.example/callback?code=secret',
        'raw_error': 'sensitive diagnostic text',
    }})['issue6_single_node']
    self.assertEqual(1, projected['node_count'])
    self.assertEqual(202, projected['proof_post_http'])
    self.assertTrue(projected['callback_replay_redirect_uri_matches'])
    self.assertTrue(projected['callback_replay_denied_safely'])
    self.assertFalse(projected['callback_replay_internal_error_page'])
    self.assertEqual('redirect_origin_mismatch', projected['callback_replay_internal_error_reason'])
    self.assertFalse(projected['callback_replay_internal_error_hostname_matches'])
    self.assertTrue(projected['callback_replay_internal_error_port_matches'])
    self.assertTrue(projected['callback_replay_guard_log_read'])
    self.assertFalse(projected['callback_replay_guard_reached'])
    self.assertTrue(projected['callback_replay_login_error_log_read'])
    self.assertEqual(1, projected['callback_replay_login_error_count'])
    self.assertEqual('invalid_code', projected['callback_replay_login_error_category'])
    self.assertEqual(0, projected['callback_replay_guard_marker_count'])
    self.assertTrue(projected['callback_replay_authenticator_entry_reached'])
    self.assertTrue(projected['callback_replay_authenticator_entry_completed'])
    self.assertEqual(2, projected['callback_replay_authenticator_entry_marker_count'])
    self.assertEqual(1, projected[
        'callback_replay_authenticator_entry_unavailable_marker_count'])
    self.assertEqual(0, projected['callback_replay_authenticator_entry_other_marker_count'])
    self.assertTrue(projected['callback_top_flow_rearm_reached'])
    self.assertTrue(projected['callback_top_flow_rearm_execution_id_present'])
    self.assertEqual(1, projected['callback_top_flow_rearm_marker_count'])
    self.assertEqual(0, projected['callback_top_flow_rearm_unavailable_marker_count'])
    self.assertEqual(0, projected['callback_top_flow_rearm_other_marker_count'])
    self.assertEqual('pkce', projected['failure_gate'])
    self.assertNotIn('callback_url', projected)
    self.assertNotIn('raw_error', projected)

  def test_profile_runner_uses_current_owned_resource_interfaces(self):
    from contextlib import ExitStack, redirect_stdout
    from types import SimpleNamespace

    with tempfile.TemporaryDirectory() as scratch:
      registry_node = object()
      client = SimpleNamespace(wallet_container_id='a' * 64)
      runtime = {
          'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
          'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
          'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
          'single_use_object_provider_path': 'unavailable',
          'single_use_object_provider_ids': ['infinispan'],
          'runtime_qualification_status': 'open_runtime_facts_unavailable',
      }
      with ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
        stack.enter_context(patch.object(probe, 'IMAGE', 'mutable-tag'))
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
        stack.enter_context(patch.dict(os.environ, {}, clear=False))
        stack.enter_context(redirect_stdout(io.StringIO()))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('immutable-image', 'sha256:' + 'b' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        start_tools = stack.enter_context(patch.object(probe, 'start_resolver_tools',
            return_value='resolver-tools-id'))
        start_registry = stack.enter_context(patch.object(probe, 'start_registry',
            return_value=(registry_node, 'bootstrap', 12345)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=12346))
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=(Path(scratch) / 'identity.pem', SimpleNamespace(name='wrapper'), 'identity-id')))
        start_keycloak = stack.enter_context(patch.object(probe, 'start_keycloak', return_value=client))
        stack.enter_context(patch.object(probe, 'admin_token', return_value='admin-token'))
        stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=runtime))
        stack.enter_context(patch.object(probe, 'configure_realm'))
        stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
        stack.enter_context(patch.object(probe, 'provision_identity_attribute'))
        events = []
        def run_auth(*_args, **_kwargs):
          events.append('auth_flow')
          return {
              'proof_post_http': 202, 'changed_retry_http': 409,
              'callback_replay_http': 302, 'callback_replay_redirect_uri_matches': True,
              'callback_replay_state_preserved': True, 'callback_replay_error_returned': True,
              'callback_replay_code_returned': False, 'pkce_token_http': 200,
          }
        auth_flow = stack.enter_context(patch.object(probe, 'auth_flow', side_effect=run_auth))
        expiry_flow = stack.enter_context(patch.object(probe, 'expiry_profile_coordinator',
            side_effect=lambda *_args, **_kwargs: events.append('expiry_flow') or {
                'stage': 'complete', 'profile': 'expiry', 'lifetime_seconds': 300,
                'wait_seconds': 301, 'proof_post_http': 404, 'status_http': 404,
                'fresh_login_transaction_available': True}))
        legacy_expiry = stack.enter_context(patch.object(probe, 'expiry_acceptance_flow'))
        stack.enter_context(patch.object(probe, 'capture_live_resolver_diagnostics', return_value=[]))
        cleanup = stack.enter_context(patch.object(probe, 'finish_owned_cleanup', return_value=0))

        probe.run_issue6_single_node_profile()

      start_tools.assert_called_once()
      start_registry.assert_called_once()
      start_keycloak.assert_called_once()
      auth_flow.assert_called_once()
      expiry_flow.assert_called_once()
      legacy_expiry.assert_not_called()
      self.assertEqual(['auth_flow', 'expiry_flow'], events)
      cleanup.assert_called_once_with(registry_node, 'resolver-tools-id')

  def test_ci_and_documented_lifecycle_include_profile_module(self):
    root = Path(probe.__file__).parents[1]
    lifecycle = (root / 'scripts/lifecycle.py').read_text()
    readme = (root / 'README.md').read_text()
    self.assertIn('scripts.test_issue6_single_node_profile', lifecycle)
    self.assertIn('python3.11 scripts/lifecycle.py run offline', readme)


if __name__ == '__main__':
  unittest.main()
