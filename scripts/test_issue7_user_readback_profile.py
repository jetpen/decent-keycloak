"""Offline contract tests for the Issue #7 user-readback profile."""
import ast
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from types import SimpleNamespace
from contextlib import ExitStack
from unittest.mock import Mock, patch
import zipfile

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))
import wallet_login_live_e2e as probe  # noqa: E402

ROOT = Path(__file__).parents[1]


class UserReadbackProfileTest(unittest.TestCase):
  def test_subject_match_predicate_compares_exact_claim_without_returning_it(self):
    self.assertTrue(probe.subject_matches_expected({'sub': 'retained-subject'},
        'retained-subject'))
    self.assertFalse(probe.subject_matches_expected({'sub': 'different-subject'},
        'retained-subject'))
    self.assertFalse(probe.subject_matches_expected({}, 'retained-subject'))

  def test_dedicated_signup_success_profile_is_allowlisted_and_selected(self):
    profile = 'issue7-signup-success'
    self.assertIn(profile, probe.SUPPORTED_LIVE_PROFILES)
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': profile}):
      self.assertEqual(profile, probe.selected_live_profile())

  def test_success_coordinator_checkpoints_sanitized_failure_without_masking_it(self):
    primary = RuntimeError('private unrelated status 503 provider=remote request=private-id')
    setattr(primary, 'failure_stage', 'signup_intent')
    setattr(primary, 'failure_gate', 'transaction_binding')
    setattr(primary, 'failure_category', 'runtime_error')
    setattr(primary, 'failure_http_status', 503)
    checkpoints = []
    def fail_after_intent(*args, **kwargs):
      args[5]('intent', {'signup_intent_action_http': 200})
      raise primary
    with patch.object(probe, 'signup_wallet_flow', side_effect=fail_after_intent), patch.object(
        probe, 'read_provider_success_log_window', side_effect=AssertionError('must not read')):
      with self.assertRaises(RuntimeError) as caught:
        probe.run_issue7_signup_success_profile(Mock(), Path('key'), 'private-identity',
            'container', Mock(), 'image', lambda *_: None, checkpoints.append)
    self.assertIs(primary, caught.exception)
    self.assertEqual(1, len(checkpoints))
    sanitized = probe.sanitize_live_checkpoint({'signup_case': checkpoints[0]})['signup_case']
    self.assertEqual({'stage': 'intent', 'provider_operation_witness': 'unavailable',
        'failure_stage': 'signup_intent',
        'failure_gate': 'transaction_binding', 'failure_category': 'runtime_error',
        'failure_http_status': 503, 'signup_intent_action_http': 200}, sanitized)
    serialized = json.dumps(sanitized)
    for forbidden in ('private unrelated', 'provider=remote', 'private-id', 'private-identity'):
      self.assertNotIn(forbidden, serialized)

  def test_status_poll_failure_uses_generic_field_and_preserves_proof_http(self):
    primary = RuntimeError('synthetic status poll failure')
    setattr(primary, 'failure_stage', 'signup_proof')
    setattr(primary, 'failure_gate', 'proof_status')
    setattr(primary, 'failure_category', 'assertion_failed')
    setattr(primary, 'failure_http_status', 503)
    checkpoints = []
    def fail_after_status_poll(*args, **kwargs):
      args[5]('proof', {'signup_proof_http': 202})
      raise primary
    with patch.object(probe, 'signup_wallet_flow', side_effect=fail_after_status_poll):
      with self.assertRaises(RuntimeError) as caught:
        probe.run_issue7_signup_success_profile(Mock(), Path('key'), 'fixture-identity',
            'container', Mock(), 'image', lambda *_: None, checkpoints.append)
    self.assertIs(primary, caught.exception)
    self.assertEqual(1, len(checkpoints))
    evidence = probe.sanitize_live_checkpoint({'signup_case': checkpoints[0]})['signup_case']
    self.assertEqual({'stage': 'proof', 'provider_operation_witness': 'unavailable',
        'failure_stage': 'signup_proof', 'failure_gate': 'proof_status',
        'failure_category': 'assertion_failed', 'failure_http_status': 503,
        'signup_proof_http': 202}, evidence)


  def test_proof_post_failure_uses_proof_http_field_for_exact_gate(self):
    primary = RuntimeError('synthetic proof POST failure')
    setattr(primary, 'failure_stage', 'signup_proof')
    setattr(primary, 'failure_gate', 'proof_http_status')
    setattr(primary, 'failure_category', 'assertion_failed')
    setattr(primary, 'failure_http_status', 503)
    checkpoints = []
    def fail_after_proof_post(*args, **kwargs):
      args[5]('proof', {'signup_proof_http': 503})
      raise primary
    with patch.object(probe, 'signup_wallet_flow', side_effect=fail_after_proof_post):
      with self.assertRaises(RuntimeError) as caught:
        probe.run_issue7_signup_success_profile(Mock(), Path('key'), 'fixture-identity',
            'container', Mock(), 'image', lambda *_: None, checkpoints.append)
    self.assertIs(primary, caught.exception)
    evidence = probe.sanitize_live_checkpoint({'signup_case': checkpoints[0]})['signup_case']
    self.assertEqual({'stage': 'proof', 'provider_operation_witness': 'unavailable',
        'failure_stage': 'signup_proof', 'failure_gate': 'proof_http_status',
        'failure_category': 'assertion_failed', 'signup_proof_http': 503}, evidence)
    self.assertNotIn('failure_http_status', evidence)

  def test_unknown_failure_is_unclassified_and_checkpoint_error_does_not_mask(self):
    primary = RuntimeError('private unknown failure')
    setattr(primary, 'failure_stage', 'private-stage')
    setattr(primary, 'failure_gate', 'private-gate')
    setattr(primary, 'failure_category', 'private-category')
    setattr(primary, 'failure_http_status', 700)
    checkpoints = []
    def failing_checkpoint(evidence):
      checkpoints.append(evidence)
      raise OSError('private checkpoint failure')
    with patch.object(probe, 'signup_wallet_flow', side_effect=primary):
      with self.assertRaises(RuntimeError) as caught:
        probe.run_issue7_signup_success_profile(Mock(), Path('key'), 'identity',
            'container', Mock(), 'image', lambda *_: None, failing_checkpoint)
    self.assertIs(primary, caught.exception)
    self.assertEqual(['Issue #7 signup failure checkpoint could not be written'],
        caught.exception.__notes__)
    self.assertEqual(1, len(checkpoints))
    evidence = probe.sanitize_live_checkpoint({'signup_case': checkpoints[0]})['signup_case']
    self.assertEqual({'stage': 'unclassified', 'provider_operation_witness': 'unavailable',
        'failure_stage': 'unclassified', 'failure_gate': 'unclassified',
        'failure_category': 'runtime_error'}, evidence)
    for forbidden in ('private unknown failure', 'private-stage', 'private-gate', 'private-category'):
      self.assertNotIn(forbidden, json.dumps(evidence))

  def test_signup_intent_response_decode_failure_gets_known_boundary(self):
    locator = ('https://idp.example:' + str(probe.KC_PORT)
        + '/auth/realms/' + probe.REALM + '/decent-wallet-login/v1/transactions/' + 'A' * 43)
    callback_query = urllib.parse.urlencode({'session_code': 's', 'execution': 'e',
        'client_id': 'c', 'tab_id': 't', 'client_data': 'd'})

    class ScriptedClient:
      def __init__(self):
        self.redirects = []
        self.requests = []
      def request(self, method, path, data=None, headers=None, timeout=10):
        self.requests.append((method, path))
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          page = (f'<p id="wallet-locator">{locator}</p><form method="post" '
              f'action="/auth/realms/{probe.REALM}/login-actions/authenticate?{callback_query}">'
              '<input type="hidden" name="wallet_intent" value="signup"></form>')
          return 200, {}, page.encode()
        if method == 'POST' and 'login-actions/authenticate?' in path:
          return 200, {}, b'\xff'
        raise AssertionError((method, path))

    client = ScriptedClient()
    progress = []
    with self.assertRaises(UnicodeDecodeError) as caught:
      probe.signup_wallet_flow(client, Path('key'), 'fixture-identity', 'container',
          Mock(), lambda stage, fields: progress.append((stage, fields)), 'image')
    self.assertEqual('signup_intent', getattr(caught.exception, 'failure_stage', None))
    self.assertEqual('signup_intent_response_decode', getattr(caught.exception, 'failure_gate', None))
    self.assertEqual('runtime_error', getattr(caught.exception, 'failure_category', None))
    self.assertEqual([('intent', {'signup_intent_action_http': 200})], progress)
    self.assertEqual(['GET', 'POST'], [method for method, _ in client.requests])

  def test_signup_failure_contexts_cover_known_require_and_boundary_calls(self):
    tree = ast.parse(Path(probe.__file__).read_text(encoding='utf-8'))
    flow = next(node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == 'signup_wallet_flow')
    contexts = {**probe.issue7_store_recovery.FAILURE_CONTEXTS,
        **probe.SIGNUP_FAILURE_CONTEXTS}
    gates = probe.issue7_store_recovery.FAILURE_GATES
    stages = probe.issue7_store_recovery.FAILURE_STAGES
    for node in ast.walk(flow):
      if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
          and node.func.id == 'require' and len(node.args) > 1
          and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
        self.assertIn(node.args[1].value, contexts)
      if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
          and node.func.id == 'signup_boundary' and len(node.args) > 1
          and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
          and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
        self.assertIn(node.args[0].value, stages)
        self.assertIn(node.args[1].value, gates)
    for stage, gate in contexts.values():
      self.assertIn(stage, stages)
      self.assertIn(gate, gates)

  def test_success_coordinator_runs_one_unfaulted_signup_and_sanitizes_evidence(self):
    calls = []
    def ordinary_signup(*args, **kwargs):
      calls.append((args, kwargs))
      self.assertEqual({}, kwargs)
      args[5]('intent', {'signup_intent_action_http': 200})
      args[5]('proof', {'signup_proof_http': 202})
      args[5]('account', {'exact_mapped_users': 1})
      args[5]('callback', {'callback_http': 302, 'callback_replay': True,
          'oidc_state_preserved': True})
      args[5]('token', {'pkce_token_http': 200})
      return {'signup_intent_action_http': 200, 'signup_proof_http': 202,
          'exact_mapped_users': 1, 'callback_http': 302, 'callback_replay': True,
          'oidc_state_preserved': True, 'pkce_token_http': 200,
          'provider_request_id': '0' * 32,
          'local_subject': 'private-subject', 'code': 'private-code',
          'exception': 'private exception', 'logs': 'private log'}
    progress_events, checkpoints = [], []
    with ExitStack() as stack:
      stack.enter_context(patch.object(probe, 'signup_wallet_flow', side_effect=ordinary_signup))
      stack.enter_context(patch.object(probe, 'read_provider_success_log_window',
          return_value='Wallet proof transaction consumed (request=' + '0' * 32 + ', provider=infinispan)'))
      evidence = probe.run_issue7_signup_success_profile(
          Mock(), Path('key'), 'private-identity', 'container', Mock(), 'ordinary-image',
          lambda stage, fields: progress_events.append((stage, fields)), checkpoints.append)
    self.assertEqual(1, len(calls))
    self.assertEqual('ordinary-image', calls[0][0][6])
    self.assertEqual('complete', evidence['stage'])
    self.assertEqual('harness-application-path-only', evidence['evidence_provenance'])
    self.assertEqual(200, evidence['pkce_token_http'])
    serialized = json.dumps(probe.sanitize_live_checkpoint({'signup_case': evidence}))
    for forbidden in ('private-subject', 'private-code', 'private exception',
        'private log', 'private-identity'):
      self.assertNotIn(forbidden, serialized)
    self.assertTrue(checkpoints and checkpoints[0] == evidence)

  def test_profile_modes_and_fail_closed_dispatch(self):
    expected = {
        'issue7-user-readback-empty': 'empty',
        'issue7-user-readback-throw': 'throw',
        'issue7-user-readback-overcap': 'over-cap',
    }
    for profile, mode in expected.items():
      with patch.dict(os.environ, {'WALLET_IT_PROFILE': profile}):
        self.assertEqual(profile, probe.selected_live_profile())
      self.assertEqual(mode, probe.user_readback_fault_mode(profile))
      self.assertIn(profile, probe.SUPPORTED_LIVE_PROFILES)
      calls = []
      self.assertEqual(mode, probe.dispatch_live_profile(
          profile, {profile: lambda mode=mode: calls.append(mode) or mode}))
      self.assertEqual([mode], calls)
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'unexpected'}):
      with self.assertRaises(ValueError):
        probe.selected_live_profile()
    with self.assertRaises(ValueError):
      probe.dispatch_live_profile('unexpected', {'default': lambda: None})

  def test_production_main_dispatches_only_success_profile_and_runs_scripted_signup(self):
    locator = ('https://idp.example:' + str(probe.KC_PORT)
        + '/auth/realms/' + probe.REALM + '/decent-wallet-login/v1/transactions/' + 'A' * 43)
    status_url = '/auth/realms/' + probe.REALM + '/decent-wallet-login/v1/transactions/status'
    callback_query = urllib.parse.urlencode({'session_code': 's', 'execution': 'e',
        'client_id': 'c', 'tab_id': 't', 'client_data': 'd'})
    callback = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
        + '/login-actions/authenticate?' + callback_query)
    class ScriptedClient:
      def __init__(self):
        self.redirects = []
        self.privateClientAdminCredential = 'ignored'
        self.wallet_container_id = None
        self.requests = []
        self.state = None
      def request(self, method, path, data=None, headers=None, timeout=10):
        self.requests.append((method, path))
        parsed = urllib.parse.urlsplit(path)
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          self.state = urllib.parse.parse_qs(parsed.query)['state'][0]
          html = (f'<p id="wallet-locator">{locator}</p>'
              f'<form method="post" action="/auth/realms/{probe.REALM}/login-actions/'
              f'authenticate?session_code=s&amp;execution=e&amp;client_id=c&amp;tab_id=t&amp;client_data=d">'
              '<input type="hidden" name="wallet_intent" value="signup"></form>')
          return 200, {}, html.encode()
        if method == 'POST' and 'login-actions/authenticate?' in path:
          html = (f'<p id="wallet-locator">{locator}</p>'
              f'<script>const statusUrl = "{status_url}"; const csrfToken = "{"A" * 43}";</script>'
              'Creating a new account with this wallet identity.')
          return 200, {}, html.encode()
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge', 'csrf_token': 'A' * 43}).encode()
        if method == 'POST' and path == locator:
          return 202, {}, b''
        if method == 'GET' and path == status_url:
          return 200, {}, json.dumps({'status': 'accepted', 'callback': callback}).encode()
        if method == 'GET' and parsed.path.endswith('/login-actions/authenticate'):
          if parsed.scheme == 'https':
            return 302, {'Location': probe.REDIRECT + '?' + urllib.parse.urlencode(
                {'error': 'invalid_request', 'state': self.state})}, b''
          return 302, {'Location': probe.REDIRECT + '?' + urllib.parse.urlencode(
              {'code': 'opaque-code', 'state': self.state})}, b''
        if method == 'POST' and parsed.path.endswith('/protocol/openid-connect/token'):
          return 200, {}, b'{"id_token":"unused-token"}'
        if method == 'GET' and parsed.path.endswith('/protocol/openid-connect/certs'):
          return 200, {}, b'{"keys":[]}'
        raise AssertionError((method, path))

    browser, wallet, admin = ScriptedClient(), ScriptedClient(), Mock(wallet_container_id='a' * 64)
    checkpoints = []
    original_write = Path.write_text
    def capture(path, data, *args, **kwargs):
      if path.name == 'live-evidence.json':
        checkpoints.append(json.loads(data))
      return original_write(path, data, *args, **kwargs)
    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
      key_path = Path(scratch) / 'identity.pem'
      for name, value in {'SCRATCH': scratch, 'IMAGE': 'original-image',
          'RUN_CID_DIR': None}.items():
        stack.enter_context(patch.object(probe, name, value))
      stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue7-signup-success'}, clear=False))
      stack.enter_context(patch.object(probe, 'resolve_immutable_image',
          return_value=('ordinary-image', 'sha256:' + 'a' * 64)))
      stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
      stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='resolver-tools'))
      stack.enter_context(patch.object(probe, 'start_registry', return_value=('registry', 'bootstrap', 1234)))
      stack.enter_context(patch.object(probe, 'free_port', return_value=4321))
      identity = stack.enter_context(patch.object(probe, 'write_identity',
          return_value=(key_path, Path(scratch) / 'wrapper', 'private-identity')))
      stack.enter_context(patch.object(probe, 'start_keycloak', return_value=admin))
      stack.enter_context(patch.object(probe, 'admin_token', return_value='token'))
      stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value={
          'runtime_qualification_status': 'runtime_facts_verified',
          'keycloak_version': '26.8.0', 'keycloak_nodes': 'one'}))
      stack.enter_context(patch.object(probe, 'configure_realm'))
      stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
      stack.enter_context(patch.object(probe, 'admin_call', side_effect=[
          (200, {}, b'[]'), (200, {}, b'[{"attributes":{"decent_identity_id":["private-identity"]},"enabled":true,"id":"private-subject"}]')]))
      stack.enter_context(patch.object(probe, 'Client', side_effect=[browser, wallet]))
      stack.enter_context(patch.object(probe.subprocess, 'run',
          return_value=SimpleNamespace(returncode=0, stdout=b's' * 64)))
      stack.enter_context(patch.object(probe, 'verify_id_token', return_value={
          'sub': 'private-subject', 'decent_identity_id': 'private-identity'}))
      request_id = probe.account_policy_request_id(locator)
      stack.enter_context(patch.object(probe, 'read_provider_success_log_window',
          return_value=f'Wallet proof transaction consumed (request={request_id}, provider=infinispan)'))
      stack.enter_context(patch.object(probe, 'finish_owned_cleanup'))
      stack.enter_context(patch.object(Path, 'write_text', autospec=True, side_effect=capture))
      actual_signup_results = []
      real_signup_flow = probe.signup_wallet_flow
      def observe_signup_flow(*args, **kwargs):
        result = real_signup_flow(*args, **kwargs)
        actual_signup_results.append(result)
        return result
      signup_flow = stack.enter_context(patch.object(probe, 'signup_wallet_flow',
          side_effect=observe_signup_flow))
      dispatcher = stack.enter_context(patch.object(probe, 'dispatch_live_profile',
          wraps=probe.dispatch_live_profile))
      printed = stack.enter_context(patch('builtins.print'))
      probe.main()
    identity.assert_called_once()
    self.assertEqual(1, signup_flow.call_count)
    self.assertNotIn('local_subject_matches_expected', actual_signup_results[0])
    self.assertNotIn('local_subject', actual_signup_results[0])
    self.assertNotIn('private-subject', json.dumps(actual_signup_results[0]))
    self.assertEqual(1, dispatcher.call_count)
    self.assertEqual('issue7-signup-success', dispatcher.call_args.args[0])
    self.assertEqual(1, len([request for request in browser.requests
        if request[0] == 'GET' and '/protocol/openid-connect/auth?' in request[1]]))
    self.assertEqual(1, len([request for request in wallet.requests
        if request == ('POST', locator)]))
    self.assertFalse(any('wallet-login-unmapped' in str(call) or 'wallet-login-replay' in str(call)
        for call in identity.call_args_list))
    final = checkpoints[-1]['signup_case']
    self.assertEqual({'stage': 'complete',
        'evidence_provenance': 'harness-application-path-only',
        'single_use_object_provider_id': 'infinispan',
        'signup_intent_action_http': 200,
        'signup_proof_http': 202, 'exact_mapped_users': 1, 'callback_http': 302,
        'callback_replay': True, 'oidc_state_preserved': True,
        'pkce_token_http': 200}, final)
    safe = json.dumps(checkpoints[-1])
    for forbidden in ('private-identity', 'private-subject', 'opaque-code',
        'challenge', 'signature', 'unused-token'):
      self.assertNotIn(forbidden, safe)
    output = [call.args[1] for call in printed.call_args_list
        if call.args and call.args[0] == 'issue7-signup-success-evidence=']
    self.assertEqual(1, len(output))
    self.assertEqual(final, json.loads(output[0])['signup_case'])

  def test_production_main_checkpoints_real_signup_intent_failure_after_200(self):
    locator = ('https://idp.example:' + str(probe.KC_PORT)
        + '/auth/realms/' + probe.REALM + '/decent-wallet-login/v1/transactions/' + 'A' * 43)
    callback_query = urllib.parse.urlencode({'session_code': 's', 'execution': 'e',
        'client_id': 'c', 'tab_id': 't', 'client_data': 'd'})

    class IntentFailureClient:
      def __init__(self):
        self.redirects = []
        self.privateClientAdminCredential = '[REDACTED]'
        self.wallet_container_id = None
        self.requests = []
      def request(self, method, path, data=None, headers=None, timeout=10):
        self.requests.append((method, path))
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          page = (f'<p id="wallet-locator">{locator}</p><form method="post" '
              f'action="/auth/realms/{probe.REALM}/login-actions/authenticate?{callback_query}">'
              '<input type="hidden" name="wallet_intent" value="signup"></form>')
          return 200, {}, page.encode()
        if method == 'POST' and 'login-actions/authenticate?' in path:
          return 200, {}, b'<p>unrelated [REDACTED] status 503 provider=remote request=opaque-fixture-id</p>'
        raise AssertionError((method, path))

    browser = IntentFailureClient()
    admin = Mock(wallet_container_id='a' * 64, privateClientAdminCredential='[REDACTED]')
    checkpoints = []
    original_write = Path.write_text
    def capture(path, data, *args, **kwargs):
      if path.name == 'live-evidence.json':
        checkpoints.append(json.loads(data))
      return original_write(path, data, *args, **kwargs)

    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
      key_path = Path(scratch) / 'identity.pem'
      for name, value in {'SCRATCH': scratch, 'IMAGE': 'original-image',
          'RUN_CID_DIR': None}.items():
        stack.enter_context(patch.object(probe, name, value))
      stack.enter_context(patch.dict(os.environ,
          {'WALLET_IT_PROFILE': 'issue7-signup-success'}, clear=False))
      stack.enter_context(patch.object(probe, 'resolve_immutable_image',
          return_value=('ordinary-image', 'sha256:' + 'a' * 64)))
      stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
      stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='resolver-tools'))
      stack.enter_context(patch.object(probe, 'start_registry', return_value=('registry', 'bootstrap', 1234)))
      stack.enter_context(patch.object(probe, 'free_port', return_value=4321))
      stack.enter_context(patch.object(probe, 'write_identity',
          return_value=(key_path, Path(scratch) / 'wrapper', 'fixture-identity')))
      stack.enter_context(patch.object(probe, 'start_keycloak', return_value=admin))
      stack.enter_context(patch.object(probe, 'admin_token', return_value='[REDACTED]'))
      stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value={
          'runtime_qualification_status': 'runtime_facts_verified',
          'keycloak_version': '26.8.0', 'keycloak_nodes': 'one'}))
      stack.enter_context(patch.object(probe, 'configure_realm'))
      stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
      stack.enter_context(patch.object(probe, 'admin_call', return_value=(200, {}, b'[]')))
      stack.enter_context(patch.object(probe, 'Client', return_value=browser))
      stack.enter_context(patch.object(probe.subprocess, 'run',
          return_value=SimpleNamespace(returncode=0, stdout=b's' * 64)))
      stack.enter_context(patch.object(probe, 'record_resolver_diagnostics', return_value=[]))
      provider_log = stack.enter_context(patch.object(probe,
          'read_provider_success_log_window', side_effect=AssertionError('no request-correlated operation')))
      stack.enter_context(patch.object(probe, 'finish_owned_cleanup'))
      stack.enter_context(patch.object(probe, 'cleanup_after_failure'))
      stack.enter_context(patch.object(Path, 'write_text', autospec=True, side_effect=capture))
      real_signup_flow = probe.signup_wallet_flow
      signup_flow = stack.enter_context(patch.object(probe, 'signup_wallet_flow',
          wraps=real_signup_flow))
      dispatcher = stack.enter_context(patch.object(probe, 'dispatch_live_profile',
          wraps=probe.dispatch_live_profile))
      printed = stack.enter_context(patch('builtins.print'))
      with self.assertRaises(RuntimeError):
        probe.main()

    self.assertEqual(1, signup_flow.call_count)
    self.assertEqual(1, dispatcher.call_count)
    self.assertEqual('issue7-signup-success', dispatcher.call_args.args[0])
    self.assertEqual(['GET', 'POST'], [method for method, _ in browser.requests])
    self.assertEqual(2, len(browser.requests))
    provider_log.assert_not_called()
    final = checkpoints[-1]['signup_case']
    self.assertEqual({'stage': 'intent', 'signup_intent_action_http': 200,
        'failure_stage': 'signup_intent', 'failure_gate': 'transaction_binding',
        'failure_category': 'assertion_failed',
        'provider_operation_witness': 'unavailable'}, final)
    for forbidden in ('failure_http_status', 'signup_proof_http', 'callback', 'callback_http',
        'authorization_code', 'single_use_object_provider_id', 'provider_id', 'code'):
      self.assertNotIn(forbidden, final)
    serialized = json.dumps(checkpoints) + repr(printed.call_args_list)
    for forbidden in ('[REDACTED]', 'unrelated', 'status 503', 'provider=remote',
        'opaque-fixture-id', 'fixture-identity', 'session_code=', 'client_data='):
      self.assertNotIn(forbidden, serialized)

  def test_production_main_runs_real_readback_failure_and_fresh_signup_for_each_mode(self):
    profiles = {
        'issue7-user-readback-empty': 'empty',
        'issue7-user-readback-throw': 'throw',
        'issue7-user-readback-overcap': 'over-cap',
    }
    for profile, mode in profiles.items():
      with self.subTest(profile=profile):
        locators = {
            1: ('https://idp.example:' + str(probe.KC_PORT) + '/auth/realms/'
                + probe.REALM + '/decent-wallet-login/v1/transactions/' + 'A' * 43),
            2: ('https://idp.example:' + str(probe.KC_PORT) + '/auth/realms/'
                + probe.REALM + '/decent-wallet-login/v1/transactions/' + 'B' * 43),
        }
        status_url = ('/auth/realms/' + probe.REALM
            + '/decent-wallet-login/v1/transactions/status')
        callback_query = urllib.parse.urlencode({'session_code': 's', 'execution': 'e',
            'client_id': 'c', 'tab_id': 't', 'client_data': 'd'})
        callback = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
            + '/login-actions/authenticate?' + callback_query)
        subject = 'private-subject'
        identifier = 'private-identity'
        user = {'attributes': {'decent_identity_id': [identifier]},
            'enabled': True, 'id': subject}
        events = []

        class ScriptedClient:
          def __init__(self, name, ceremony, kind):
            self.name = name
            self.ceremony = ceremony
            self.kind = kind
            self.redirects = []
            self.privateClientAdminCredential = '[REDACTED]'
            self.wallet_container_id = None
            self.requests = []
            self.state = None
            self.callback_count = 0

          def request(self, method, path, data=None, headers=None, timeout=10):
            self.requests.append((method, path, data, headers))
            parsed = urllib.parse.urlsplit(path)
            if (self.kind == 'browser' and method == 'GET'
                and '/protocol/openid-connect/auth?' in path):
              events.append(self.name + ':auth')
              self.state = urllib.parse.parse_qs(parsed.query)['state'][0]
              html = (f'<p id="wallet-locator">{locators[self.ceremony]}</p>'
                  f'<form method="post" action="/auth/realms/{probe.REALM}/login-actions/'
                  f'authenticate?session_code=s&amp;execution=e&amp;client_id=c&amp;tab_id=t&amp;client_data=d">'
                  '<input type="hidden" name="wallet_intent" value="signup"></form>')
              return 200, {}, html.encode()
            if (self.kind == 'browser' and method == 'POST'
                and 'login-actions/authenticate?' in path):
              events.append(self.name + ':intent')
              html = (f'<p id="wallet-locator">{locators[self.ceremony]}</p>'
                  f'<script>const statusUrl = "{status_url}"; const csrfToken = "{"A" * 43}";</script>'
                  'Creating a new account with this wallet identity.')
              return 200, {}, html.encode()
            if self.kind == 'wallet' and method == 'GET' and path == locators[self.ceremony]:
              events.append(self.name + ':challenge')
              return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
                  'challenge': 'challenge-' + str(self.ceremony),
                  'csrf_token': 'A' * 43}).encode()
            if self.kind == 'wallet' and method == 'POST' and path == locators[self.ceremony]:
              events.append(self.name + ':proof')
              if self.ceremony == 1:
                return 503, {}, b''
              return 202, {}, b''
            if self.kind == 'browser' and method == 'GET' and path == status_url:
              events.append(self.name + ':status')
              if self.ceremony == 1:
                return 200, {}, b'{"status":"pending"}'
              return 200, {}, json.dumps({'status': 'accepted', 'callback': callback}).encode()
            if (self.kind == 'browser' and method == 'GET'
                and parsed.path.endswith('/login-actions/authenticate')):
              events.append(self.name + ':callback')
              self.callback_count += 1
              if self.callback_count == 1:
                return 302, {'Location': probe.REDIRECT + '?' + urllib.parse.urlencode(
                    {'code': 'opaque-code', 'state': self.state})}, b''
              return 302, {'Location': probe.REDIRECT + '?' + urllib.parse.urlencode(
                  {'error': 'invalid_request', 'state': self.state})}, b''
            if (self.kind == 'browser' and method == 'POST'
                and parsed.path.endswith('/protocol/openid-connect/token')):
              events.append(self.name + ':token')
              return 200, {}, b'{"id_token":"unused-token"}'
            raise AssertionError((self.name, method, path))

        browser_failed = ScriptedClient('browser-1', 1, 'browser')
        wallet_failed = ScriptedClient('wallet-1', 1, 'wallet')
        browser_recovered = ScriptedClient('browser-2', 2, 'browser')
        wallet_recovered = ScriptedClient('wallet-2', 2, 'wallet')
        client_factory = Mock(side_effect=[browser_failed, wallet_failed,
            browser_recovered, wallet_recovered])
        admin = Mock(wallet_container_id='a' * 64)
        admin_reads = [
            (200, {}, b'[]'),
            (200, {}, json.dumps([user]).encode()),
            (200, {}, json.dumps([user]).encode()),
            (200, {}, json.dumps([user]).encode()),
        ]
        request_id = hashlib.sha256(('A' * 43).encode('ascii')).hexdigest()[:32]
        fault_tail = ('ISSUE7_USER_READBACK_PROVIDER: factory selected' + chr(10)
            + f'ISSUE7_USER_READBACK_PROVIDER: fault mode={mode}')
        fault_window = ('ISSUE7_USER_READBACK_PROVIDER: factory selected' + chr(10)
            + f'ISSUE7_USER_READBACK_PROVIDER: fault mode={mode}' + chr(10)
            + 'ISSUE7_USER_READBACK_FAULT: post-create exact attribute read intercepted' + chr(10)
            + f'Wallet account mapping lookup unavailable (request={request_id}, '
            + 'IdentityMappingUnavailableException)')
        checkpoints = []
        original_write_text = Path.write_text

        def capture_checkpoint(path, data, *args, **kwargs):
          if path.name == 'live-evidence.json':
            checkpoints.append(json.loads(data))
          return original_write_text(path, data, *args, **kwargs)

        with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
          key_path = Path(scratch) / 'identity.pem'
          stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
          stack.enter_context(patch.object(probe, 'IMAGE', probe.IMAGE))
          stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
          stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': profile,
              'WALLET_IT_USER_READBACK_IMAGE': 'test-image'}, clear=False))
          stack.enter_context(patch.object(probe, 'resolve_immutable_image',
              return_value=('test-image', 'sha256:' + 'a' * 64)))
          stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
          stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='resolver-tools'))
          stack.enter_context(patch.object(probe, 'start_registry',
              return_value=('registry', 'bootstrap', 1234)))
          stack.enter_context(patch.object(probe, 'free_port', return_value=4321))
          identity = stack.enter_context(patch.object(probe, 'write_identity',
              return_value=(key_path, Path(scratch) / 'wrapper', identifier)))
          stack.enter_context(patch.object(probe, 'start_keycloak', return_value=admin))
          stack.enter_context(patch.object(probe, 'admin_token', return_value='[REDACTED]'))
          stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value={
              'runtime_qualification_status': 'runtime_facts_verified',
              'keycloak_version': '26.8.0', 'keycloak_nodes': 'one'}))
          stack.enter_context(patch.object(probe, 'configure_realm'))
          stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
          admin_call = stack.enter_context(patch.object(probe, 'admin_call', side_effect=admin_reads))
          stack.enter_context(patch.object(probe, 'Client', client_factory))
          stack.enter_context(patch.object(probe.subprocess, 'run',
              return_value=SimpleNamespace(returncode=0, stdout=b's' * 64)))
          stack.enter_context(patch.object(probe, 'verify_id_token', return_value={
              'sub': subject, 'decent_identity_id': identifier}))
          stack.enter_context(patch.object(probe, 'read_provider_fault_log_tail',
              return_value=fault_tail))
          window = stack.enter_context(patch.object(probe, 'read_provider_fault_log_window',
              return_value=fault_window))
          sleep = stack.enter_context(patch.object(probe.time, 'sleep'))
          stack.enter_context(patch.object(probe, 'finish_owned_cleanup'))
          stack.enter_context(patch.object(Path, 'write_text', autospec=True,
              side_effect=capture_checkpoint))
          dispatcher = stack.enter_context(patch.object(probe, 'dispatch_live_profile',
              wraps=probe.dispatch_live_profile))
          printed = stack.enter_context(patch('builtins.print'))
          probe.main()

        identity.assert_called_once()
        self.assertEqual(4, client_factory.call_count)
        self.assertEqual(4, admin_call.call_count)
        self.assertEqual(1, window.call_count)
        self.assertEqual('issue7-user-readback-' + ('overcap' if mode == 'over-cap' else mode),
            dispatcher.call_args.args[0])
        self.assertEqual(1, dispatcher.call_count)
        self.assertEqual(1, len([request for request in wallet_failed.requests
            if request[0] == 'POST' and request[1] == locators[1]]))
        self.assertEqual(1, len([request for request in wallet_recovered.requests
            if request[0] == 'POST' and request[1] == locators[2]]))
        self.assertNotEqual(locators[1], locators[2])
        self.assertEqual([], wallet_failed.redirects)
        self.assertEqual(1, sum(1 for event in events if event == 'browser-1:status'))
        self.assertEqual(2, sum(1 for event in events if event == 'browser-2:callback'))
        self.assertEqual(1, sleep.call_count)
        sleep.assert_called_once_with(probe.IDENTITY_LOOKUP_COOLDOWN_SECONDS
            + probe.IDENTITY_LOOKUP_COOLDOWN_MARGIN_SECONDS)
        self.assertEqual(['GET'] * 4, [call.args[2] for call in admin_call.call_args_list])
        for call in admin_call.call_args_list:
          self.assertIn('decent_identity_id', call.args[3])
          self.assertIn('max=10', call.args[3])
        self.assertEqual([
            'browser-1:auth', 'browser-1:intent', 'wallet-1:challenge',
            'wallet-1:proof', 'browser-1:status', 'browser-2:auth',
            'browser-2:intent', 'wallet-2:challenge', 'wallet-2:proof',
            'browser-2:status', 'browser-2:callback', 'browser-2:callback',
            'browser-2:token'], events)
        self.assertGreaterEqual(len(checkpoints), 12)
        evidence = checkpoints[-1]['issue7_single_node_signup_recovery']
        self.assertEqual('complete', evidence['stage'])
        self.assertEqual('one-keycloak-node', evidence['scope'])
        self.assertEqual(mode, evidence['user_readback_fault_mode'])
        self.assertEqual(mode, evidence['effective_user_readback_fault_mode'])
        self.assertEqual('wrapper-mediated-application-path', evidence['fault_evidence_provenance'])
        self.assertTrue(evidence['same_local_subject'])
        self.assertTrue(evidence['account_retained_after_failure'])
        self.assertTrue(evidence['failure_responses_no_callback_or_code'])
        self.assertTrue(evidence['browser_status_pending'])
        self.assertEqual(503, evidence['provider_fault_http'])
        self.assertEqual(200, evidence['browser_status_http'])
        self.assertEqual(1, evidence['post_create_read_fault_count'])
        self.assertGreaterEqual(evidence['correlated_mapping_failure_count'], 1)
        self.assertEqual([1, 1], evidence['exact_enabled_local_accounts_after_each_signup'])
        self.assertEqual(65 if mode == 'over-cap' else 0, evidence['synthetic_candidate_count'])
        self.assertEqual(202, evidence['fresh_signup_proof_http'])
        self.assertEqual(302, evidence['fresh_signup_callback_http'])
        self.assertEqual(200, evidence['fresh_signup_pkce_token_http'])
        serialized = json.dumps(checkpoints)
        for forbidden in (identifier, subject, locators[1], locators[2], 'opaque-code',
            'challenge-1', 'challenge-2', 'unused-token', 'A' * 43,
            'expected_existing_subject', 'IdentityMappingUnavailableException'):
          self.assertNotIn(forbidden, serialized)
        printed_payloads = [call.args[1] for call in printed.call_args_list
            if call.args and call.args[0] == 'issue7-user-readback-evidence=']
        self.assertEqual(1, len(printed_payloads))
        self.assertEqual(evidence, json.loads(printed_payloads[0])[
            'issue7_single_node_signup_recovery'])

  def test_ordinary_failure_projection_preserves_status_poll_and_prior_proof_http(self):
    projected = probe.sanitize_live_checkpoint({'signup_case': {
        'stage': 'proof', 'signup_intent_action_http': 200,
        'failure_stage': 'signup_proof', 'failure_gate': 'proof_status',
        'failure_category': 'assertion_failed', 'failure_http_status': 422,
        'signup_proof_http': 202}})['signup_case']
    self.assertEqual({'stage': 'proof', 'signup_intent_action_http': 200,
        'failure_stage': 'signup_proof', 'failure_gate': 'proof_status',
        'failure_category': 'assertion_failed', 'failure_http_status': 422,
        'signup_proof_http': 202}, projected)

  def test_selected_provider_checkpoint_is_complete_only_and_allowlisted(self):
    complete = probe.sanitize_live_checkpoint({'signup_case': {
        'stage': 'complete', 'single_use_object_provider_id': 'infinispan'}})
    self.assertEqual('infinispan', complete['signup_case'].get('single_use_object_provider_id'))
    partial = probe.sanitize_live_checkpoint({'signup_case': {
        'stage': 'proof', 'single_use_object_provider_id': 'infinispan'}})
    self.assertNotIn('single_use_object_provider_id', partial['signup_case'])
    unallowlisted = probe.sanitize_live_checkpoint({'signup_case': {
        'stage': 'complete', 'single_use_object_provider_id': 'test-fake'}})
    self.assertNotIn('single_use_object_provider_id', unallowlisted['signup_case'])

  def test_success_provider_witness_requires_one_correlated_allowlisted_marker(self):
    request_id = '0123456789abcdef0123456789abcdef'
    marker = f'Wallet proof transaction consumed (request={request_id}, provider=infinispan)'
    parse = getattr(probe, 'sanitize_success_provider_witness', lambda *_: None)
    self.assertEqual('infinispan', parse(marker, request_id))
    self.assertIsNone(parse('', request_id))
    self.assertEqual('jpa', parse(marker.replace('infinispan', 'jpa'), request_id))
    self.assertIsNone(parse(marker + '\n' + marker.replace('infinispan', 'jpa'), request_id))
    self.assertIsNone(parse(marker.replace(request_id, 'f' * 32), request_id))
    self.assertIsNone(parse(marker + '\n' + marker, request_id))
    self.assertIsNone(parse(marker + ' private-identity private-handle proof', request_id))

  def test_success_profile_rejects_missing_provider_witness_and_checkpoints_projection(self):
    def ordinary_signup(*args, **kwargs):
      args[5]('intent', {'signup_intent_action_http': 200})
      args[5]('proof', {'signup_proof_http': 202, 'provider_request_id': '0' * 32})
      args[5]('account', {'exact_mapped_users': 1})
      args[5]('callback', {'callback_http': 302, 'callback_replay': True,
          'oidc_state_preserved': True})
      args[5]('token', {'pkce_token_http': 200})
      return {'signup_intent_action_http': 200, 'signup_proof_http': 202,
          'exact_mapped_users': 1, 'callback_http': 302, 'callback_replay': True,
          'oidc_state_preserved': True, 'pkce_token_http': 200,
          'provider_request_id': '0' * 32, 'provider_log': 'unrelated marker'}
    checkpoints = []
    with ExitStack() as stack:
      stack.enter_context(patch.object(probe, 'signup_wallet_flow', side_effect=ordinary_signup))
      stack.enter_context(patch.object(probe, 'read_provider_success_log_window', return_value='', create=True))
      with self.assertRaisesRegex(RuntimeError, 'provider witness'):
        probe.run_issue7_signup_success_profile(
            Mock(), Path('key'), 'private-identity', 'a' * 64, Mock(), 'image',
            lambda *_: None, checkpoints.append)
    self.assertEqual([], checkpoints)
    self.assertNotIn('private-identity', json.dumps(checkpoints))

  def test_fault_diagnostics_are_correlated_bounded_and_sanitized(self):
    request_id = '0123456789abcdef0123456789abcdef'
    logs = (
        'ISSUE7_USER_READBACK_PROVIDER: factory selected\n'
        'ISSUE7_USER_READBACK_PROVIDER: fault mode=empty\n'
        'ISSUE7_USER_READBACK_FAULT: post-create exact attribute read intercepted\n'
        f'Wallet account mapping lookup unavailable (request={request_id}, IdentityMappingUnavailableException)\n'
        'private-identity wallet-handle callback-code')
    diagnostics = probe.sanitize_user_readback_fault_diagnostics(logs, request_id)
    self.assertEqual({'factory_selected': True, 'effective_fault_mode': 'empty',
        'post_create_read_fault_count': 1, 'correlated_mapping_failure_count': 1}, diagnostics)
    self.assertNotIn(request_id, json.dumps(diagnostics))
    self.assertNotIn('private-identity', json.dumps(diagnostics))
    self.assertFalse(probe.sanitize_user_readback_fault_diagnostics(
        logs, 'bad-request-id')['correlated_mapping_failure_count'])

  def test_log_tail_drains_large_burst_and_oversized_line_with_byte_cap(self):
    result = probe._bounded_command_tail([sys.executable, '-c',
        "import sys; sys.stdout.write('x' * 200000 + chr(69) + chr(78) + chr(68) + chr(10))"],
        timeout=5, max_bytes=128)
    encoded = result.stdout.encode('utf-8')
    self.assertEqual(0, result.returncode)
    self.assertLessEqual(len(encoded), 128)
    self.assertTrue(result.stdout.endswith('END' + chr(10)))
    with self.assertRaises(subprocess.TimeoutExpired):
      probe._bounded_command_tail([sys.executable, '-c',
          'import time; time.sleep(5)'], timeout=0.05, max_bytes=16)

  def test_fault_window_uses_run_cursor_and_bounded_tail(self):
    container_id = 'a' * 64
    cursor = '2026-10-21T15:04:05.123456Z'
    window = 'fresh-window-only'
    with patch.object(probe, '_bounded_command_tail',
        return_value=probe.subprocess.CompletedProcess([], 0, window)) as bounded:
      result = probe.read_provider_fault_log_window(container_id, cursor)
    self.assertEqual(window, result)
    self.assertEqual(['podman', 'logs', '--since', cursor, '--tail', '160', container_id],
        bounded.call_args.args[0])
    with patch.object(probe, '_bounded_command_tail') as unused:
      with self.assertRaises(ValueError):
        probe.read_provider_fault_log_window(container_id, '--tail 160')
      unused.assert_not_called()

  def test_fault_launch_args_are_test_only_and_failures_expose_no_callback(self):
    command = ['podman', 'run', '--env-file', 'admin.env']
    probe.add_test_user_readback_fault_args(command, 'test-image', 'empty')
    self.assertIn('ISSUE7_USER_READBACK_FAULT_MODE=empty', command)
    self.assertEqual('test-image', command[-2])
    self.assertEqual('start-dev', command[-1])
    with self.assertRaises(ValueError):
      probe.add_test_user_readback_fault_args([], 'image', 'production')
    self.assertFalse(probe.failure_response_has_no_callback_or_code(
        b'', {'Location': '/cb?code=x'}))
    self.assertFalse(probe.failure_response_has_no_callback_or_code(
        b'', {}, redirects=[{'status': 302}]))
    self.assertFalse(probe.failure_response_has_no_callback_or_code(b'body', {}))
    self.assertTrue(probe.failure_response_has_no_callback_or_code(b'', {}))
    self.assertTrue(probe.browser_status_is_pending(200, b'{"status":"pending"}'))
    self.assertFalse(probe.browser_status_is_pending(200, b'{"status":"accepted"}'))

  def test_recovery_wait_exceeds_production_identity_admission_cooldown(self):
    store = (ROOT / 'src/main/java/org/decentwallet/keycloak/wallet/WalletLoginTransactionStore.java').read_text()
    match = re.search(r'IDENTITY_LOOKUP_COOLDOWN_SECONDS = ([0-9]+)', store)
    self.assertIsNotNone(match, 'production cooldown constant is discoverable')
    if match is None:
      self.fail('production cooldown constant is unavailable')
    cooldown = int(match.group(1))
    shared_duration = (probe.IDENTITY_LOOKUP_COOLDOWN_SECONDS
        + probe.IDENTITY_LOOKUP_COOLDOWN_MARGIN_SECONDS)
    self.assertGreater(shared_duration, cooldown)
    with patch.object(probe.time, 'sleep') as sleep:
      probe.wait_for_identity_lookup_cooldown()
    sleep.assert_called_once_with(shared_duration)

  def test_provider_packager_emits_exact_test_factory_and_spi_registration(self):
    relative_factory = 'org/decentwallet/keycloak/wallet/Issue7FaultInjectingUserProviderFactory.class'
    service_name = 'META-INF/services/org.keycloak.models.UserProviderFactory'
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      scripts = root / 'scripts'
      classes = root / 'target/test-classes'
      scripts.mkdir()
      (classes / relative_factory).parent.mkdir(parents=True)
      (classes / 'META-INF/services').mkdir(parents=True)
      (classes / relative_factory).write_bytes(b'fixture-bytecode')
      (classes / service_name).write_text(
          'org.decentwallet.keycloak.wallet.Issue7FaultInjectingUserProviderFactory\\n',
          encoding='utf-8')
      shutil.copy2(ROOT / 'scripts/build_issue7_user_readback_provider.py', scripts)
      result = subprocess.run([sys.executable,
          str(scripts / 'build_issue7_user_readback_provider.py')],
          cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
      self.assertEqual(0, result.returncode, result.stderr)
      jar_path = root / 'target/issue7-user-readback-provider.jar'
      self.assertEqual(str(jar_path), result.stdout.strip())
      with zipfile.ZipFile(jar_path) as archive:
        self.assertEqual({relative_factory, service_name}, set(archive.namelist()))
        self.assertEqual(b'fixture-bytecode', archive.read(relative_factory))
        self.assertEqual('org.decentwallet.keycloak.wallet.Issue7FaultInjectingUserProviderFactory\\n',
            archive.read(service_name).decode('utf-8'))

  def test_test_provider_image_is_separate_from_normal_runtime(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    self.assertIn('FROM runtime AS issue7-user-readback-test-runtime', dockerfile)
    self.assertIn('issue7-user-readback-provider.jar', dockerfile)
    self.assertIn('--spi-user--provider-default=issue7-user-readback-fault', dockerfile)
    normal_runtime = dockerfile.split('FROM runtime AS issue7-user-readback-test-runtime')[0]
    self.assertNotIn('issue7-user-readback-provider.jar', normal_runtime)

  def test_coordinator_runs_faulted_signup_then_fresh_signup_against_same_subject(self):
    failed = {'signup_proof_http': 503, 'browser_status_http': 200,
        'browser_status_pending': True, 'failure_responses_no_callback_or_code': True,
        'account_retained_after_failure': True, 'user_readback_factory_selected': True,
        'post_create_read_fault_observed': True, 'post_create_read_fault_count': 1,
        'effective_user_readback_fault_mode': 'over-cap', 'correlated_mapping_failure_count': 1,
        'exact_mapped_users': 1, 'expected_existing_subject': 'local-subject'}
    recovered = {'signup_proof_http': 202, 'callback_http': 302,
        'pkce_token_http': 200, 'exact_mapped_users': 1,
        'local_subject_matches_expected': True}
    with patch.object(probe, 'signup_wallet_flow', side_effect=[failed, recovered]) as signup, \
        patch.object(probe, 'Client', return_value=Mock()), \
        patch.object(probe, 'wait_for_identity_lookup_cooldown') as wait:
      evidence = probe.run_issue7_single_node_signup_recovery_profile(
          Mock(), 'key', 'identifier', 'a' * 64, Mock(), 'test-image',
          lambda *_: None, lambda _: None, 'issue7-user-readback-overcap')
    wait.assert_called_once_with()
    self.assertEqual(2, signup.call_count)
    self.assertTrue(signup.call_args_list[0].kwargs['expect_user_readback_fault'])
    self.assertTrue(signup.call_args_list[1].kwargs['reuse_existing'])
    self.assertTrue(evidence['same_local_subject'])
    self.assertEqual([1, 1], evidence['exact_enabled_local_accounts_after_each_signup'])
    self.assertEqual(65, evidence['synthetic_candidate_count'])
    safe = probe.sanitize_live_checkpoint({'issue7_single_node_signup_recovery': evidence})
    self.assertEqual([1, 1], safe['issue7_single_node_signup_recovery'][
        'exact_enabled_local_accounts_after_each_signup'])

  def test_entrypoint_rejects_missing_image_before_setup(self):
    profile = 'issue7-user-readback-empty'
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': profile}, clear=False):
      os.environ.pop('WALLET_IT_USER_READBACK_IMAGE', None)
      with patch.object(probe, 'resolve_immutable_image') as resolve, \
          patch.object(probe, '_prepare_resolver_runtime') as prepare:
        with self.assertRaisesRegex(ValueError, 'WALLET_IT_USER_READBACK_IMAGE'):
          probe.main()
      resolve.assert_not_called()
      prepare.assert_not_called()

  def test_entrypoint_dispatches_and_persists_final_sanitized_checkpoint(self):
    failed = {'signup_proof_http': 503, 'browser_status_http': 200,
        'browser_status_pending': True, 'failure_responses_no_callback_or_code': True,
        'account_retained_after_failure': True, 'user_readback_factory_selected': True,
        'post_create_read_fault_observed': True, 'post_create_read_fault_count': 1,
        'effective_user_readback_fault_mode': 'over-cap', 'correlated_mapping_failure_count': 1,
        'exact_mapped_users': 1, 'expected_existing_subject': 'local-subject'}
    recovered = {'signup_proof_http': 202, 'callback_http': 302,
        'pkce_token_http': 200, 'exact_mapped_users': 1,
        'local_subject_matches_expected': True}
    original_write_text = Path.write_text
    checkpoints = []
    def capture(path, data, *args, **kwargs):
      if path.name == 'live-evidence.json':
        checkpoints.append(json.loads(data))
      return original_write_text(path, data, *args, **kwargs)
    client = Mock()
    client.wallet_container_id = 'a' * 64
    client.request.return_value = (200, {}, '{}')
    image_original = probe.IMAGE
    cid_original = probe.RUN_CID_DIR
    with tempfile.TemporaryDirectory() as scratch:
      with ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
        stack.enter_context(patch.object(probe, 'IMAGE', image_original))
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', cid_original))
        stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue7-user-readback-overcap',
            'WALLET_IT_USER_READBACK_IMAGE': 'test-image'}))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('test-image', 'sha256:test')))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='resolver-tools'))
        stack.enter_context(patch.object(probe, 'start_registry',
            return_value=('registry', 'bootstrap', 1234)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=4321))
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=('key', 'wrapper', 'identifier')))
        stack.enter_context(patch.object(probe, 'start_keycloak', return_value=client))
        stack.enter_context(patch.object(probe, 'admin_token', return_value='token'))
        stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value={
            'runtime_qualification_status': 'runtime_facts_verified',
            'keycloak_version': '26.8.0', 'keycloak_nodes': 'one'}))
        stack.enter_context(patch.object(probe, 'configure_realm'))
        stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
        stack.enter_context(patch.object(probe, 'Client', return_value=client))
        signup = stack.enter_context(patch.object(probe, 'signup_wallet_flow', side_effect=[failed, recovered]))
        stack.enter_context(patch.object(probe, 'checkpoint_signup_stage'))
        stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=0))
        recovery_wait = stack.enter_context(patch.object(probe, 'wait_for_identity_lookup_cooldown'))
        calls = Mock()
        calls.attach_mock(signup, 'signup')
        calls.attach_mock(recovery_wait, 'wait')
        stack.enter_context(patch.object(Path, 'write_text', autospec=True, side_effect=capture))
        dispatcher = stack.enter_context(patch.object(probe, 'dispatch_live_profile',
            wraps=probe.dispatch_live_profile))
        printed = stack.enter_context(patch('builtins.print'))
        probe.main()
    self.assertEqual(1, dispatcher.call_count)
    self.assertEqual('issue7-user-readback-overcap', dispatcher.call_args.args[0])
    self.assertEqual(['signup', 'wait', 'signup'], [call[0] for call in calls.mock_calls])
    self.assertGreaterEqual(len(checkpoints), 12)
    stages = [entry['issue7_single_node_signup_recovery'].get('stage') for entry in checkpoints]
    self.assertEqual('setup', stages[0])
    required_setup_order = ['resolver_tools_starting', 'resolver_tools_started',
        'registry_starting', 'registry_started', 'identity_writing', 'identity_ready',
        'keycloak_starting', 'keycloak_started', 'runtime_verifying', 'runtime_verified',
        'realm_configuring', 'realm_configured', 'events_configuring', 'events_configured']
    positions = [stages.index(stage) for stage in required_setup_order]
    self.assertEqual(sorted(positions), positions)
    evidence = checkpoints[-1]['issue7_single_node_signup_recovery']
    self.assertEqual('complete', evidence['stage'])
    self.assertTrue(evidence['same_local_subject'])
    self.assertEqual(65, evidence['synthetic_candidate_count'])
    self.assertEqual(503, evidence['provider_fault_http'])
    printed_payloads = [call.args[1] for call in printed.call_args_list
        if call.args and call.args[0] == 'issue7-user-readback-evidence=']
    self.assertEqual(1, len(printed_payloads))
    persisted = json.loads(printed_payloads[0])['issue7_single_node_signup_recovery']
    self.assertEqual(evidence['exact_enabled_local_accounts_after_each_signup'],
        persisted['exact_enabled_local_accounts_after_each_signup'])


if __name__ == '__main__':
  unittest.main()
