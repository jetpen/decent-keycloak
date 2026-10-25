"""Offline application-path contracts; no runtime qualification."""
import json
import os
from pathlib import Path
import sys
import unittest
import hashlib
import tempfile
from contextlib import ExitStack, redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))
import wallet_login_live_e2e as probe


class StoreRecoveryTest(unittest.TestCase):
  def test_non_http_return_code_is_not_labeled_or_serialized_as_http(self):
    with self.assertRaises(RuntimeError) as caught:
      probe.require(False, 'packaged Registry command', 503)

    self.assertNotIn('HTTP 503', str(caught.exception))
    self.assertIn('(code 503)', str(caught.exception))
    self.assertFalse(hasattr(caught.exception, 'failure_http_status'))

  def test_explicit_gate_does_not_type_an_unlabelled_code_as_http(self):
    with self.assertRaises(RuntimeError) as caught:
      probe.require(False, 'wallet proof POST failed', 503, failure_gate='proof_post')

    self.assertEqual('proof_post', getattr(caught.exception, 'failure_gate', None))
    self.assertFalse(hasattr(caught.exception, 'failure_http_status'))

  def test_non_integer_diagnostic_detail_is_not_called_a_return_code(self):
    with self.assertRaises(RuntimeError) as caught:
      probe.require(False, 'fresh resolver result', 'unavailable')

    self.assertNotIn('(code unavailable)', str(caught.exception))

  def test_unrelated_http_status_is_not_mislabeled_as_signup_proof(self):
    with self.assertRaises(RuntimeError) as caught:
      probe.require(False, 'signup intent action returned unexpected status', 503, http_status=503)

    self.assertEqual('unclassified', getattr(caught.exception, 'failure_gate', None))
    self.assertEqual(503, getattr(caught.exception, 'failure_http_status', None))

  def test_explicit_failure_gate_is_preserved(self):
    with self.assertRaises(RuntimeError) as caught:
      probe.require(False, 'wallet proof POST failed', 503,
          failure_gate='proof_post', http_status=503)

    self.assertEqual('proof_post', getattr(caught.exception, 'failure_gate', None))

  def test_store_failure_checkpoint_does_not_mask_original_exception(self):
    failure = RuntimeError('original signup failure')
    api = Mock()
    api.signup_wallet_flow.side_effect = failure

    def broken_checkpoint(_):
      raise ValueError('checkpoint write failed')

    with self.assertRaises(RuntimeError) as caught:
      probe.issue7_store_recovery.run(api, None, None, None, None, None, None,
          None, broken_checkpoint, 'issue7-consume-loss-recovery')

    self.assertIs(failure, caught.exception)
    self.assertIn('Issue #7 failure checkpoint could not be written', failure.__notes__)

  def test_issue7_failure_assertion_attaches_only_allowlisted_context(self):
    with self.assertRaises(RuntimeError) as caught:
      probe.require(False,
          'post-create UserProvider readback fault returns empty 503 without redirect, callback, or code',
          503, http_status=503)

    failure = caught.exception
    self.assertEqual('signup_proof', getattr(failure, 'failure_stage', None))
    self.assertEqual('proof_http_status', getattr(failure, 'failure_gate', None))
    self.assertEqual('assertion_failed', getattr(failure, 'failure_category', None))
    self.assertEqual(503, getattr(failure, 'failure_http_status', None))
    self.assertNotIn('private', str(failure))

  def test_issue7_readback_assertion_gets_its_own_bounded_stage_and_gate(self):
    with self.assertRaises(RuntimeError) as caught:
      probe.require(False, 'post-create readback failure retains one exact enabled account')

    self.assertEqual('user_readback', getattr(caught.exception, 'failure_stage', None))
    self.assertEqual('account_readback', getattr(caught.exception, 'failure_gate', None))

  def test_store_failure_checkpoint_captures_sanitized_stage_gate_and_http_status(self):
    failure = RuntimeError('private exception details')
    setattr(failure, 'failure_stage', 'signup_proof')
    setattr(failure, 'failure_gate', 'proof_http_status')
    setattr(failure, 'failure_category', 'assertion_failed')
    setattr(failure, 'failure_http_status', 503)
    api = Mock()
    api.signup_wallet_flow.side_effect = failure
    checkpoints = []

    def checkpoint(value):
      checkpoints.append(probe.sanitize_live_checkpoint(
          {'issue7_store_recovery': value})['issue7_store_recovery'])

    with self.assertRaisesRegex(RuntimeError, 'private exception details'):
      probe.issue7_store_recovery.run(api, None, None, None, None, None, None,
          None, checkpoint, 'issue7-consume-loss-recovery')

    api.signup_wallet_flow.assert_called_once()
    self.assertEqual(1, len(checkpoints))
    self.assertEqual({
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'store_fault_mode': 'consume-loss', 'failure_stage': 'signup_proof',
        'failure_gate': 'proof_http_status', 'failure_category': 'assertion_failed',
        'signup_proof_http': 503}, checkpoints[0])
    self.assertNotIn('private exception details', json.dumps(checkpoints))

  def test_nonzero_log_read_is_distinct_from_observed_empty_window(self):
    container = 'a' * 64
    cursor = '2026-10-21T15:04:05.123456Z'
    with patch.object(probe, '_bounded_command_tail',
        return_value=probe.subprocess.CompletedProcess([], 1, 'secret provider output')):
      self.assertEqual('', probe.read_provider_fault_log_window(container, cursor))
      with self.assertRaisesRegex(RuntimeError, 'provider fault log window unavailable'):
        probe.read_provider_fault_log_window(container, cursor, strict=True)

  def test_store_failure_checkpoint_preserves_bounded_diagnostic_snapshot(self):
    failure = RuntimeError('private exception details')
    setattr(failure, 'issue7_diagnostics', {
        'store_diagnostic_read_status': 'observed',
        'store_provider_selected': True,
        'store_fault_count': 1,
        'correlated_store_failure_count': 2,
        'exception': 'private message', 'request_id': 'private'})
    api = Mock()
    api.signup_wallet_flow.side_effect = failure
    checkpoints = []

    with self.assertRaises(RuntimeError):
      probe.issue7_store_recovery.run(api, None, None, None, None, None, None,
          None, lambda value: checkpoints.append(probe.sanitize_live_checkpoint(
              {'issue7_store_recovery': value})['issue7_store_recovery']),
          'issue7-consume-loss-recovery')

    self.assertEqual({
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'store_fault_mode': 'consume-loss',
        'failure_stage': 'signup_flow', 'failure_gate': 'unclassified',
        'failure_category': 'runtime_error',
        'store_diagnostic_read_status': 'observed',
        'store_provider_selected': True, 'store_fault_count': 1,
        'correlated_store_failure_count': 2}, checkpoints[0])
    self.assertNotIn('private', json.dumps(checkpoints))

  def test_diagnostics_require_exact_request_correlated_provider_and_fault_witnesses(self):
    request_id = '1234567890abcdef1234567890abcdef'
    other_id = 'f' * 32
    mode = 'consume-loss'
    provider = f'ISSUE7_TEST_PROVIDER_OPERATION: operation=transaction_remove request={request_id}'
    fault = f'ISSUE7_TEST_FAULT: {probe.issue7_store_recovery.MARKERS[mode]} request={request_id}'
    production = f'Wallet pending transaction unavailable (request={request_id}, reason=consume-unavailable)'
    observed = probe.issue7_store_recovery.diagnostics('\n'.join((provider, fault, production)), mode, request_id)
    self.assertEqual({'store_fault_count': 1, 'correlated_store_failure_count': 1,
        'store_provider_selected': True}, observed)

    unrelated = '\n'.join((
        f'ISSUE7_TEST_PROVIDER_OPERATION: operation=transaction_remove request={other_id}',
        f'ISSUE7_TEST_FAULT: {probe.issue7_store_recovery.MARKERS[mode]} request={other_id}',
        production))
    self.assertEqual({'store_fault_count': 0, 'correlated_store_failure_count': 1,
        'store_provider_selected': False},
        probe.issue7_store_recovery.diagnostics(unrelated, mode, request_id))

  def test_diagnostics_do_not_accept_factory_or_unrelated_marker_only_evidence(self):
    request_id = '1234567890abcdef1234567890abcdef'
    logs = ('ISSUE7_TEST_PROVIDER: factory selected\n'
        f'ISSUE7_TEST_FAULT: {probe.issue7_store_recovery.MARKERS["consume-loss"]}\n'
        f'ISSUE7_TEST_PROVIDER_OPERATION: operation=transaction_remove request={"f" * 32}\n'
        f'ISSUE7_TEST_FAULT: {probe.issue7_store_recovery.MARKERS["consume-loss"]} request={"f" * 32}')
    observed = probe.issue7_store_recovery.diagnostics(logs, 'consume-loss', request_id)
    self.assertEqual({'store_fault_count': 0, 'correlated_store_failure_count': 0,
        'store_provider_selected': False}, observed)

  def test_failure_gate_sanitizer_uses_shared_allowlist(self):
    gates = probe.issue7_store_recovery.FAILURE_GATES
    accepted = 'store_correlation'
    self.assertIn(accepted, gates)
    sanitized = probe.sanitize_live_checkpoint({'issue7_store_recovery': {
        'failure_gate': accepted}})['issue7_store_recovery']
    self.assertEqual(accepted, sanitized['failure_gate'])
    rejected = probe.sanitize_live_checkpoint(
        {'issue7_store_recovery': {'failure_gate': 'unsupported_gate'}})
    self.assertNotIn('failure_gate', rejected.get('issue7_store_recovery', {}))

  def test_store_profiles_are_explicitly_allowlisted(self):
    for profile in ('issue7-consume-loss-recovery', 'issue7-accepted-receipt-write-recovery',
        'issue7-accepted-receipt-write-false-recovery'):
      with self.subTest(profile=profile), patch.dict(os.environ, {'WALLET_IT_PROFILE': profile}):
        self.assertIn(profile, probe.SUPPORTED_LIVE_PROFILES)
        self.assertEqual(profile, probe.selected_live_profile())


class ScriptClient:
  def __init__(self, responses):
    self.responses = list(responses)
    self.redirects = []
    self.calls = []

  def request(self, method, url, data=None, headers=None, **kwargs):
    self.calls.append((method, url, data, headers))
    response = self.responses.pop(0)
    if isinstance(response, BaseException):
      raise response
    if len(response) == 4:
      self.redirects.extend(response[3])
    return response[:3]


class FailureFlowTest(unittest.TestCase):
  def run_signup(self, mode, mutation=None, users=None, logs=None):
    locator = f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/' + 'A' * 43
    request_id = hashlib.sha256(('A' * 43).encode()).hexdigest()[:32]
    page = ('<p id="wallet-locator">' + locator + '</p>'
        '<form method="post" action="/auth/action"><input type="hidden" name="wallet_intent" value="signup"></form>')
    signup = ('Creating a new account with this wallet identity.'
        '<p id="wallet-locator">' + locator + '</p>'
        'const statusUrl = "/auth/status"; const csrfToken = "' + 'B' * 43 + '";')
    responses = [(503, {}, b''), (404, {}, b''), (404, {}, b'')]
    if mutation is not None:
      index, response = mutation
      responses[index] = response
    browser = ScriptClient([(200, {}, page.encode()), (200, {}, signup.encode()), responses[1]])
    wallet = ScriptClient([(200, {}, b'{"challenge":"challenge","profile":"decent-wallet-login-v1"}'),
        responses[0], responses[2]])
    admin = Mock()
    admin.privateClientAdminCredential = 'admin-password'
    matched = [{'id': 'retained-subject', 'enabled': True,
        'attributes': {'decent_identity_id': ['identity']}}] if users is None else users
    if logs is None:
      branch = (f'Wallet pending transaction unavailable (request={request_id}, reason=consume-unavailable)'
          if mode == 'consume-loss' else
          f'Wallet proof acceptance unavailable (request={request_id}, outcome=not_accepted)')
      logs = (f'ISSUE7_TEST_PROVIDER_OPERATION: operation={"transaction_remove" if mode == "consume-loss" else "accepted_replace"} request={request_id}\n'
          + f'ISSUE7_TEST_FAULT: {probe.issue7_store_recovery.MARKERS[mode]} request={request_id}\n' + branch)
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
      stack.enter_context(patch.object(probe, 'Client', return_value=wallet))
      stack.enter_context(patch.object(probe, 'admin_token', return_value='token'))
      stack.enter_context(patch.object(probe, 'admin_call', side_effect=[(200, {}, b'[]'),
          (200, {}, json.dumps(matched).encode())]))
      stack.enter_context(patch.object(probe.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'x' * 64)))
      window = stack.enter_context(patch.object(probe, 'read_provider_fault_log_window', return_value=logs))
      result = probe.signup_wallet_flow(browser, Path(directory) / 'key.pem', 'identity', 'a' * 64,
          admin, lambda *_: None, 'test-image', store_fault_mode=mode)
    self.assertEqual('POST', browser.calls[1][0])
    self.assertEqual(b'wallet_intent=signup', browser.calls[1][2])
    self.assertRegex(window.call_args.args[1], r'^\d{4}-.*Z$')
    self.assertEqual([], browser.responses)
    self.assertEqual([], wallet.responses)
    return result

  def test_real_signup_proof_request_exception_still_reads_bounded_fixture_diagnostics(self):
    failure = RuntimeError('private transport detail')
    with redirect_stdout(StringIO()):
      with self.assertRaises(RuntimeError) as caught:
        self.run_signup('consume-loss', mutation=(0, failure))

    self.assertIs(failure, caught.exception)
    self.assertEqual('signup_proof', getattr(failure, 'failure_stage', None))
    self.assertEqual('proof_post', getattr(failure, 'failure_gate', None))
    self.assertEqual('runtime_error', getattr(failure, 'failure_category', None))
    checkpoints = []
    probe.issue7_store_recovery.checkpoint_signup_failure(
        lambda evidence: checkpoints.append(probe.sanitize_live_checkpoint(
            {'issue7_store_recovery': evidence})['issue7_store_recovery']),
        failure, mode_field='store_fault_mode', mode='consume-loss')
    self.assertEqual(('signup_proof', 'proof_post', 'runtime_error'),
        (checkpoints[0]['failure_stage'], checkpoints[0]['failure_gate'],
         checkpoints[0]['failure_category']))
    diagnostics = getattr(failure, 'issue7_diagnostics')
    self.assertEqual({
        'store_diagnostic_read_status': 'observed',
        'store_provider_selected': True,
        'store_fault_count': 1,
        'correlated_store_failure_count': 1}, diagnostics)
    sanitized = probe.sanitize_live_checkpoint({'issue7_store_recovery': {
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'store_fault_mode': 'consume-loss', **diagnostics}})
    self.assertEqual({
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'store_fault_mode': 'consume-loss',
        'store_diagnostic_read_status': 'observed',
        'store_provider_selected': True, 'store_fault_count': 1,
        'correlated_store_failure_count': 1}, sanitized['issue7_store_recovery'])
    self.assertNotIn('private transport detail', json.dumps(sanitized))

  def test_proof_http_contract_failure_is_classified(self):
    with redirect_stdout(StringIO()):
      with self.assertRaises(RuntimeError) as caught:
        self.run_signup('consume-loss', mutation=(0, (502, {}, b'')))
    self.assertEqual(('signup_proof', 'proof_http_status', 'assertion_failed'),
        (caught.exception.failure_stage, caught.exception.failure_gate,
         caught.exception.failure_category))

  def test_status_and_identical_retry_contract_failures_have_distinct_gates(self):
    for index, gate in ((1, 'proof_status'), (2, 'identical_retry')):
      with self.subTest(index=index), redirect_stdout(StringIO()):
        with self.assertRaises(RuntimeError) as caught:
          self.run_signup('consume-loss', mutation=(index, (200, {}, b'')))
      self.assertEqual(('signup_proof', gate, 'assertion_failed'),
          (caught.exception.failure_stage, caught.exception.failure_gate,
           caught.exception.failure_category))

  def test_store_correlation_failure_has_explicit_bounded_gate(self):
    logs = 'ISSUE7_TEST_PROVIDER: factory selected\\nISSUE7_TEST_FAULT: pending consume committed then threw'
    with redirect_stdout(StringIO()):
      with self.assertRaises(RuntimeError) as caught:
        self.run_signup('consume-loss', logs=logs)
    self.assertEqual(('signup_proof', 'store_correlation', 'assertion_failed'),
        (caught.exception.failure_stage, caught.exception.failure_gate,
         caught.exception.failure_category))

  def test_real_signup_failure_path_for_each_mode(self):
    for mode in probe.issue7_store_recovery.PROFILES.values():
      with self.subTest(mode=mode), redirect_stdout(StringIO()):
        result = self.run_signup(mode)
        self.assertEqual('retained-subject', result['expected_existing_subject'])
        self.assertEqual(1, result['correlated_store_failure_count'])

  def test_original_status_and_retry_each_reject_body_location_and_followed_redirect(self):
    for index, status in enumerate((503, 404, 404)):
      for response in ((status, {}, b'{"callback":"private"}'),
          (status, {'lOcAtIoN': '/callback?code='}, b''),
          (status, {}, b'', [{'status': 302, 'location': '/callback?code=private'}]),
          (200, {}, b'')):
        with self.subTest(index=index, response=response), redirect_stdout(StringIO()):
          with self.assertRaises(RuntimeError):
            self.run_signup('consume-loss', (index, response))

  def test_missing_or_wrong_correlated_production_signal_rejects_failure(self):
    for logs in ('', 'ISSUE7_TEST_PROVIDER: factory selected\nISSUE7_TEST_FAULT: pending consume committed then threw',
        'Wallet pending transaction unavailable (request=' + 'f' * 32 + ', reason=consume-unavailable)'):
      with self.subTest(logs=logs), redirect_stdout(StringIO()):
        with self.assertRaises(RuntimeError):
          self.run_signup('consume-loss', logs=logs)

  def test_failure_readback_requires_exactly_one_enabled_exact_account(self):
    for users in ([], [{'id': 'subject', 'enabled': False, 'attributes': {'decent_identity_id': ['identity']}}],
        [{'id': 'subject', 'enabled': True, 'attributes': {'decent_identity_id': ['other']}}],
        [{'id': 'a', 'enabled': True, 'attributes': {'decent_identity_id': ['identity']}}] * 2):
      with self.subTest(users=users), redirect_stdout(StringIO()):
        with self.assertRaises(RuntimeError):
          self.run_signup('consume-loss', users=users)


class LoginRecoveryFlowTest(unittest.TestCase):
  def scripted_login(self, subject='retained-subject', expected_subject='retained-subject'):
    issuer = f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
    locator = issuer + '/decent-wallet-login/v1/transactions/fresh-login-handle'
    state = probe.b64url(b'x' * 24)
    callback = issuer + '/callback'
    security = {'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store', 'Vary': 'Origin'}
    page = (f'<p id="wallet-locator">{locator}</p>Example Wallet Demo Site'
        'const csrfToken = "' + 'c' * 43 + '"; const statusUrl = "/status";').encode()
    browser = ScriptClient([(200, {}, page), *[(404, {}, b'')] * 3,
        (202, {}, b'{"status":"accepted"}'),
        (200, security, json.dumps({'status': 'accepted', 'callback': callback}).encode()),
        (302, {'Location': probe.REDIRECT + '?state=' + state + '&code=one-use'}, b''),
        (302, {'Location': probe.REDIRECT + '?state=' + state + '&error=denied'}, b''),
        (404, {}, b''), (200, {}, b'{"id_token":"a.b.c"}')])
    wallet = ScriptClient([(200, security, json.dumps({'profile': 'decent-wallet-login-v1',
        'challenge': 'fresh-login-challenge', 'csrf_token': 'c' * 43}).encode()),
        (202, security, b'{"status":"pending"}'), (202, {}, b'{"status":"accepted"}'),
        (409, {}, b''), (413, security, b''), (404, {}, b'')])
    # The changed-proof replay must use different signature bytes, not JSON whitespace.
    signed = iter((b'p' * 64, b's' * 64, b't' * 64))
    def openssl(command, **kwargs):
      return Mock(returncode=0, stdout=next(signed) if 'pkeyutl' in command or 'pkey' in command else b'')
    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
      stack.enter_context(patch.object(probe, 'Client', side_effect=[ScriptClient([(404, {}, b'')]), wallet]))
      stack.enter_context(patch.object(probe.secrets, 'token_bytes', side_effect=lambda n: b'x' * n))
      stack.enter_context(patch.object(probe.subprocess, 'run', side_effect=openssl))
      stack.enter_context(patch.object(probe, 'run', return_value=Mock(returncode=0, stdout='', stderr='')))
      stack.enter_context(patch.object(probe, 'verify_id_token', return_value={
          'sub': subject, 'exp': 10**12, 'iss': issuer, 'aud': probe.CLIENT, 'nonce': state}))
      with redirect_stdout(StringIO()):
        result = probe.auth_flow(browser, Path(scratch) / 'key.pem', 'wallet@example.invalid',
            'container', 'image', prior_locator='old-locator', expected_subject=expected_subject)
    for client in (browser, wallet):
      self.assertFalse(any(data and b'wallet_intent=signup' in data for _, _, data, _ in client.calls))
    proofs = [json.loads(data) for method, url, data, _ in wallet.calls
        if method == 'POST' and url == locator and len(data) < 8193]
    self.assertNotEqual(proofs[0]['signature'], proofs[-1]['signature'])
    return result

  def test_real_login_completion_checks_retained_subject_callback_and_pkce(self):
    result = self.scripted_login()
    self.assertTrue(result['local_subject_matches_expected'])
    self.assertNotIn('local_subject', result)
    self.assertTrue(result['fresh_locator_distinct'])
    self.assertTrue(result['callback_replay_denied_safely'])
    self.assertEqual(200, result['pkce_token_http'])

  def test_real_login_wrong_subject_is_rejected(self):
    with self.assertRaisesRegex(RuntimeError, 'retained exact account subject'):
      self.scripted_login(subject='wrong-subject')


class MainCoordinatorTest(unittest.TestCase):
  def fixtures(self):
    failed = {'signup_proof_http': 503, 'browser_status_http': 404, 'retry_http': 404,
        'failure_responses_no_callback_or_code': True, 'account_retained_after_failure': True,
        'exact_mapped_users': 1, 'expected_existing_subject': 'retained-subject',
        'prior_locator': 'private-old-locator', 'store_fault_count': 1,
        'store_provider_selected': True, 'correlated_store_failure_count': 1}
    recovered = {'signup_proof_http': 202, 'proof_post_http': 202, 'exact_mapped_users': 1,
        'local_subject': 'retained-subject', 'local_subject_matches_expected': True,
        'callback_http': 302, 'pkce_token_http': 200,
        'fresh_locator_distinct': True, 'callback_replay_denied_safely': True,
        'callback_state_preserved': True, 'callback_code_returned': True}
    return failed, recovered

  def run_main(self, profile, failed=None, recovered=None, expect_failure=False):
    default_failed, default_recovered = self.fixtures()
    failed = default_failed if failed is None else failed
    recovered = default_recovered if recovered is None else recovered
    receipt = probe.issue7_store_recovery.PROFILES[profile] != 'consume-loss'
    client = Mock(wallet_container_id='a' * 64)
    checkpoints = []
    original_write = Path.write_text
    def capture(path, data, *args, **kwargs):
      if path.name == 'live-evidence.json':
        checkpoints.append(json.loads(data))
      return original_write(path, data, *args, **kwargs)
    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
      for name, value in {'SCRATCH': scratch, 'IMAGE': probe.IMAGE, 'RUN_CID_DIR': probe.RUN_CID_DIR}.items():
        stack.enter_context(patch.object(probe, name, value))
      stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': profile,
          'WALLET_IT_STORE_RECOVERY_IMAGE': 'store-test-image'}))
      mocks = {}
      for name, value in {
          'resolve_immutable_image': ('immutable-test-image', 'sha256:test'),
          '_prepare_resolver_runtime': {}, 'start_resolver_tools': 'resolver-tools',
          'start_registry': ('registry', 'bootstrap', 1234), 'free_port': 4321,
          'write_identity': ('key', 'wrapper', 'identity'), 'start_keycloak': client,
          'admin_token': 'token', 'keycloak_runtime_provenance': {
              'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
              'single_use_object_provider_ids': ['issue7-fault-injection']},
          'configure_realm': None, 'enable_keycloak_login_events': None,
          'Client': client, 'cleanup_owned_resources': 0,
          'finish_owned_cleanup': None, 'wait_for_identity_lookup_cooldown': None}.items():
        mocks[name] = stack.enter_context(patch.object(probe, name, return_value=value))
      signup_effect = failed if callable(failed) else ([failed] if receipt else [failed, recovered])
      signup = stack.enter_context(patch.object(probe, 'signup_wallet_flow',
          side_effect=signup_effect))
      login = stack.enter_context(patch.object(probe, 'auth_flow', return_value=recovered))
      calls = Mock()
      calls.attach_mock(signup, 'signup')
      calls.attach_mock(mocks['wait_for_identity_lookup_cooldown'], 'wait')
      calls.attach_mock(login, 'login')
      stack.enter_context(patch.object(Path, 'write_text', capture))
      with redirect_stdout(StringIO()):
        if expect_failure:
          with self.assertRaises(RuntimeError):
            probe.main()
        else:
          probe.main()
      if expect_failure:
        mocks['cleanup_owned_resources'].assert_called_once()
      else:
        mocks['finish_owned_cleanup'].assert_called_once_with('registry', 'resolver-tools')
      self.assertEqual(probe.issue7_store_recovery.PROFILES[profile],
          mocks['start_keycloak'].call_args.kwargs['store_fault_mode'])
      mocks['write_identity'].assert_called_once()
    return checkpoints, signup, login, calls, mocks

  def test_production_main_preserves_failure_facts_in_final_sanitized_checkpoint(self):
    failure = RuntimeError('private exception details')
    setattr(failure, 'failure_stage', 'signup_proof')
    setattr(failure, 'failure_gate', 'proof_http_status')
    setattr(failure, 'failure_category', 'assertion_failed')
    setattr(failure, 'failure_http_status', 503)

    def fail_after_progress(*args, **kwargs):
      args[5]('faulted_signup', {'signup_intent_action_http': 200})
      raise failure

    checkpoints, signup, login, calls, mocks = self.run_main(
        'issue7-accepted-receipt-write-recovery', failed=fail_after_progress, expect_failure=True)

    signup.assert_called_once()
    login.assert_not_called()
    mocks['wait_for_identity_lookup_cooldown'].assert_not_called()
    self.assertGreaterEqual(len(checkpoints), 1)
    evidence = checkpoints[-1]['issue7_store_recovery']
    self.assertEqual({
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'store_fault_mode': 'accepted-receipt-write',
        'fault_evidence_provenance': 'wrapper-mediated-application-path',
        'failure_stage': 'signup_proof', 'failure_gate': 'proof_http_status',
        'failure_category': 'assertion_failed',
        'signup_intent_action_http': 200, 'signup_proof_http': 503}, evidence)
    self.assertNotIn('private exception details', json.dumps(checkpoints))

  def test_production_main_failure_checkpoint_preserves_bounded_diagnostic_snapshot(self):
    failure = RuntimeError('private exception details')
    failure.failure_stage = 'signup_proof'
    failure.failure_gate = 'proof_http_status'
    failure.failure_category = 'runtime_error'
    failure.failure_http_status = 503
    setattr(failure, 'issue7_diagnostics', {
        'store_diagnostic_read_status': 'unavailable',
        'store_provider_selected': False,
        'store_fault_count': 0,
        'correlated_store_failure_count': 0,
        'exception': 'private message'})

    def fail_after_progress(*args, **kwargs):
      args[5]('faulted_signup', {'signup_intent_action_http': 200})
      raise failure

    checkpoints, *_ = self.run_main(
        'issue7-accepted-receipt-write-recovery', failed=fail_after_progress,
        expect_failure=True)

    self.assertEqual({
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'store_fault_mode': 'accepted-receipt-write',
        'fault_evidence_provenance': 'wrapper-mediated-application-path',
        'failure_stage': 'signup_proof', 'failure_gate': 'proof_http_status',
        'failure_category': 'runtime_error', 'signup_proof_http': 503,
        'signup_intent_action_http': 200,
        'store_diagnostic_read_status': 'unavailable',
        'store_provider_selected': False, 'store_fault_count': 0,
        'correlated_store_failure_count': 0}, checkpoints[-1]['issue7_store_recovery'])
    self.assertNotIn('private', json.dumps(checkpoints))

  def test_production_main_does_not_label_unclassified_status_as_signup_proof(self):
    failure = RuntimeError('private exception details')
    setattr(failure, 'failure_stage', 'signup_flow')
    setattr(failure, 'failure_gate', 'unclassified')
    setattr(failure, 'failure_category', 'assertion_failed')
    setattr(failure, 'failure_http_status', 503)

    def fail_after_progress(*args, **kwargs):
      args[5]('faulted_signup', {'signup_intent_action_http': 200})
      raise failure

    checkpoints, _, _, _, _ = self.run_main(
        'issue7-accepted-receipt-write-recovery', failed=fail_after_progress, expect_failure=True)
    evidence = checkpoints[-1]['issue7_store_recovery']

    self.assertEqual('unclassified', evidence['failure_gate'])
    self.assertIn('failure_http_status', evidence)
    self.assertEqual(503, evidence['failure_http_status'])
    self.assertNotIn('signup_proof_http', evidence)

  def test_user_readback_checkpoint_does_not_mask_original_exception(self):
    failure = RuntimeError('original readback failure')

    def broken_checkpoint(_):
      raise ValueError('checkpoint write failed')

    with patch.object(probe, 'signup_wallet_flow', side_effect=failure):
      with self.assertRaises(RuntimeError) as caught:
        probe.run_issue7_single_node_signup_recovery_profile(
            None, None, None, None, None, None, None, broken_checkpoint,
            'issue7-user-readback-empty')

    self.assertIs(failure, caught.exception)
    self.assertIn('Issue #7 failure checkpoint could not be written', failure.__notes__)

  def test_user_readback_failure_checkpoint_captures_sanitized_stage_and_status(self):
    failure = RuntimeError('private exception details')
    setattr(failure, 'failure_stage', 'signup_proof')
    setattr(failure, 'failure_gate', 'proof_http_status')
    setattr(failure, 'failure_category', 'assertion_failed')
    setattr(failure, 'failure_http_status', 503)
    checkpoints = []

    def checkpoint(value):
      checkpoints.append(probe.sanitize_live_checkpoint(
          {'issue7_single_node_signup_recovery': value})['issue7_single_node_signup_recovery'])

    with patch.object(probe, 'signup_wallet_flow', side_effect=failure):
      with self.assertRaisesRegex(RuntimeError, 'private exception details'):
        probe.run_issue7_single_node_signup_recovery_profile(
            None, None, None, None, None, None, None, checkpoint, 'issue7-user-readback-empty')

    self.assertEqual(1, len(checkpoints))
    self.assertEqual({
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'user_readback_fault_mode': 'empty', 'failure_stage': 'signup_proof',
        'failure_gate': 'proof_http_status', 'failure_category': 'assertion_failed',
        'signup_proof_http': 503}, checkpoints[0])
    self.assertNotIn('private exception details', json.dumps(checkpoints))

  def test_production_main_runs_real_coordinator_through_final_sanitized_checkpoint(self):
    for profile, mode in probe.issue7_store_recovery.PROFILES.items():
      with self.subTest(profile=profile):
        checkpoints, signup, login, calls, mocks = self.run_main(profile)
        safe = checkpoints[-1]['issue7_store_recovery']
        self.assertEqual('complete', safe['stage'])
        self.assertTrue(safe['same_local_subject'])
        self.assertEqual(mode, safe['store_fault_mode'])
        self.assertEqual(200, safe['pkce_token_http'])
        self.assertEqual(mode, signup.call_args_list[0].kwargs['store_fault_mode'])
        if mode == 'consume-loss':
          self.assertEqual(['signup', 'wait', 'signup'], [c[0] for c in calls.mock_calls])
          self.assertTrue(signup.call_args_list[1].kwargs['reuse_existing'])
          login.assert_not_called()
          self.assertEqual(2, safe['fresh_explicit_signup_transactions'])
          self.assertEqual(0, safe['fresh_login_transactions'])
          self.assertEqual('signup', safe['recovery_intent'])
        else:
          self.assertEqual(['signup', 'wait', 'login'], [c[0] for c in calls.mock_calls])
          self.assertEqual('private-old-locator', login.call_args.kwargs['prior_locator'])
          self.assertEqual('retained-subject', login.call_args.kwargs['expected_subject'])
          self.assertEqual(1, safe['fresh_explicit_signup_transactions'])
          self.assertEqual(1, safe['fresh_login_transactions'])
          self.assertEqual('login', safe['recovery_intent'])
        serialized = json.dumps(checkpoints)
        self.assertNotIn('retained-subject', serialized)
        self.assertNotIn('private-old-locator', serialized)

  def test_incomplete_failure_evidence_prevents_recovery_and_cleans_owned_resources(self):
    failed, _ = self.fixtures()
    for field, value in {'failure_responses_no_callback_or_code': False,
        'expected_existing_subject': None, 'store_fault_count': 0,
        'correlated_store_failure_count': 0, 'browser_status_http': 200,
        'retry_http': 202, 'account_retained_after_failure': False}.items():
      with self.subTest(field=field):
        _, signup, login, _, mocks = self.run_main('issue7-accepted-receipt-write-recovery',
            failed={**failed, field: value}, expect_failure=True)
        signup.assert_called_once()
        login.assert_not_called()
        mocks['wait_for_identity_lookup_cooldown'].assert_not_called()

  def test_bad_recovery_or_wrong_subject_never_produces_complete_checkpoint(self):
    _, recovered = self.fixtures()
    for profile in probe.issue7_store_recovery.PROFILES:
      for field, value in {'local_subject_matches_expected': False, 'callback_http': 500,
          'pkce_token_http': 400}.items():
        with self.subTest(profile=profile, field=field):
          checkpoints, *_ = self.run_main(profile, recovered={**recovered, field: value},
              expect_failure=True)
          self.assertEqual('recovery', checkpoints[-1]['issue7_store_recovery']['stage'])
          self.assertTrue(checkpoints[-1]['issue7_store_recovery']['account_retained_after_failure'])
          self.assertEqual(404, checkpoints[-1]['issue7_store_recovery']['retry_http'])
    for field in ('fresh_locator_distinct', 'callback_replay_denied_safely',
        'callback_state_preserved', 'callback_code_returned'):
      with self.subTest(field=field):
        self.run_main('issue7-accepted-receipt-write-recovery',
            recovered={**recovered, field: False}, expect_failure=True)

  def test_missing_image_and_unsupported_modes_stop_before_external_actions(self):
    for profile in probe.issue7_store_recovery.PROFILES:
      with patch.dict(os.environ, {'WALLET_IT_PROFILE': profile}), \
          patch.object(probe, 'resolve_immutable_image') as resolve:
        os.environ.pop('WALLET_IT_STORE_RECOVERY_IMAGE', None)
        with self.assertRaisesRegex(ValueError, 'WALLET_IT_STORE_RECOVERY_IMAGE'):
          probe.main()
        resolve.assert_not_called()
    with patch.object(probe, 'run') as external:
      with self.assertRaises(ValueError):
        probe.start_keycloak('container', 'password', 'wrapper', 4321, 'bootstrap', 'image',
            store_fault_mode='concurrent-consume')
      external.assert_not_called()
    for profile in ('issue7-consume-loser-interleaving', 'issue7-concurrent-consume'):
      with patch.dict(os.environ, {'WALLET_IT_PROFILE': profile}):
        with self.assertRaises(ValueError):
          probe.selected_live_profile()

  def test_nested_sanitizer_rejects_private_invalid_and_unbounded_fields(self):
    safe = probe.sanitize_live_checkpoint({'issue7_store_recovery': {
        'stage': 'complete', 'store_fault_mode': 'consume-loss', 'same_local_subject': True,
        'fresh_explicit_signup_transactions': 2, 'fresh_login_transactions': 0,
        'recovery_intent': 'signup', 'retry_http': 404, 'store_fault_count': 1,
        'correlated_store_failure_count': 1, 'account_retained_after_failure': True,
        'identity': 'private', 'local_subject': 'private', 'logs': 'private', 'callback_http': 999,
        'keycloak_node_count': True, 'exact_mapped_users': 999}})
    self.assertEqual({'issue7_store_recovery': {'stage': 'complete', 'store_fault_mode': 'consume-loss',
        'same_local_subject': True, 'fresh_explicit_signup_transactions': 2, 'fresh_login_transactions': 0,
        'recovery_intent': 'signup', 'retry_http': 404, 'store_fault_count': 1,
        'correlated_store_failure_count': 1, 'account_retained_after_failure': True}}, safe)

  def test_readback_failure_metadata_survives_both_checkpoint_projectors(self):
    issue7 = {'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'failure_stage': 'user_readback', 'failure_gate': 'account_readback',
        'failure_category': 'assertion_failed'}
    store_safe = probe.issue7_store_recovery.sanitize(issue7)
    readback_safe = probe.sanitize_live_checkpoint(
        {'issue7_single_node_signup_recovery': issue7})['issue7_single_node_signup_recovery']
    expected = {
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'failure_stage': 'user_readback', 'failure_gate': 'account_readback',
        'failure_category': 'assertion_failed'}
    self.assertEqual(expected, store_safe)
    self.assertEqual(expected, readback_safe)

  def test_unclassified_failure_http_status_survives_both_checkpoint_projectors(self):
    issue7 = {'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'failure_stage': 'signup_flow', 'failure_gate': 'unclassified',
        'failure_category': 'assertion_failed', 'failure_http_status': 503}
    expected = {
        'stage': 'faulted_signup', 'scope': 'one-keycloak-node',
        'failure_stage': 'signup_flow', 'failure_gate': 'unclassified',
        'failure_category': 'assertion_failed', 'failure_http_status': 503}
    self.assertEqual(expected, probe.issue7_store_recovery.sanitize(issue7))
    self.assertEqual(expected, probe.sanitize_live_checkpoint(
        {'issue7_single_node_signup_recovery': issue7})['issue7_single_node_signup_recovery'])

  def test_failed_signup_checkpoint_preserves_allowlisted_stage_gate_and_http_facts(self):
    safe = probe.sanitize_live_checkpoint({'issue7_store_recovery': {
        'stage': 'faulted_signup', 'failure_stage': 'signup_proof',
        'failure_gate': 'proof_http_status', 'failure_category': 'assertion_failed',
        'signup_intent_action_http': 200, 'signup_proof_http': 503,
        'fault_evidence_provenance': 'wrapper-mediated-application-path',
        'exception': 'private message', 'subject': 'private', 'url': 'private',
        'token': 'private', 'logs': 'private'}})['issue7_store_recovery']
    self.assertEqual({
        'stage': 'faulted_signup', 'failure_stage': 'signup_proof',
        'failure_gate': 'proof_http_status', 'failure_category': 'assertion_failed',
        'signup_intent_action_http': 200, 'signup_proof_http': 503,
        'fault_evidence_provenance': 'wrapper-mediated-application-path'}, safe)


  def test_receipt_projection_never_reports_two_signup_transactions(self):
    for mode in ('accepted-receipt-write', 'accepted-receipt-write-false'):
      safe = probe.sanitize_live_checkpoint({'issue7_store_recovery': {
          'store_fault_mode': mode, 'fresh_explicit_signup_transactions': 2,
          'fresh_login_transactions': 1}})['issue7_store_recovery']
      self.assertNotIn('fresh_explicit_signup_transactions', safe)
    safe = probe.sanitize_live_checkpoint({'issue7_store_recovery': {
        'store_fault_mode': 'consume-loss', 'fresh_login_transactions': 1}})['issue7_store_recovery']
    self.assertNotIn('fresh_login_transactions', safe)


class PackagingTest(unittest.TestCase):
  def test_isolated_image_build_selects_spi_and_launch_does_not_override_it(self):
    root = Path(__file__).parents[1]
    dockerfile = (root / 'container/Dockerfile').read_text()
    stage = dockerfile.split('FROM runtime AS issue7-store-recovery-test-runtime', 1)[1].split('FROM ', 1)[0]
    self.assertIn('COPY target/issue7-fault-provider.jar /opt/keycloak/providers/', stage)
    self.assertIn('--spi-single-use-object--provider-default=issue7-fault-injection', stage)
    self.assertNotIn('issue7-fault-provider.jar', dockerfile.split('FROM runtime AS issue7-store-recovery-test-runtime')[0])
    client = Mock()
    client.request.return_value = (200, {}, json.dumps({'issuer': f'https://idp.example:{probe.KC_PORT}/auth/realms/master'}).encode())
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
      stack.enter_context(patch.object(probe, 'SCRATCH', directory))
      stack.enter_context(patch.object(probe, '_cid_file', return_value=Path(directory) / 'cid'))
      stack.enter_context(patch.object(probe, 'run', return_value=Mock(returncode=0, stdout='')))
      stack.enter_context(patch.object(probe, 'Client', return_value=client))
      launch = stack.enter_context(patch.object(probe, 'start_owned_container',
          return_value=(probe.subprocess.CompletedProcess([], 0, ''), 'a' * 64)))
      probe.start_keycloak('container', 'password', 'wrapper', 1234, 'bootstrap', 'test-image',
          store_fault_mode='accepted-receipt-write')
      command = launch.call_args.args[0]
      self.assertIn('ISSUE7_TEST_FAULT_MODE=accepted-receipt-write', command)
      self.assertEqual('start-dev', command[command.index('test-image') + 1])
      self.assertFalse(any(arg.startswith('--spi-single-use-object') for arg in command))
      self.assertEqual([], list(Path(directory).glob('*.env')))

  def test_builder_includes_nested_delegates_but_not_test_classes(self):
    import shutil
    import subprocess
    import tempfile
    import zipfile
    root_source = Path(__file__).parents[1]
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      (root / 'scripts').mkdir()
      factory = 'org/decentwallet/keycloak/wallet/Issue7FaultInjectingSingleUseObjectProviderFactory'
      classes = root / 'target/test-classes'
      (classes / factory).parent.mkdir(parents=True)
      for suffix in ('.class', '$1.class', 'Test.class', '$Delegate.class'):
        (classes / (factory + suffix)).write_bytes(b'fixture-bytecode')
      builder = root_source / 'scripts/build_issue7_fault_provider.py'
      self.assertTrue(builder.is_file(), 'dedicated SPI builder must exist')
      shutil.copy2(builder, root / 'scripts')
      result = subprocess.run([sys.executable, str(root / 'scripts/build_issue7_fault_provider.py')],
          cwd=root, capture_output=True, text=True)
      self.assertEqual(0, result.returncode, result.stderr)
      with zipfile.ZipFile(root / 'target/issue7-fault-provider.jar') as archive:
        self.assertEqual({factory + '.class', factory + '$1.class', factory + '$Delegate.class',
            'META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory'}, set(archive.namelist()))
        self.assertEqual(factory.replace('/', '.') + '\n', archive.read(
            'META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory').decode())


if __name__ == '__main__':
  unittest.main()
