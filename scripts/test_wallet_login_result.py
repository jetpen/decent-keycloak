import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from email.message import Message
from pathlib import Path

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

from wallet_login_live_e2e import classify_and_parse_result, classify_identity_lookup, json_object_is_balanced, packaged_resolver_readback, parse_exact_identity_result, sanitize_live_checkpoint  # noqa: E402
import wallet_login_live_e2e as live  # noqa: E402


class IdentityLookupClassificationTest(unittest.TestCase):

  def test_checkpoint_preserves_dht_lookup_unavailable_resolver_diagnostic(self):
    candidate = {'resolver_runtime': {
        'diagnostic_categories': ['ok:dht_lookup_unavailable']}}

    self.assertEqual(candidate, sanitize_live_checkpoint(candidate))

  def _run_missing_identity_probe(self, redirect_during=None, provider_http=503, log_mode=None,
      provider_body=b'', provider_headers=None, status_headers=None, probe='missing'):
    from types import SimpleNamespace
    from unittest.mock import patch

    generated_keys = []
    resolver_arguments = []
    submitted_proofs = []
    signing_inputs = []
    locator = (f'https://idp.example:{live.KC_PORT}/auth/realms/{live.REALM}'
        '/decent-wallet-login/v1/transactions/test-handle')
    status_url = f'/auth/realms/{live.REALM}/decent-wallet-login/v1/status/test-handle'
    csrf = 'A' * 43
    page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const statusUrl = "{status_url}"; const csrfToken = "{csrf}";</script>')
    challenge = {'profile': 'decent-wallet-login-v1', 'challenge': 'test-challenge',
        'csrf_token': csrf}

    class FakeClient:
      def __init__(self, redirect_here=None):
        self.redirects = []
        self.redirect_here = redirect_here

      def request(self, method, path, body=None, headers=None):
        if method == 'GET' and 'protocol/openid-connect/auth?' in path:
          return 200, {}, page.encode()
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps(challenge).encode()
        if method == 'POST' and path == locator:
          if body is None:
            raise AssertionError('provider proof body was absent')
          submitted_proofs.append(json.loads(body))
          if self.redirect_here == 'proof':
            self.redirects.append({'status': 302, 'method': 'POST',
                'source_path': '/transaction', 'target_path': '/callback',
                'target_query_names': ['code', 'state']})
          return provider_http, provider_headers or {}, provider_body
        if method == 'GET' and path == status_url:
          if self.redirect_here == 'status':
            self.redirects.append({'status': 302, 'method': 'GET',
                'source_path': '/status', 'target_path': '/callback',
                'target_query_names': ['code', 'state']})
          return 200, status_headers or {}, b'{"status":"pending"}'
        raise AssertionError(f'unexpected mocked request: {method} {path}')

    def fake_generate_owner_key(temp, label, image):
      key = Path(temp) / (label + '-identity.pem')
      key.write_bytes(b'fixture-private-key')
      generated_keys.append(key)
      return key

    def fake_resolver(container, arguments, **kwargs):
      resolver_arguments.append(arguments)
      return SimpleNamespace(returncode=1, stdout='not found')

    log_reads = []
    def fake_openssl(arguments, **kwargs):
      if arguments[:2] == ['podman', 'logs']:
        log_reads.append(True)
        marker = ('Wallet Identity lookup completed (request='
            + live.account_policy_request_id(locator) + ', outcome=not_found)')
        text = 'baseline\n'
        if len(log_reads) > 1 and log_mode == 'witness':
          text += marker + '\n'
        return SimpleNamespace(returncode=0, stdout=text)
      if arguments[:3] == ['openssl', 'pkeyutl', '-sign']:
        signing_inputs.append(Path(arguments[arguments.index('-in') + 1]).read_bytes())
        return SimpleNamespace(returncode=0, stdout=b'\x91' * 64)
      raise AssertionError(f'unexpected signing command: {arguments}')

    clients = [FakeClient('status' if redirect_during == 'status' else None),
        FakeClient('proof' if redirect_during == 'proof' else None)]
    with tempfile.TemporaryDirectory() as temp:
      with patch.object(live, 'SCRATCH', Path(temp)), \
          patch.object(live, 'Client', side_effect=clients), \
          patch.object(live, 'generate_owner_key', side_effect=fake_generate_owner_key), \
          patch.object(live, 'run_image_resolver', side_effect=fake_resolver), \
          patch.object(live, 'classify_identity_lookup',
              return_value=(('not_found', ['registry_miss', 'not_found']) if log_mode
                  else ('unavailable', ['dial_warning', 'not_found']))), \
          patch.object(live.subprocess, 'run', side_effect=fake_openssl), \
          patch.dict(os.environ, {'WALLET_IT_RESOLVER_TOOLS_CONTAINER': 'resolver-tools'}):
        flow = live.missing_identity_flow if probe == 'missing' else live.registry_proof_probe
        result = flow(Path(temp), 18887, 'bootstrap', 'image',
            container='provider-container' if log_mode else None)
    return result, generated_keys, resolver_arguments, submitted_proofs, signing_inputs, clients

  def test_missing_identity_probe_signs_exact_unpublished_identity(self):
    result, generated_keys, resolver_arguments, submitted_proofs, signing_inputs, _ = \
        self._run_missing_identity_probe()

    self.assertEqual(1, len(generated_keys))
    self.assertEqual(1, len(signing_inputs))
    proof = submitted_proofs[0]
    identifier = proof['identity_id']
    self.assertTrue(identifier.startswith('wallet-login-unpublished-'))
    self.assertTrue(identifier.endswith('@example.invalid'))
    self.assertEqual(identifier, resolver_arguments[0][resolver_arguments[0].index('--identifier') + 1])
    self.assertEqual('get', resolver_arguments[0][0])
    expected_signed = json.dumps({'challenge': 'test-challenge', 'identity_id': identifier,
        'profile': 'decent-wallet-login-v1'}, ensure_ascii=False, separators=(',', ':'),
        sort_keys=True).encode('utf-8')
    self.assertEqual(expected_signed, signing_inputs[0])
    self.assertEqual(live.b64url(b'\x91' * 64), proof['signature'])
    self.assertTrue(result['no_acceptance_or_callback'])
    self.assertTrue(result['redirects_safe'])
    checkpoint = live.sanitize_live_checkpoint({'missing_identity_case': result})
    self.assertTrue(checkpoint['missing_identity_case']['status_pending'])
    self.assertTrue(checkpoint['missing_identity_case']['redirects_safe'])
    self.assertNotIn('identity_id', checkpoint['missing_identity_case'])

  def test_missing_identity_probe_fails_closed_on_followed_redirect(self):
    for redirect_during in ('proof', 'status'):
      with self.subTest(redirect_during=redirect_during):
        with self.assertRaisesRegex(RuntimeError,
            'unpublished Identity produced no accepted receipt, callback, or code'):
          self._run_missing_identity_probe(redirect_during)

  def test_current_identity_attempt_retains_failed_auth_outcomes(self):
    from types import SimpleNamespace
    from unittest.mock import patch

    statuses = iter((503, 202))
    def auth_flow_runner(*_args):
      status = next(statuses)
      if status == 503:
        raise live.AuthFlowFailure({
            'proof_post_http': 503, 'initial_status_http': 200, 'status_pending': True})
      return {'proof_post_http': 202, 'initial_status_http': 200}

    def resolver_lookup(_attempt):
      return SimpleNamespace(stdout='{"identity_id":"id-1","owner_public_key":"'
          + 'ab' * 32 + '"}', returncode=0)

    def public_key(*_args, **_kwargs):
      return SimpleNamespace(returncode=0, stdout=b'\x00' * 32 + bytes.fromhex('ab' * 32))

    with patch.object(live.subprocess, 'run', side_effect=public_key), \
        patch.object(live, 'packaged_resolver_readback', return_value=True), \
        patch.object(live, 'classify_identity_lookup', return_value=('resolved', [])), \
        patch.object(live, 'Client', return_value=object()):
      attempts = [live.invoke_current_identity_attempt('id-1', Path('/fixture.key'),
          'kc', 'image', number, resolver_lookup, auth_flow_runner)
          for number in (1, 2)]

    self.assertEqual([503, 202], [attempt['provider_http'] for attempt in attempts])
    self.assertEqual([200, 200], [attempt['status_http'] for attempt in attempts])
    self.assertTrue(attempts[0]['status_pending'])
    self.assertTrue(all(attempt['exact_readback'] for attempt in attempts))

  def test_current_identity_attempt_checkpoints_resolver_failure_without_raw_error(self):
    checkpoints = []
    def mark_stage(stage, failure_category=None):
      checkpoints.append((stage, failure_category))
    def failed_lookup(_attempt_number):
      raise RuntimeError('raw resolver failure must not be copied')

    with self.assertRaisesRegex(RuntimeError, 'raw resolver failure'):
      live.invoke_current_identity_attempt('id-1', Path('/fixture.key'), 'kc', 'image', 1,
          failed_lookup, stage_checkpoint=mark_stage)

    self.assertEqual([
        ('current_identity_direct_lookup_start', None),
        ('current_identity_direct_lookup_start', 'runtime_error'),
    ], checkpoints)
    projected = sanitize_live_checkpoint({'issue5_profile': {
        'stage': checkpoints[-1][0], 'failure_category': checkpoints[-1][1],
        'exception_text': 'raw resolver failure must not be copied'}})
    self.assertEqual({
        'stage': 'current_identity_direct_lookup_start', 'failure_category': 'runtime_error'},
        projected['issue5_profile'])

  def test_live_probe_rotates_registry_identity_and_checks_old_and_new_keys(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def stale_key_rotation_flow(')
    end = source.index('def signup_wallet_flow(', start)
    body = source[start:end]
    self.assertIn("helper = project / 'scripts/rotation_registry_roundtrip.py'", body)
    self.assertIn("readback[0] == str(expected_sequence)", body)
    self.assertIn("separate Identity resolver confirms sequence {expected_sequence} and exact successor key", body)
    helper = Path(__file__).with_name('rotation_registry_roundtrip.py').read_text()
    self.assertIn('draft_identity_bundle(', helper)
    self.assertIn('predecessor_state_hash=predecessor_hash', helper)
    self.assertIn('OPERATION_OWNER_KEY_ROTATION', helper)
    self.assertIn('predecessor_signed_update(', helper)
    self.assertIn('put_identity(', helper)
    self.assertIn('get_identity_record(', helper)
    self.assertIn('observed.seq == expected_seq', helper)
    self.assertNotIn('decent.wallet.test.rotated-owner-public-key', body)
    self.assertGreaterEqual(body.count('start_rotation_transaction()'), 2)
    self.assertIn('stale_key_status == 401', body)
    self.assertIn('current_key_status == 202', body)
    self.assertIn("callback.startswith(f'https://idp.example:{KC_PORT}/auth/')", body)
    self.assertIn("{'status': 'pending'}", body)

  def test_rotation_retry_checkpoints_preserve_stale_attempt_status(self):
    from wallet_login_live_e2e import checkpoint_rotation_stage, sanitize_live_checkpoint
    for stage in ('stale_attempt', 'stale_proof_pending'):
      with self.subTest(stage=stage):
        result = {}
        checkpoint_rotation_stage(result, stage, {
            'attempt_number': 1, 'stale_key_proof_http': 503,
            'status_http': 200, 'status_pending': True}, lambda: None)
        projected = sanitize_live_checkpoint(result)
        self.assertEqual(stage, projected['rotated_identity_case']['stage'])
        self.assertEqual(503, projected['rotated_identity_case']['stale_key_proof_http'])
        self.assertEqual(200, projected['rotated_identity_case']['status_http'])
        self.assertTrue(projected['rotated_identity_case']['status_pending'])

  def test_rotation_diagnostic_checkpoint_records_allowlisted_classifier_categories(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def rotation_readback_samples(')
    end = source.index('def stale_key_rotation_flow(', start)
    body = source[start:end]
    self.assertIn("'diagnostic_categories': categories[:12]", body)
    self.assertIn("unexpected_diagnostic': any(category == 'other'", body)
    self.assertIn("'outcome': outcome", body)
    self.assertIn("'json_balanced': json_object_is_balanced(lookup.stdout)", body)
    self.assertIn("'exact_identity_and_successor_match': exact", body)

  def test_rotated_identity_proofs_require_exact_fresh_readback(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def rotation_readback_samples(')
    end = source.index('def stale_key_rotation_flow(', start)
    body = source[start:end]
    self.assertIn("if exact:", body)
    self.assertIn("resolved = True", body)
    self.assertIn("elif outcome == 'resolved':", body)
    self.assertIn("outcome = 'unavailable'", body)
    self.assertIn("packaged_resolver_readback", body)
    flow = source.split('def stale_key_rotation_flow(', 1)[1].split('def sanitized_resolver_diagnostic_lines(', 1)[0]
    self.assertIn("expected_key.stdout[-32:].hex()", flow)
    self.assertIn("resolver_samples, resolved_fresh_read = rotation_readback_samples(", source)
    self.assertIn("require(resolved_fresh_read", flow)
    self.assertLess(flow.index("require(resolved_fresh_read"), flow.index("stale_attempts = run_bounded_resolver_attempts"))

  def test_replay_identity_is_seeded_once_and_reused_for_both_local_mappings(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main_body = source[source.index('def main():'):]
    self.assertEqual(1, main_body.count("label='wallet-login-replay'"))
    duplicate_fixture_creation = "replay_fixture_status, _, _ = admin_call(client, token, 'POST'"
    self.assertNotIn(duplicate_fixture_creation, main_body)
    replay_mapping = "provision_identity_attribute(client, token, 'wallet-owner-duplicate', replay_identifier)"
    self.assertEqual(1, main_body.count(replay_mapping))
    duplicate_attr = "'attributes': {'decent_identity_id': [replay_identifier]}"
    self.assertEqual(1, main_body.count(duplicate_attr))


  def test_live_probe_includes_stale_key_after_registry_rotation_case(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main_start = source.index('def main():')
    main_body = source[main_start:]
    self.assertIn('stale_key_rotation_flow(', source)
    self.assertIn("result['rotated_identity_case']", main_body)
    self.assertIn("account_policy_denial_is_attributed(outcome)", main_body)
    self.assertIn("max_concurrent >= 2", main_body)
    self.assertIn("'username': 'wallet-owner-duplicate', 'enabled': True", source)
    self.assertIn("provision_identity_attribute(client, token, 'wallet-owner-duplicate', identifier)", main_body)

  def test_replay_mapping_reuses_seeded_fixture_instead_of_creating_a_second_user(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main_body = source[source.index('def main():'):]
    self.assertIn("provision_identity_attribute(client, token, 'wallet-owner-duplicate', replay_identifier)", main_body)
    self.assertIn("provision_identity_attribute(client, token, 'wallet-owner-duplicate', identifier)", main_body)
    replay_creation = "replay_status, _, _ = admin_call(client, token, 'POST'"
    self.assertIn(replay_creation, main_body)
    self.assertIn("replay_users = json.loads(admin_call(client, token, 'GET'", main_body)
    self.assertIn("duplicate_users = json.loads(admin_call(client, token, 'GET'", main_body)

  def test_duplicate_mapping_denial_runs_only_after_duplicate_fixture_is_seeded(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main_body = source[source.index('def main():'):]
    duplicate_fixture = "provision_identity_attribute(client, token, 'wallet-owner-duplicate', identifier)"
    self.assertIn(duplicate_fixture, main_body)
    concurrent_runner = "run_concurrent_account_denial_flows(["
    duplicate_denial = "('ambiguous-account', lambda: account_mapping_denial_flow("
    self.assertLess(main_body.index(duplicate_fixture), main_body.index(concurrent_runner))
    self.assertLess(main_body.index(concurrent_runner), main_body.index(duplicate_denial))

  def test_live_probe_exercises_streaming_body_limit_and_retry_semantics(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def auth_flow(')
    end = source.index('\ndef require_transport_security_headers', start)
    body = source[start:end]
    self.assertIn("wallet.request('POST', locator, proof", body)
    self.assertIn('require(submitted == 202', body)
    self.assertIn("set(envelope) == {'profile', 'challenge', 'csrf_token'}", body)
    self.assertIn("'Example Wallet Demo Site' in text", body)
    self.assertIn("require(retried == 202 and json.loads(retry_raw).get('status') == 'accepted'", body)
    self.assertIn('require(changed == 409', body)
    self.assertIn("b' ' * 8193", source)
    self.assertIn("oversized_status == 413", source)
    route_test = Path(__file__).parents[1] / 'src/test/java/org/decentwallet/keycloak/wallet/WalletLoginTransportResourceRouteTest.java'
    self.assertIn('proofBodyReaderStopsAtTheConfiguredLimitPlusOneByte', route_test.read_text())

  def test_live_probe_exercises_acceptance_and_rejections_for_cors_routes(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def browser_preflight_flow(image):')
    end = source.index('\ndef negative_proof_flow', start)
    body = source[start:end]
    self.assertIn("'Access-Control-Request-Method': 'GET'", body)
    self.assertIn("'Access-Control-Request-Method': 'POST'", body)
    self.assertIn('require(get_status == 204', body)
    self.assertIn('require(post_status == 204', body)
    self.assertIn('rejected_status == 403', body)
    self.assertIn('wrong_origin_status == 403', body)

  def test_live_probe_uses_tls_terminated_frontend_instead_of_forwarded_http(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    client_start = source.index('class Client:')
    client_end = source.index('\n\nclass BareLocalClient', client_start)
    client_body = source[client_start:client_end]
    self.assertIn("result = f'http://127.0.0.1:{KC_PORT}{path}'", client_body)
    self.assertIn('X-Forwarded-Proto', client_body)
    self.assertIn('class LocalKeycloakRedirects', source)
    self.assertIn("'X-Forwarded-Proto': 'https'", source)
    self.assertIn('simulates TLS termination over loopback', client_body)

  def test_live_probe_exercises_exact_browser_cors_preflight_matrix(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def browser_preflight_flow(')
    end = source.index('\ndef negative_proof_flow', start)
    body = source[start:end]
    expected = (
        'browser_challenge_status == 200',
        "browser_challenge_headers.get('Access-Control-Allow-Origin') == WALLET_ORIGIN",
        'missing_csrf_status == 403',
        'browser_proof_status == 401',
        "json.loads(status_raw) == {'status': 'pending'}",
        "'Access-Control-Request-Method': 'GET'",
        "'Access-Control-Request-Method': 'POST'",
        "'Access-Control-Request-Headers': 'content-type,x-decent-csrf'",
        "'Access-Control-Request-Headers': 'authorization,content-type,x-decent-csrf'",
        'require(get_status == 204',
        'require(post_status == 204',
        'rejected_status == 403',
        'wrong_origin_status == 403',
    )
    for assertion in expected:
      self.assertIn(assertion, body)

  def test_live_browser_flow_checks_shared_transport_security_headers(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def browser_preflight_flow(')
    end = source.index('def negative_proof_flow', start)
    body = source[start:end]
    self.assertIn("require_transport_security_headers(browser_challenge_headers", body)
    self.assertIn("require_transport_security_headers(missing_csrf_headers", body)
    self.assertIn("require_transport_security_headers(browser_proof_headers", body)
    self.assertIn("require_transport_security_headers(status_response_headers", body)
    self.assertIn("expected['Cache-Control'] = 'no-store'", source)
    self.assertIn("'Referrer-Policy': 'no-referrer'", source)
    self.assertIn("'X-Content-Type-Options': 'nosniff'", source)
    self.assertIn("headers.get('Vary') is not None", source)
    self.assertEqual(body.count('expect_no_store=False'), 2)

  def test_cors_browser_actors_preserve_session_and_keep_native_client_separate(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def browser_preflight_flow(')
    end = source.index('\ndef negative_proof_flow', start)
    body = source[start:end]
    self.assertIn('browser = Client()', body)
    self.assertIn("browser.request('POST', locator", body)
    self.assertIn("'X-Decent-CSRF': challenge_csrf", body)
    self.assertIn("status_headers = {'Sec-Fetch-Site': 'same-origin'", body)
    self.assertIn("json.loads(status_raw) == {'status': 'pending'}", body)
    self.assertNotIn('BareLocalClient()', body)

  def test_invalid_proof_throttle_probe_checks_fifth_attempt_and_pending_status(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def invalid_proof_throttle_flow(')
    end = source.index('\ndef account_mapping_denial_flow', start)
    body = source[start:end]
    self.assertIn('wallet = BareLocalClient()', body)
    self.assertIn('browser = Client()', body)
    self.assertIn("json.loads(status_raw) == {'status': 'pending'}", body)
    for expected in ('range(4)', 'malformed_results == [400, 400, 400, 400]',
        'throttled == 429'):
      self.assertIn(expected, body)

  def test_per_transaction_throttle_keeps_fresh_proof_unqualified(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def invalid_proof_throttle_flow(')
    end = source.index('\ndef account_mapping_denial_flow', start)
    body = source[start:end]
    for expected in (
        'range(4)',
        'malformed_results == [400, 400, 400, 400]',
        'throttled == 429',
        "json.loads(status_raw) == {'status': 'pending'}",
    ):
      self.assertIn(expected, body)

  def test_missing_identity_acceptance_evidence_fails_closed(self):
    response_headers = Message()
    response_headers['Content-Type'] = 'application/json'
    self.assertFalse(live._response_has_acceptance_evidence(
        response_headers, b'{"status":"pending"}'))
    self.assertEqual('structured_no_acceptance', live._response_acceptance_category(
        response_headers, b'{"status":"pending"}'))
    self.assertFalse(live._response_has_acceptance_evidence({}, b'{"status":"pending"}'))
    self.assertTrue(live._response_has_acceptance_evidence(
        {'Location': '/callback?code=redacted'}, b''))
    self.assertEqual('callback_location', live._response_acceptance_category(
        {'Location': '/callback?code=redacted'}, b''))
    self.assertEqual('structured_no_acceptance', live._response_acceptance_category(
        {'Location': '/auth/realms/wallet-login/transactions/opaque/status'},
        b'{"status":"pending"}'))
    self.assertFalse(live._response_has_acceptance_evidence(
        {'Location': '/auth/realms/wallet-login/transactions/opaque/status'},
        b'{"status":"pending"}'))
    self.assertTrue(live._response_has_acceptance_evidence({}, b'{"code":"redacted"}'))
    self.assertTrue(live._response_has_acceptance_evidence({}, b'{"callback_url":"redacted"}'))
    self.assertTrue(live._response_has_acceptance_evidence({}, b'{"accepted_receipt":"redacted"}'))
    self.assertTrue(live._response_has_acceptance_evidence({}, b'{"status":"accepted","status":"pending"}'))
    self.assertTrue(live._response_has_acceptance_evidence({}, b'unstructured response'))
    for headers in ({'XAuthorizationCode': 'opaque'}, {'XCallbackUrl': 'opaque'},
        {'XReceiptId': 'opaque'}):
      with self.subTest(headers=headers):
        self.assertTrue(live._response_has_acceptance_evidence(headers,
            b'{"status":"pending"}'))
    duplicate_locations = Message()
    duplicate_locations.add_header('Location', '/ordinary-one')
    duplicate_locations.add_header('Location', '/ordinary-two')
    self.assertTrue(live._response_has_acceptance_evidence(
        duplicate_locations, b'{"status":"pending"}'))
    self.assertFalse(live._response_has_acceptance_evidence(
        {}, b'provider unavailable', terminal_http_status=503))
    self.assertFalse(live._response_has_acceptance_evidence(
        {}, b'provider denied', terminal_http_status=401))
    self.assertTrue(live._response_has_acceptance_evidence(
        {}, b'{"code":"redacted"}', terminal_http_status=401))

  def test_terminal_denial_sensitive_material_never_counts_as_safe(self):
    for status in (401, 503):
      for headers, body in (
          ({}, b'authorization code=redacted'),
          ({}, b'code = redacted'),
          ({}, b'{"message":"receipt=redacted"}'),
          ({}, b'callback=https%3A%2F%2Fexample.invalid'),
          ({}, b'accepted'),
          ({'Location': '/other?code='}, b''),
          ({'Location': '/other?receipt=redacted'}, b''),
          ({'Location': '/other#authorization_code='}, b''),
          ({'Location': '/other?co%64e='}, b''),
      ):
        with self.subTest(status=status, headers=headers, body=body):
          self.assertTrue(live._response_has_acceptance_evidence(headers, body, status))

  def test_same_line_duplicated_or_malformed_identity_marker_cannot_attribute_absence(self):
    request = 'ab' * 16
    marker = f'Wallet Identity lookup completed (request={request}, outcome=not_found)'
    for line in (marker + ' ' + marker,
        'Wallet Identity lookup completed (malformed) ' + marker):
      with self.subTest(line=line):
        evidence = live.new_identity_lookup_log_evidence(['baseline'], ['baseline', line], request)
        self.assertFalse(evidence['provider_identity_not_found_observed'])
        self.assertEqual('provider_denied_unclassified', live.classify_provider_identity_outcome(401, evidence))

  def test_provider_not_found_diagnostic_profile_is_explicitly_separate(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main = source[source.index('def main():'):]
    self.assertIn("'provider-not-found-diagnostic'", main)
    self.assertNotIn("'issue4-not-found'", main)
    self.assertIn('run_provider_missing_identity_profile', main)
    self.assertIn('provider_missing_identity_is_qualified(evidence)', source)
    self.assertNotIn('issue4_missing_identity_is_qualified', main)
    self.assertNotIn('Issue #4 clean provider-level terminal', main)

  def test_provider_missing_identity_profile_checkpoints_two_distinct_denials(self):
    seen = []
    checkpoints = []
    def attempt(number):
      result, _, _, proofs, *_ = self._run_missing_identity_probe(provider_http=401, log_mode='witness')
      seen.append((number, proofs[0]['identity_id']))
      return result
    snapshot = live.run_provider_missing_identity_profile(attempt, checkpoints.append)
    self.assertEqual([1, 2], [number for number, _ in seen])
    self.assertEqual(2, len({identity for _, identity in seen}))
    self.assertEqual(2, len(checkpoints))
    attempts = snapshot['registry_matrix']['missing_identity']['attempts']
    self.assertEqual(['provider_not_found'] * 2, [item['outcome'] for item in attempts])
    self.assertEqual([1, 1], [item['provider_identity_not_found_marker_count'] for item in attempts])
    self.assertEqual(snapshot, live.sanitize_live_checkpoint(snapshot))

  def test_provider_missing_identity_profile_checkpoints_then_stops_on_unattributed_denial(self):
    seen = []
    checkpoints = []
    def attempt(number):
      seen.append(number)
      return self._run_missing_identity_probe(provider_http=401, log_mode='absent')[0]
    with self.assertRaisesRegex(RuntimeError, 'fresh correlated absence evidence'):
      live.run_provider_missing_identity_profile(attempt, checkpoints.append)
    self.assertEqual([1], seen)
    self.assertEqual(1, len(checkpoints))
    self.assertEqual('provider_denied_unclassified',
        checkpoints[0]['registry_matrix']['missing_identity']['attempts'][0]['outcome'])

  def test_registry_proof_probe_uses_same_correlated_missing_identity_observer(self):
    result, *_ = self._run_missing_identity_probe(provider_http=401, log_mode='witness', probe='registry')
    self.assertEqual('provider_not_found', result['provider_resolution_outcome'])
    self.assertTrue(result['provider_identity_not_found_observed'])
    self.assertTrue(result['no_authorization_code'])
    self.assertEqual('provider_not_found', live.classify_registry_matrix_attempt(
        result['cli_resolution'], result['direct_provider_http'], status_pending=result['status_pending'],
        exact_readback=False, provider_evidence=result))

  def test_registry_proof_probe_rejects_sensitive_headers_and_duplicate_locations(self):
    duplicate_locations = Message()
    duplicate_locations.add_header('Location', '/ordinary-one')
    duplicate_locations.add_header('Location', '/ordinary-two')
    unsafe_headers = (
        {'XAuthorizationCode': 'opaque'},
        {'XCallbackUrl': 'opaque'},
        {'XReceiptId': 'opaque'},
        duplicate_locations,
    )
    for headers in unsafe_headers:
      with self.subTest(headers=headers):
        result, *_ = self._run_missing_identity_probe(
            provider_http=401, log_mode='witness', provider_headers=headers, probe='registry')
        self.assertFalse(result['no_authorization_code'])
        self.assertFalse(result['no_acceptance_or_callback'])
        self.assertNotIn('opaque', repr(result))
    for headers in unsafe_headers:
      with self.subTest(status_headers=headers):
        result, *_ = self._run_missing_identity_probe(
            provider_http=401, log_mode='witness', status_headers=headers, probe='registry')
        self.assertFalse(result['no_authorization_code'])
        self.assertFalse(result['no_acceptance_or_callback'])

  def test_missing_identity_probe_rejects_sensitive_response_even_with_valid_absence_witness(self):
    duplicate_locations = Message()
    duplicate_locations.add_header('Location', '/ordinary-one')
    duplicate_locations.add_header('Location', '/ordinary-two')
    for headers, body in (({}, b'authorization code=redacted'),
        ({}, b'{"message":"receipt=redacted"}'),
        ({}, b'{"status":"accepted","status":"pending"}'),
        ({'Location': '/other?code='}, b''),
        ({'XAuthorizationCode': 'opaque'}, b''),
        ({'XCallbackUrl': 'opaque'}, b''),
        ({'XReceiptId': 'opaque'}, b''), (duplicate_locations, b'')):
      with self.subTest(headers=headers, body=body):
        with self.assertRaisesRegex(RuntimeError, 'no accepted receipt, callback, or code') as raised:
          self._run_missing_identity_probe(provider_http=401, log_mode='witness',
              provider_body=body, provider_headers=headers)
        self.assertNotIn('redacted', str(raised.exception))
    for headers in ({'XAuthorizationCode': 'opaque'}, {'XCallbackUrl': 'opaque'},
        {'XReceiptId': 'opaque'}, duplicate_locations):
      with self.subTest(status_headers=headers):
        with self.assertRaisesRegex(RuntimeError, 'no accepted receipt, callback, or code'):
          self._run_missing_identity_probe(provider_http=401, log_mode='witness',
              status_headers=headers)

  def test_provider_missing_identity_probe_retains_only_correlated_branch_witness(self):
    result, *_ = self._run_missing_identity_probe(provider_http=401, log_mode='witness')
    self.assertEqual('provider_not_found', result['provider_resolution_outcome'])
    self.assertTrue(live.provider_missing_identity_is_qualified(result))
    safe = live.sanitize_live_checkpoint({'missing_identity_case': result})
    self.assertTrue(safe['missing_identity_case']['provider_identity_not_found_observed'])
    self.assertEqual(1, safe['missing_identity_case']['provider_identity_not_found_marker_count'])
    self.assertNotIn('test-handle', json.dumps(safe))

  def test_provider_missing_identity_probe_does_not_attribute_unwitnessed_401(self):
    result, *_ = self._run_missing_identity_probe(provider_http=401, log_mode='absent')
    self.assertEqual('provider_denied_unclassified', result['provider_resolution_outcome'])
    self.assertFalse(live.provider_missing_identity_is_qualified(result))

  def test_provider_missing_identity_witness_cannot_relabel_503(self):
    result, *_ = self._run_missing_identity_probe(provider_http=503, log_mode='witness')
    self.assertEqual('unavailable', result['provider_resolution_outcome'])
    self.assertFalse(live.provider_missing_identity_is_qualified(result))

  def test_identity_lookup_witness_requires_fresh_single_exact_request_record(self):
    request = 'ab' * 16
    marker = f'Wallet Identity lookup completed (request={request}, outcome=not_found)'
    valid = live.new_identity_lookup_log_evidence(['baseline'], ['baseline', marker], request)
    self.assertTrue(valid['provider_identity_not_found_observed'])
    self.assertEqual('provider_not_found', live.classify_provider_identity_outcome(401, valid))
    for before, after, expected in (
        (None, [marker], request), (['baseline'], None, request),
        (['before'], [marker], request), (['baseline', marker], ['baseline', marker], request),
        (['baseline'], ['baseline', marker.replace(request, 'cd' * 16)], request),
        (['baseline'], ['baseline', marker, marker], request),
        (['baseline'], ['baseline', marker + ' private=value'], request),
        (['baseline'], ['baseline', marker.replace('not_found', 'unknown')], request),
        (['baseline'], ['baseline', marker], 'invalid correlation token'),
        (['baseline'], ['baseline', marker, f'Wallet Identity resolver unavailable (request={request}, IdentityResolutionException)'], request),
        (['baseline'], ['baseline'] * 121, request),
    ):
      with self.subTest(before=before, after=after):
        evidence = live.new_identity_lookup_log_evidence(before, after, expected)
        self.assertFalse(evidence['provider_identity_not_found_observed'])
        self.assertEqual('provider_denied_unclassified', live.classify_provider_identity_outcome(401, evidence))
        self.assertNotIn(request, json.dumps(evidence))
        self.assertNotIn('private=value', json.dumps(evidence))

  def test_missing_identity_attribution_checkpoint_rejects_unknown_and_sensitive_fields(self):
    fields = {'provider_resolution_outcome': 'provider_not_found',
        'provider_identity_log_read': True, 'provider_identity_not_found_observed': True,
        'provider_identity_not_found_marker_count': 1}
    candidate = {'missing_identity_case': {**fields, 'request_id': 'private', 'raw_logs': 'private'}}
    self.assertEqual({'missing_identity_case': fields}, live.sanitize_live_checkpoint(candidate))
    for bad_count in (True, -1, 11, '1'):
      safe = live.sanitize_live_checkpoint({'missing_identity_case': {
          **fields, 'provider_identity_not_found_marker_count': bad_count}})
      self.assertNotIn('provider_identity_not_found_marker_count', safe['missing_identity_case'])

  def test_provider_missing_identity_cannot_qualify_without_correlated_provider_evidence(self):
    evidence = {
        'cli_resolution': 'not_found', 'cli_output_categories': ['registry_miss', 'not_found'],
        'direct_provider_http': 401, 'provider_resolution_outcome': 'provider_denied_unclassified',
        'status_pending': True, 'redirects_safe': True, 'no_acceptance_or_callback': True,
    }
    self.assertFalse(live.provider_missing_identity_is_qualified(evidence))

  def test_provider_not_found_diagnostic_requires_exact_clean_miss_and_denial(self):
    accepted = {
        'cli_resolution': 'not_found',
        'cli_output_categories': ['registry_miss', 'not_found'],
        'direct_provider_http': 401,
        'provider_resolution_outcome': 'provider_not_found',
        'provider_identity_not_found_observed': True,
        'provider_identity_log_read': True,
        'provider_identity_not_found_marker_count': 1,
        'status_pending': True,
        'redirects_safe': True,
        'no_acceptance_or_callback': True,
    }
    self.assertTrue(live.provider_missing_identity_is_qualified(accepted))
    for change in (
        {'cli_resolution': 'unavailable'},
        {'cli_output_categories': ['dial_warning', 'registry_miss', 'not_found']},
        {'direct_provider_http': 503},
        {'status_pending': False},
        {'redirects_safe': False},
        {'no_acceptance_or_callback': False},
    ):
      with self.subTest(change=change):
        self.assertFalse(live.provider_missing_identity_is_qualified({**accepted, **change}))

  def test_live_e2e_probe_reports_registry_and_account_misses_distinctly(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def missing_identity_flow(')
    end = source.index('\ndef main(', start)
    body = source[start:end]
    self.assertIn("['get', '--identifier', missing_id", body)
    self.assertIn("'identity_id': missing_id, 'signature': b64url(signature.stdout)", body)
    self.assertIn("'direct_provider_http': provider_http", body)
    self.assertIn('provider_resolution_outcome = classify_provider_identity_outcome(provider_http, provider_evidence)', body)
    self.assertIn('provider_headers, provider_body, terminal_http_status=provider_http)', body)
    self.assertIn("', status_evidence=' + status_acceptance_category", body)
    self.assertIn("return 'provider_denied_unclassified'", source)

  def test_partial_failure_evidence_includes_only_bounded_resolver_categories(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('@contextmanager\ndef report_partial_evidence_on_failure(')
    end = source.index('\n\ndef checkpoint_signup_stage(', start)
    emitted = []
    namespace = {'contextmanager': __import__('contextlib').contextmanager,
        'sanitize_live_checkpoint': sanitize_live_checkpoint,
        'json': __import__('json'), 'print': lambda *args, **kwargs: emitted.append(args),
        'Path': Path, 're': __import__('re'), 'record_resolver_diagnostics': lambda _container: [],
        'checkpoint': lambda: None, 'result': {}, 'runtime_provenance': {},
        'resolver_tools': 'tools', 'container': 'container'}
    exec(source[start:end], namespace)
    with tempfile.TemporaryDirectory() as directory:
      evidence = Path(directory) / 'receipt.json'
      with self.assertRaises(RuntimeError):
        with namespace['report_partial_evidence_on_failure'](evidence,
            lambda: {'rotated_identity_case': {'stage': 'diagnostic_probe',
                'diagnostic_categories': ['ok:registry_miss', 'invalid']}}):
          raise RuntimeError('do not expose raw failure text')
    text = repr(emitted)
    self.assertIn('diagnostic_categories', text)
    self.assertIn('ok:registry_miss', text)
    self.assertNotIn('do not expose raw failure text', text)

  def test_final_evidence_captures_allowlisted_resolver_categories_before_success_exit(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main = source[source.index('def main():'):]
    capture = "runtime_provenance['diagnostic_categories'] = capture_live_resolver_diagnostics("
    self.assertIn(capture, main)
    self.assertLess(main.index(capture), main.index("print('evidence=', json.dumps"))

  def test_resolver_debug_log_lines_are_sanitized_to_fixed_categories(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def sanitized_resolver_diagnostic_lines(')
    end = source.index('def classify_oidc_action_error(', start)
    namespace = {'run': lambda *args, **kwargs: None, 're': __import__('re')}
    exec(source[start:end], namespace)
    record = '[WALLET-RESOLVER-DIAG] exit=0, reason=registry_miss|dial_warning|unknown, lines=64, capped=true, dht=get_value:1/1/0/0/0|remote_identity:2/2/0/0/0'
    prefixed_record = ('2026-10-17 11:23:45,678 DEBUG [org.decentwallet.keycloak.wallet.ProcessIdentityResolver] '
        '(executor-thread-2) [WALLET-RESOLVER-DIAG] exit=3, reason=history_unavailable, lines=1, capped=false, dht=none')
    secrets = '[WALLET-RESOLVER-DIAG] exit=0, reason=registry_miss|mailto:private@example.invalid, lines=4, capped=false, dht=none'
    self.assertEqual(['ok:registry_miss|dial_warning|unknown'],
        namespace['sanitized_resolver_diagnostic_lines'](record))
    nonzero_record = ('2026-10-17 11:23:45,678 DEBUG [org.decentwallet.keycloak.wallet.ProcessIdentityResolver] '
        '(executor-thread-2) [WALLET-RESOLVER-DIAG] exit=7, reason=nonzero_exit, lines=0, capped=false, dht=none')
    process_start_record = ('2026-10-17 11:23:45,678 DEBUG [org.decentwallet.keycloak.wallet.ProcessIdentityResolver] '
        '(executor-thread-2) [WALLET-RESOLVER-DIAG] exit=-1, reason=process_start, lines=0, capped=false, dht=none')
    self.assertEqual(['ok:process_start'],
        namespace['sanitized_resolver_diagnostic_lines'](process_start_record))
    failure_records = [
        f'[WALLET-RESOLVER-DIAG] exit=-1, reason=unknown|{category}, lines=1, capped=false, dht=none'
        for category in ('timeout', 'interrupted', 'termination_interrupted', 'output_overflow')]
    self.assertEqual([f'ok:unknown|{category}' for category in
        ('timeout', 'interrupted', 'termination_interrupted', 'output_overflow')],
        [namespace['sanitized_resolver_diagnostic_lines'](record)[0] for record in failure_records])
    checkpoint = {'rotated_identity_case': {'stage': 'diagnostic_probe',
        'diagnostic_categories': ['ok:unknown|timeout', 'ok:unknown|output_overflow']}}
    self.assertEqual(checkpoint, sanitize_live_checkpoint(checkpoint))
    self.assertEqual(['invalid'], namespace['sanitized_resolver_diagnostic_lines'](secrets))

  def test_resolver_debug_log_line_count_and_exit_are_bounded(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def sanitized_resolver_diagnostic_lines(')
    end = source.index('def classify_oidc_action_error(', start)
    namespace = {'run': lambda *args, **kwargs: None, 're': __import__('re')}
    exec(source[start:end], namespace)
    oversized = '[WALLET-RESOLVER-DIAG] exit=999, reason=unknown, lines=65, capped=true, dht=none'
    invalid_negative = '[WALLET-RESOLVER-DIAG] exit=-2, reason=process_start, lines=0, capped=false, dht=none'
    self.assertEqual(['invalid'], namespace['sanitized_resolver_diagnostic_lines'](oversized))
    self.assertEqual(['invalid'], namespace['sanitized_resolver_diagnostic_lines'](invalid_negative))

  def test_classify_and_parse_result_require_complete_exact_identity(self):
    identity = 'mailto:owner@example.invalid'
    identifier_hex = identity.encode('utf-8').hex()
    expected_key = 'ab' * 32
    exact_output = '{\n  "identifier": "' + identity + '",\n  "owner_name_hex": "' + identifier_hex + '",\n  "owner_public_key_hex": "' + expected_key + '",\n  "seq": 2\n}'
    malformed_output = '{\n  "identifier": "' + identity + '",\n  "owner_name_hex": "' + identifier_hex + '",\n  "owner_public_key_hex": "' + expected_key + '",\n  "seq": 2'
    wrong_identifier = exact_output.replace(identity, 'mailto:other@example.invalid')
    wrong_key = exact_output.replace(expected_key, 'cd' * 32)

    self.assertEqual('resolved', classify_identity_lookup(exact_output, 0)[0])
    self.assertIsNotNone(packaged_resolver_readback(exact_output, 0, identity, expected_key))
    self.assertFalse(packaged_resolver_readback(malformed_output, 0, identity, expected_key))
    self.assertFalse(packaged_resolver_readback(wrong_identifier, 0, identity, expected_key))
    self.assertFalse(packaged_resolver_readback(wrong_key, 0, identity, expected_key))

  def test_classifier_and_parser_accept_nested_extension_after_core_members(self):
    identity = 'mailto:owner@example.invalid'
    identifier_hex = identity.encode('utf-8').hex()
    expected_key = 'ab' * 32
    output = ('{\n  "identifier": "' + identity + '",\n  "owner_name_hex": "' + identifier_hex
        + '",\n  "owner_public_key_hex": "' + expected_key + '",\n  "seq": 2,\n  "authorization": {\n    "status": "active"\n  }\n}')

    resolution, categories = classify_identity_lookup(output, 0, identity)
    exact = packaged_resolver_readback(output, 0, identity, expected_key)

    self.assertEqual('resolved', resolution)
    self.assertTrue(exact)
    self.assertTrue(all(category == 'json' for category in categories))

    classification, parse_success, _ = classify_and_parse_result(output, 0, identity, expected_key)
    self.assertEqual('resolved', classification)
    self.assertTrue(parse_success)

    escaped_value = 'active {braces} and "quoted"'
    escaped = output.replace('active', json.dumps(escaped_value)[1:-1])
    parsed = parse_exact_identity_result(escaped, identity)
    self.assertTrue(json_object_is_balanced(escaped))
    self.assertEqual(escaped_value, parsed['authorization']['status'])

  def test_rotation_cli_summary_and_sorted_authorization_are_exact(self):
    identity = 'rotation-parser@example.invalid'
    expected_key = 'ab' * 32
    payload = {
      'identifier': identity, 'owner_name_hex': identity.encode().hex(),
      'owner_public_key_hex': expected_key, 'seq': 2,
      'authorization': {'version': 1, 'operation': 5, 'epoch': 1, 'threshold': 2,
        'signer_set': [{'signer_id': name, 'public_key': key * 32}
          for name, key in [('new', 'ab'), ('old', 'cd'), ('cosigner', 'ef')]],
        'predecessor_state_hash': '12' * 32, 'state_hash': '34' * 32},
    }
    output = json.dumps(payload, indent=2, sort_keys=True)
    summary = 'DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=0 failed=0 timeouts=0 incomplete=0'
    for decorated in (summary + '\n' + output, output + '\n' + summary):
      with self.subTest(summary_before_json=decorated.startswith(summary)):
        resolution, categories = classify_identity_lookup(decorated, 0, identity)
        self.assertEqual('resolved', resolution)
        self.assertTrue(all(category == 'json' for category in categories))
        self.assertEqual(payload, parse_exact_identity_result(decorated, identity))
        self.assertTrue(packaged_resolver_readback(decorated, 0, identity, expected_key))
        self.assertFalse(packaged_resolver_readback(decorated, 1, identity, expected_key))
        self.assertFalse(packaged_resolver_readback(decorated, 0, identity, 'ff' * 32))
        self.assertFalse(packaged_resolver_readback(decorated, 0, 'other@example.invalid', expected_key))

  def test_rotation_summary_cannot_hide_unknown_output_or_lookup_uncertainty(self):
    identity = 'rotation-parser@example.invalid'
    expected_key = 'ab' * 32
    output = json.dumps({'identifier': identity, 'owner_name_hex': identity.encode().hex(),
      'owner_public_key_hex': expected_key, 'seq': 2}, indent=2, sort_keys=True)
    summary = 'DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=0 failed=0 timeouts=0 incomplete=0'
    for prefix in (
      summary + '\n' + summary,
      summary.replace('failed=0', 'failed=1'),
      summary.replace('incomplete=0', 'incomplete=1'),
      summary.replace('timeouts=0', 'timeouts=1'),
      summary.replace('attempts=1', 'attempts=1000'),
      summary.replace('attempts=1', 'attempts=0'),
      summary.replace('empty=0', 'empty=999'),
      summary + '\nunknown transport text',
    ):
      with self.subTest(prefix_kind=prefix.splitlines()[0]):
        decorated = prefix + '\n' + output
        self.assertEqual('unavailable', classify_identity_lookup(decorated, 0, identity)[0])
        self.assertIsNone(parse_exact_identity_result(decorated, identity))
        self.assertFalse(packaged_resolver_readback(decorated, 0, identity, expected_key))
    for trailing in ('\nunknown transport text', '\n{"second": "object"}', '\n]'):
      decorated = summary + '\n' + output + trailing
      self.assertFalse(packaged_resolver_readback(decorated, 0, identity, expected_key))

  def test_classify_identity_lookup_accepts_exact_single_line_json(self):
    identity = 'mailto:single-line@example.invalid'
    identifier_hex = identity.encode('utf-8').hex()
    expected_key = 'ab' * 32
    output = json.dumps({'identifier': identity, 'owner_name_hex': identifier_hex,
        'owner_public_key_hex': expected_key, 'seq': 2}, separators=(',', ':'))

    outcome, _ = classify_identity_lookup(output, 0, identity)
    exact = packaged_resolver_readback(output, 0, identity, expected_key)

    self.assertEqual('resolved', outcome)
    self.assertTrue(exact)

  def test_classify_identity_lookup_accepts_exact_pretty_printed_json(self):
    identity = 'mailto:single-line@example.invalid'
    identifier_hex = identity.encode('utf-8').hex()
    expected_key = 'ab' * 32
    output = json.dumps({'identifier': identity, 'owner_name_hex': identifier_hex,
        'owner_public_key_hex': expected_key, 'seq': 2}, indent=2)

    outcome, _ = classify_identity_lookup(output, 0, identity)
    exact = packaged_resolver_readback(output, 0, identity, expected_key)

    self.assertEqual('resolved', outcome)
    self.assertTrue(exact)

  def test_exact_success_with_unrecognized_trailing_output_is_unavailable(self):
    identity = 'mailto:owner@example.invalid'
    identifier_hex = identity.encode('utf-8').hex()
    expected_key = 'ab' * 32
    output = '{\n  "identifier": "' + identity + '",\n  "owner_name_hex": "' + identifier_hex + '",\n  "owner_public_key_hex": "' + expected_key + '",\n  "seq": 2\n}\nunrecognized transport text'
    resolution, categories = classify_identity_lookup(output, 0, identity)
    self.assertEqual('unavailable', resolution)
    self.assertEqual(['json', 'json', 'json', 'json', 'json', 'json', 'other'], categories)

  def test_exact_registry_miss_with_dial_warning_is_unavailable(self):
    identifier = 'mailto:alice@example.org'
    expected_key = '4aa8889aa1e3f193844b32d36e58b50a8817304b9e15d798d460d00bff828a29'
    output = chr(10).join((
        'Failed to open TCP stream: all attempts to connect to /ip4/127.0.0.1/tcp/9000 failed',
        'Value not found for key /decent-registry/identity/' + expected_key,
        'not found',
    ))

    resolution, categories = classify_identity_lookup(output, 1, identifier)

    self.assertEqual('unavailable', resolution)
    self.assertEqual(['dial_warning', 'registry_miss', 'not_found'], categories)

  def test_unavailable_categories_preserve_history_and_traceback_reason(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def parse_dht_lookup_summary_line(')
    end = source.index('def parse_exact_identity_result(', start)
    namespace = {'re': __import__('re')}
    exec(source[start:end], namespace)

    for diagnostic, expected_category in (
        ('history unavailable: predecessor missing', 'history_unavailable'),
        ('Traceback (most recent call last):', 'traceback'),
    ):
      with self.subTest(expected_category=expected_category):
        resolution, categories = namespace['classify_identity_lookup'](diagnostic, 3)
        self.assertEqual('unavailable', resolution)
        self.assertEqual([expected_category], categories)

  def test_handshake_error_keeps_mixed_lookup_unavailable(self):
    output = '\n'.join((
        'Value not found for key /decent-registry/identity/' + 'ab' * 32,
        'failed to upgrade security for peer 12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X: handshake failed when upgrading to secure connection',
        'not found',
    ))

    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def parse_dht_lookup_summary_line(')
    end = source.index('def parse_exact_identity_result(', start)
    namespace = {'re': __import__('re')}
    exec(source[start:end], namespace)
    resolution, categories = namespace['classify_identity_lookup'](output, 1)

    self.assertEqual('unavailable', resolution)
    self.assertEqual(['registry_miss', 'peer_handshake', 'not_found'], categories)

  def test_well_formed_registry_miss_with_handshake_failure_stays_unavailable(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def parse_dht_lookup_summary_line(')
    end = source.index('def parse_exact_identity_result(', start)
    namespace = {'re': __import__('re')}
    exec(source[start:end], namespace)
    output = '\n'.join((
        'Value not found for key /decent-registry/identity/' + 'ab' * 32,
        'failed to upgrade security for peer 12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X: handshake failed when upgrading to secure connection',
        'not found',
    ))
    resolution, categories = namespace['classify_identity_lookup'](output, 1)
    self.assertEqual('unavailable', resolution)
    self.assertEqual(['registry_miss', 'peer_handshake', 'not_found'], categories)

  def test_malformed_or_foreign_namespace_diagnostic_is_not_absence(self):
    outputs = (
        'Value not found for key /decent-registry/identity/not-hex\nnot found',
        'Value not found for key /other-namespace/' + 'ab' * 32 + '\nnot found',
    )

    for output in outputs:
      with self.subTest(output=output.splitlines()[0]):
        resolution, categories = classify_identity_lookup(output, 1)
        self.assertEqual('unavailable', resolution)
        self.assertIn('not_found', categories)


  def test_exact_registry_miss_for_different_identity_key_is_unavailable(self):
    identifier = 'mailto:alice@example.org'
    mismatched_key = 'ab' * 32
    output = chr(10).join((
        'Value not found for key /decent-registry/identity/' + mismatched_key,
        'not found',
    ))

    import wallet_login_live_e2e as probe
    resolution, categories = probe.classify_identity_lookup(output, 1, identifier)

    self.assertEqual('unavailable', resolution)
    self.assertEqual(['registry_miss', 'not_found'], categories)

  def test_exact_requested_identity_registry_miss_is_not_found(self):
    identifier = 'mailto:alice@example.org'
    expected_key = '4aa8889aa1e3f193844b32d36e58b50a8817304b9e15d798d460d00bff828a29'
    output = chr(10).join((
        'DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=1 failed=0 timeouts=0 incomplete=0',
        'DHT_LOOKUP_SUMMARY stage=remote_identity attempts=1 empty=1 failed=0 timeouts=0 incomplete=0',
        'Value not found for key /decent-registry/identity/' + expected_key,
        'not found',
    ))

    resolution, categories = classify_identity_lookup(output, 1, identifier)

    self.assertEqual('not_found', resolution)
    self.assertEqual(['registry_miss', 'not_found'], categories)

  def test_exact_miss_requires_clean_summaries_from_both_lookup_stages(self):
    identifier = 'mailto:alice@example.org'
    expected_key = '4aa8889aa1e3f193844b32d36e58b50a8817304b9e15d798d460d00bff828a29'
    registry_miss = 'Value not found for key /decent-registry/identity/' + expected_key
    clean_remote = 'DHT_LOOKUP_SUMMARY stage=remote_identity attempts=2 empty=2 failed=0 timeouts=0 incomplete=0'
    cases = (
        (chr(10).join((registry_miss, 'not found')), 'missing summaries'),
        (chr(10).join(('DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=1 failed=0 timeouts=0 incomplete=0', registry_miss, 'not found')), 'missing fallback summary'),
        (chr(10).join(('DHT_LOOKUP_SUMMARY stage=get_value attempts=2 empty=1 failed=1 timeouts=0 incomplete=0', clean_remote, registry_miss, 'not found')), 'mixed peer outcome'),
        (chr(10).join(('DHT_LOOKUP_SUMMARY stage=get_value attempts=0 empty=0 failed=0 timeouts=0 incomplete=0', clean_remote, registry_miss, 'not found')), 'zero peer attempts'),
    )
    for output, label in cases:
      with self.subTest(label=label):
        self.assertEqual('unavailable', classify_identity_lookup(output, 1, identifier)[0])

  def test_registry_miss_for_another_identity_key_is_unavailable(self):
    identifier = 'mailto:alice@example.org'
    unrelated_key = 'ab' * 32
    output = '\n'.join((
        'Value not found for key /decent-registry/identity/' + unrelated_key,
        'not found',
    ))

    import wallet_login_live_e2e as probe
    resolution, categories = probe.classify_identity_lookup(output, 1, identifier)

    self.assertEqual('unavailable', resolution)
    self.assertEqual(['registry_miss', 'not_found'], categories)

  def test_registry_misses_must_all_match_the_requested_identity_key(self):
    identifier = 'mailto:alice@example.org'
    expected_key = '4aa8889aa1e3f193844b32d36e58b50a8817304b9e15d798d460d00bff828a29'
    output = 'Value not found for key /decent-registry/identity/' + expected_key + chr(10) + 'Value not found for key /decent-registry/identity/' + 'ab' * 32 + chr(10) + 'not found'

    resolution, categories = classify_identity_lookup(output, 1, identifier)

    self.assertEqual('unavailable', resolution)
    self.assertEqual(['registry_miss', 'registry_miss', 'not_found'], categories)

  def test_non_not_found_exit_is_never_absence(self):
    output = 'Value not found for key /decent-registry/identity/' + 'ab' * 32 + '\nnot found'

    resolution, _ = classify_identity_lookup(output, 0)

    self.assertEqual('unavailable', resolution)


  def test_owned_container_cleanup_accepts_missing_cid_after_exact_absence_readback(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'a' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        if args[:3] == ['podman', 'inspect', '--format']:
          if len([call for call in calls if call[:2] == ['podman', 'inspect']]) <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=1, stdout='Error: no such container: ' + container_id)
        cid_file.unlink()
        return SimpleNamespace(returncode=0, stdout='')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': True, 'retained_cid': False}, status)
      self.assertFalse(cid_file.exists())
      inspections = [call for call in calls if call[:2] == ['podman', 'inspect']]
      self.assertEqual(3, len(inspections))
      self.assertTrue(all(call[-1] == container_id for call in inspections))

  def test_owned_container_cleanup_accepts_nonzero_rm_only_after_exact_absence(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'b' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        if args[:3] == ['podman', 'inspect', '--format']:
          if len([call for call in calls if call[:2] == ['podman', 'inspect']]) <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=1, stdout='Error: no such container: ' + container_id)
        return SimpleNamespace(returncode=125, stdout='opaque rm failure')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': True, 'retained_cid': False}, status)
      self.assertFalse(cid_file.exists())
      self.assertEqual(3, len([call for call in calls if call[:2] == ['podman', 'inspect']]))

  def test_owned_container_cleanup_rejects_absence_for_different_container_id(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'a' * 64
    unrelated_id = 'b' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        if args[:3] == ['podman', 'inspect', '--format']:
          if len([call for call in calls if call[:2] == ['podman', 'inspect']]) <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=1, stdout='Error: no such container: ' + unrelated_id)
        return SimpleNamespace(returncode=0, stdout='')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': False, 'retained_cid': True}, status)
      self.assertTrue(cid_file.exists())
      inspections = [call for call in calls if call[:2] == ['podman', 'inspect']]
      self.assertEqual(3, len(inspections))
      self.assertTrue(all(call[-1] == container_id for call in inspections))

  def test_owned_container_cleanup_rejects_generic_not_found_output(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'c' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        if args[:3] == ['podman', 'inspect', '--format']:
          if len([call for call in calls if call[:2] == ['podman', 'inspect']]) <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=1, stdout='Error: resource not found')
        return SimpleNamespace(returncode=0, stdout='')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': False, 'retained_cid': True}, status)
      self.assertTrue(cid_file.exists())
      self.assertEqual(3, len([call for call in calls if call[:2] == ['podman', 'inspect']]))

  def test_owned_container_cleanup_retains_cid_when_nonzero_rm_postcondition_is_unknown(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'c' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        if args[:3] == ['podman', 'inspect', '--format']:
          if len([call for call in calls if call[:2] == ['podman', 'inspect']]) <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=2, stdout='inspection unavailable')
        return SimpleNamespace(returncode=125, stdout='opaque rm failure')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': False, 'retained_cid': True}, status)
      self.assertTrue(cid_file.exists())
      self.assertEqual(3, len([call for call in calls if call[:2] == ['podman', 'inspect']]))

  def test_owned_container_cleanup_keeps_cid_for_unconfirmed_postcondition(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'd' * 64
    postconditions = (
        SimpleNamespace(returncode=0, stdout=container_id + '\n'),
        SimpleNamespace(returncode=0, stdout=('e' * 64) + '\n'),
        SimpleNamespace(returncode=1, stdout='inspection unavailable'),
        subprocess.TimeoutExpired(['podman', 'inspect'], 15),
    )
    for postcondition in postconditions:
      with self.subTest(postcondition=type(postcondition).__name__), tempfile.TemporaryDirectory() as scratch:
        cid_dir = Path(scratch) / 'run-owned'
        cid_dir.mkdir(mode=0o700)
        cid_file = cid_dir / 'keycloak.cid'
        cid_file.write_text(container_id, encoding='ascii')
        calls = []
        def fake_run(args, **_kwargs):
          calls.append(args)
          if args[:3] == ['podman', 'inspect', '--format']:
            count = len([call for call in calls if call[:2] == ['podman', 'inspect']])
            if count <= 2:
              return SimpleNamespace(returncode=0, stdout=container_id + '\n')
            if isinstance(postcondition, BaseException):
              raise postcondition
            return postcondition
          return SimpleNamespace(returncode=125, stdout='opaque rm failure')

        with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
          status = probe.remove_owned_container(cid_file)

        self.assertEqual({'removed': False, 'retained_cid': True}, status)
        self.assertTrue(cid_file.exists())

  def test_owned_container_cleanup_accepts_absence_after_rm_timeout(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'f' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        if args[:3] == ['podman', 'inspect', '--format']:
          if len([call for call in calls if call[:2] == ['podman', 'inspect']]) <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=1, stdout='Error: no such container: ' + container_id)
        raise subprocess.TimeoutExpired(args, 20)

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': True, 'retained_cid': False}, status)
      self.assertFalse(cid_file.exists())
      self.assertEqual(3, len([call for call in calls if call[:2] == ['podman', 'inspect']]))

  def test_owned_container_cleanup_removes_only_verified_full_cid(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'a' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      inspect_count = 0
      def fake_run(args, **_kwargs):
        nonlocal inspect_count
        calls.append(args)
        if args[:3] == ['podman', 'inspect', '--format']:
          inspect_count += 1
          if inspect_count <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=1, stdout='', stderr='Error: no such container: ' + container_id)
        return SimpleNamespace(returncode=0, stdout='')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': True, 'retained_cid': False}, status)
      self.assertFalse(cid_file.exists())
      self.assertEqual([['podman', 'rm', '--force', container_id]],
          [call for call in calls if call[:2] == ['podman', 'rm']])

  def test_owned_container_cleanup_accepts_podman_removed_cid_file(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'd' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      inspect_count = 0
      def fake_run(args, **_kwargs):
        nonlocal inspect_count
        if args[:3] == ['podman', 'inspect', '--format']:
          inspect_count += 1
          if inspect_count <= 2:
            return SimpleNamespace(returncode=0, stdout=container_id + '\n')
          return SimpleNamespace(returncode=1, stdout='', stderr='Error: no such object: "' + container_id + '"')
        cid_file.unlink(missing_ok=True)
        return SimpleNamespace(returncode=0, stdout='')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': True, 'retained_cid': False}, status)
      self.assertFalse(cid_file.exists())

  def test_owned_container_cleanup_refuses_inspect_id_mismatch(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    container_id = 'b' * 64
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text(container_id, encoding='ascii')
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=('c' * 64) + '\n')

      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        status = probe.remove_owned_container(cid_file)

      self.assertEqual({'removed': False, 'retained_cid': True}, status)
      self.assertTrue(cid_file.exists())
      self.assertFalse(any(call[:2] == ['podman', 'rm'] for call in calls), calls)

  def test_main_does_not_remove_named_containers_when_startup_fails(self):
    from contextlib import ExitStack, redirect_stdout
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    with tempfile.TemporaryDirectory() as scratch:
      output = StringIO()
      calls = []
      def fake_run(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout='')

      with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'default'}), redirect_stdout(output), ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', Path(scratch)))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('a' * 64, 'sha256:' + 'b' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools',
            side_effect=RuntimeError('simulated name collision')))
        stack.enter_context(patch.object(probe, 'run', side_effect=fake_run))
        with self.assertRaisesRegex(RuntimeError, 'simulated name collision'):
          probe.main()
      self.assertFalse(any(args[:2] == ['podman', 'rm'] for args in calls), calls)

  def test_main_surfaces_owned_container_cleanup_failure(self):
    import inspect
    import wallet_login_live_e2e as probe

    main_source = inspect.getsource(probe.main)
    cleanup_source = inspect.getsource(probe.finish_owned_cleanup)
    failure_cleanup_source = inspect.getsource(probe.cleanup_after_failure)
    self.assertIn('finish_owned_cleanup(registry, resolver_tools)', main_source)
    self.assertIn('owned container cleanup incomplete', cleanup_source)
    self.assertIn('interruption_collector', inspect.getsource(probe.cleanup_owned_resources))
    self.assertIn('cleanup_owned_resources(registry_node, resolver_tools, cleanup_interruptions)', failure_cleanup_source)

  def test_cleanup_reports_sanitized_resource_categories_without_container_ids(self):
    from contextlib import redirect_stdout
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'run-owned'
      cid_dir.mkdir(mode=0o700)
      ids = {'keycloak': 'a' * 64, 'registry': 'b' * 64, 'resolver-tools': 'c' * 64}
      for role, container_id in ids.items():
        (cid_dir / (role + '.cid')).write_text(container_id, encoding='ascii')

      def fake_run(args, **_kwargs):
        if args[:3] == ['podman', 'inspect', '--format']:
          return SimpleNamespace(returncode=0, stdout=args[-1] + chr(10))
        if args[:2] == ['podman', 'rm']:
          return SimpleNamespace(returncode=1, stdout='private failure detail')
        raise AssertionError(args)

      output = StringIO()
      with patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(
          probe, 'run', side_effect=fake_run), redirect_stdout(output):
        errors = probe.cleanup_owned_resources(None, None)

      self.assertEqual(3, errors)
      diagnostic = output.getvalue()
      self.assertIn('owned_container_cleanup_categories=', diagnostic)
      self.assertIn('keycloak_removal_unconfirmed', diagnostic)
      self.assertIn('registry_removal_unconfirmed', diagnostic)
      self.assertIn('resolver_tools_removal_unconfirmed', diagnostic)
      self.assertNotIn('private failure detail', diagnostic)
      for container_id in ids.values():
        self.assertNotIn(container_id, diagnostic)
      self.assertEqual(3, len(list(cid_dir.glob('*.cid'))))

  def test_main_records_runtime_provenance_and_fails_closed_when_unavailable(self):
    from contextlib import ExitStack, redirect_stdout
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    facts = {
        'keycloak_version': 'unavailable', 'keycloak_nodes': 'unknown',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'unavailable',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'unavailable',
        'cache_stack_effective': None, 'single_use_object_provider_configured': 'unavailable',
        'single_use_object_provider_path': 'unavailable', 'single_use_object_provider_ids': [],
        'runtime_command_fields_present': [],
        'runtime_qualification_status': 'open_runtime_facts_unavailable',
    }
    with tempfile.TemporaryDirectory() as scratch:
      output = StringIO()
      client = probe.Client()
      client.wallet_container_id = 'a' * 64
      wrapper = SimpleNamespace(name='wrapper')
      with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'default'}), redirect_stdout(output), ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', Path(scratch)))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('a' * 64, 'sha256:' + 'b' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='d' * 64))
        stack.enter_context(patch.object(probe, 'start_registry', return_value=(None, 'bootstrap', 12345)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=12346))
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=('wallet-key', wrapper, 'mailto:owner@example.org')))
        stack.enter_context(patch.object(probe, 'start_keycloak', return_value=client))
        stack.enter_context(patch.object(probe, 'admin_token', return_value='secret-token'))
        stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=facts))
        stack.enter_context(patch.object(probe, 'record_resolver_diagnostics', return_value=[]))
        stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=0))
        with self.assertRaisesRegex(RuntimeError,
            'pinned Keycloak version and single-node baseline verified'):
          probe.main()

      evidence = output.getvalue()
      self.assertIn('open_runtime_facts_unavailable', evidence)
      self.assertIn('database_mode_configured', evidence)
      self.assertNotIn('secret-token', evidence)

  def test_show_config_parser_accepts_keycloak_source_suffix_and_fails_closed_on_duplicates(self):
    import wallet_login_live_e2e as probe
    facts = probe.parse_keycloak_show_config(
        'kc.db = dev-file (PersistedConfigSource)\n'
        'kc.cache = local (SysPropConfigSource)\n'
        'kc.cache-stack = jdbc-ping (ConfigSource)\n'
        'kc.db = postgres (EnvVarConfigSource)\n'
        'kc.hostname = idp.example (SysPropConfigSource)\n'
        'kc.cache=unsafe value (sensitive-source)\n')
    self.assertEqual({'cache_mode_effective': 'local', 'cache_stack_effective': 'jdbc-ping'}, facts)
    self.assertNotIn('PersistedConfigSource', json.dumps(facts))
    self.assertNotIn('idp.example', json.dumps(facts))
    self.assertEqual({}, probe.parse_keycloak_show_config(
        'kc.spi-single-use-object--provider-default = infinispan\n'
        'kc.spi-single-use-object--provider-default = jpa\n'))

  def test_runtime_show_config_does_not_parse_provider_value_when_keycloak_masks_it(self):
    import wallet_login_live_e2e as probe
    output = ('kc.db = dev-file (Persisted)\n'
        'kc.cache = local (Persisted)\n'
        'kc.spi-single-use-object--provider-default = ******* (Persisted)\n')
    self.assertEqual({'database_mode_effective': 'dev-file', 'cache_mode_effective': 'local'},
        probe.parse_keycloak_show_config(output))

  def test_duplicate_unmasked_provider_values_do_not_pass_show_config_parser(self):
    import wallet_login_live_e2e as probe
    self.assertEqual({}, probe.parse_keycloak_show_config(
        'kc.spi-single-use-object--provider-default = infinispan\n'
        'kc.spi-single-use-object--provider-default = jpa\n'))

  def test_show_config_unmasked_provider_is_accepted_only_when_serverinfo_advertises_it(self):
    import wallet_login_live_e2e as probe
    from types import SimpleNamespace
    from unittest.mock import patch

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'},
            'providers': {'single-use-object': {'providers': {
                'infinispan': {'order': 0, 'operationalInfo': {}}}}}}).encode())

    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout='a' * 64 + '|["start-dev","--db=dev-file","--cache=local"]\n'),
        SimpleNamespace(returncode=0, stdout='kc.db = dev-file (Persisted)\n'
            'kc.cache = local (Persisted)\n'
            'kc.spi-single-use-object--provider-default = infinispan (Persisted)\n'),
        SimpleNamespace(returncode=0, stdout='Infinispan configuration:\n<local-cache name="sessions"/>')]):
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', 'a' * 64)
    self.assertEqual('infinispan', facts['single_use_object_provider_configured'])
    self.assertEqual('show_config_fields_complete', facts['keycloak_config_read_status'])

  def test_show_config_provider_not_advertised_is_unavailable(self):
    import wallet_login_live_e2e as probe
    from types import SimpleNamespace
    from unittest.mock import patch

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'},
            'providers': {'single-use-object': {'providers': {
                'jpa': {'order': 0, 'operationalInfo': {}}}}}}).encode())

    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout='a' * 64 + '|["start-dev","--db=dev-file","--cache=local"]\n'),
        SimpleNamespace(returncode=0, stdout='kc.db = dev-file (Persisted)\n'
            'kc.cache = local (Persisted)\n'
            'kc.spi-single-use-object--provider-default = infinispan (Persisted)\n'),
        SimpleNamespace(returncode=0, stdout='Infinispan configuration:\n<local-cache name="sessions"/>')]):
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', 'a' * 64)
    self.assertEqual('unavailable', facts['single_use_object_provider_configured'])
    self.assertEqual('show_config_fields_missing', facts['keycloak_config_read_status'])

  def test_account_denial_runtime_provider_facts_are_sanitized_into_top_level_runtime(self):
    import wallet_login_live_e2e as probe
    facts = {'resolver_runtime': {'runtime_qualification_status': 'open_runtime_facts_unavailable'}}
    facts['ambiguous_account_case'] = {
        'single_use_object_provider_path': 'infinispan',
        'single_use_object_provider_evidence': 'request_correlated_consumed_transaction',
        'runtime_qualification_status': 'runtime_facts_verified',
        'request_id': 'private-request', 'raw_logs': 'private-log'}
    safe = probe.sanitize_live_checkpoint(facts)
    runtime = safe['resolver_runtime']
    self.assertEqual('infinispan', runtime['single_use_object_provider_path'])
    self.assertEqual('request_correlated_consumed_transaction',
        runtime['single_use_object_provider_evidence'])
    self.assertEqual('runtime_facts_verified', runtime['runtime_qualification_status'])
    self.assertNotIn('private-request', json.dumps(safe))
    self.assertNotIn('private-log', json.dumps(safe))

  def test_fresh_provider_log_window_classifies_only_the_exact_consumed_transaction(self):
    request_id = 'a' * 32
    line = ('INFO [org.decentwallet.keycloak.wallet.WalletLoginTransportHandler] '
        '(executor-thread-1) Wallet proof transaction consumed '
        f'(request={request_id}, provider=infinispan)')
    before = ['startup log']
    after = ['startup log', line]
    fresh = live.fresh_log_window_lines(before, after)
    self.assertEqual([line], fresh)
    self.assertIsNotNone(fresh)
    witness = live.classify_success_provider_witness('\n'.join(fresh or []), request_id)
    self.assertEqual({'status': 'observed', 'provider_id': 'infinispan'}, witness)
    self.assertIsNone(live.sanitize_success_provider_witness(line, 'b' * 32))

  def test_top_level_runtime_gate_accepts_selected_provider_witness_when_show_config_masks_it(self):
    import wallet_login_live_e2e as probe
    candidate = {'resolver_runtime': {
        'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
        'cache_stack_effective': None, 'keycloak_config_read_status': 'show_config_fields_missing',
        'single_use_object_provider_configured': 'unavailable',
        'single_use_object_provider_ids': ['infinispan'],
        'single_use_object_provider_path': 'infinispan',
        'single_use_object_provider_evidence': 'request_correlated_consumed_transaction',
        'runtime_qualification_status': 'open_runtime_facts_unavailable'}}
    safe = probe.sanitize_live_checkpoint(candidate)
    self.assertEqual('runtime_facts_verified', safe['resolver_runtime']['runtime_qualification_status'])
    self.assertEqual('show_config_fields_missing', safe['resolver_runtime']['keycloak_config_read_status'])

  def test_runtime_cache_mode_requires_unambiguous_applied_infinispan_configuration(self):
    import wallet_login_live_e2e as probe
    prefix = 'INFO boot\nDEBUG Infinispan configuration:\n'
    self.assertEqual('local', probe.parse_infinispan_runtime_cache_mode(
        prefix + '<local-cache name="sessions"/><local-cache name="realms"/>'))
    self.assertIsNone(probe.parse_infinispan_runtime_cache_mode(
        prefix + '<local-cache name="sessions"/><distributed-cache name="sessions"/>'))
    self.assertIsNone(probe.parse_infinispan_runtime_cache_mode(
        prefix + '<local-cache name="sessions"/>\nInfinispan configuration: <local-cache/>'))
    self.assertIsNone(probe.parse_infinispan_runtime_cache_mode(
        '<local-cache name="sessions"/>'))

  def test_request_correlated_store_outcome_rejects_duplicates_malformed_and_unknown(self):
    import wallet_login_live_e2e as probe
    prefix = ('INFO [org.decentwallet.keycloak.wallet.WalletLoginTransportHandler] '
        '(executor-thread-1) ')
    valid = prefix + 'Wallet proof transaction consumed (request=' + 'a' * 32 + ', provider=infinispan)'
    self.assertEqual({'request_id': 'a' * 32, 'provider_id': 'infinispan'},
        probe.parse_request_correlated_store_outcome(valid))
    for text in (None, '', valid + '\n' + valid,
        valid + '\n' + prefix + 'Wallet proof transaction consumed malformed',
        valid.replace('provider=infinispan', 'provider=unknown-private-value'),
        valid.replace('a' * 32, 'PRIVATE-ID'),
        valid.replace('WalletLoginTransportHandler', 'DifferentLogger'),
        valid + ' private-value'):
      with self.subTest(text=text):
        self.assertIsNone(probe.parse_request_correlated_store_outcome(text))

  def test_runtime_provenance_profile_starts_only_one_keycloak_and_no_wallet_flow(self):
    from contextlib import ExitStack, redirect_stdout
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    facts = {'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_effective': 'dev-file', 'cache_mode_effective': 'local',
        'single_use_object_provider_path': 'infinispan',
        'single_use_object_provider_ids': ['infinispan'],
        'single_use_object_provider_evidence': 'request_correlated_production_acceptance',
        'runtime_qualification_status': 'runtime_facts_verified'}
    output = StringIO()
    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
      stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': 'runtime-provenance'}))
      stack.enter_context(patch.object(probe, 'SCRATCH', Path(scratch)))
      stack.enter_context(redirect_stdout(output))
      stack.enter_context(patch.object(probe, 'resolve_immutable_image',
          return_value=('a' * 64, 'sha256:' + 'b' * 64)))
      stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
      start = stack.enter_context(patch.object(probe, 'start_keycloak',
          return_value=SimpleNamespace(wallet_container_id='c' * 64)))
      stack.enter_context(patch.object(probe, 'admin_token', return_value='private-token'))
      stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=facts))
      cleanup = stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=0))
      forbidden = [stack.enter_context(patch.object(probe, name)) for name in
          ('start_registry', 'start_resolver_tools', 'write_identity', 'configure_realm', 'auth_flow')]
      probe.main()
      start.assert_called_once()
      cleanup.assert_called_once()
      for mocked in forbidden:
        mocked.assert_not_called()
    self.assertIn('runtime-provenance-evidence=', output.getvalue())
    self.assertIn('runtime_facts_verified', output.getvalue())
    self.assertNotIn('private-token', output.getvalue())

  def test_runtime_provenance_profile_preserves_unqualified_evidence_on_failure(self):
    from contextlib import ExitStack, redirect_stdout
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    output = StringIO()
    facts = {'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'single_use_object_provider_path': 'unavailable',
        'runtime_qualification_status': 'open_runtime_facts_unavailable'}
    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
      stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': 'runtime-provenance'}))
      stack.enter_context(patch.object(probe, 'SCRATCH', Path(scratch)))
      stack.enter_context(redirect_stdout(output))
      stack.enter_context(patch.object(probe, 'resolve_immutable_image',
          return_value=('a' * 64, 'sha256:' + 'b' * 64)))
      stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
      stack.enter_context(patch.object(probe, 'start_keycloak',
          return_value=SimpleNamespace(wallet_container_id='c' * 64)))
      stack.enter_context(patch.object(probe, 'admin_token', return_value='private-token'))
      stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=facts))
      cleanup = stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=0))
      with self.assertRaisesRegex(RuntimeError, 'runtime provenance verified'):
        probe.main()
      cleanup.assert_called_once()
    line = next(line for line in output.getvalue().splitlines() if line.startswith('partial_evidence='))
    evidence = json.loads(line.partition('=')[2])
    self.assertEqual('runtime_read', evidence['resolver_runtime']['provenance_probe_stage'])
    self.assertEqual('open_runtime_facts_unavailable', evidence['resolver_runtime']['runtime_qualification_status'])
    self.assertNotIn('private-token', output.getvalue())

  def test_runtime_provenance_profile_does_not_lose_facts_on_cleanup_failure(self):
    from contextlib import ExitStack, redirect_stdout
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe
    facts = {'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_effective': 'dev-file', 'cache_mode_effective': 'local',
        'single_use_object_provider_path': 'infinispan',
        'single_use_object_provider_ids': ['infinispan'],
        'runtime_qualification_status': 'runtime_facts_verified'}
    output = StringIO()
    with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
      stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': 'runtime-provenance'}))
      stack.enter_context(patch.object(probe, 'SCRATCH', Path(scratch)))
      stack.enter_context(redirect_stdout(output))
      stack.enter_context(patch.object(probe, 'resolve_immutable_image',
          return_value=('a' * 64, 'sha256:' + 'b' * 64)))
      stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
      stack.enter_context(patch.object(probe, 'start_keycloak',
          return_value=SimpleNamespace(wallet_container_id='c' * 64)))
      stack.enter_context(patch.object(probe, 'admin_token', return_value='private-token'))
      stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=facts))
      cleanup = stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=1))
      with self.assertRaisesRegex(RuntimeError, 'owned container cleanup incomplete'):
        probe.main()
      cleanup.assert_called_once()
    self.assertNotIn('runtime-provenance-evidence=', output.getvalue())
    line = next(line for line in output.getvalue().splitlines() if line.startswith('partial_evidence='))
    self.assertEqual('cleanup', json.loads(line.partition('=')[2])['resolver_runtime']['provenance_probe_stage'])

  def test_runtime_provenance_uses_request_correlated_acceptance_not_masked_config(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'},
            'providers': {'single-use-object': {'providers': {
                'infinispan': {'order': 0, 'operationalInfo': {}}}}}}).encode())

    log = ('INFO [org.decentwallet.keycloak.wallet.WalletLoginTransportHandler] '
        '(executor-thread-1) Wallet proof transaction consumed (request=' + 'a' * 32
        + ', provider=infinispan)\n'
        'Infinispan configuration:\n<local-cache name="sessions"/>')
    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout='a' * 64 + '|["start-dev","--db=dev-file","--cache=local"]\n'),
        SimpleNamespace(returncode=0, stdout='kc.db = dev-file (Persisted)\n'
            'kc.cache = local (Persisted)\n'
            'kc.spi-single-use-object--provider-default = ******* (Persisted)\n'),
        SimpleNamespace(returncode=0, stdout=log, stderr='')]):
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', 'a' * 64)
    self.assertEqual('infinispan', facts['single_use_object_provider_path'])
    self.assertEqual('request_correlated_consumed_transaction', facts['single_use_object_provider_evidence'])
    self.assertEqual('unavailable', facts['single_use_object_provider_configured'])
    self.assertEqual('show_config_fields_missing', facts['keycloak_config_read_status'])
    self.assertTrue(probe.runtime_qualification_is_verified(facts))
    safe = probe.sanitize_live_checkpoint({'resolver_runtime': facts})['resolver_runtime']
    self.assertEqual('request_correlated_consumed_transaction', safe['single_use_object_provider_evidence'])
    self.assertNotIn('opaque-token', json.dumps(safe))
    self.assertNotIn('WalletLoginTransportHandler', json.dumps(safe))

  def test_runtime_provenance_reads_allowlisted_config_but_does_not_infer_selected_provider(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'},
            'providers': {'single-use-object': {'providers': {
                'infinispan': {'order': 0, 'operationalInfo': {}},
                'jpa': {'order': 1, 'operationalInfo': {}}}}}}).encode())

    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout='a' * 64 + '|["start-dev","--db=dev-file","--cache=local","--spi-single-use-object--provider-default=infinispan"]\n'),
        SimpleNamespace(returncode=0, stdout=(
            'kc.db = dev-file (Persisted)\n'
            'kc.cache = local (Persisted)\n'
            'kc.spi-single-use-object--provider-default = ******* (Persisted)\n')),
        SimpleNamespace(returncode=0, stdout='Infinispan configuration:\n<local-cache name="sessions"/>')]) as mocked_run:
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', 'a' * 64)
    self.assertEqual(3, mocked_run.call_count)
    self.assertEqual(['podman', 'inspect', '--format', '{{.Id}}|{{json .Config.Cmd}}', 'a' * 64], mocked_run.call_args_list[0].args[0])
    self.assertEqual(['podman', 'exec', 'a' * 64, '/opt/keycloak/bin/kc.sh', 'show-config',
        '--db=dev-file', '--cache=local', '--spi-single-use-object--provider-default=infinispan'],
        mocked_run.call_args_list[1].args[0])
    self.assertEqual(['podman', 'logs', '--tail', '300', 'a' * 64], mocked_run.call_args_list[2].args[0])
    self.assertEqual({'timeout': 8, 'max_bytes': 262144}, mocked_run.call_args_list[2].kwargs)
    self.assertEqual('26.8.0', facts['keycloak_version'])
    self.assertEqual('one', facts['keycloak_nodes'])
    self.assertEqual('dev-file', facts['database_mode_effective'])
    self.assertEqual('local', facts['cache_mode_effective'])
    self.assertEqual('infinispan_configuration_log', facts['cache_mode_effective_evidence'])
    self.assertEqual(['cache_mode_configured', 'database_mode_configured',
        'single_use_object_provider_configured'],
        facts['runtime_command_fields_present'])
    self.assertEqual(['infinispan', 'jpa'], facts['single_use_object_provider_ids'])
    self.assertEqual('unavailable', facts['single_use_object_provider_path'])
    self.assertEqual('show_config_fields_missing', facts['keycloak_config_read_status'])
    self.assertEqual(['cache_mode_effective', 'database_mode_effective'],
        facts['keycloak_config_fields_present'])
    self.assertEqual('open_runtime_facts_unavailable', facts['runtime_qualification_status'])
    rendered = json.dumps(probe.sanitize_live_checkpoint({'resolver_runtime': facts}))
    self.assertNotIn('opaque-token', rendered)
    self.assertNotIn('PersistedConfigSource', rendered)

  def test_runtime_provenance_reports_nonzero_show_config_without_raw_output(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'},
            'providers': {'single-use-object': {'providers': {
                'infinispan': {'order': 0, 'operationalInfo': {}}}}}}).encode())

    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout='a' * 64 + '|["start-dev","--db=dev-file","--cache=local","--spi-single-use-object--provider-default=infinispan"]' + chr(10)),
        SimpleNamespace(returncode=17, stdout='private show-config output'),
        SimpleNamespace(returncode=0, stdout='')]):
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', 'a' * 64)

    self.assertEqual('show_config_nonzero', facts.get('keycloak_config_read_status'))
    self.assertEqual([], facts.get('keycloak_config_fields_present'))
    self.assertNotIn('private show-config output', json.dumps(facts))
    self.assertEqual('dev-file', facts['database_mode_configured'])
    self.assertEqual('local', facts['cache_mode_configured'])
    self.assertEqual('unavailable', facts['database_mode_effective'])
    self.assertEqual('unavailable', facts['cache_mode_effective'])
    self.assertEqual(['cache_mode_configured', 'database_mode_configured',
        'single_use_object_provider_configured'],
        facts['runtime_command_fields_present'])

  def test_runtime_provenance_reports_show_config_timeout(self):
    import subprocess
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'}}).encode())

    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout='a' * 64 + '|["start-dev","--db=dev-file","--cache=local","--spi-single-use-object--provider-default=infinispan"]' + chr(10)),
        subprocess.TimeoutExpired('show-config', 8),
        SimpleNamespace(returncode=0, stdout='')]):
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', 'a' * 64)

    self.assertEqual('show_config_timeout', facts.get('keycloak_config_read_status'))
    self.assertEqual([], facts.get('keycloak_config_fields_present'))

  def test_runtime_qualification_requires_selected_provider_to_be_available(self):
    import wallet_login_live_e2e as probe
    facts = {
        'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
        'single_use_object_provider_path': 'jpa',
        'single_use_object_provider_ids': ['infinispan'],
    }
    self.assertFalse(probe.runtime_qualification_is_verified(facts))

  def test_runtime_qualification_requires_build_selected_infinispan_provider(self):
    import wallet_login_live_e2e as probe
    facts = {
        'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
        'single_use_object_provider_path': 'jpa',
        'single_use_object_provider_ids': ['infinispan', 'jpa', 'remote'],
    }
    self.assertFalse(probe.runtime_qualification_is_verified(facts))

  def test_runtime_provenance_rejects_container_id_inspect_mismatch(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'},
            'providers': {'single-use-object': {'providers': {
                'infinispan': {'order': 0, 'operationalInfo': {}}}}}}).encode())

    with patch.object(probe, 'run', return_value=SimpleNamespace(
        returncode=0, stdout='b' * 64 + '|["start-dev","--db=dev-file","--cache=local","--spi-single-use-object--provider-default=infinispan"]\\n')) as mocked_run:
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', 'a' * 64)
    mocked_run.assert_called_once_with(
        ['podman', 'inspect', '--format', '{{.Id}}|{{json .Config.Cmd}}', 'a' * 64], timeout=8)
    self.assertEqual('unknown', facts['keycloak_nodes'])
    self.assertEqual('container_id_unverified', facts['keycloak_config_read_status'])
    self.assertEqual('unavailable', facts['database_mode_effective'])
    self.assertEqual('open_runtime_facts_unavailable', facts['runtime_qualification_status'])

  def test_runtime_provenance_keeps_command_inputs_separate_from_effective_readbacks(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    import json
    import wallet_login_live_e2e as probe

    class InfoClient:
      def request(self, *_args, **_kwargs):
        return (200, {}, json.dumps({'systemInfo': {'version': '26.8.0'},
            'providers': {'single-use-object': {'providers': {
                'infinispan': {'order': 0, 'operationalInfo': {}}}}}}).encode())

    container_id = 'a' * 64
    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout=container_id + '|["start-dev","--db=postgres","--cache=local","--spi-single-use-object--provider-default=infinispan"]\n'),
        SimpleNamespace(returncode=0,
            stdout='kc.db = postgres (classpath application.properties)\n', stderr=''),
        SimpleNamespace(returncode=0, stdout='')]):
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        facts = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', container_id)

    self.assertEqual('postgres', facts['database_mode_configured'])
    self.assertEqual('local', facts['cache_mode_configured'])
    self.assertEqual('postgres', facts['database_mode_effective'])
    self.assertEqual('unavailable', facts['cache_mode_effective'])
    self.assertEqual(['cache_mode_configured', 'database_mode_configured',
        'single_use_object_provider_configured'],
        facts['runtime_command_fields_present'])
    self.assertEqual(['database_mode_effective'], facts['keycloak_config_fields_present'])
    self.assertEqual('show_config_fields_missing', facts['keycloak_config_read_status'])
    self.assertEqual('open_runtime_facts_unavailable', facts['runtime_qualification_status'])

    with patch.object(probe, 'run', side_effect=[
        SimpleNamespace(returncode=0, stdout=container_id + '|["start-dev","--db=postgres","--cache=local","--spi-single-use-object--provider-default=infinispan"]\n'),
        SimpleNamespace(returncode=0, stdout=(
            'kc.db = mysql (classpath application.properties)\n'
            'kc.cache = local (classpath application.properties)\n'), stderr=''),
        SimpleNamespace(returncode=0, stdout='')]):
      with patch.object(probe, '_bounded_command_tail', side_effect=probe.run):
        conflicting = probe.keycloak_runtime_provenance(InfoClient(), 'opaque-token', container_id)
    self.assertEqual('unavailable', conflicting['database_mode_effective'])
    self.assertEqual('local', conflicting['cache_mode_effective'])
    self.assertEqual('show_config_conflict', conflicting['keycloak_config_read_status'])

  def test_runtime_checkpoint_projects_allowlisted_facts_without_raw_or_provider_class_data(self):
    candidate = {'resolver_runtime': {
        'identity_commit': 'a' * 40, 'registry_commit': 'b' * 40,
        'harness_sha256': 'c' * 64, 'runtime_manifest_sha256': 'd' * 64,
        'runtime_lock_sha256': 'e' * 64, 'runtime_patcher_sha256': '1' * 64,
        'pinned_lookup_outcomes_sha256': '2' * 64,
        'rotation_registry_roundtrip_sha256': '3' * 64,
        'issue5_adversarial_cases_sha256': '4' * 64,
        'image_digest': 'sha256:' + 'f' * 64,
        'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
        'cache_mode_effective_evidence': 'infinispan_configuration_log',
        'cache_stack_effective': 'jdbc-ping',
        'single_use_object_provider_configured': 'infinispan',
        'single_use_object_provider_path': 'infinispan',
        'single_use_object_provider_ids': ['infinispan', 'jpa'],
        'runtime_command_fields_present': ['cache_mode_configured', 'database_mode_configured',
        'single_use_object_provider_configured'],
        'keycloak_config_read_status': 'show_config_fields_complete',
        'keycloak_config_fields_present': ['cache_mode_effective',
            'database_mode_effective', 'single_use_object_provider_configured'],
        'runtime_qualification_status': 'runtime_facts_verified',
        'raw_show_config': 'marker-raw-config', 'selected_provider_class': 'marker-class',
        'admin_token': 'marker-token'}}
    projected = sanitize_live_checkpoint(candidate)
    facts = projected['resolver_runtime']
    self.assertEqual('26.8.0', facts.get('keycloak_version'))
    self.assertEqual('one', facts.get('keycloak_nodes'))
    self.assertEqual('jdbc-ping', facts.get('cache_stack_effective'))
    self.assertEqual('infinispan_configuration_log', facts.get('cache_mode_effective_evidence'))
    self.assertEqual(['infinispan', 'jpa'], facts.get('single_use_object_provider_ids'))
    self.assertEqual(['cache_mode_configured', 'database_mode_configured',
        'single_use_object_provider_configured'],
        facts.get('runtime_command_fields_present'))
    self.assertEqual('runtime_facts_verified', facts.get('runtime_qualification_status'))
    for field in ('runtime_patcher_sha256','pinned_lookup_outcomes_sha256',
        'rotation_registry_roundtrip_sha256','issue5_adversarial_cases_sha256'):
      self.assertRegex(facts[field], r'^[0-9a-f]{64}$')
    self.assertEqual('show_config_fields_complete', facts.get('keycloak_config_read_status'))
    self.assertEqual(['cache_mode_effective', 'database_mode_effective',
        'single_use_object_provider_configured'], facts.get('keycloak_config_fields_present'))
    for field in ('runtime_patcher_sha256','pinned_lookup_outcomes_sha256',
        'rotation_registry_roundtrip_sha256','issue5_adversarial_cases_sha256'):
      self.assertRegex(facts[field], r'^[0-9a-f]{64}$')
    rendered = json.dumps(projected)
    self.assertNotIn('marker-raw-config', rendered)
    self.assertNotIn('marker-class', rendered)
    self.assertNotIn('marker-token', rendered)

  def test_rejects_unexpected_issue5_runtime_input_hash_projection(self):
    candidate = {'resolver_runtime': {
        'issue5_runtime_input_hashes': {
            'runtime_patcher': {'file': 'container/patch_resolver_runtime.py', 'sha256': 'a' * 64},
            'pinned_lookup_outcomes': {'file': 'container/pinned_lookup_outcomes.py', 'sha256': 'b' * 64},
            'rotation_helper': {'file': 'container/rotation_registry_roundtrip.py', 'sha256': 'c' * 64},
            'adversarial_fixture': {'file': 'scripts/test_pinned_adversarial_identity_peer.py', 'sha256': 'd' * 64},
            'adversarial_case_constants': {'file': 'scripts/issue5_adversarial_cases.py', 'sha256': 'e' * 64},
        }}}
    expected = candidate['resolver_runtime']['issue5_runtime_input_hashes']
    self.assertEqual(expected, sanitize_live_checkpoint(candidate)['resolver_runtime']['issue5_runtime_input_hashes'])
    for invalid in ({**expected, 'extra': {'file': '/etc/passwd', 'sha256': 'f' * 64}},
        {**expected, 'runtime_patcher': {'file': '/etc/passwd', 'sha256': 'a' * 64}},
        {**expected, 'runtime_patcher': {'file': 'container/patch_resolver_runtime.py', 'sha256': 'secret'}}):
      with self.subTest(invalid=invalid):
        candidate['resolver_runtime']['issue5_runtime_input_hashes'] = invalid
        self.assertNotIn('issue5_runtime_input_hashes',
            sanitize_live_checkpoint(candidate).get('resolver_runtime', {}))

    candidate = {'expiry_case': {
        'stage': 'complete', 'ttl_seconds': 300, 'wait_seconds': 305,
        'login_page_http': 200, 'challenge_get_http': 200,
        'proof_post_http': 404, 'status_http': 404,
        'proof_denied': True, 'status_denied': True,
        'no_accepted_receipt': True, 'no_callback': True,
        'no_authorization_code': True, 'request_correlated_denial': True,
        'response_body_safe': True, 'location_safe': True, 'redirects_safe': True,
        'runtime_qualification_status': 'runtime_facts_verified',
        'single_use_object_provider_path': 'infinispan',
        'transaction_handle': 'handle-marker-secret', 'raw_response': 'response-marker-secret'}}

    projected = sanitize_live_checkpoint(candidate)

    self.assertEqual({'expiry_case': {
        'stage': 'complete', 'ttl_seconds': 300, 'wait_seconds': 305,
        'login_page_http': 200, 'challenge_get_http': 200,
        'proof_post_http': 404, 'status_http': 404,
        'proof_denied': True, 'status_denied': True,
        'no_accepted_receipt': True, 'no_callback': True,
        'no_authorization_code': True, 'request_correlated_denial': True,
        'response_body_safe': True, 'location_safe': True, 'redirects_safe': True,
        'runtime_qualification_status': 'runtime_facts_verified',
        'single_use_object_provider_path': 'infinispan'}}, projected)
    self.assertNotIn('handle-marker-secret', repr(projected))
    self.assertNotIn('response-marker-secret', repr(projected))

  def test_expiry_profile_runs_through_main_to_final_sanitized_checkpoint(self):
    from contextlib import ExitStack, redirect_stdout
    from io import StringIO
    from tempfile import TemporaryDirectory
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    class FakeClient:
      def __init__(self, responses):
        self.responses = iter(responses)
        self.privateClientAdminCredential = None
        self.redirects = []
        self.wallet_container_id = 'a' * 64
        self.calls = []

      def request(self, method, path, data=None, headers=None, timeout=10):
        self.calls.append((method, path))
        return next(self.responses)

    locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/wallet-e2e/'
        'decent-wallet-login/v1/transactions/' + 'h' * 43)
    fresh_locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/wallet-e2e/'
        'decent-wallet-login/v1/transactions/' + 'j' * 43)
    status_url = locator + '/status?client_id=client'
    login_page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const statusUrl = "{status_url}"; const csrfToken = "{"x" * 43}";</script>').encode()
    fresh_login_page = (f'<p id="wallet-locator">{fresh_locator}</p>'
        f'<script>const statusUrl = "{fresh_locator}/status"; const csrfToken = "{"y" * 43}";</script>').encode()
    wallet = FakeClient([
        (200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
            'challenge': 'c' * 43, 'csrf_token': 'z' * 43}).encode()),
        (404, {}, b'{"status":"expired"}'),
        (200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
            'challenge': 'd' * 43, 'csrf_token': 'y' * 43}).encode()),
    ])
    client = FakeClient([
        (200, {}, login_page),
        (404, {}, b'{}'),
        (200, {}, fresh_login_page),
    ])
    stdout = StringIO()
    registry_calls = []
    def start_fake_registry(*_args, **kwargs):
      registry_calls.append(kwargs)
      return 'registry-owned', 'bootstrap-safe', 1234

    with TemporaryDirectory() as scratch, ExitStack() as stack:
      stack.enter_context(patch.dict(os.environ, {'WALLET_IT_PROFILE': 'expiry'}))
      stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
      stack.enter_context(patch.object(probe, 'IMAGE', None))
      stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
      stack.enter_context(patch.object(probe, 'resolve_immutable_image',
          return_value=('a' * 64, 'sha256:' + 'b' * 64)))
      stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={
          'source_commit': 'c' * 40, 'identity_commit': 'd' * 40,
          'registry_commit': 'e' * 40, 'harness_sha256': 'f' * 64,
          'runtime_manifest_sha256': '1' * 64, 'runtime_lock_sha256': '2' * 64}))
      resolver_start = stack.enter_context(patch.object(
          probe, 'start_resolver_tools', return_value='resolver-owned'))
      stack.enter_context(patch.object(probe, 'start_registry', side_effect=start_fake_registry))
      write_identity = stack.enter_context(patch.object(probe, 'write_identity',
          return_value=(Path('/unused/key.pem'), Path('/unused/wrapper'), 'fixture@example.invalid')))
      stack.enter_context(patch.object(probe, 'start_keycloak', return_value=client))
      stack.enter_context(patch.object(probe, 'admin_token', return_value='admin-token'))
      stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value={
          'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
          'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
          'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
          'cache_stack_effective': None,
          'single_use_object_provider_path': 'infinispan',
          'single_use_object_provider_ids': ['infinispan'],
          'runtime_qualification_status': 'runtime_facts_verified'}))
      for name in ('configure_realm', 'enable_keycloak_login_events',
          'provision_identity_attribute', 'stop_registry', 'stop_resolver_tools', 'run'):
        stack.enter_context(patch.object(probe, name))
      stack.enter_context(patch.object(probe, 'Client', return_value=wallet))
      stack.enter_context(patch.object(probe.subprocess, 'run',
          return_value=SimpleNamespace(returncode=0, stdout=b's' * 64)))
      sleep = stack.enter_context(patch.object(probe.time, 'sleep'))
      stack.enter_context(patch.object(probe, '_inspect_cid', return_value='a' * 64))
      stack.enter_context(patch.object(probe, '_expiry_denial_signal', return_value='infinispan'))
      stack.enter_context(redirect_stdout(stdout))
      probe.main()

    sleep.assert_called_once_with(305)
    self.assertEqual(['GET', 'GET', 'GET'], [method for method, _ in client.calls])
    self.assertIn('/protocol/openid-connect/auth?', client.calls[0][1])
    self.assertEqual(status_url, client.calls[1][1])
    self.assertIn('/protocol/openid-connect/auth?', client.calls[2][1])
    self.assertEqual([
        ('GET', locator), ('POST', locator), ('GET', fresh_locator),
    ], wallet.calls)
    self.assertEqual([{'run_seconds': 1200}], registry_calls)
    self.assertEqual(1200, resolver_start.call_args.kwargs['lifetime'])
    write_identity.assert_called_once()
    lines = [line for line in stdout.getvalue().splitlines() if line.startswith('expiry-evidence= ')]
    self.assertEqual(1, len(lines))
    evidence = json.loads(lines[0].split('=', 1)[1])
    self.assertEqual('complete', evidence['expiry_case']['stage'])
    self.assertEqual(300, evidence['expiry_case']['ttl_seconds'])
    self.assertEqual(305, evidence['expiry_case']['wait_seconds'])
    self.assertTrue(evidence['expiry_case']['proof_denied'])
    self.assertTrue(evidence['expiry_case']['status_denied'])
    self.assertTrue(evidence['expiry_case']['no_accepted_receipt'])
    self.assertTrue(evidence['expiry_case']['no_callback'])
    self.assertTrue(evidence['expiry_case']['no_authorization_code'])
    self.assertTrue(evidence['expiry_case']['request_correlated_denial'])
    self.assertEqual(200, evidence['expiry_case']['fresh_login_http'])
    self.assertEqual(200, evidence['expiry_case']['fresh_challenge_http'])
    self.assertTrue(evidence['expiry_case']['fresh_locator_distinct'])
    self.assertTrue(evidence['expiry_case']['fresh_login_transaction_available'])
    self.assertEqual({
        'stage', 'ttl_seconds', 'wait_seconds', 'login_page_http', 'challenge_get_http',
        'proof_post_http', 'status_http', 'proof_denied', 'status_denied', 'no_accepted_receipt',
        'no_authorization_code', 'no_callback', 'request_correlated_denial',
        'response_body_safe', 'location_safe', 'redirects_safe', 'runtime_qualification_status',
        'single_use_object_provider_path', 'fresh_login_http', 'fresh_challenge_http',
        'fresh_locator_distinct', 'fresh_login_transaction_available',
    }, set(evidence['expiry_case']))
    self.assertEqual('sha256:' + 'b' * 64, evidence['resolver_runtime']['image_digest'])

  def test_expiry_evidence_requires_exact_denial_and_runtime_provider(self):
    import wallet_login_live_e2e as probe

    evidence = {
        'stage': 'complete', 'login_page_http': 200, 'challenge_get_http': 200,
        'proof_post_http': 404, 'status_http': 404, 'proof_denied': True,
        'status_denied': True, 'no_accepted_receipt': True, 'no_callback': True,
        'no_authorization_code': True, 'request_correlated_denial': True,
        'fresh_login_http': 200, 'fresh_challenge_http': 200,
        'fresh_locator_distinct': True, 'fresh_login_transaction_available': True,
        'response_body_safe': True, 'location_safe': True, 'redirects_safe': True,
        'runtime_qualification_status': 'runtime_facts_verified',
        'single_use_object_provider_path': 'infinispan'}
    self.assertTrue(probe.expiry_acceptance_passes(evidence))
    for field, value in (
        ('proof_post_http', 202), ('status_http', 200), ('no_accepted_receipt', False),
        ('no_callback', False), ('no_authorization_code', False),
        ('fresh_login_http', 500), ('fresh_challenge_http', 404),
        ('fresh_locator_distinct', False), ('fresh_login_transaction_available', False),
        ('request_correlated_denial', False), ('response_body_safe', False),
        ('runtime_qualification_status', 'open_runtime_facts_unavailable'),
        ('single_use_object_provider_path', 'jpa')):
      with self.subTest(field=field):
        self.assertFalse(probe.expiry_acceptance_passes(dict(evidence, **{field: value})))

  def test_expiry_marker_requires_allowlisted_provider_and_exact_request_id(self):
    import wallet_login_live_e2e as probe

    handle = 'h' * 43
    request_id = hashlib.sha256(handle.encode('ascii')).digest()[:16].hex()
    marker = (f'Wallet transaction proof rejected (request={request_id}, '
        'reason=transaction_unavailable, provider=infinispan)')
    self.assertEqual('infinispan', probe._parse_expiry_denial_provider(
        marker, request_id, ['infinispan', 'jpa']))
    self.assertIsNone(probe._parse_expiry_denial_provider(
        marker, '0' * 32, ['infinispan', 'jpa']))
    self.assertIsNone(probe._parse_expiry_denial_provider(
        marker.replace('infinispan', 'unknown'), request_id, ['infinispan', 'jpa']))
    self.assertIsNone(probe._parse_expiry_denial_provider(
        marker, request_id, ['jpa']))

  def test_expiry_response_safety_rejects_acceptance_callback_and_code_surfaces(self):
    import wallet_login_live_e2e as probe

    self.assertTrue(probe._expiry_body_is_safe(b''))
    self.assertTrue(probe._expiry_body_is_safe(b'{"status":"expired"}'))
    for body in (b'{"status":"accepted"}', b'{"callback":null}',
        b'{"authorization_code":"secret"}', b'{"receipt_id":"secret"}',
        b'{"message":"code = secret"}',
        b'{"message":"callback_url=secret"}', b'{"receipt_token":"secret"}',
        b'{"message":"x_callback_url=secret"}', b'{"message":"x_receipt_id=secret"}',
        b'{"message":"x_authorization_code=secret"}',
        b'{"x_callback_url":"secret"}', b'{"x_receipt_id":"secret"}',
        b'{"x_authorization_code":"secret"}', b'not-json'):
      with self.subTest(body=body):
        self.assertFalse(probe._expiry_body_is_safe(body))
    self.assertTrue(probe._expiry_location_is_safe(''))
    for location in (
        'https://rp.example/callback?code=secret',
        'https://rp.example/callback?receipt_id=secret',
        'https://rp.example/callback?result=accepted',
        'https://rp.example/callback#code=secret',
        'https://rp.example/callback',
        'https://rp.example/failure?callback_url=https%3A%2F%2Frp.example%2Fcallback',
        'https://rp.example/failure?receipt_token=secret',
        'https://rp.example/failure?x_callback_url=opaque',
        'https://rp.example/failure?x_receipt_id=opaque',
        'https://rp.example/failure?callback%5Furl=opaque',
        'https://rp.example/failure#receipt%5Fid=opaque',
        'https://rp.example/failure?authorization%5Fcode=opaque',
        'https://rp.example/failure?x_authorization_code=opaque',
        'https://rp.example/failure#x_callback_url=opaque',
        'https://rp.example/failure/x_receipt_id/opaque',
        'https://rp.example/failure/x%5Freceipt%5Fid/opaque',
        'https://rp.example/failure/x_authorization_code/opaque',
        'https://rp.example/failure/code=opaque',
        'https://rp.example/oauth/code/secret'):
      with self.subTest(location=location):
        self.assertFalse(probe._expiry_location_is_safe(location))
    self.assertTrue(probe._expiry_redirects_are_safe([]))
    self.assertFalse(probe._expiry_redirects_are_safe([{'target_query_names': []}]))

  def test_unknown_live_profile_is_rejected_before_resolving_an_image(self):
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'unrecognized'}), \
        patch.object(probe, 'resolve_immutable_image', side_effect=AssertionError(
            'profile validation must precede image inspection')) as resolve_image:
      with self.assertRaisesRegex(ValueError, 'WALLET_IT_PROFILE'):
        probe.main()
    resolve_image.assert_not_called()


if __name__ == '__main__':
  unittest.main()
