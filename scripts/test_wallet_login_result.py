import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

from wallet_login_live_e2e import classify_identity_lookup  # noqa: E402


class IdentityLookupClassificationTest(unittest.TestCase):

  def test_live_probe_rotates_registry_identity_and_checks_old_and_new_keys(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def stale_key_rotation_flow(')
    end = source.index('def signup_wallet_flow(', start)
    body = source[start:end]
    self.assertIn("helper = project / 'scripts/rotation_registry_roundtrip.py'", body)
    self.assertIn('separate Identity resolver confirms seq 2 and exact successor key', body)
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

  def test_live_probe_includes_stale_key_after_registry_rotation_case(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main_start = source.index('def main():')
    main_body = source[main_start:]
    self.assertIn('stale_key_rotation_flow(', source)
    self.assertIn("result['rotated_identity_case']", main_body)
    self.assertIn("account_policy_denial_is_attributed(ambiguity_result)", source)
    self.assertIn("'username': 'wallet-owner-duplicate', 'enabled': True", source)
    self.assertIn("provision_identity_attribute(client, token, 'wallet-owner-duplicate', identifier)", main_body)

  def test_duplicate_mapping_denial_runs_only_after_duplicate_fixture_is_seeded(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    main_body = source[source.index('def main():'):]
    duplicate_fixture = "provision_identity_attribute(client, token, 'wallet-owner-duplicate', identifier)"
    duplicate_denial = "client, key, identifier, 'ambiguous-account'"

    first_duplicate_denial = main_body.index(duplicate_denial)
    self.assertLess(main_body.index(duplicate_fixture), first_duplicate_denial)

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
    start = source.index('def browser_preflight_flow():')
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
    end = source.index('\ndef negative_proof_flow', start)
    body = source[start:end]
    self.assertIn('require_transport_security_headers(browser_challenge_headers', body)
    self.assertIn('require_transport_security_headers(missing_csrf_headers', body)
    self.assertIn('require_transport_security_headers(browser_proof_headers', body)
    self.assertIn('require_transport_security_headers(status_response_headers', body)
    self.assertIn("'Cache-Control': 'no-store'", source)
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

  def test_live_browser_flow_checks_shared_transport_security_headers(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def browser_preflight_flow(')
    end = source.index('\ndef negative_proof_flow', start)
    body = source[start:end]
    for source_call in (
        'require_transport_security_headers(status_response_headers',
        'require_transport_security_headers(wallet_headers',
        'require_transport_security_headers(proof_headers',
        'require_transport_security_headers(status_headers_out',
    ):
      self.assertIn(source_call, source)
    self.assertIn("if expect_no_store:", source)
    self.assertEqual(body.count('expect_no_store=False'), 2)
    self.assertIn("'Referrer-Policy': 'no-referrer'", source)
    self.assertIn("'X-Content-Type-Options': 'nosniff'", source)
    self.assertIn("stage + ' varies by Origin'", source)
    self.assertIn("headers.get('Vary') is not None", source)

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

  def test_live_e2e_probe_reports_registry_and_account_misses_distinctly(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def missing_identity_flow(')
    end = source.index('\ndef main(', start)
    body = source[start:end]
    self.assertIn("identity_id': direct_lookup_id", body)
    self.assertIn("'direct_provider_http': direct_http", body)
    self.assertIn("resolution_category = 'unavailable'", body)

  def test_exact_registry_miss_with_only_dial_warnings_is_absence(self):
    output = '\n'.join((
        'Failed to open TCP stream: all attempts to connect to /ip4/127.0.0.1/tcp/9000 failed',
        'Value not found for key /decent-registry/identity/' + 'ab' * 32,
        'not found',
    ))

    resolution, categories = classify_identity_lookup(output, 1)

    self.assertEqual('not_found', resolution)
    self.assertEqual(['dial_warning', 'registry_miss', 'not_found'], categories)

  def test_handshake_error_keeps_mixed_lookup_unavailable(self):
    output = '\n'.join((
        'Value not found for key /decent-registry/identity/' + 'ab' * 32,
        'failed to upgrade security for peer 12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X: handshake failed when upgrading to secure connection',
        'not found',
    ))

    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def classify_identity_lookup(')
    end = source.index('\n\ndef parse_exact_identity_result', start)
    namespace = {}
    exec(source[start:end], namespace)
    resolution, categories = namespace['classify_identity_lookup'](output, 1)

    self.assertEqual('unavailable', resolution)
    self.assertEqual(['registry_miss', 'peer_handshake', 'not_found'], categories)

  def test_well_formed_registry_miss_with_handshake_failure_stays_unavailable(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def classify_identity_lookup(')
    end = source.index('\ndef parse_exact_identity_result', start)
    namespace = {}
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


  def test_non_not_found_exit_is_never_absence(self):
    output = 'Value not found for key /decent-registry/identity/' + 'ab' * 32 + '\nnot found'

    resolution, _ = classify_identity_lookup(output, 0)

    self.assertEqual('unavailable', resolution)


if __name__ == '__main__':
  unittest.main()
