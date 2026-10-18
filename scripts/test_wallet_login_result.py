import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

from wallet_login_live_e2e import classify_and_parse_result, classify_identity_lookup, json_object_is_balanced, packaged_resolver_readback, parse_exact_identity_result, sanitize_live_checkpoint  # noqa: E402


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
    self.assertIn("account_policy_denial_is_attributed(ambiguity_result)", source)
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
    duplicate_denial = "client, key, identifier, 'ambiguous-account'"
    self.assertLess(main_body.index(duplicate_fixture), main_body.index(duplicate_denial))

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

  def test_live_e2e_probe_reports_registry_and_account_misses_distinctly(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def missing_identity_flow(')
    end = source.index('\ndef main(', start)
    body = source[start:end]
    self.assertIn("identity_id': direct_lookup_id", body)
    self.assertIn("'direct_provider_http': direct_http", body)
    self.assertIn("provider_resolution_outcome = classify_provider_identity_outcome(direct_http)", body)
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
    record = '[WALLET-RESOLVER-DIAG] exit=0, reason=registry_miss|dial_warning|unknown, lines=64, capped=true'
    prefixed_record = ('2026-10-17 11:23:45,678 DEBUG [org.decentwallet.keycloak.wallet.ProcessIdentityResolver] '
        '(executor-thread-2) [WALLET-RESOLVER-DIAG] exit=3, reason=history_unavailable, lines=1, capped=false')
    secrets = '[WALLET-RESOLVER-DIAG] exit=0, reason=registry_miss|mailto:private@example.invalid, lines=4, capped=false'
    self.assertEqual(['ok:registry_miss|dial_warning|unknown'],
        namespace['sanitized_resolver_diagnostic_lines'](record))
    nonzero_record = ('2026-10-17 11:23:45,678 DEBUG [org.decentwallet.keycloak.wallet.ProcessIdentityResolver] '
        '(executor-thread-2) [WALLET-RESOLVER-DIAG] exit=7, reason=nonzero_exit, lines=0, capped=false')
    process_start_record = ('2026-10-17 11:23:45,678 DEBUG [org.decentwallet.keycloak.wallet.ProcessIdentityResolver] '
        '(executor-thread-2) [WALLET-RESOLVER-DIAG] exit=-1, reason=process_start, lines=0, capped=false')
    self.assertEqual(['ok:process_start'],
        namespace['sanitized_resolver_diagnostic_lines'](process_start_record))
    failure_records = [
        f'[WALLET-RESOLVER-DIAG] exit=-1, reason=unknown|{category}, lines=1, capped=false'
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
    oversized = '[WALLET-RESOLVER-DIAG] exit=999, reason=unknown, lines=65, capped=true'
    invalid_negative = '[WALLET-RESOLVER-DIAG] exit=-2, reason=process_start, lines=0, capped=false'
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

  def test_exact_registry_miss_with_only_dial_warnings_is_absence(self):
    identifier = 'mailto:alice@example.org'
    expected_key = '4aa8889aa1e3f193844b32d36e58b50a8817304b9e15d798d460d00bff828a29'
    output = chr(10).join((
        'Failed to open TCP stream: all attempts to connect to /ip4/127.0.0.1/tcp/9000 failed',
        'Value not found for key /decent-registry/identity/' + expected_key,
        'not found',
    ))

    resolution, categories = classify_identity_lookup(output, 1, identifier)

    self.assertEqual('not_found', resolution)
    self.assertEqual(['dial_warning', 'registry_miss', 'not_found'], categories)

  def test_unavailable_categories_preserve_history_and_traceback_reason(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def classify_identity_lookup(')
    end = source.index('def parse_exact_identity_result(', start)
    namespace = {}
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
        'Value not found for key /decent-registry/identity/' + expected_key,
        'not found',
    ))

    resolution, categories = classify_identity_lookup(output, 1, identifier)

    self.assertEqual('not_found', resolution)
    self.assertEqual(['registry_miss', 'not_found'], categories)

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


if __name__ == '__main__':
  unittest.main()
