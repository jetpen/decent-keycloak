"""Regression coverage for the Keycloak login-to-signup intent action."""
from __future__ import annotations

import json
import hashlib
import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("WALLET_IT_NATIVE_LIBS", "/unused-test-library-path")
sys.path.insert(0, str(Path(__file__).parent))
import wallet_login_live_e2e as probe  # noqa: E402

SAFE_ACCOUNT_DENIAL_RESPONSE = {
    'response_body_safe': True, 'headers_safe': True, 'location_safe': True,
    'redirects_safe': True, 'status_pending': True,
    'no_acceptance_or_callback': True,
}


class SignupIntentProbeTest(unittest.TestCase):
  def test_credential_file_unlink_retries_transient_errors(self):
    import tempfile
    from pathlib import Path
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as scratch:
      secret = Path(scratch) / 'credential.env'
      secret.write_text('secret')
      original = Path.unlink
      attempts = []
      def transient(path, *args, **kwargs):
        if path == secret and len(attempts) == 0:
          attempts.append(1)
          raise OSError('transient')
        return original(path, *args, **kwargs)
      with patch.object(Path, 'unlink', transient):
        retained = probe.unlink_with_retries(secret, sleep=lambda _: None)
      self.assertTrue(retained)
      self.assertFalse(secret.exists())

  def test_credential_file_unlink_persistent_error_is_sanitized_retained_status(self):
    import tempfile
    from pathlib import Path
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as scratch:
      secret = Path(scratch) / 'credential.env'
      secret.write_text('never-print-this')
      with patch.object(Path, 'unlink', side_effect=PermissionError('secret-value')):
        removed = probe.unlink_with_retries(secret, sleep=lambda _: None)
      evidence = probe.sanitize_live_checkpoint({'resolver_runtime': {
          'credential_file_retained': not removed}})
      self.assertFalse(removed)
      self.assertTrue(secret.exists())
      self.assertNotIn('never-print-this', repr(evidence))
      self.assertNotIn('secret-value', repr(evidence))

  def test_admin_env_file_launch_failure_is_checked_and_cleanup_runs(self):
    from pathlib import Path
    from unittest.mock import patch
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / "run-owned-cids"
      cid_dir.mkdir(mode=0o700)
      observed = {}
      def fake_run(argv, **kwargs):
        if argv[0] == "ss":
          return subprocess.CompletedProcess(argv, 0, "", "")
        env_path = Path(argv[argv.index("--env-file") + 1])
        observed["mode"] = env_path.stat().st_mode & 0o777
        observed["argv"] = argv
        return subprocess.CompletedProcess(argv, 125, "", "")

      with patch.object(probe, "SCRATCH", Path(scratch)), \
           patch.object(probe, "RUN_CID_DIR", cid_dir), \
           patch.object(probe, "run", side_effect=fake_run), \
           patch.object(probe, "Client", side_effect=AssertionError("discovery must not run after failed launch")):
        with self.assertRaisesRegex(RuntimeError, "start disposable Keycloak"):
          probe.start_keycloak("test", "fixture-only-value", Path(scratch) / "wrapper", 1234, "bootstrap", "sha256:" + "a" * 64)

      self.assertEqual(observed["mode"], 0o600)
      self.assertNotIn("fixture-only-value", observed["argv"])
      self.assertFalse(list(Path(scratch).glob("wallet-login-admin-*.env")))

  def test_admin_credential_holder_is_used_for_signup_readback_and_callback_diagnostics(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    flow = source[source.index("def signup_wallet_flow("):source.index("def missing_identity_flow")]
    self.assertRegex(flow, r"admin = signup_boundary\(\s*'account_readback', 'account_readback', lambda: admin_token\(\s*admin_client, AdminPassword\(admin_client\.privateClientAdminCredential\)\)\)")
    self.assertIn("recent_login_error_categories(admin_client, safe_token)", flow)
    self.assertNotIn("AdminPassword(client.privateClientAdminCredential)", flow)
    self.assertRegex(flow, r"exact_users_raw = signup_boundary\(\s*'account_readback', 'account_readback', lambda: admin_call\(\s*admin_client, admin, 'GET'")
    self.assertIn("admin_client, admin, 'GET'", flow)
    self.assertIn("signup_result = signup_wallet_flow(signup_browser, signup_key, signup_identifier,", source)


  def test_signup_action_trace_parser_preserves_only_allowlisted_methods_and_line_numbers(self):
    logs = """2026 ERROR [org.keycloak.services.resources.LoginActionsService] java.lang.NullPointerException: hidden
\tat org.keycloak.authentication.DefaultAuthenticationFlow.processResult(DefaultAuthenticationFlow.java:1234)
\tat org.decentwallet.keycloak.wallet.WalletChallengeAuthenticator.action(WalletChallengeAuthenticator.java:145)
"""
    result = probe.sanitize_signup_action_diagnostics('{"error_description":"Internal server error"}', logs)
    self.assertEqual(result["stack_frames"], [
        {"method": "org.keycloak.authentication.DefaultAuthenticationFlow.processResult", "line": 1234},
        {"method": "org.decentwallet.keycloak.wallet.WalletChallengeAuthenticator.action", "line": 145},
    ])
    serialized = __import__("json").dumps(result)
    self.assertNotIn("hidden", serialized)

  def test_signup_action_diagnostics_emit_only_error_classes_and_allowlisted_stack_frames(self):
    logs = """2026 INFO Request on /realm/login-actions
2026 ERROR [org.keycloak.services.resources.LoginActionsService] (executor-thread-1) failure with secret-cookie=not-print
2026 ERROR [org.keycloak.services.resources.LoginActionsService] (executor-thread-1) java.lang.IllegalStateException: proprietary-error-description
\tat org.keycloak.authentication.AuthenticationProcessor.processAction(AuthenticationProcessor.java:1)
\tat org.decentwallet.keycloak.wallet.WalletChallengeAuthenticator.action(WalletChallengeAuthenticator.java:2)
2026 ERROR [org.keycloak.services.resources.LoginActionsService] (executor-thread-1) Caused by: java.lang.IllegalArgumentException: hidden-session-value
\tat org.keycloak.services.resources.LoginActionsService.authenticate(LoginActionsService.java:3)
"""
    response = '{"error":"unknown_error","error_description":"Internal server error"}'

    result = probe.sanitize_signup_action_diagnostics(response, logs)

    self.assertEqual(result["error"], "other-error:internal-error")
    self.assertEqual(result["exceptions"], ["IllegalStateException", "IllegalArgumentException"])
    self.assertEqual(result["frames"], [
        "org.keycloak.authentication.AuthenticationProcessor.processAction",
        "org.decentwallet.keycloak.wallet.WalletChallengeAuthenticator.action",
        "org.keycloak.services.resources.LoginActionsService.authenticate",
    ])
    serialized = __import__("json").dumps(result)
    for forbidden in ("not-print", "proprietary-error-description", "hidden-session-value"):
      self.assertNotIn(forbidden, serialized)

  def test_untrusted_exception_messages_and_response_descriptions_are_redacted(self):
    result = probe.sanitize_signup_action_diagnostics(
        '{"error":"unknown_error","error_description":"Internal server error session=do-not-leak"}',
        '2026 ERROR java.lang.IllegalStateException: cookie=do-not-leak\n'
        '\tat org.keycloak.services.resources.LoginActionsService.authenticate(LoginActionsService.java:9)\n')
    rendered = __import__("json").dumps(result)
    self.assertNotIn("do-not-leak", rendered)
    self.assertEqual(result["exceptions"], ["IllegalStateException"])
    self.assertEqual(result["stack_frames"], [
        {"method": "org.keycloak.services.resources.LoginActionsService.authenticate", "line": 9}])
  def test_disposable_realm_enables_registration_before_signup_action(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def configure_realm(")
    end = source.index("\ndef der(", start)
    configure = source[start:end]
    self.assertIn("'verifyEmail': False", configure)
    self.assertIn("'loginWithEmailAllowed': True", configure)
    self.assertIn("'duplicateEmailsAllowed': False", configure)

  def test_signup_uses_current_keycloak_flow_then_explicit_wallet_intent_post(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def signup_wallet_flow(")
    end = source.index("\ndef missing_identity_flow", start)
    body = source[start:end]
    self.assertNotIn("'prompt': 'create'", body)
    self.assertIn("name=\"wallet_intent\" value=\"signup\"", body)
    self.assertIn("'wallet_intent': 'signup'", body)
    self.assertIn("'Content-Type': 'application/x-www-form-urlencoded'", body)
    self.assertIn("Creating a new account with this wallet identity.", body)
    self.assertLess(body.index("action_status == 200"),
        body.index("wallet.request('POST', signup_locator"))

  def test_signup_resumes_from_browser_bound_status_callback(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def signup_wallet_flow(")
    end = source.index("\ndef missing_identity_flow", start)
    body = source[start:end]
    self.assertIn("polled == 200", body)
    self.assertIn("lambda: signup_callback_from_status(", body)
    self.assertIn("status_body,", body)
    self.assertIn("callback_body.decode('utf-8', errors='replace')", body)
    self.assertIn("callback, OIDC state, and no-code replay", body)
    self.assertNotIn("callback_url = f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/login-actions/authenticate'", body)

  def test_signup_resume_callback_uses_the_validated_same_origin_keycloak_action_path(self):
    callback = ('https://idp.example:18886/auth/realms/demo/login-actions/authenticate'
        '?session_code=opaque&execution=exec&client_id=client&tab_id=tab&client_data=data')
    method, path, body = probe.signup_callback_submission(
        {'status': 'accepted', 'callback': callback}, 'https://idp.example:18886/auth', 'demo')
    self.assertEqual('GET', method)
    self.assertEqual('/auth/realms/demo/login-actions/authenticate'
        '?session_code=opaque&execution=exec&client_id=client&tab_id=tab&client_data=data', path)
    self.assertEqual(b'', body)
    self.assertEqual(callback, probe.signup_resume_action_path(
        callback, 'https://idp.example:18886/auth', 'demo'))
    for invalid in (
        callback.replace('idp.example', 'evil.example'),
        callback.replace('/login-actions/authenticate', '/login-actions/required-action'),
        callback + '&execution=duplicate', callback.split('?', 1)[0],
    ):
      with self.subTest(invalid=invalid):
        with self.assertRaises(ValueError):
          probe.signup_resume_action_path(invalid, 'https://idp.example:18886/auth', 'demo')



    status = {
        "status": "accepted",
        "callback": "https://idp.example:18886/auth/realms/wallet-e2e/login-actions/authenticate"
            "?session_code=opaque&execution=exec&client_id=wallet-e2e-client&tab_id=tab"
            "&client_data=opaque",
    }
    callback = probe.signup_callback_from_status(status, f"https://idp.example:{probe.KC_PORT}/auth", probe.REALM)
    parsed = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(callback)
    self.assertEqual("/auth/realms/wallet-e2e/login-actions/authenticate", parsed.path)
    names = __import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(parsed.query)
    self.assertEqual({"session_code", "execution", "client_id", "tab_id", "client_data"}, set(names))
    self.assertIsNone(probe.signup_callback_from_status({"status": "accepted"},
        f"https://idp.example:{probe.KC_PORT}/auth", probe.REALM))

  def test_signup_callback_parser_fails_closed_on_wrong_origin_or_missing_keycloak_fields(self):
    callback = (f"https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}/login-actions/authenticate"
        "?session_code=opaque&execution=exec&client_id=wallet-e2e-client&tab_id=tab&client_data=opaque")
    for status in (
        {"status": "pending", "callback": callback},
        {"status": "accepted", "callback": callback.replace("idp.example", "evil.example")},
        {"status": "accepted", "callback": callback.split("?", 1)[0]},
        {"status": "accepted", "callback": callback + "&session_code=duplicate"},
    ):
      with self.subTest(status=status["status"]):
        with self.assertRaises(ValueError):
          probe.signup_callback_from_status(status, f"https://idp.example:{probe.KC_PORT}/auth", probe.REALM)

    with self.assertRaises(ValueError):
      probe.signup_callback_from_status({"status": "accepted", "callback": "https://idp.example.evil:18886/auth/realms/wallet-e2e/login-actions/authenticate?session_code=x&execution=e&client_id=c&tab_id=t&client_data=d"},
          f"https://idp.example:{probe.KC_PORT}/auth", probe.REALM)

  def test_signup_resume_error_classification_accepts_only_known_coarse_clues(self):
    result = probe.sanitize_signup_action_diagnostics(
        '{"error":"invalid_code","error_description":"login restart is invalid"}', '')
    self.assertEqual('invalid_code:restart-path+invalid', result['error'])

  def test_signup_callback_diagnostics_classify_keycloak_400_without_emitting_response_values(self):
    logs = ('ERROR org.keycloak: Invalid session code for client secret-client\n'
        '\tat org.keycloak.services.LoginActionsService.authenticate(LoginActionsService.java:123)')
    diagnostics = probe.sanitize_signup_callback_response(
        400, {'Content-Type': 'text/html'},
        '<html><body><h1>Invalid code for session secret-session</h1></body></html>', logs)
    serialized = __import__('json').dumps(diagnostics)
    self.assertEqual(['invalid_session_code'], diagnostics['server_error_categories'])
    self.assertIn('LoginActionsService.authenticate', serialized)
    self.assertEqual(123, diagnostics['stack_frames'][0]['line'])
    for secret in ('secret-client', 'secret-session', 'Invalid code for session'):
      self.assertNotIn(secret, serialized)

  def test_signup_callback_event_diagnostics_keep_only_error_categories(self):
    raw = __import__('json').dumps([{
        'type': 'LOGIN_ERROR', 'error': 'invalid_code',
        'details': {'client_id': 'client-private', 'tab_id': 'tab-secret',
            'redirect_uri': 'https://rp.example/private', 'reason': 'hidden'},
    }])
    result = probe.sanitize_keycloak_events(raw)
    self.assertEqual([{'type': 'LOGIN_ERROR', 'error': 'invalid_code',
        'detail_names': ['client_id', 'reason', 'redirect_uri', 'tab_id']}], result)
    serialized = __import__('json').dumps(result)
    for secret in ('client-private', 'tab-secret', 'rp.example', 'hidden'):
      self.assertNotIn(secret, serialized)


    diagnostics = probe.sanitize_signup_callback_response(
        200, {"Content-Type": "text/html; charset=utf-8",
              "Location": "https://rp.example/callback?state=secret"},
        '<html><title>Unexpected login</title><form method="post" action="/safe?a=opaque">'
        '<input name="username" value="private"><input name="session_code" value="secret"></form></html>')
    self.assertEqual(200, diagnostics["status"])
    self.assertEqual("text/html", diagnostics["content_type"])
    self.assertEqual("/callback", diagnostics["location_path"])
    self.assertEqual(["state"], diagnostics["location_query_names"])
    self.assertEqual([{"method": "POST", "action_path": "/safe", "query_names": ["a"],
        "input_fields": [{"name": "username", "invalid": False},
            {"name": "session_code", "invalid": False}]}], diagnostics["forms"])
    serialized = __import__("json").dumps(diagnostics)
    for secret in ("secret", "private", "opaque", "rp.example"):
      self.assertNotIn(secret, serialized)

  def test_signup_callback_continuation_is_posted_to_the_bound_keycloak_action(self):
    status = {'status': 'accepted', 'callback':
        'https://idp.example:18886/auth/realms/demo/login-actions/authenticate'
        '?session_code=s&execution=e&client_id=c&tab_id=t&client_data=d'}
    method, path, data = probe.signup_callback_submission(
        status, 'https://idp.example:18886/auth', 'demo')
    self.assertEqual('GET', method)
    self.assertEqual('/auth/realms/demo/login-actions/authenticate'
        '?session_code=s&execution=e&client_id=c&tab_id=t&client_data=d', path)
    self.assertEqual(b'', data)


    body = ('<form method="post" action="/auth/realms/demo/login-actions/required-action?'
        'session_code=s&amp;execution=e&amp;client_id=c&amp;tab_id=t&amp;client_data=d">'
        '<input type="hidden" name="stateChecker" value="checker">'
        '<input name="email"><input name="firstName"><input name="lastName"></form>')
    path, encoded = probe.signup_form_action(body, 'https://idp.example:18886/auth', 'demo', True,
        {'email': 'wallet@example.com', 'firstName': 'Wallet', 'lastName': 'Account'})
    self.assertTrue(path.startswith('/auth/realms/demo/login-actions/required-action?'))
    fields = __import__('urllib.parse', fromlist=['parse_qs']).parse_qs(encoded.decode())
    self.assertEqual(['checker'], fields['stateChecker'])
    self.assertEqual(['wallet@example.com'], fields['email'])
    self.assertEqual(['Wallet'], fields['firstName'])
    self.assertEqual(['Account'], fields['lastName'])

  def test_signup_callback_continuation_uses_the_validated_bound_action(self):
    status = {'status': 'accepted', 'callback':
        'https://idp.example:18886/auth/realms/demo/login-actions/authenticate'
        '?session_code=s&execution=e&client_id=c&tab_id=t&client_data=d'}
    method, path, data = probe.signup_callback_submission(
        status, 'https://idp.example:18886/auth', 'demo')
    self.assertEqual('GET', method)
    self.assertEqual('/auth/realms/demo/login-actions/authenticate'
        '?session_code=s&execution=e&client_id=c&tab_id=t&client_data=d', path)
    self.assertEqual(b'', data)

  def test_signup_contact_email_uses_a_valid_synthetic_domain_not_reserved_invalid(self):
    email = probe.signup_contact_email('mailto:wallet-user@example.net')
    self.assertTrue(email.endswith('@example.com'))
    self.assertNotIn('.invalid', email)
    self.assertRegex(email, r'^wallet-[0-9a-f]{32}@example\.com$')
    self.assertLessEqual(len(email.split('@', 1)[0]), 64)


  def test_profile_diagnostics_classify_email_duplicate_without_emitting_page_text(self):
    result = probe.sanitize_signup_callback_response(200,
        {"Content-Type": "text/html"},
        '<div id="input-error-email">Email already exists: private@example.net</div>')
    self.assertEqual([{"field": "email", "category": "duplicate"}], result["field_errors"])
    self.assertNotIn("private@example.net", __import__("json").dumps(result))


  def test_signup_profile_action_builds_same_origin_post_from_profile_field_names(self):
    html_body = ('<form method="post" action="/auth/realms/demo/login-actions/required-action?'
        'session_code=opaque&amp;execution=exec&amp;client_id=client&amp;tab_id=tab&amp;client_data=data">'
        '<input type="hidden" name="stateChecker" value="secret">'
        '<input name="email" value="old@example.invalid">'
        '<input name="firstName" value=""><input name="lastName" value=""></form>')
    url, fields = probe.signup_form_action(html_body,
        'https://idp.example:18886/auth', 'demo', True,
        {'email': 'wallet-user@wallet.com', 'firstName': 'Wallet', 'lastName': 'Account'})
    parsed = __import__('urllib.parse', fromlist=['urlsplit']).urlsplit('https://idp.example:18886' + url)
    self.assertEqual('https://idp.example:18886', parsed.scheme + '://' + parsed.netloc)
    self.assertEqual('/auth/realms/demo/login-actions/required-action', parsed.path)
    self.assertEqual({'session_code', 'execution', 'client_id', 'tab_id', 'client_data'},
        set(__import__('urllib.parse', fromlist=['parse_qs']).parse_qs(parsed.query)))
    self.assertEqual({'stateChecker': ['secret'], 'email': ['wallet-user@wallet.com'],
        'firstName': ['Wallet'], 'lastName': ['Account']},
        __import__('urllib.parse', fromlist=['parse_qs']).parse_qs(fields.decode(), keep_blank_values=True))


  def test_signup_profile_action_rejects_wrong_origin_and_unknown_profile_fields(self):
    values = {'email': 'wallet-user@wallet.invalid', 'firstName': 'Wallet', 'lastName': 'Account'}
    for action, body in (
        ('https://evil.example/auth/realms/demo/login-actions/required-action?session_code=s&execution=e&client_id=c&tab_id=t&client_data=d',
         '<input name="email"><input name="firstName"><input name="lastName">'),
        ('/auth/realms/demo/login-actions/required-action?session_code=s&execution=e&client_id=c&tab_id=t&client_data=d',
         '<input name="email"><input name="firstName"><input name="lastName"><input name="credential">'),
    ):
      html_body = f'<form method="post" action="{action}">{body}</form>'
      with self.assertRaises(ValueError):
        probe.signup_profile_submission(html_body, 'https://idp.example:18886/auth', 'demo', values)

  def test_signup_callback_action_never_provisions_or_deletes_a_post_consume_user(self):
    source = (Path(__file__).parents[1] / 'src/main/java/org/decentwallet/keycloak/wallet/'
        'WalletChallengeAuthenticator.java').read_text()
    start = source.index('public void action(AuthenticationFlowContext context)')
    action = source[start:source.index('static boolean isSingleExactHttpsRedirect', start)]
    self.assertIn('WalletLoginAccountMapping.findUniqueEnabledUser(', action)
    self.assertNotIn('WalletLoginAccountMapping.ensureEnabledUser(', action)
    self.assertNotIn('removeUser(', action)
    self.assertIn('store.getAccepted(handle, binding)', action)
    self.assertLess(action.index('store.getAccepted(handle, binding)'),
        action.index('store.takeAccepted(handle, binding)'))

  def test_signup_callback_failure_does_not_delete_provisioned_account(self):
    source = (Path(__file__).parents[1] / 'src/main/java/org/decentwallet/keycloak/wallet/'
        'WalletChallengeAuthenticator.java').read_text()
    failure_start = source.index('private static void failClosed(AuthenticationFlowContext context)')
    failure_path = source[failure_start:source.index('@Override', failure_start)]
    self.assertIn('Ignored legacy signup provisioning marker', source)
    self.assertNotIn('removeUser(', failure_path)

  def test_unmapped_account_evidence_does_not_call_unavailable_result_policy_denial(self):
    denied = probe.unmapped_account_case_evidence({
        'outcome': 'policy_denied', 'current_registry_proof_http': 403,
        'local_account_mapping_decision_observed': True, 'registry_unavailable': False,
        'no_acceptance_or_callback': True})
    unavailable = probe.unmapped_account_case_evidence({
        'outcome': 'registry_unavailable', 'current_registry_proof_http': 503,
        'local_account_mapping_decision_observed': False, 'registry_unavailable': True,
        'no_acceptance_or_callback': True})
    self.assertTrue(denied['local_account_mapping_decision_observed'])
    self.assertEqual(denied['outcome'], 'policy_denied')
    self.assertFalse(unavailable['local_account_mapping_decision_observed'])
    self.assertTrue(unavailable['registry_unavailable'])
    self.assertEqual(unavailable['outcome'], 'registry_unavailable')
    self.assertTrue(unavailable['no_acceptance_or_callback'])

  def test_exact_registry_precheck_requires_a_valid_record_for_the_requested_identity(self):
    identifier = 'mailto:verified@example.test'
    expected_key = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    record = {'identifier': identifier, 'owner_name_hex': identifier.encode('utf-8').hex(),
        'seq': 2, 'owner_public_key_hex': 'ab' * 32}
    stdout = json.dumps(record, indent=2)
    self.assertTrue(probe.exact_registry_lookup_succeeded(stdout, 0, identifier))
    self.assertFalse(probe.exact_registry_lookup_succeeded(stdout, 0, 'mailto:other@example.test'))
    self.assertFalse(probe.exact_registry_lookup_succeeded(stdout, 1, identifier))
    self.assertFalse(probe.exact_registry_lookup_succeeded('{malformed', 0, identifier))
    invalid_key_record = {**record, 'owner_public_key_hex': 'ab' * 15 + '  ' + 'cd' * 16}
    self.assertEqual(64, len(invalid_key_record['owner_public_key_hex']))
    malformed_key_output = json.dumps(invalid_key_record, indent=2)
    self.assertFalse(probe.exact_registry_lookup_succeeded(malformed_key_output, 0, identifier))
    self.assertEqual('unavailable', probe.exact_registry_lookup_outcome(
        malformed_key_output, 0, identifier))
    miss_key = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    clean_summary = '\n'.join((
        'DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=1 failed=0 timeouts=0 incomplete=0',
        'DHT_LOOKUP_SUMMARY stage=remote_identity attempts=1 empty=1 failed=0 timeouts=0 incomplete=0'))
    miss_output = '\n'.join((
        clean_summary,
        'Value not found for key /decent-registry/identity/' + miss_key,
        'not found'))
    handshake_output = '\n'.join((
        clean_summary,
        'Value not found for key /decent-registry/identity/' + miss_key,
        'failed to upgrade security for peer 12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X: handshake failed',
        'not found'))
    self.assertEqual('not_found', probe.exact_registry_lookup_outcome(miss_output, 1, identifier))
    self.assertEqual('unavailable', probe.exact_registry_lookup_outcome(handshake_output, 1, identifier))

  def test_unmapped_account_403_requires_a_successful_registry_lookup_for_policy_attribution(self):
    denied = probe.account_mapping_denial_result(403, 'resolved', ['account-policy-rejected'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    missing_policy_trace = probe.account_mapping_denial_result(403, 'resolved', [],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    resolver_failed = probe.account_mapping_denial_result(
        403, 'resolved', ['account-policy-rejected', 'identity-resolver-unavailable'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    mapping_failed = probe.account_mapping_denial_result(
        403, 'resolved', ['account-policy-rejected', 'account-mapping-unavailable'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    unclassified = probe.account_mapping_denial_result(403, 'unavailable', ['account-policy-rejected'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    unavailable = probe.account_mapping_denial_result(503, 'unavailable', ['peer_handshake'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    policy_log_on_unavailable = probe.account_mapping_denial_result(
        503, 'resolved', ['account-policy-rejected'], response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    mapping_unavailable = probe.account_mapping_denial_result(
        503, 'resolved', ['account-mapping-unavailable'], response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    confirmed_missing = probe.account_mapping_denial_result(503, 'not_found', [],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    lookup_unavailable = probe.account_mapping_denial_result(503, 'unavailable', [],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    inconsistent_account_mapping = probe.account_mapping_denial_result(
        403, 'not_found', ['account-policy-rejected'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    self.assertEqual(confirmed_missing['outcome'], 'provider_registry_inconsistent')
    self.assertEqual(lookup_unavailable['outcome'], 'registry_unavailable')
    self.assertEqual(inconsistent_account_mapping['outcome'], 'provider_denied_unclassified')
    self.assertFalse(inconsistent_account_mapping['registry_unavailable'])
    self.assertEqual(missing_policy_trace['outcome'], 'provider_denied_unclassified')
    self.assertTrue(unclassified['registry_unavailable'])
    self.assertEqual(unclassified['registry_lookup_outcome'], 'unavailable')
    self.assertEqual(inconsistent_account_mapping['registry_lookup_outcome'], 'not_found')
    self.assertEqual(policy_log_on_unavailable['outcome'], 'provider_unavailable')
    self.assertEqual(mapping_unavailable['outcome'], 'account_mapping_unavailable')
    self.assertEqual(resolver_failed['outcome'], 'provider_denied_unclassified')
    self.assertEqual(mapping_failed['outcome'], 'provider_denied_unclassified')
    self.assertFalse(resolver_failed['local_account_mapping_decision_observed'])
    self.assertFalse(mapping_failed['local_account_mapping_decision_observed'])
    self.assertEqual(denied['outcome'], 'policy_denied')
    self.assertTrue(denied['local_account_mapping_decision_observed'])
    self.assertEqual(unclassified['outcome'], 'provider_denied_unclassified')
    self.assertFalse(unclassified['local_account_mapping_decision_observed'])
    self.assertEqual(unavailable['outcome'], 'registry_unavailable')
    self.assertTrue(unavailable['no_acceptance_or_callback'])
    accepted = probe.account_mapping_denial_result(202, 'resolved', [])
    self.assertEqual(accepted['outcome'], 'unexpected_acceptance')
    self.assertFalse(accepted['no_acceptance_or_callback'])

  def test_account_policy_request_id_has_128_bits(self):
    identifier = 'handle-123'
    expected = __import__('hashlib').sha256(identifier.encode('ascii')).hexdigest()[:32]
    actual = probe.account_policy_request_id('https://idp.example/transactions/' + identifier)
    self.assertEqual(expected, actual)

  def test_account_policy_denial_requires_fresh_attribution_and_pending_state(self):
    attributed = probe.account_mapping_denial_result(403, 'resolved', ['account-policy-rejected'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    unclassified = probe.account_mapping_denial_result(403, 'resolved', [],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    accepted = probe.account_mapping_denial_result(202, 'resolved', [])
    self.assertTrue(probe.account_policy_denial_is_attributed(attributed))
    self.assertFalse(probe.account_policy_denial_is_attributed(unclassified))
    self.assertFalse(probe.account_policy_denial_is_attributed(accepted))
    unclassified['no_acceptance_or_callback'] = False
    self.assertFalse(probe.account_policy_denial_is_attributed(unclassified))

    self.assertEqual(probe.account_policy_request_id('https://idp.example/transactions/handle-123'),
        __import__('hashlib').sha256(b'handle-123').hexdigest()[:32])
    prior = ['prior log line']
    request_id = '0123456789abcdef0123456789abcdef'
    current = prior + [
        'INFO Identity ID must not be emitted',
        f'DEBUG Wallet account policy rejected proof (request={request_id}, signup=true, registered=false, occupied=true)',
        f'WARN Wallet Identity resolver unavailable (request={request_id}, IdentityResolutionException)',
        f'WARN Wallet account mapping lookup unavailable (request={request_id}, IllegalStateException)',
    ]
    self.assertEqual(probe.new_account_mapping_log_categories(prior, current, request_id), [
        'account-policy-rejected', 'identity-resolver-unavailable', 'account-mapping-unavailable'])
    self.assertEqual(probe.new_account_mapping_log_categories(prior, ['rotated log'], request_id), [])
    self.assertNotIn('must not be emitted', repr(probe.new_account_mapping_log_categories(prior, current, request_id)))

    full_tail = [f'log-{index}' for index in range(120)]
    rolled_tail = full_tail[17:] + [
        f'DEBUG Wallet account policy rejected proof (request={request_id}, signup=true, registered=false, occupied=true)']
    self.assertEqual(probe.new_account_mapping_log_categories(full_tail, rolled_tail, request_id),
        ['account-policy-rejected'])
    self.assertEqual(probe.new_account_mapping_log_categories(full_tail, ['unrelated log'], request_id), [])

  def test_account_policy_attribution_ignores_other_request_log_events(self):
    expected_request_id = '0123456789abcdef0123456789abcdef'
    other_request_id = 'ffffffffffffffffffffffffffffffff'
    prior = ['prior log line']
    current = prior + [
        f'DEBUG Wallet account policy rejected proof (request={expected_request_id}, signup=true, registered=false, occupied=true)',
        f'DEBUG Wallet Identity resolver unavailable (request={other_request_id}, IdentityResolutionException)',
        f'DEBUG Wallet account policy rejected proof (request={other_request_id}, signup=true, registered=false, occupied=true)',
    ]
    self.assertEqual(probe.new_account_mapping_log_categories(prior, current, expected_request_id),
        ['account-policy-rejected'])

  def test_account_policy_marker_parser_rejects_duplicate_malformed_and_conflicting_lines(self):
    request_id = '0123456789abcdef0123456789abcdef'
    policy = (f'DEBUG Wallet account policy rejected proof (request={request_id}, '
        'signup=false, registered=false, occupied=false)')
    resolver = (f'WARN Wallet Identity resolver unavailable (request={request_id}, '
        'IdentityResolutionException)')
    malformed = 'DEBUG Wallet account policy rejected proof (request=bad, signup=false, registered=false, occupied=false)'
    prior = ['prior log line']

    for line in (policy + ' ' + policy, policy + ' ' + malformed, policy + ' ' + resolver):
      with self.subTest(line=line):
        self.assertEqual([], probe.new_account_mapping_log_categories(
            prior, prior + [line], request_id))

  def test_account_policy_attribution_rejects_duplicate_request_witnesses(self):
    duplicate = probe.account_mapping_denial_result(403, 'resolved', [
        'account-policy-rejected', 'account-policy-rejected'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    self.assertEqual(duplicate['outcome'], 'provider_denied_unclassified')
    self.assertFalse(probe.account_policy_denial_is_attributed(duplicate))

  def test_account_policy_denial_requires_safe_proof_and_status_responses(self):
    denial = probe.account_mapping_denial_result(
        403, 'resolved', ['account-policy-rejected'],
        response_safety={'response_body_safe': True, 'headers_safe': True,
            'location_safe': True, 'redirects_safe': True, 'status_pending': True,
            'no_acceptance_or_callback': False})
    self.assertEqual(denial['outcome'], 'provider_denied_unclassified')
    self.assertFalse(probe.account_policy_denial_is_attributed(denial))

  def test_account_policy_denial_response_safety_rejects_leaked_material_and_redirects(self):
    safe = probe.account_policy_denial_response_safety(
        b'{}', {}, [], 200, b'{"status":"pending"}', {}, [])
    self.assertTrue(safe['no_acceptance_or_callback'])
    unsafe_evidence = (
        probe.account_policy_denial_response_safety(
            b'{"message":"code=private-code","message":"ordinary denial"}', {}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {'Location': 'https://rp.example/callback?code=private-code'}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{"message":"x_receipt_id=private-receipt"}', {}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {'Location': 'https://rp.example/failure?x_callback_url=opaque'}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {'Location': 'https://rp.example/failure/x_receipt_id/opaque'}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {'X-Callback-URL': 'https://rp.example/callback'}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {'XCallbackUrl': 'opaque'}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {'XReceiptId': 'opaque'}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {'XAuthorizationCode': 'opaque'}, [],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {}, [{'status': 302}],
            200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            None, {}, [], 200, b'{"status":"pending"}', {}, []),
        probe.account_policy_denial_response_safety(
            b'{}', {}, [], 200, b'{"status":"accepted","callback":"private"}', {}, []),
    )
    for unsafe in unsafe_evidence:
      self.assertFalse(unsafe['no_acceptance_or_callback'])
      self.assertNotIn('private-code', repr(unsafe))

    class DuplicateLocationHeaders(dict):
      def get_all(self, _name):
        return ['https://rp.example/ordinary',
            'https://rp.example/callback?code=private-code']

    duplicate_location = probe.account_policy_denial_response_safety(
        b'{}', DuplicateLocationHeaders({'Location': 'https://rp.example/ordinary'}), [],
        200, b'{"status":"pending"}', {}, [])
    self.assertFalse(duplicate_location['no_acceptance_or_callback'])
    self.assertNotIn('private-code', repr(duplicate_location))
    self.assertTrue(safe['response_body_safe'])

  def test_interleaved_concurrent_denial_markers_are_attributed_to_their_opaque_requests(self):
    first_request = '0123456789abcdef0123456789abcdef'
    second_request = 'abcdef0123456789abcdef0123456789'
    prior = ['baseline log']
    current = prior + [
        'DEBUG Wallet account policy lookup started (signup=false, registration-enabled=false)',
        f'DEBUG Wallet account policy rejected proof (request={first_request}, signup=false, registered=false, occupied=false)',
        'DEBUG Wallet account policy occupancy observed (occupied=true)',
        f'DEBUG Wallet account policy rejected proof (request={second_request}, signup=false, registered=false, occupied=true)',
    ]
    first = probe.new_account_mapping_log_categories(prior, current, first_request)
    second = probe.new_account_mapping_log_categories(prior, current, second_request)
    first_result = probe.account_mapping_denial_result(403, 'resolved', first,
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    second_result = probe.account_mapping_denial_result(403, 'resolved', second,
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)

    self.assertEqual(first, ['account-policy-rejected'])
    self.assertEqual(second, ['account-policy-rejected'])
    self.assertTrue(probe.account_policy_denial_is_attributed(first_result))
    self.assertTrue(probe.account_policy_denial_is_attributed(second_result))
    self.assertNotIn(first_request, repr((first_result, second_result)))
    self.assertNotIn(second_request, repr((first_result, second_result)))

  def test_concurrent_account_denial_runner_observes_overlapping_flows(self):
    import threading

    barrier = threading.Barrier(3)
    completions = []
    def make_flow(name):
      def flow():
        barrier.wait(timeout=2)
        return {'outcome': 'policy_denied', 'scenario': name}
      return flow

    cases = [
        ('unmapped-account', make_flow('unmapped-account')),
        ('disabled-account', make_flow('disabled-account')),
        ('ambiguous-account', make_flow('ambiguous-account')),
    ]
    observed = probe.run_concurrent_account_denial_flows(
        cases, on_case_complete=lambda name, _outcome: completions.append(name))

    self.assertEqual(observed['max_concurrent_flows'], 3)
    self.assertEqual(set(observed['cases']), {name for name, _flow in cases})
    self.assertCountEqual(completions, [name for name, _flow in cases])

  def test_account_denial_concurrency_sanitizer_keeps_only_bounded_facts(self):
    request_id = '0123456789abcdef0123456789abcdef'
    evidence = probe.sanitize_live_checkpoint({'account_denial_concurrency': {
        'case_count': 3, 'max_concurrent_flows': 3, 'overlap_observed': True,
        'all_policy_denied': True, 'request_id': request_id}})
    self.assertEqual(evidence, {'account_denial_concurrency': {
        'case_count': 3, 'max_concurrent_flows': 3, 'overlap_observed': True,
        'all_policy_denied': True}})
    self.assertNotIn(request_id, repr(evidence))
    case = probe.account_mapping_denial_result(403, 'resolved', ['account-policy-rejected'],
        response_safety=SAFE_ACCOUNT_DENIAL_RESPONSE)
    case.update({'request_id': request_id, 'identity_id': 'private-identity'})
    case_evidence = probe.sanitize_live_checkpoint({'disabled_account_case': case})
    self.assertTrue(case_evidence['disabled_account_case']['response_body_safe'])
    self.assertTrue(case_evidence['disabled_account_case']['headers_safe'])
    self.assertTrue(case_evidence['disabled_account_case']['location_safe'])
    self.assertTrue(case_evidence['disabled_account_case']['redirects_safe'])
    self.assertTrue(case_evidence['disabled_account_case']['status_pending'])
    self.assertNotIn(request_id, repr(case_evidence))
    self.assertNotIn('private-identity', repr(case_evidence))

    inconsistent = probe.sanitize_live_checkpoint({'account_denial_concurrency': {
        'case_count': 3, 'max_concurrent_flows': 1, 'overlap_observed': True,
        'all_policy_denied': True}})
    self.assertEqual(inconsistent, {})

  def test_signup_template_starts_status_polling_for_signup_as_well_as_login(self):
    source = (Path(__file__).parents[1] / 'src/main/resources/theme-resources/templates/wallet-login.ftl').read_text()
    self.assertIn('if (walletIntent === "login" || walletIntent === "signup") {', source)


  def test_signup_requires_exact_mapping_readback_and_pkce_oidc_completion(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def signup_wallet_flow(")
    end = source.index("\ndef missing_identity_flow", start)
    body = source[start:end]
    for expected in (
        "no exact Keycloak account exists before signup proof",
        "signup proof provisions exact account before pending consume",
        "len(matched) == 1 and matched[0].get('enabled')",
        "polled == 200",
        "status_body.get('status') == 'accepted'",
        "lambda: signup_callback_from_status(",
        "callback_body.decode('utf-8', errors='replace')",
        "token_status == 200",
        "claims.get('sub') == matched[0].get('id')",
        "claims.get('decent_identity_id') == identifier",
    ):
      self.assertIn(expected, body)

  def test_authenticator_does_not_overwrite_keycloak_challenged_execution_when_rendering_wallet(self):
    source = (Path(__file__).parents[1] / 'src/main/java/org/decentwallet/keycloak/wallet/'
        'WalletChallengeAuthenticator.java').read_text()
    body = source[source.index('String accessCode = context.generateAccessCode();'):]
    body = body[:body.index('var response = context.form()')]
    self.assertNotIn('CURRENT_AUTHENTICATION_EXECUTION', body)
    self.assertNotIn('LAST_PROCESSED_EXECUTION', body)
    self.assertIn('context.getActionUrl(accessCode)', body)
  def test_signup_flow_submits_required_action_and_validates_email_on_post(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def signup_wallet_flow(")
    end = source.index("\ndef missing_identity_flow", start)
    body = source[start:end]
    self.assertIn("action_match = re.search(r'<form method=", body)
    self.assertIn("lambda: signup_callback_submission(status_body,", body)
    self.assertIn("lambda: signup_form_action(", body)
    self.assertIn("signup_contact_email(identifier)", body)
    self.assertIn("callback_status not in (302, 303) or not code", body)

  def test_signup_flow_does_not_retry_original_signup_action_after_successful_proof(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def signup_wallet_flow(")
    end = source.index("\ndef missing_identity_flow", start)
    body = source[start:end]
    proof = body.index("require(proof_status == 202")
    followup = body[proof:]
    self.assertIn("client.request('GET', status_callback)", followup)
    self.assertNotIn("wallet_intent': 'signup", followup)
    self.assertNotIn("resume_action = signup_resume_action_path", followup)

  def test_signup_flow_uses_fresh_browser_cookie_jar_after_existing_user_login(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    main = source[source.index("def main():"):]
    self.assertIn("signup_browser = Client()", main)
    self.assertIn("signup_result = signup_wallet_flow(signup_browser, signup_key, signup_identifier,", main)
    signup = main.index("signup_result = signup_wallet_flow(")
    rotation = main.index("rotation_result = stale_key_rotation_flow(")
    self.assertLess(signup, rotation)

  def test_disposable_realm_registers_email_login_and_preserves_unique_emails(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def configure_realm(")
    end = source.index("\ndef der(", start)
    block = source[start:end]
    self.assertIn("'registrationAllowed': True", block)
    self.assertIn("'verifyEmail': False", block)
    self.assertIn("'loginWithEmailAllowed': True", block)
    self.assertIn("'duplicateEmailsAllowed': False", block)
    self.assertIn("'browserFlow': alias, 'loginWithEmailAllowed': True", block)


  def test_disposable_oidc_client_exposes_the_exact_identity_attribute_as_a_signed_claim(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def configure_realm(')
    end = source.index('\ndef der(', start)
    configure = source[start:end]
    self.assertIn("'protocolMappers': [{", configure)
    self.assertIn("'protocolMapper': 'oidc-usermodel-attribute-mapper'", configure)
    self.assertIn("'user.attribute': 'decent_identity_id'", configure)
    self.assertIn("'claim.name': 'decent_identity_id'", configure)
    self.assertIn("'id.token.claim': 'true'", configure)
    self.assertIn("claims.get('decent_identity_id') == identifier", source)
    self.assertIn("ensureEnabledUser", (Path(__file__).parents[1] / 'src/main/java/org/decentwallet/keycloak/wallet/WalletLoginTransportHandler.java').read_text())

  def test_disposable_realm_seeds_one_existing_identity_mapping_with_a_valid_email(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def configure_realm(")
    end = source.index("\ndef der(", start)
    block = source[start:end]
    self.assertIn("'users': [{", block)
    self.assertIn("'email': 'wallet-owner@example.com', 'emailVerified': True", block)
    self.assertIn("'attributes': {'decent_identity_id': [identifier]}", block)
    self.assertNotIn("'email': identifier", block)
    self.assertNotIn("/users', {\n          'username': 'wallet-owner'", block)

  def test_prompt_create_is_not_used_and_signup_fixture_runs_in_full_probe(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    main = source[source.index("def main():"):]
    self.assertNotIn("provision_exact_identity_user(", main)
    signup_flow = source[source.index("def signup_wallet_flow("):source.index("\ndef missing_identity_flow")]
    self.assertIn("signup proof provisions exact account before pending consume", signup_flow)
    self.assertIn("signup_result = signup_wallet_flow(signup_browser, signup_key, signup_identifier,", main)
    self.assertIn("label='wallet-login-signup'", main)


  def test_signup_action_unescapes_html_ampersands_before_posting(self):
    action = ('/auth/realms/demo/login-actions/authenticate?session_code=opaque'
        '&amp;execution=exec&amp;client_id=public&amp;tab_id=tab')
    action_url = probe.signup_action_path(action, 'https://idp.example:18886/auth/')
    parsed = __import__('urllib.parse', fromlist=['urlsplit']).urlsplit(action_url)
    values = __import__('urllib.parse', fromlist=['parse_qs']).parse_qs(parsed.query)
    self.assertEqual('/auth/realms/demo/login-actions/authenticate', parsed.path)
    self.assertEqual({'session_code': ['opaque'], 'execution': ['exec'],
        'client_id': ['public'], 'tab_id': ['tab']}, values)

  def test_signup_login_action_and_post_preserve_initiating_browser_cookie_jar(self):
    events = []
    class FakeClient:
      def request(self, method, path, data=None, headers=None, timeout=10):
        events.append((method, path, data, headers))
        if method == "GET" and "protocol/openid-connect/auth" in path:
          html = ('<p id="wallet-locator">https://idp.example:18886/auth/realms/wallet-e2e/'
              'decent-wallet-login/v1/transactions/' + 'A' * 43 + '</p>'
              '<form method="post" action="/auth/action?session_code=opaque&execution=e">'
              '<input type="hidden" name="wallet_intent" value="signup"></form>')
          return 200, {}, html.encode()
        if method == "POST" and path.startswith("/auth/action?"):
          return 200, {}, b"signup-intent-bound-to-new-transaction"
        raise AssertionError((method, path))
    with self.assertRaisesRegex(RuntimeError, "fresh wallet transaction is bound to signup intent"):
      probe.signup_wallet_flow(FakeClient(), Path("missing-key"), "identity", "container", FakeClient(), lambda *_: None, "sha256:" + "a" * 64)
    posts = [event for event in events if event[0] == "POST"]
    self.assertEqual(1, len(posts))
    self.assertEqual("/auth/action?session_code=opaque&execution=e", posts[0][1])
    self.assertEqual(b"wallet_intent=signup", posts[0][2])
    self.assertEqual("application/x-www-form-urlencoded", posts[0][3]["Content-Type"])


if __name__ == "__main__":
  unittest.main()
