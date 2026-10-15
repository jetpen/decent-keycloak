"""Regression coverage for the Keycloak login-to-signup intent action."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("WALLET_IT_NATIVE_LIBS", "/unused-test-library-path")
sys.path.insert(0, str(Path(__file__).parent))
import wallet_login_live_e2e as probe  # noqa: E402


class SignupIntentProbeTest(unittest.TestCase):
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
    self.assertIn("signup_callback_from_status(status_body,", body)
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

  def test_signup_requires_exact_mapping_readback_and_pkce_oidc_completion(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    start = source.index("def signup_wallet_flow(")
    end = source.index("\ndef missing_identity_flow", start)
    body = source[start:end]
    for expected in (
        "len(matched) == 1 and matched[0].get('enabled')",
        "polled == 200",
        "status_body.get('status') == 'accepted'",
        "signup_callback_from_status(status_body,",
        "callback_body.decode('utf-8', errors='replace')",
        "token_status == 200",
        "claims.get('sub') == matched[0].get('id')",
        "claims.get('decent_identity_id') == identifier",
        "signup proof provisions exact account before pending consume",
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
    self.assertIn("callback_method, callback_path, callback_data = signup_callback_submission", body)
    self.assertIn("profile_path, profile_data = signup_form_action", body)
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
    self.assertIn("signup_wallet_flow(signup_browser, signup_key, signup_identifier, container)", main)


    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    main = source[source.index("def main():"):]
    signup = main.index("result['signup_case'] = signup_wallet_flow(")
    rotation = main.index("result['rotated_identity_case'] = stale_key_rotation_flow(")
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
    self.assertIn("'email': identifier, 'emailVerified': True", block)
    self.assertNotIn("/users', {\n          'username': 'wallet-owner'", block)

  def test_prompt_create_is_not_used_and_signup_fixture_runs_in_full_probe(self):
    source = Path(__file__).with_name("wallet_login_live_e2e.py").read_text()
    main = source[source.index("def main():"):]
    self.assertNotIn("provision_exact_identity_user(", main)
    signup_flow = source[source.index("def signup_wallet_flow("):source.index("\ndef missing_identity_flow")]
    self.assertIn("signup proof provisions exact account before pending consume", signup_flow)
    self.assertIn("result['signup_case'] = signup_wallet_flow(signup_browser, signup_key, signup_identifier, container)", main)
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
      probe.signup_wallet_flow(FakeClient(), Path("missing-key"), "identity", "container")
    posts = [event for event in events if event[0] == "POST"]
    self.assertEqual(1, len(posts))
    self.assertEqual("/auth/action?session_code=opaque&execution=e", posts[0][1])
    self.assertEqual(b"wallet_intent=signup", posts[0][2])
    self.assertEqual("application/x-www-form-urlencoded", posts[0][3]["Content-Type"])


if __name__ == "__main__":
  unittest.main()
