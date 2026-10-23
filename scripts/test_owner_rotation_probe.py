from __future__ import annotations

import ast
import unittest
from pathlib import Path

PROJECT = Path(__file__).parents[1]
LIVE_PROBE = PROJECT / 'scripts/wallet_login_live_e2e.py'


class OwnerRotationProbeTest(unittest.TestCase):
  @staticmethod
  def _function(source: str, name: str) -> str:
    module = ast.parse(source)
    function = next(node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == name)
    result = ast.get_source_segment(source, function)
    if result is None:
      raise AssertionError(f'could not recover function source: {name}')
    return result

  def test_rotation_helper_publishes_and_reads_exact_new_key_before_proof_requests(self):
    source = LIVE_PROBE.read_text()
    flow = self._function(source, 'stale_key_rotation_flow')

    self.assertIn("helper = project / 'scripts/rotation_registry_roundtrip.py'", flow)
    self.assertNotIn("str(PROJECTS / 'decent-registry/.venv/bin/python')", flow)
    self.assertIn("'/opt/decent-resolver/rotation_registry_roundtrip.py'", flow)
    self.assertIn("str(old_key_in_tools)", flow)
    self.assertIn("str(new_key_in_tools)", flow)
    assert "separate Identity resolver confirms seq 2 and exact successor key" in flow
    assert "status == 401" in flow
    assert "rotation_browser, rotation_csrf" in flow
    assert "current_browser, current_csrf" in flow
    assert "submit_signed(key, label, proof_envelope, transaction_locator, browser=None, csrf_token=None)" in flow
    assert "json.loads(stale_body) == {'status': 'pending'}" in flow
    assert "current_key_status == 202" in flow
    assert "start_rotation_transaction()" in flow
    assert "callback.startswith(f'https://idp.example:{KC_PORT}/auth/')" in flow

  def test_live_entry_point_rotates_the_same_mapped_identity_not_a_fixture_pair(self):
    main = self._function(LIVE_PROBE.read_text(), 'main')
    self.assertEqual(main.count("label='wallet-login-rotated'"), 1)
    self.assertIn("rotated_key = generate_owner_key(temp, 'wallet-login-rotated-successor', IMAGE)", main)
    self.assertIn("rotation_result = stale_key_rotation_flow(", main)

  def test_rotation_helper_uses_registry_predecessor_and_publish_readback_apis(self):
    helper = (PROJECT / 'scripts/rotation_registry_roundtrip.py').read_text()
    module = ast.parse(helper)
    rotate = next(node for node in module.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == 'rotate_and_confirm')
    rotate_source = ast.get_source_segment(helper, rotate)
    self.assertIsNotNone(rotate_source)
    assert rotate_source is not None
    self.assertIn('predecessor_signed_update(', rotate_source)
    self.assertIn('state_fields(predecessor)', rotate_source)
    self.assertIn('draft_identity_bundle(', rotate_source)
    self.assertIn('OPERATION_OWNER_KEY_ROTATION', rotate_source)
    self.assertIn('predecessor_state_hash=predecessor_hash', rotate_source)
    self.assertIn('finalized_envelope_cbor=envelope', rotate_source)
    self.assertIn('put_identity(', rotate_source)
    self.assertIn('get_identity_record(', rotate_source)
    self.assertIn('observed.seq == expected_seq', rotate_source)
    self.assertIn('observed.owner_public_key_hex == expected_key', rotate_source)
    self.assertIn('trio.run(rotate_and_confirm, args)', helper)


  def test_live_probe_signing_inputs_use_short_lived_private_tempfiles(self):
    source = LIVE_PROBE.read_text()
    auth = self._function(source, 'auth_flow')
    denied = self._function(source, 'account_mapping_denial_flow')
    rotation = self._function(source, 'stale_key_rotation_flow')
    signup = self._function(source, 'signup_wallet_flow')
    for body in (auth, denied, rotation, signup):
      self.assertIn('write_private_signing_input(', body)
      self.assertIn("os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)", source)
      self.assertIn("unlink(missing_ok=True)", body)
    self.assertNotIn("Path(SCRATCH) / f'wallet-login-", rotation)
    self.assertNotIn("Path(SCRATCH) / f'signup-signing-", signup)
    self.assertNotIn("'-signing-input.json'", denied)

    main = self._function(LIVE_PROBE.read_text(), 'main')
    self.assertEqual(main.count("label='wallet-login-rotated'"), 1)
    self.assertIn("rotated_key = generate_owner_key(temp, 'wallet-login-rotated-successor', IMAGE)", main)
    self.assertIn("client, rotated_old_key, rotated_key, rotated_identifier", main)
    self.assertNotIn("identity_id=rotated_identifier", main)

  def test_rotation_fixture_publishes_old_identity_once_and_only_generates_successor_key_locally(self):
    main = self._function(LIVE_PROBE.read_text(), 'main')
    rotation_start = main.index("rotated_old_key, rotated_wrapper, rotated_identifier = write_identity(")
    rotation_end = main.index("rotated_key = generate_owner_key(temp, 'wallet-login-rotated-successor', IMAGE)", rotation_start)
    setup = main[rotation_start:rotation_end]
    self.assertEqual(setup.count('write_identity('), 1)
    self.assertNotIn('identity_id=', setup)
    self.assertIn("client, rotated_old_key, rotated_key, rotated_identifier", main)

  def test_login_template_uses_same_post_intent_not_action_url_as_submit_target(self):
    template = Path(__file__).parents[1].joinpath(
        'src/main/resources/theme-resources/templates/wallet-login.ftl').read_text()
    form = template[template.index('<form method="post"'):template.index('</form>')]
    self.assertIn('name="wallet_intent" value="signup"', form)
    self.assertIn('action="${url.loginAction?no_esc}"', form)
    self.assertNotIn('session_code', form)
    self.assertNotIn('execution', form)

  def test_signup_intent_flow_uses_keycloak_action_and_no_prompt_create(self):
    source = LIVE_PROBE.read_text()
    helper = self._function(source, 'signup_wallet_flow')
    self.assertIn("'wallet_intent': 'signup'", helper)
    self.assertIn('action_data', helper)
    source = Path(__file__).parents[1].joinpath(
        'src/main/java/org/decentwallet/keycloak/wallet/WalletChallengeAuthenticator.java').read_text()
    java_action = source[source.index('public void action('):source.index('static boolean isSingleExactHttpsRedirect')]
    self.assertIn('initialAuthSession.setClientNote', java_action)
    self.assertIn('authSession.setAuthNote(SIGNUP_AUTH_NOTE', source)
    self.assertIn('context.resetFlow(() -> initialAuthSession.setClientNote', java_action)
    self.assertNotIn("'prompt': 'create'", helper)

  def test_authenticate_uses_signup_intent_from_authentication_session_client_note(self):
    java = Path(__file__).parents[1].joinpath(
        'src/main/java/org/decentwallet/keycloak/wallet/WalletChallengeAuthenticator.java').read_text()
    self.assertIn('"signup".equals(authSession.getClientNote(SIGNUP_AUTH_NOTE))', java)
    self.assertIn('authSession.setAuthNote(SIGNUP_AUTH_NOTE, "signup")', java)
    self.assertIn('store.issue(binding, signupIntent', java)

  def test_live_entry_point_runs_rotation_with_separate_mapped_identity(self):
    source = LIVE_PROBE.read_text()
    main_body = self._function(source, 'main')
    self.assertIn("rotation_result = stale_key_rotation_flow(", main_body)
    self.assertIn("rotated_old_key, rotated_wrapper, rotated_identifier = write_identity(", main_body)
    self.assertIn("rotated_key = generate_owner_key(temp, 'wallet-login-rotated-successor', IMAGE)", main_body)
    self.assertIn("client, rotated_old_key, rotated_key, rotated_identifier", main_body)
    self.assertIn('local_mapping_persisted', main_body)


if __name__ == '__main__':
  unittest.main()
