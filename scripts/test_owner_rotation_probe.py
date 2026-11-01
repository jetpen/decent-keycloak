from __future__ import annotations

import ast
import contextlib
import json
import io
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

PROJECT = Path(__file__).parents[1]
LIVE_PROBE = PROJECT / 'scripts/wallet_login_live_e2e.py'
sys.path.insert(0, str(Path(__file__).parent))
import wallet_login_live_e2e as live  # noqa: E402
import rotation_registry_roundtrip as rotation_helper  # noqa: E402


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
    self.assertIn("'--checkpoint', str(helper_checkpoint_path)", flow)
    self.assertIn("str(old_key_in_tools)", flow)
    self.assertIn("str(new_key_in_tools)", flow)
    assert "readback[0] == str(expected_sequence)" in flow
    assert "separate Identity resolver confirms sequence {expected_sequence} and exact successor key" in flow
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
    self.assertIn('expected_sequence=3, authorizing_keys=(rotated_old_key,)', main)

  def test_rotation_helper_uses_registry_predecessor_and_publish_readback_apis(self):
    helper = (PROJECT / 'scripts/rotation_registry_roundtrip.py').read_text()
    self.assertEqual(helper, (PROJECT / 'container/rotation_registry_roundtrip.py').read_text())
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

  def test_rotation_helper_checkpoint_is_fixed_schema_and_redacts_exception_text(self):
    with TemporaryDirectory() as temp:
      path = Path(temp) / 'rotation-checkpoint.json'
      category = rotation_helper.classify_rotation_failure(
          ValueError('sensitive identifier=rotation-fixture@example.invalid'))
      self.assertEqual('registry_validation_error', category)
      rotation_helper.write_rotation_checkpoint(
          path, 'registry_publish', 'failed', category)

      expected = {
          'failure_category': 'registry_validation_error',
          'stage': 'registry_publish',
          'status': 'failed',
      }
      self.assertEqual(expected, json.loads(path.read_text()))
      self.assertNotIn('sensitive', path.read_text())
      self.assertEqual(expected, rotation_helper.read_rotation_checkpoint(path))

  def test_rotation_helper_checkpoint_classifies_known_validation_failure(self):
    category = rotation_helper.classify_rotation_failure(
        ValueError('legacy owner rotation proof signer_id must be null'))
    self.assertEqual('rotation_proof_signer_invalid', category)

  def test_rotation_helper_entrypoint_retains_only_sanitized_child_failure(self):
    with TemporaryDirectory() as temp:
      root = Path(temp)
      checkpoint = root / 'rotation-checkpoint.json'
      argv = [
          'rotation_registry_roundtrip.py', '--identifier', 'fixture@example.invalid',
          '--old-key', str(root / 'old.pem'), '--new-key', str(root / 'new.pem'),
          '--bootstrap', '127.0.0.1', '--datastore', str(root / 'db'),
          '--envelope', str(root / 'envelope.cbor'), '--readback', str(root / 'readback.txt'),
          '--checkpoint', str(checkpoint),
      ]

      def fail_with_sensitive_message(*_args):
        raise ValueError('sensitive identifier=fixture@example.invalid')

      output = io.StringIO()
      with patch('sys.argv', argv), patch.dict(sys.modules,
          {'trio': SimpleNamespace(run=fail_with_sensitive_message)}), \
          contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
        rotation_helper.main()

      self.assertEqual(1, raised.exception.code)
      self.assertEqual('rotation_helper_failure=registry_validation_error\n', output.getvalue())
      self.assertEqual({
          'failure_category': 'registry_validation_error',
          'stage': 'owner_key_load',
          'status': 'failed',
      }, rotation_helper.read_rotation_checkpoint(checkpoint))
      self.assertNotIn('fixture@example.invalid', checkpoint.read_text())

  def test_rotation_helper_entrypoint_marks_successful_checkpoint_as_passed(self):
    with TemporaryDirectory() as temp:
      root = Path(temp)
      checkpoint = root / 'rotation-checkpoint.json'
      argv = [
          'rotation_registry_roundtrip.py', '--identifier', 'fixture@example.invalid',
          '--old-key', str(root / 'old.pem'), '--new-key', str(root / 'new.pem'),
          '--bootstrap', '127.0.0.1', '--datastore', str(root / 'db'),
          '--envelope', str(root / 'envelope.cbor'), '--readback', str(root / 'readback.txt'),
          '--checkpoint', str(checkpoint),
      ]

      def complete_rotation(_function, args):
        args._rotation_stage = 'complete'
        rotation_helper.write_rotation_checkpoint(args.checkpoint, 'complete', 'running')

      with patch('sys.argv', argv), patch.dict(sys.modules,
          {'trio': SimpleNamespace(run=complete_rotation)}):
        rotation_helper.main()

      self.assertEqual({'stage': 'complete', 'status': 'passed'},
          rotation_helper.read_rotation_checkpoint(checkpoint))

  def test_rotation_helper_checkpoint_rejects_unknown_stage_and_extra_fields(self):
    with TemporaryDirectory() as temp:
      path = Path(temp) / 'rotation-checkpoint.json'
      with self.assertRaises(ValueError):
        rotation_helper.write_rotation_checkpoint(path, 'arbitrary path', 'failed', 'other')
      path.write_text(json.dumps({
          'failure_category': 'other', 'stage': 'registry_publish', 'status': 'failed',
          'raw_exception': 'do not retain',
      }))
      self.assertIsNone(rotation_helper.read_rotation_checkpoint(path))

  def test_rotation_helper_diagnostic_survives_stage_checkpoint_projection(self):
    result = {}

    live.checkpoint_rotation_stage(result, 'publish', {
        'rotation_publish': 'failed',
        'rotation_helper_stage': 'predecessor_envelope_read',
        'rotation_helper_failure_category': 'predecessor_unavailable',
    }, lambda: None)

    self.assertEqual('predecessor_envelope_read',
        result['rotated_identity_case']['rotation_helper_stage'])
    self.assertEqual('predecessor_unavailable',
        result['rotated_identity_case']['rotation_helper_failure_category'])

  def test_rotation_helper_diagnostic_survives_final_checkpoint_sanitizer(self):
    candidate = {'rotated_identity_case': {
        'stage': 'publish',
        'rotation_publish': 'failed',
        'rotation_helper_stage': 'registry_publish',
        'rotation_helper_failure_category': 'predecessor_history_unavailable',
    }}

    self.assertEqual(candidate, live.sanitize_live_checkpoint(candidate))


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
