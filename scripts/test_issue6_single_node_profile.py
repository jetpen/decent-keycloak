"""Focused Issue #6 acceptance-profile regressions."""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

import wallet_login_live_e2e as probe  # noqa: E402


class Issue6SingleNodeProfileTest(unittest.TestCase):
  def test_profile_dispatch_is_separate_from_broad_e2e_matrix(self):
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue6-single-node'}):
      with patch.object(probe, 'resolve_immutable_image',
          side_effect=AssertionError('broad E2E path selected')):
        with patch.object(probe, 'run_issue6_single_node_profile', create=True) as selected:
          probe.main()
    selected.assert_called_once_with()

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

  def test_callback_replay_requires_registered_redirect_and_no_code(self):
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
    }, valid)

    wrong_target = probe.callback_replay_outcome(
        302,
        'https://attacker.example/callback?state=state-1&error=access_denied',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertFalse(wrong_target['redirect_uri_matches'])
    self.assertFalse(wrong_target['state_preserved'])

    code_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&code=reused',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertTrue(code_replay['authorization_code_returned'])
    self.assertFalse(code_replay['error_returned'])

    empty_error_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=&code=',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertFalse(empty_error_replay['error_returned'])
    self.assertTrue(empty_error_replay['authorization_code_returned'])

    duplicate_error_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=first&error=second',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertFalse(duplicate_error_replay['error_returned'])

    empty_code_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=access_denied&code=',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertTrue(empty_code_replay['authorization_code_returned'])

    duplicate_code_replay = probe.callback_replay_outcome(
        302,
        'https://rp.example/callback?state=state-1&error=access_denied&code=one&code=two',
        'state-1',
        'https://rp.example/callback',
    )
    self.assertTrue(duplicate_code_replay['authorization_code_returned'])

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

  def test_auth_flow_failure_checkpoints_allowlisted_status_without_error_text(self):
    result = {'issue6_single_node': {'stage': 'auth_flow', 'node_count': 1}}
    checkpoints = []
    attempt = probe.AuthFlowAttempt()
    attempt.record('proof_post_http', 202)

    with self.assertRaises(probe.AuthFlowFailure) as raised:
      probe.run_issue6_auth_flow(
          result,
          attempt,
          lambda: (_ for _ in ()).throw(RuntimeError('raw secret-bearing failure')),
          lambda: checkpoints.append(probe.sanitize_live_checkpoint(result)),
      )

    self.assertEqual(1, len(checkpoints))
    self.assertEqual(202, checkpoints[0]['issue6_single_node']['proof_post_http'])
    self.assertNotIn('raw secret-bearing failure', str(raised.exception))

  def test_profile_checkpoint_keeps_only_bounded_single_node_evidence(self):
    projected = probe.sanitize_live_checkpoint({'issue6_single_node': {
        'stage': 'auth_flow_failed', 'node_count': 1,
        'keycloak_version': '26.8.0', 'proof_post_http': 202,
        'callback_replay_http': 302, 'callback_replay_redirect_uri_matches': True,
        'callback_replay_state_preserved': True, 'callback_replay_error_returned': True,
        'callback_replay_code_returned': False, 'failure_gate': 'pkce',
        'callback_url': 'https://secret.example/callback?code=secret',
        'raw_error': 'sensitive diagnostic text',
    }})['issue6_single_node']
    self.assertEqual(1, projected['node_count'])
    self.assertEqual(202, projected['proof_post_http'])
    self.assertTrue(projected['callback_replay_redirect_uri_matches'])
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
          'single_use_object_provider_path': 'infinispan',
          'single_use_object_provider_ids': ['infinispan'],
          'runtime_qualification_status': 'runtime_facts_verified',
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
        expiry_flow = stack.enter_context(patch.object(probe, 'expiry_acceptance_flow',
            side_effect=lambda *_args, **_kwargs: events.append('expiry_flow') or {
                'stage': 'complete', 'profile': 'expiry', 'lifetime_seconds': 300,
                'wait_seconds': 301, 'proof_http': 404, 'status_http': 404,
                'fresh_login_transaction_available': True}))
        stack.enter_context(patch.object(probe, 'capture_live_resolver_diagnostics', return_value=[]))
        cleanup = stack.enter_context(patch.object(probe, 'finish_owned_cleanup', return_value=0))

        probe.run_issue6_single_node_profile()

      start_tools.assert_called_once()
      start_registry.assert_called_once()
      start_keycloak.assert_called_once()
      auth_flow.assert_called_once()
      expiry_flow.assert_called_once()
      self.assertEqual(['auth_flow', 'expiry_flow'], events)
      cleanup.assert_called_once_with(registry_node, 'resolver-tools-id')

  def test_ci_and_documented_unittest_commands_include_profile_module(self):
    root = Path(probe.__file__).parents[1]
    workflow = (root / '.github/workflows/acceptance.yml').read_text()
    readme = (root / 'README.md').read_text()
    self.assertIn('scripts.test_issue6_single_node_profile', workflow)
    self.assertGreaterEqual(readme.count('scripts.test_issue6_single_node_profile'), 2)


if __name__ == '__main__':
  unittest.main()
