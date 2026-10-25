import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

from wallet_login_live_e2e import (  # noqa: E402
    b64url,
    classify_identity_lookup,
    expiry_acceptance_flow,
    run_acceptance_profile,
    sanitize_live_checkpoint,
    selected_acceptance_profile,
)


class AuthStatusBindingProbeTest(unittest.TestCase):
  def test_real_e2e_flow_tests_wrong_session_contexts_before_acceptance(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    start = source.index('def auth_flow(')
    end = source.index('\ndef negative_proof_flow(', start)
    body = source[start:end]
    self.assertIn("'wrong_client'", body)
    self.assertIn("'wrong_tab'", body)
    self.assertIn("'wrong_realm'", body)
    self.assertIn('wrong_binding_statuses', body)
    self.assertIn('all(status == 404 for status in wrong_binding_statuses.values())', body)


  def test_expiry_profile_runs_expiry_branch_and_persists_sanitized_checkpoint(self):
    import json
    import wallet_login_live_e2e as probe

    calls = []
    waits = []
    progress = []
    locator_a = f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/' + 'a' * 43
    locator_b = f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/' + 'b' * 43
    status_url = f'/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/' + 'a' * 43 + '/status'
    csrf = 'C' * 43

    def login_page(locator):
      return (f'<p id="wallet-locator">{locator}</p>'
          f'<script>const csrfToken = "{csrf}"; const statusUrl = "{status_url}";</script>').encode()

    class FakeClient:
      redirect_on_expired_proof = False
      redirect_on_expired_status = False

      def __init__(self):
        self.index = len(calls)
        self.login_count = 0
        self.redirects = []
        calls.append([])

      def request(self, method, path, data=None, headers=None, timeout=10):
        calls[self.index].append((method, path, data, headers))
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          self.login_count += 1
          locator = locator_a if self.login_count == 1 else locator_b
          return 200, {}, login_page(locator)
        if method == 'GET' and path == locator_a:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge-value', 'csrf_token': csrf}).encode()
        if method == 'POST' and path == locator_a:
          proof = json.loads(data)
          if proof['challenge'] != 'challenge-value' or proof['identity_id'] != 'fixture-id':
            raise AssertionError('proof does not bind to the fresh pending transaction')
          if self.redirect_on_expired_proof:
            self.redirects.append({'status': 302, 'target_query_names': ['code', 'state']})
          return 404, {}, b''
        if method == 'GET' and path == status_url:
          if self.redirect_on_expired_status:
            self.redirects.append({'status': 302, 'target_query_names': ['code', 'state']})
          return 404, {}, b''
        if method == 'GET' and path == locator_b:
          return 200, {}, b'{}'
        raise AssertionError('unexpected expiry request')

    def expiry_branch():
      return probe.expiry_acceptance_flow(None, 'fixture-id', client_factory=FakeClient,
          wait=waits.append,
          signer=lambda envelope, identity: json.dumps({'profile': envelope['profile'],
              'challenge': envelope['challenge'], 'identity_id': identity,
              'signature': 'A' * 86}).encode(),
          progress=lambda stage, fields: progress.append((stage,
              sanitize_live_checkpoint({'expiry_case': fields})['expiry_case'])))

    FakeClient.redirect_on_expired_proof = True
    with self.assertRaisesRegex(RuntimeError, 'expired proof response redirected'):
      expiry_branch()
    calls.clear()
    waits.clear()
    progress.clear()

    FakeClient.redirect_on_expired_proof = False
    FakeClient.redirect_on_expired_status = True
    with self.assertRaisesRegex(RuntimeError, 'expired status response redirected'):
      expiry_branch()
    FakeClient.redirect_on_expired_status = False
    calls.clear()
    waits.clear()
    progress.clear()

    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'expiry'}):
      profile = selected_acceptance_profile()
    self.assertEqual('expiry', profile)
    selected = run_acceptance_profile(profile, expiry_branch,
        lambda: self.fail('expiry profile must not execute the full matrix'))
    checkpoint = sanitize_live_checkpoint(selected)

    self.assertEqual([301], waits)
    self.assertEqual([3, 2, 1], [len(requests) for requests in calls])
    self.assertEqual(['GET', 'GET', 'GET'], [request[0] for request in calls[0]])
    self.assertEqual(['GET', 'POST'], [request[0] for request in calls[1]])
    self.assertEqual(locator_a, calls[1][1][1])
    self.assertEqual(csrf, calls[0][1][3]['X-Decent-CSRF'])
    self.assertIn('/protocol/openid-connect/auth?', calls[0][2][1])
    self.assertEqual(['GET'], [request[0] for request in calls[2]])
    self.assertEqual(locator_b, calls[2][0][1])
    self.assertEqual(['transaction_issued', 'challenge_fetched', 'proof_submitted',
        'expired_denied', 'fresh_login', 'fresh_login'],
        [stage for stage, _ in progress])
    self.assertEqual(200, progress[0][1]['login_page_http'])
    self.assertEqual(200, progress[1][1]['challenge_http'])
    self.assertEqual('complete', checkpoint['expiry_case']['stage'])
    self.assertEqual('expiry', checkpoint['expiry_case']['profile'])
    self.assertEqual(300, checkpoint['expiry_case']['lifetime_seconds'])
    self.assertEqual(404, checkpoint['expiry_case']['proof_http'])
    self.assertEqual(404, checkpoint['expiry_case']['status_http'])
    self.assertTrue(checkpoint['expiry_case']['proof_body_empty'])
    self.assertTrue(checkpoint['expiry_case']['status_body_empty'])
    self.assertFalse(checkpoint['expiry_case']['proof_location_present'])
    self.assertFalse(checkpoint['expiry_case']['proof_redirect_followed'])
    self.assertFalse(checkpoint['expiry_case']['status_location_present'])
    self.assertFalse(checkpoint['expiry_case']['status_redirect_followed'])
    self.assertFalse(checkpoint['expiry_case']['accepted_status'])
    self.assertFalse(checkpoint['expiry_case']['oidc_code_exposed'])
    self.assertFalse(checkpoint['expiry_case']['status_callback_exposed'])
    self.assertTrue(checkpoint['expiry_case']['fresh_login_transaction_available'])
    self.assertEqual(200, checkpoint['expiry_case']['fresh_challenge_http'])
    self.assertNotIn('callback_url', checkpoint['expiry_case'])
    self.assertNotIn('identity_id', checkpoint['expiry_case'])
    unsafe = sanitize_live_checkpoint({'expiry_case': {'stage': 'complete', 'profile': 'expiry',
        'proof_http': 404, 'proof_body_empty': True, 'identity_id': 'private-id',
        'signature': 'private-signature', 'callback_url': 'https://rp.example/?code=secret',
        'fresh_login_transaction_available': 'true'}})
    self.assertEqual({'stage': 'complete', 'profile': 'expiry', 'proof_http': 404,
        'proof_body_empty': True}, unsafe['expiry_case'])
    with self.assertRaises(ValueError):
      run_acceptance_profile('multi-node', expiry_branch, lambda: None)
    with self.assertRaisesRegex(ValueError, 'issue6-single-node'):
      selected_acceptance_profile({'WALLET_IT_PROFILE': 'unknown'})

  def test_single_node_profile_runs_auth_then_expiry_with_bounded_checkpoint(self):
    events = []
    checkpoints = []

    def auth_flow():
      events.append('auth_flow')
      return {'wallet_login': {'proof_post_http': 202, 'changed_retry_denied': True}}

    def expiry_flow():
      events.append('expiry_flow')
      return {'stage': 'complete', 'profile': 'expiry', 'lifetime_seconds': 300,
          'wait_seconds': 301, 'proof_http': 404, 'proof_body_empty': True,
          'status_http': 404, 'status_body_empty': True,
          'fresh_login_transaction_available': True}

    selected = run_acceptance_profile('issue6-single-node', expiry_flow, auth_flow,
        checkpoint=lambda snapshot: checkpoints.append(sanitize_live_checkpoint(snapshot)))
    final = sanitize_live_checkpoint(selected)

    self.assertEqual(['auth_flow', 'expiry_flow'], events)
    self.assertEqual(2, len(checkpoints))
    self.assertEqual(202, checkpoints[0]['wallet_login']['proof_post_http'])
    self.assertNotIn('expiry_case', checkpoints[0])
    self.assertEqual(['auth_flow'], checkpoints[0]['issue6_single_node_case']['phase_order'])
    self.assertFalse(checkpoints[0]['issue6_single_node_case']['expiry_flow_complete'])
    self.assertEqual('issue6-single-node', selected['profile'])
    self.assertFalse(selected['broad_matrix_started'])
    self.assertEqual('complete', final['issue6_single_node_case']['stage'])
    self.assertEqual(['auth_flow', 'expiry_flow'], final['issue6_single_node_case']['phase_order'])
    self.assertTrue(final['issue6_single_node_case']['auth_flow_complete'])
    self.assertTrue(final['issue6_single_node_case']['expiry_flow_complete'])
    inconsistent = sanitize_live_checkpoint({'issue6_single_node_case': {
        'stage': 'complete', 'auth_flow_complete': True,
        'expiry_flow_complete': False, 'phase_order': ['auth_flow']}})
    self.assertNotIn('issue6_single_node_case', inconsistent)
    self.assertEqual(202, final['wallet_login']['proof_post_http'])
    self.assertEqual(301, final['expiry_case']['wait_seconds'])
    self.assertEqual(404, final['expiry_case']['proof_http'])
    self.assertTrue(final['expiry_case']['fresh_login_transaction_available'])
    unsafe = sanitize_live_checkpoint({'expiry_case': {'stage': 'complete',
        'proof_http': 404, 'identity_id': 'private-id', 'signature': 'private-signature',
        'callback_url': 'https://rp.example/?code=secret'}})
    self.assertNotIn('identity_id', unsafe['expiry_case'])
    self.assertNotIn('signature', unsafe['expiry_case'])
    self.assertNotIn('callback_url', unsafe['expiry_case'])

    def expiry_failure():
      raise RuntimeError('expiry failed')

    failed_checkpoints = []
    with self.assertRaisesRegex(RuntimeError, 'expiry failed'):
      run_acceptance_profile('issue6-single-node', expiry_failure, auth_flow,
          checkpoint=lambda snapshot: failed_checkpoints.append(
              sanitize_live_checkpoint(snapshot)))
    self.assertEqual(1, len(failed_checkpoints))
    self.assertEqual(202, failed_checkpoints[0]['wallet_login']['proof_post_http'])
    self.assertEqual(['auth_flow'], failed_checkpoints[0]['issue6_single_node_case']['phase_order'])
    self.assertFalse(failed_checkpoints[0]['issue6_single_node_case']['expiry_flow_complete'])

  def test_auth_flow_profile_does_not_run_expiry(self):
    events = []
    checkpoints = []

    def auth_flow():
      events.append('auth_flow')
      return {'wallet_login': {'proof_post_http': 202}}

    def forbidden_expiry():
      events.append('expiry_flow')
      raise AssertionError('expiry must be explicitly authorized')

    self.assertEqual('issue6-auth-flow',
        selected_acceptance_profile({'WALLET_IT_PROFILE': 'issue6-auth-flow'}))
    selected = run_acceptance_profile('issue6-auth-flow', forbidden_expiry, auth_flow,
        checkpoint=lambda snapshot: checkpoints.append(sanitize_live_checkpoint(snapshot)))

    self.assertEqual(['auth_flow'], events)
    self.assertEqual('issue6-auth-flow', selected['profile'])
    self.assertFalse(selected['broad_matrix_started'])
    self.assertEqual(['auth_flow'], selected['issue6_single_node_case']['phase_order'])
    self.assertTrue(selected['issue6_single_node_case']['auth_flow_complete'])
    self.assertFalse(selected['issue6_single_node_case']['expiry_flow_complete'])
    self.assertEqual('auth_flow_complete', selected['issue6_single_node_case']['stage'])
    self.assertNotIn('expiry_case', selected)
    self.assertEqual(202, checkpoints[0]['wallet_login']['proof_post_http'])

  def test_keycloak_nonzero_run_recovers_verified_cid_before_credential_unlink(self):
    import subprocess
    import tempfile
    from pathlib import Path
    import wallet_login_live_e2e as probe
    identifier = 'e' * 64
    events = []
    def fake_run(argv, **kwargs):
      if argv[0] == 'ss':
        return subprocess.CompletedProcess(argv, 0, '', '')
      if argv[0:2] == ['podman', 'run']:
        cidfile = Path(argv[argv.index('--cidfile') + 1])
        events.append(('run', cidfile))
        cidfile.write_text(identifier + '\n')
        return subprocess.CompletedProcess(argv, 125, identifier + '\n', '')
      if argv[0:2] == ['podman', 'inspect']:
        events.append(('inspect', argv[-1]))
        return subprocess.CompletedProcess(argv, 0, identifier + '\n', '')
      raise AssertionError(argv)
    with tempfile.TemporaryDirectory() as scratch:
      (Path(scratch) / 'cids').mkdir()
      credential = {}
      owned = []
      with patch.object(probe, 'SCRATCH', Path(scratch)), patch.object(probe, 'RUN_CID_DIR', Path(scratch) / 'cids'), patch.object(probe, 'run', side_effect=fake_run), \
          patch.object(probe, 'unlink_with_retries', side_effect=lambda path: events.append(('unlink', path)) or True):
        with self.assertRaisesRegex(RuntimeError, 'start disposable Keycloak'):
          probe.start_keycloak('test', 'credential', Path(scratch) / 'wrapper', 1,
              'bootstrap', 'image', ownership_callback=lambda path, cid: (events.append(('own', cid)), owned.append(path)),
              credential_status=credential)
      self.assertEqual(['run', 'inspect', 'own', 'unlink'], [event[0] for event in events])
      self.assertEqual(identifier, events[1][1])
      self.assertEqual([identifier], [identifier for _ in owned])
      self.assertFalse(credential['credential_file_retained'])
      self.assertTrue(owned[0].exists())

  def test_keycloak_success_requires_run_cidfile_and_inspected_id_match(self):
    import subprocess
    import tempfile
    from pathlib import Path
    import wallet_login_live_e2e as probe
    identifier = 'f' * 64
    def fake_run(argv, **kwargs):
      if argv[0] == 'ss':
        return subprocess.CompletedProcess(argv, 0, '', '')
      if argv[0:2] == ['podman', 'run']:
        Path(argv[argv.index('--cidfile') + 1]).write_text(identifier + '\n')
        return subprocess.CompletedProcess(argv, 0, 'a' * 64 + '\n', '')
      if argv[0:2] == ['podman', 'inspect']:
        return subprocess.CompletedProcess(argv, 0, identifier + '\n', '')
      raise AssertionError(argv)
    with tempfile.TemporaryDirectory() as scratch:
      (Path(scratch) / 'cids').mkdir()
      owned = []
      with patch.object(probe, 'SCRATCH', Path(scratch)), patch.object(probe, 'RUN_CID_DIR', Path(scratch) / 'cids'), patch.object(probe, 'run', side_effect=fake_run), \
          patch.object(probe, 'unlink_with_retries', return_value=True):
        with self.assertRaisesRegex(RuntimeError, 'ownership verification'):
          probe.start_keycloak('test', 'credential', Path(scratch) / 'wrapper', 1,
              'bootstrap', 'image', ownership_callback=lambda path, cid: owned.append((path, cid)))
      self.assertEqual([], owned)

  def test_persistent_credential_unlink_stops_startup_after_ownership_is_registered(self):
    import subprocess
    import tempfile
    from pathlib import Path
    import wallet_login_live_e2e as probe
    identifier = '9' * 64
    events = []
    env_paths = []
    def fake_run(argv, **kwargs):
      if argv[0] == 'ss':
        return subprocess.CompletedProcess(argv, 0, '', '')
      if argv[0:2] == ['podman', 'run']:
        env_paths.append(Path(argv[argv.index('--env-file') + 1]))
        Path(argv[argv.index('--cidfile') + 1]).write_text(identifier + '\n')
        return subprocess.CompletedProcess(argv, 0, identifier + '\n', '')
      if argv[0:2] == ['podman', 'inspect']:
        return subprocess.CompletedProcess(argv, 0, identifier + '\n', '')
      raise AssertionError(argv)
    with tempfile.TemporaryDirectory() as scratch:
      (Path(scratch) / 'cids').mkdir()
      credential = {}
      with patch.object(probe, 'SCRATCH', Path(scratch)), patch.object(probe, 'RUN_CID_DIR', Path(scratch) / 'cids'), patch.object(probe, 'run', side_effect=fake_run), \
          patch.object(probe, 'unlink_with_retries', return_value=False):
        with self.assertRaisesRegex(RuntimeError, 'protected credential file may remain'):
          probe.start_keycloak('test', 'credential', Path(scratch) / 'wrapper', 1,
              'bootstrap', 'image', ownership_callback=lambda path, cid: events.append(('owned', cid)),
              credential_status=credential)
      self.assertEqual([('owned', identifier)], events)
      self.assertTrue(credential['credential_file_retained'])
      self.assertEqual(1, len(env_paths))
      self.assertTrue(env_paths[0].exists())
      self.assertNotIn('never-print-this', repr(credential))

  def test_keycloak_interrupt_is_preserved_after_cid_recovery(self):
    import tempfile
    import subprocess
    from pathlib import Path
    import wallet_login_live_e2e as probe
    identifier = '8' * 64
    observed = []
    def fake_run(argv, **kwargs):
      if argv[0] == 'ss':
        return subprocess.CompletedProcess(argv, 0, '', '')
      if argv[0:2] == ['podman', 'run']:
        Path(argv[argv.index('--cidfile') + 1]).write_text(identifier + '\n')
        raise KeyboardInterrupt()
      if argv[0:2] == ['podman', 'inspect']:
        return subprocess.CompletedProcess(argv, 0, identifier + '\n', '')
      raise AssertionError(argv)
    with tempfile.TemporaryDirectory() as scratch:
      (Path(scratch) / 'cids').mkdir()
      with patch.object(probe, 'SCRATCH', Path(scratch)), patch.object(probe, 'RUN_CID_DIR', Path(scratch) / 'cids'), patch.object(probe, 'run', side_effect=fake_run):
        with self.assertRaises(KeyboardInterrupt):
          probe.start_keycloak('test', 'credential', Path(scratch) / 'wrapper', 1,
              'bootstrap', 'image', ownership_callback=lambda path, cid: observed.append((path, cid)))
      self.assertEqual(identifier, observed[0][1])
      self.assertTrue(observed[0][0].exists())

  def test_keycloak_ownership_is_registered_when_podman_run_times_out(self):
    import subprocess
    import tempfile
    from pathlib import Path
    from unittest.mock import patch
    import wallet_login_live_e2e as probe
    calls = []
    identifier = 'd' * 64
    def fake_run(argv, **kwargs):
      if argv[0] == 'ss':
        return subprocess.CompletedProcess(argv, 0, '', '')
      if argv[0:2] == ['podman', 'run']:
        Path(argv[argv.index('--cidfile') + 1]).write_text(identifier + '\n')
        raise TimeoutError('podman launch timed out')
      if argv[0:2] == ['podman', 'inspect']:
        return subprocess.CompletedProcess(argv, 0, identifier + '\n', '')
      raise AssertionError(argv)
    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'cids'
      cid_dir.mkdir()
      observed = []
      credential = {}
      with patch.object(probe, 'SCRATCH', Path(scratch)), patch.object(probe, 'RUN_CID_DIR', cid_dir), patch.object(probe, 'run', side_effect=fake_run):
        with self.assertRaisesRegex(TimeoutError, 'timed out'):
          probe.start_keycloak('test', 'credential', Path(scratch) / 'wrapper', 1,
              'bootstrap', 'image', ownership_callback=lambda path, cid: observed.append((path, cid)),
              credential_status=credential)
      self.assertEqual([(observed[0][0], identifier)], observed)
      self.assertTrue(observed[0][0].exists())
      self.assertFalse(credential['credential_file_retained'])

  def test_runtime_evidence_rejects_version_other_than_project_pin(self):
    import wallet_login_live_e2e as probe
    pinned = probe.pinned_keycloak_version()
    matching = probe.sanitize_live_checkpoint({'resolver_runtime': {
        'profile': 'issue6-single-node', 'keycloak_version': pinned}})
    self.assertEqual(pinned, matching['resolver_runtime']['keycloak_version'])
    wrong_version = '26.8.1' if pinned != '26.8.1' else '26.8.0'
    evidence = probe.sanitize_live_checkpoint({'resolver_runtime': {
        'profile': 'issue6-single-node', 'keycloak_version': wrong_version}})
    self.assertNotIn('keycloak_version', evidence['resolver_runtime'])

  def test_single_node_runtime_evidence_does_not_claim_unobserved_provider(self):
    evidence = sanitize_live_checkpoint({'resolver_runtime': {
        'profile': 'issue6-single-node', 'node_count': 1, 'keycloak_version': '26.8.0',
        'database': 'dev-file', 'cache': 'local',
        'single_use_object_provider': 'production', 'single_use_object_provider_evidence': 'not_observed',
        'credential_file_retained': False,
        'password': 'must-not-appear', 'container_name': 'untrusted'}})
    self.assertNotIn('single_use_object_provider', evidence['resolver_runtime'])
    self.assertEqual('not_observed', evidence['resolver_runtime']['single_use_object_provider_evidence'])
    self.assertEqual({'profile': 'issue6-single-node', 'node_count': 1,
        'keycloak_version': '26.8.0', 'database': 'dev-file', 'cache': 'local',
        'single_use_object_provider_evidence': 'not_observed', 'credential_file_retained': False},
        evidence['resolver_runtime'])

  def test_masked_runtime_provider_is_not_inferred_until_request_witness(self):
    import wallet_login_live_e2e as probe
    parsed = probe.parse_keycloak_show_config(
        'kc.db = dev-file (classpath application.properties)\n'
        'kc.spi-single-use-object--provider-default = ******* (Persisted)\n')
    self.assertEqual({'database_mode_effective': 'dev-file'}, parsed)
    self.assertEqual({'database_mode_configured': 'dev-file',
        'cache_mode_configured': 'local',
        'single_use_object_provider_configured': 'infinispan'}, probe.parse_keycloak_runtime_command(
            ['start-dev', '--db=dev-file', '--cache=local',
                '--spi-single-use-object--provider-default=infinispan']))
    self.assertEqual({'cache_mode_configured': 'local'}, probe.parse_keycloak_runtime_command(
        ['start-dev', '--db=dev-file', '--db=dev-file', '--cache=local']))
    facts = {
        'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'unavailable',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'unavailable',
        'single_use_object_provider_configured': 'infinispan',
        'single_use_object_provider_path': 'unavailable',
        'single_use_object_provider_ids': ['infinispan'],
    }
    self.assertTrue(probe.runtime_baseline_is_verified(facts))
    self.assertFalse(probe.runtime_qualification_is_verified(facts))
    facts['single_use_object_provider_path'] = 'infinispan'
    self.assertFalse(probe.runtime_qualification_is_verified(facts))
    facts['cache_mode_effective'] = 'local'
    self.assertFalse(probe.runtime_qualification_is_verified(facts))
    facts['database_mode_effective'] = 'dev-file'
    self.assertTrue(probe.runtime_qualification_is_verified(facts))
    facts['database_mode_configured'] = 'unavailable'
    facts['cache_mode_configured'] = 'unavailable'
    self.assertTrue(probe.runtime_qualification_is_verified(facts))
    import inspect
    main_source = inspect.getsource(probe.main)
    self.assertIn('require(runtime_baseline_is_verified(runtime_provenance)', main_source)
    self.assertNotIn("runtime_provenance['runtime_qualification_status'] == 'runtime_facts_verified'",
        main_source)
    coordinator_source = inspect.getsource(probe.expiry_profile_coordinator)
    self.assertIn("checkpoint(evidence)\n  require(evidence['proof_denied']", coordinator_source)
    self.assertNotIn("require(evidence['runtime_qualification_status']", coordinator_source)

  def test_owned_container_cleanup_requires_verified_full_id(self):
    import subprocess
    from tempfile import TemporaryDirectory
    from pathlib import Path
    import wallet_login_live_e2e as probe

    with TemporaryDirectory() as scratch:
      cidfile = Path(scratch) / 'cid'
      cidfile.write_text('a' * 64 + '\n')
      calls = []
      def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == 'inspect' and len(calls) == 1:
          return subprocess.CompletedProcess(argv, 0, ('a' * 64) + '\n', '')
        if argv[1] == 'rm':
          return subprocess.CompletedProcess(argv, 0, '', '')
        return subprocess.CompletedProcess(argv, 125, '', 'Error: no such container ' + ('a' * 64))
      with patch.object(probe, 'RUN_CID_DIR', Path(scratch)), patch.object(probe, 'run', side_effect=fake_run):
        result = probe.remove_owned_container(cidfile)
      self.assertEqual({'removed': True, 'retained_cid': False}, result)
      self.assertEqual(['podman', 'inspect', '--format', '{{.Id}}', 'a' * 64], calls[0])
      self.assertEqual(['podman', 'rm', '--force', 'a' * 64], calls[1])
      self.assertEqual(['podman', 'inspect', '--format', '{{.Id}}', 'a' * 64], calls[2])
      self.assertFalse(cidfile.exists())

  def test_owned_container_cleanup_retains_unverified_cidfile(self):
    import subprocess
    from tempfile import TemporaryDirectory
    from pathlib import Path
    import wallet_login_live_e2e as probe

    with TemporaryDirectory() as scratch:
      cidfile = Path(scratch) / 'cid'
      cidfile.write_text('b' * 64 + '\n')
      with patch.object(probe, 'RUN_CID_DIR', Path(scratch)), patch.object(
          probe, 'run', return_value=subprocess.CompletedProcess([], 0, 'c' * 64, '')):
        result = probe.remove_owned_container(cidfile)
      self.assertEqual({'removed': False, 'retained_cid': True}, result)
      self.assertTrue(cidfile.exists())

  def test_expired_transaction_proof_does_not_reach_identity_resolution(self):
    test_source = Path(__file__).parents[1] / 'src/test/java/org/decentwallet/keycloak/wallet/WalletLoginTransportHandlerTest.java'
    body = test_source.read_text()
    self.assertIn('rejectsSubmissionAfterPendingTransactionExpiresWithoutReceipt', body)
    self.assertIn('clock.advanceSeconds(WalletLoginTransactionStore.TRANSACTION_LIFESPAN_SECONDS)', body)
    self.assertIn('assertEquals(0, lookups.get())', body)


class Issue6PostConsumeRuntimeProfileTest(unittest.TestCase):
  def test_postconsume_runtime_profile_dispatches_to_issue6_runner(self):
    from unittest.mock import patch
    import wallet_login_live_e2e as probe

    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue6-postconsume-receipt-failure'}):
      with patch.object(probe, 'run_issue6_postconsume_receipt_failure_profile',
          return_value='selected', create=True) as runner:
        self.assertEqual('selected', probe.main())
    runner.assert_called_once_with()

  def test_postconsume_profile_invalid_value_lists_the_new_selector(self):
    import wallet_login_live_e2e as probe
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'unknown-profile'}):
      with self.assertRaisesRegex(ValueError, 'issue6-postconsume-receipt-failure'):
        probe.main()

  def test_postconsume_profile_requires_registered_test_provider(self):
    import wallet_login_live_e2e as probe
    self.assertTrue(probe.issue6_postconsume_provider_is_registered({
        'single_use_object_provider_ids': ['infinispan', 'issue6-postconsume-receipt-failure']}))
    self.assertFalse(probe.issue6_postconsume_provider_is_registered({
        'single_use_object_provider_ids': ['infinispan']}))
    self.assertFalse(probe.issue6_postconsume_provider_is_registered({
        'single_use_object_provider_ids': 'issue6-postconsume-receipt-failure'}))

  def test_postconsume_evidence_keeps_only_bounded_runtime_fields(self):
    from wallet_login_live_e2e import sanitize_live_checkpoint

    candidate = {
        'issue6_postconsume_receipt_failure_case': {
            'stage': 'failed_then_denied', 'proof_http': 503, 'retry_http': 404,
            'status_http': 404, 'proof_body_empty': True, 'proof_location_present': False,
            'proof_redirect_followed': False, 'status_body_empty': True,
            'status_location_present': False, 'status_redirect_followed': False,
            'callback_exposed': False, 'oidc_code_exposed': False,
            'fault_signal_correlated': True, 'delegate_commit_then_throw': True,
            'retry_redirect_followed': False, 'fault_signal_count': 1,
            'request_id': 'private', 'locator': 'https://private.example/path',
            'proof': 'secret', 'raw_logs': 'private diagnostic',
        },
        'issue6_postconsume_receipt_recovery': {
            'fresh_login_http': 200, 'fresh_login_transaction_available': True,
            'callback_http': 302, 'callback_code': True,
            'callback_replay_denied': True, 'pkce_token_http': 200,
            'authorization_code': 'secret', 'callback_url': 'https://private.example/cb',
        },
    }
    safe = sanitize_live_checkpoint(candidate)
    self.assertEqual({
        'issue6_postconsume_receipt_failure_case': {
            'stage': 'failed_then_denied', 'proof_http': 503, 'retry_http': 404,
            'status_http': 404, 'proof_body_empty': True, 'proof_location_present': False,
            'proof_redirect_followed': False, 'status_body_empty': True,
            'status_location_present': False, 'status_redirect_followed': False,
            'callback_exposed': False, 'oidc_code_exposed': False,
            'fault_signal_correlated': True, 'delegate_commit_then_throw': True,
            'retry_redirect_followed': False, 'fault_signal_count': 1,
        },
        'issue6_postconsume_receipt_recovery': {
            'fresh_login_http': 200, 'fresh_login_transaction_available': True,
            'callback_http': 302, 'callback_code': True,
            'callback_replay_denied': True, 'pkce_token_http': 200,
        },
    }, safe)

  def test_postconsume_failure_flow_checks_consumption_status_and_correlated_fault(self):
    import hashlib
    import json
    import subprocess
    import wallet_login_live_e2e as probe

    handle = 'H' * 43
    locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
        f'/decent-wallet-login/v1/transactions/{handle}')
    status_url = (f'/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/'
        f'{handle}/status')
    csrf = 'C' * 43
    login_page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const csrfToken = "{csrf}"; const statusUrl = "{status_url}";</script>').encode()

    class FakeClient:
      def __init__(self):
        self.redirects = []
        self.calls = []
      def request(self, method, path, data=None, headers=None, timeout=10):
        self.calls.append((method, path, data, headers))
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          return 200, {}, login_page
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge', 'csrf_token': csrf}).encode()
        if method == 'POST' and path == locator:
          posts = sum(call[0] == 'POST' for call in self.calls)
          return (503, {}, b'') if posts == 1 else (404, {}, b'')
        if method == 'GET' and path == status_url:
          return 404, {}, b''
        raise AssertionError('unexpected request boundary')

    clients = []
    def client_factory():
      client = FakeClient()
      clients.append(client)
      return client

    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    def fake_run(argv, **kwargs):
      self.assertEqual(argv[:3], ['podman', 'logs', '--since'])
      self.assertIn('--timestamps', argv)
      logs = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={probe.ISSUE6_POSTCONSUME_TEST_PROVIDER_ID} '
          f'operation=transaction_put_if_absent request={request_id}\\n'
          f'Wallet proof acceptance unavailable (request={request_id}, outcome=not_accepted)\\n'
          'ISSUE6_TEST_FAULT: accepted receipt delegate write committed; test decorator threw\\n')
      return subprocess.CompletedProcess(argv, 0, logs, None)

    browser_state = {}
    with patch('wallet_login_live_e2e.run', side_effect=fake_run):
      evidence = probe.postconsume_receipt_failure_flow(None, 'fixture-identity', 'container',
          browser_state=browser_state, client_factory=client_factory,
          signer=lambda envelope, identity: 'A' * 86)
    self.assertIs(browser_state['browser'], clients[0])
    self.assertEqual('failed_then_denied', evidence['stage'])
    self.assertEqual(503, evidence['proof_http'])
    self.assertEqual(404, evidence['retry_http'])
    self.assertEqual(404, evidence['status_http'])
    self.assertFalse(evidence['callback_exposed'])
    self.assertTrue(evidence['fault_signal_correlated'])
    self.assertTrue(evidence['delegate_commit_then_throw'])

  def test_test_provider_selection_witness_is_request_and_factory_specific(self):
    import wallet_login_live_e2e as probe
    request_id = 'a' * 32
    provider = probe.ISSUE6_POSTCONSUME_TEST_PROVIDER_ID
    marker = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={provider} '
        f'operation=transaction_put_if_absent request={request_id}')
    self.assertTrue(probe.issue6_test_provider_selection_is_verified(marker, provider, request_id))
    self.assertFalse(probe.issue6_test_provider_selection_is_verified(
        marker, probe.ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID, request_id))
    self.assertFalse(probe.issue6_test_provider_selection_is_verified(marker, provider, 'b' * 32))
    self.assertFalse(probe.issue6_test_provider_selection_is_verified(marker + '\\n' + marker,
        provider, request_id))

  def test_test_provider_is_test_image_only_and_selected_at_image_build(self):
    root = Path(__file__).parents[1]
    dockerfile = (root / 'container/Dockerfile').read_text()
    harness = (root / 'scripts/wallet_login_live_e2e.py').read_text()
    builder = (root / 'scripts/build_issue6_postconsume_provider.py').read_text()
    test_source = (root / 'src/test/java/org/decentwallet/keycloak/issue6test/'
        'Issue6PostConsumeReceiptFailureProviderFactory.java').read_text()
    main_sources = [path.read_text() for path in (root / 'src/main').rglob('*') if path.is_file()]

    self.assertIn('AS issue6-postconsume-test-runtime', dockerfile)
    self.assertIn('target/issue6-postconsume-receipt-failure-provider.jar', dockerfile)
    self.assertIn('--cache=local', dockerfile)
    self.assertIn('--spi-single-use-object--provider-default=issue6-postconsume-receipt-failure', dockerfile)
    self.assertIn('--db=dev-file', dockerfile)
    self.assertIn('--spi-single-use-object--provider-default=infinispan', dockerfile)
    self.assertIn('--spi-single-use-object--provider-default=issue6-postconsume-callback-gate-failure', dockerfile)
    self.assertNotIn('--spi-singleUseObject--provider-default=', dockerfile)
    startup = harness.split('def start_keycloak(', 1)[1].split('def admin_token', 1)[0]
    self.assertIn("'--cache=local'", startup)
    command = startup.split('cmd = [', 1)[1].split(']', 1)[0]
    self.assertNotIn('--spi-single-use-object--provider-default=', command)
    self.assertIn("image, 'start-dev'", startup)
    self.assertIn("cmd.append(f'--spi-single-use-object--provider-default={single_use_object_provider}')", startup)
    self.assertIn('single_use_object_provider=ISSUE6_POSTCONSUME_TEST_PROVIDER_ID', harness)
    self.assertIn('single_use_object_provider=ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID', harness)
    self.assertIn('IDENTITY_LOOKUP_COOLDOWN_SECONDS = 2', harness)
    self.assertGreaterEqual(harness.count('wait_for_identity_lookup_cooldown()'), 3)
    self.assertNotIn("'show-config', '--all'", harness)
    self.assertNotIn('Issue6PostConsumeReceiptFailureProviderFactory', '\\n'.join(main_sources))
    self.assertIn('target/test-classes', builder)
    self.assertIn("os.environ.get('WALLET_IT_TEST_IMAGE')", harness)
    self.assertIn('issue6_postconsume_provider_is_registered(runtime_provenance)', harness)
    self.assertNotIn('--spi-single-use-object-provider-provider=', harness)
    self.assertIn('session.getProvider(SingleUseObjectProvider.class, "infinispan")', test_source)

  def test_postconsume_profile_requires_explicit_test_image_before_preflight(self):
    import wallet_login_live_e2e as probe
    with patch.dict(os.environ, {'WALLET_IT_TEST_IMAGE': ''}):
      with patch.object(probe, 'resolve_immutable_image') as resolve:
        with self.assertRaisesRegex(RuntimeError, 'WALLET_IT_TEST_IMAGE'):
          probe.run_issue6_postconsume_receipt_failure_profile()
    resolve.assert_not_called()

  def test_postconsume_profile_runs_fault_then_recovery_and_sanitizes_evidence(self):
    import hashlib
    import io
    import json
    import subprocess
    from contextlib import ExitStack, redirect_stdout
    from types import SimpleNamespace
    import wallet_login_live_e2e as probe

    handle = 'H' * 43
    locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
        f'/decent-wallet-login/v1/transactions/{handle}')
    status_url = (f'/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/'
        f'{handle}/status')
    csrf = 'C' * 43
    login_page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const csrfToken = "{csrf}"; const statusUrl = "{status_url}";</script>').encode()

    class FakeClient:
      def __init__(self, role):
        self.role = role
        self.redirects = []
        self.posts = 0
      def request(self, method, path, data=None, headers=None, timeout=10):
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          return 200, {}, login_page
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge', 'csrf_token': csrf}).encode()
        if method == 'POST' and path == locator and self.role == 'wallet':
          self.posts += 1
          return (503, {}, b'') if self.posts == 1 else (404, {}, b'')
        if method == 'GET' and path == status_url and self.role == 'browser':
          return 404, {}, b''
        raise AssertionError('unexpected profile request boundary')

    clients = []
    def client_factory():
      role = 'browser' if not clients else 'wallet'
      client = FakeClient(role)
      clients.append(client)
      return client

    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    def fake_run(argv, **kwargs):
      logs = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={probe.ISSUE6_POSTCONSUME_TEST_PROVIDER_ID} '
          f'operation=transaction_put_if_absent request={request_id}\\n'
          f'Wallet proof acceptance unavailable (request={request_id}, outcome=not_accepted)\\n'
          'ISSUE6_TEST_FAULT: accepted receipt delegate write committed; test decorator threw\\n')
      return subprocess.CompletedProcess(argv, 0, logs, '')

    def fake_openssl(argv, **kwargs):
      output = b'X' * 44 if argv[1] == 'pkey' else b'S' * 64
      return subprocess.CompletedProcess(argv, 0, output, b'')

    runtime = {
        'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
        'single_use_object_provider_path': 'unavailable',
        'single_use_object_provider_ids': ['issue6-postconsume-receipt-failure'],
        'runtime_qualification_status': 'open_runtime_facts_unavailable',
    }
    keycloak = SimpleNamespace(wallet_container_id='a' * 64)
    recovery = {
        'login_page_http': 200, 'fresh_locator_distinct': True,
        'initial_status_accepted': True, 'callback_http': 302,
        'callback_code_returned': True, 'callback_replay_error_returned': True,
        'callback_replay_code_returned': False, 'pkce_token_http': 200,
    }
    with tempfile.TemporaryDirectory() as scratch:
      output = io.StringIO()
      with ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
        stack.enter_context(patch.object(probe, 'IMAGE', 'mutable-tag'))
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
        stack.enter_context(patch.dict(os.environ,
            {'WALLET_IT_TEST_IMAGE': 'isolated-test-image'}))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('immutable-test-image', 'sha256:' + 'b' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='resolver-tools'))
        registry = object()
        stack.enter_context(patch.object(probe, 'start_registry',
            return_value=(registry, 'bootstrap', 12345)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=12346))
        key = Path(scratch) / 'identity.pem'
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=(key, SimpleNamespace(name='wrapper'), 'identity-id')))
        stack.enter_context(patch.object(probe, 'start_keycloak', return_value=keycloak))
        stack.enter_context(patch.object(probe, 'admin_token', return_value='admin-token'))
        stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=runtime))
        stack.enter_context(patch.object(probe, 'configure_realm'))
        stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
        stack.enter_context(patch.object(probe, 'provision_identity_attribute'))
        selected_recovery = stack.enter_context(patch.object(probe, 'auth_flow', return_value=recovery))
        cleanup = stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=0))
        stack.enter_context(patch.object(probe, 'Client', side_effect=client_factory))
        stack.enter_context(patch.object(probe, 'run', side_effect=fake_run))
        stack.enter_context(patch.object(probe.subprocess, 'run', side_effect=fake_openssl))
        stack.enter_context(patch.object(probe, 'write_private_signing_input'))
        with redirect_stdout(output):
          probe.run_issue6_postconsume_receipt_failure_profile()

      selected_recovery.assert_called_once()
      self.assertIs(selected_recovery.call_args.args[0], clients[0])
      self.assertEqual(key, selected_recovery.call_args.args[1])
      self.assertEqual('identity-id', selected_recovery.call_args.args[2])
      self.assertEqual('a' * 64, selected_recovery.call_args.args[3])
      self.assertEqual(locator, selected_recovery.call_args.kwargs['prior_locator'])
      self.assertEqual('immutable-test-image', selected_recovery.call_args.args[4])
      cleanup.assert_called_once_with(registry, 'resolver-tools')
      prefix = 'issue6_postconsume_receipt_failure_evidence='
      rendered = next(line[len(prefix):] for line in output.getvalue().splitlines()
          if line.startswith(prefix))
      evidence = json.loads(rendered)
      self.assertEqual(503, evidence['issue6_postconsume_receipt_failure_case']['proof_http'])
      self.assertEqual(404, evidence['issue6_postconsume_receipt_failure_case']['retry_http'])
      self.assertTrue(evidence['issue6_postconsume_receipt_recovery']['fresh_login_transaction_available'])
      self.assertTrue(evidence['issue6_postconsume_receipt_recovery']['callback_replay_denied'])
      self.assertEqual(200, evidence['issue6_postconsume_receipt_recovery']['pkce_token_http'])
      self.assertNotIn(locator, rendered)
      self.assertNotIn(handle, rendered)

  def test_callback_gate_provider_targets_callback_key_and_commits_before_throwing(self):
    root = Path(__file__).parents[1]
    source = (root / 'src/test/java/org/decentwallet/keycloak/issue6test/'
        'Issue6PostConsumeCallbackGateFailureProviderFactory.java').read_text()
    dockerfile = (root / 'container/Dockerfile').read_text()
    builder = (root / 'scripts/build_issue6_callback_gate_provider.py').read_text()
    main_sources = [path.read_text() for path in (root / 'src/main').rglob('*') if path.is_file()]
    self.assertIn('delegate.putIfAbsent(key, lifespanSeconds)', source)
    self.assertIn('key.startsWith(CALLBACK_PREFIX)', source)
    self.assertIn('ISSUE6_TEST_FAULT: callback gate delegate putIfAbsent committed', source)
    self.assertIn('AS issue6-callback-gate-test-runtime', dockerfile)
    self.assertIn('--spi-single-use-object--provider-default=issue6-postconsume-callback-gate-failure', dockerfile)
    self.assertIn('target/issue6-postconsume-callback-gate-failure-provider.jar', dockerfile)
    self.assertIn('target/test-classes', builder)
    self.assertNotIn('Issue6PostConsumeCallbackGateFailureProviderFactory', '\\n'.join(main_sources))

  def test_issue6_provider_builders_include_anonymous_delegate_classes(self):
    import shutil
    import zipfile
    root = Path(__file__).parents[1]
    cases = [
        ('build_issue6_postconsume_provider.py',
         'Issue6PostConsumeReceiptFailureProviderFactory'),
        ('build_issue6_callback_gate_provider.py',
         'Issue6PostConsumeCallbackGateFailureProviderFactory'),
    ]
    for builder_name, factory_name in cases:
      with self.subTest(factory=factory_name), tempfile.TemporaryDirectory() as temp:
        fixture = Path(temp)
        scripts = fixture / 'scripts'
        classes = fixture / 'target/test-classes'
        scripts.mkdir()
        classes.mkdir(parents=True)
        shutil.copyfile(root / 'scripts' / builder_name, scripts / builder_name)
        class_dir = classes / 'org/decentwallet/keycloak/issue6test'
        class_dir.mkdir(parents=True)
        outer = class_dir / (factory_name + '.class')
        inner = class_dir / (factory_name + '$1.class')
        test_class = class_dir / (factory_name + 'Test.class')
        outer.write_bytes(b'outer class fixture')
        inner.write_bytes(b'anonymous delegate class fixture')
        test_class.write_bytes(b'test class must not be packaged')
        service = classes / 'META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory'
        service.parent.mkdir(parents=True)
        service.write_text('org.decentwallet.keycloak.issue6test.' + factory_name + '\n')

        completed = subprocess.run([sys.executable, str(scripts / builder_name)],
            cwd=fixture, capture_output=True, text=True, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr)
        jar_path = next((fixture / 'target').glob('issue6-postconsume-*-provider.jar'))
        with zipfile.ZipFile(jar_path) as jar:
          expected = {
              outer.relative_to(classes).as_posix(),
              inner.relative_to(classes).as_posix(),
              'META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory',
          }
          self.assertEqual(expected, set(jar.namelist()))
          self.assertEqual('org.decentwallet.keycloak.issue6test.' + factory_name,
              jar.read('META-INF/services/org.keycloak.models.SingleUseObjectProviderFactory').decode().strip())

  def test_callback_gate_evidence_sanitizer_drops_identifiers_and_raw_material(self):
    from wallet_login_live_e2e import sanitize_live_checkpoint
    unsafe = {'issue6_postconsume_callback_gate_failure_case': {
        'stage': 'failed_then_denied', 'proof_http': 503, 'retry_http': 404,
        'status_http': 404, 'proof_body_empty': True, 'proof_redirect_followed': False,
        'status_body_empty': True, 'status_redirect_followed': False,
        'callback_exposed': False, 'oidc_code_exposed': False,
        'fault_signal_correlated': True, 'fault_signal_count': 1,
        'delegate_commit_then_throw': True, 'request_id': 'secret',
        'locator': 'https://private.invalid/locator', 'proof': 'secret'},
        'issue6_postconsume_callback_gate_recovery': {
            'fresh_login_http': 200, 'fresh_login_transaction_available': True,
            'callback_http': 302, 'callback_code': True,
            'callback_replay_denied': True, 'pkce_token_http': 200,
            'authorization_code': 'secret'}}
    safe = sanitize_live_checkpoint(unsafe)
    self.assertEqual(503, safe['issue6_postconsume_callback_gate_failure_case']['proof_http'])
    self.assertTrue(safe['issue6_postconsume_callback_gate_recovery']['callback_replay_denied'])
    self.assertNotIn('request_id', str(safe))
    self.assertNotIn('private.invalid', str(safe))
    self.assertNotIn('authorization_code', str(safe))

  def test_callback_gate_failure_flow_checks_real_proof_retry_status_and_correlated_markers(self):
    import hashlib
    import json
    import subprocess
    import wallet_login_live_e2e as probe
    handle = 'G' * 43
    locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
        f'/decent-wallet-login/v1/transactions/{handle}')
    status_url = (f'/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/'
        f'{handle}/status')
    csrf = 'C' * 43
    login_page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const csrfToken = "{csrf}"; const statusUrl = "{status_url}";</script>').encode()
    class FakeClient:
      def __init__(self, role): self.role, self.redirects, self.calls = role, [], []
      def request(self, method, path, data=None, headers=None, timeout=10):
        self.calls.append((method, path, data, headers))
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          return 200, {}, login_page
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge', 'csrf_token': csrf}).encode()
        if method == 'POST' and path == locator:
          return (503, {}, b'') if sum(call[0] == 'POST' for call in self.calls) == 1 else (404, {}, b'')
        if method == 'GET' and path == status_url:
          return 404, {}, b''
        raise AssertionError('unexpected callback-gate production endpoint request')
    clients = []
    def factory():
      client = FakeClient('browser' if not clients else 'wallet'); clients.append(client); return client
    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    def fake_run(argv, **kwargs):
      logs = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={probe.ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID} '
          f'operation=transaction_put_if_absent request={request_id}\\n'
          f'Wallet proof acceptance unavailable (request={request_id}, outcome=not_accepted)\\n'
          f'Wallet accepted receipt publication unavailable (request={request_id}, '
          'cause=post_consume_receipt_failure)\\n'
          'ISSUE6_TEST_FAULT: callback gate delegate putIfAbsent committed; test decorator threw\\n')
      return subprocess.CompletedProcess(argv, 0, logs, '')
    state = {}
    with patch('wallet_login_live_e2e.run', side_effect=fake_run):
      with self.assertRaisesRegex(RuntimeError, 'not misattributed as receipt publication failure'):
        probe.postconsume_callback_gate_failure_flow(None, 'fixture-id', 'container',
            browser_state=state, client_factory=factory, signer=lambda *_: 'A' * 86)

  def test_callback_gate_profile_orchestrates_fault_recovery_and_sanitized_checkpoint(self):
    import hashlib
    import io
    import json
    import subprocess
    from contextlib import ExitStack, redirect_stdout
    from types import SimpleNamespace
    import wallet_login_live_e2e as probe
    handle = 'J' * 43
    locator = (f'https://idp.example:{probe.KC_PORT}/auth/realms/{probe.REALM}'
        f'/decent-wallet-login/v1/transactions/{handle}')
    status_url = (f'/auth/realms/{probe.REALM}/decent-wallet-login/v1/transactions/'
        f'{handle}/status')
    csrf = 'C' * 43
    login_page = (f'<p id="wallet-locator">{locator}</p>'
        f'<script>const csrfToken = "{csrf}"; const statusUrl = "{status_url}";</script>').encode()
    class FakeClient:
      def __init__(self): self.redirects, self.posts = [], 0
      def request(self, method, path, data=None, headers=None, timeout=10):
        if method == 'GET' and '/protocol/openid-connect/auth?' in path:
          return 200, {}, login_page
        if method == 'GET' and path == locator:
          return 200, {}, json.dumps({'profile': 'decent-wallet-login-v1',
              'challenge': 'challenge', 'csrf_token': csrf}).encode()
        if method == 'POST' and path == locator:
          self.posts += 1
          return (503, {}, b'') if self.posts == 1 else (404, {}, b'')
        if method == 'GET' and path == status_url:
          return 404, {}, b''
        raise AssertionError('unexpected callback-gate endpoint')
    clients = []
    def client_factory():
      client = FakeClient(); clients.append(client); return client
    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    def fake_run(argv, **kwargs):
      logs = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={probe.ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID} '
          f'operation=transaction_put_if_absent request={request_id}\\n'
          f'Wallet proof acceptance unavailable (request={request_id}, outcome=not_accepted)\\n'
          'ISSUE6_TEST_FAULT: callback gate delegate putIfAbsent committed; test decorator threw\\n')
      return subprocess.CompletedProcess(argv, 0, logs, '')
    runtime = {'keycloak_version': '26.8.0', 'keycloak_nodes': 'one',
        'database_mode_configured': 'dev-file', 'database_mode_effective': 'dev-file',
        'cache_mode_configured': 'local', 'cache_mode_effective': 'local',
        'single_use_object_provider_path': 'unavailable',
        'single_use_object_provider_ids': ['issue6-postconsume-callback-gate-failure'],
        'runtime_qualification_status': 'open_runtime_facts_unavailable'}
    recovery = {'login_page_http': 200, 'fresh_locator_distinct': True,
        'initial_status_accepted': True, 'callback_http': 302, 'callback_code_returned': True,
        'callback_replay_error_returned': True, 'callback_replay_code_returned': False,
        'pkce_token_http': 200}
    with tempfile.TemporaryDirectory() as scratch:
      output = io.StringIO()
      with ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'SCRATCH', scratch))
        stack.enter_context(patch.object(probe, 'IMAGE', 'mutable-tag'))
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', None))
        stack.enter_context(patch.dict(os.environ, {'WALLET_IT_TEST_IMAGE': 'isolated-test-image'}))
        stack.enter_context(patch.object(probe, 'resolve_immutable_image',
            return_value=('immutable-test-image', 'sha256:' + 'b' * 64)))
        stack.enter_context(patch.object(probe, '_prepare_resolver_runtime', return_value={}))
        stack.enter_context(patch.object(probe, 'start_resolver_tools', return_value='resolver-tools'))
        registry = object()
        stack.enter_context(patch.object(probe, 'start_registry', return_value=(registry, 'bootstrap', 12345)))
        stack.enter_context(patch.object(probe, 'free_port', return_value=12346))
        key = Path(scratch) / 'identity.pem'
        stack.enter_context(patch.object(probe, 'write_identity',
            return_value=(key, SimpleNamespace(name='wrapper'), 'identity-id')))
        keycloak = SimpleNamespace(wallet_container_id='a' * 64)
        stack.enter_context(patch.object(probe, 'start_keycloak', return_value=keycloak))
        stack.enter_context(patch.object(probe, 'admin_token', return_value='admin-token'))
        stack.enter_context(patch.object(probe, 'keycloak_runtime_provenance', return_value=runtime))
        stack.enter_context(patch.object(probe, 'configure_realm'))
        stack.enter_context(patch.object(probe, 'enable_keycloak_login_events'))
        stack.enter_context(patch.object(probe, 'provision_identity_attribute'))
        stack.enter_context(patch.object(probe, 'auth_flow', return_value=recovery))
        stack.enter_context(patch.object(probe, 'cleanup_owned_resources', return_value=0))
        stack.enter_context(patch.object(probe, 'Client', side_effect=client_factory))
        stack.enter_context(patch.object(probe, 'run', side_effect=fake_run))
        def fake_openssl(argv, **kwargs):
          return subprocess.CompletedProcess(argv, 0, b'X' * (44 if argv[1] == 'pkey' else 64), b'')
        stack.enter_context(patch.object(probe.subprocess, 'run', side_effect=fake_openssl))
        stack.enter_context(patch.object(probe, 'write_private_signing_input'))
        with redirect_stdout(output):
          probe.run_issue6_postconsume_callback_gate_failure_profile()
      rendered = next(line.split('=', 1)[1] for line in output.getvalue().splitlines()
          if line.startswith('issue6_postconsume_callback_gate_failure_evidence='))
      evidence = json.loads(rendered)
      self.assertEqual(503, evidence['issue6_postconsume_callback_gate_failure_case']['proof_http'])
      self.assertEqual(404, evidence['issue6_postconsume_callback_gate_failure_case']['status_http'])
      self.assertFalse(evidence['issue6_postconsume_callback_gate_failure_case']['callback_exposed'])
      self.assertFalse(evidence['issue6_postconsume_callback_gate_failure_case']['oidc_code_exposed'])
      self.assertFalse(evidence['issue6_postconsume_callback_gate_failure_case']['proof_redirect_followed'])
      self.assertTrue(evidence['issue6_postconsume_callback_gate_recovery']['callback_replay_denied'])
      self.assertEqual(200, evidence['issue6_postconsume_callback_gate_recovery']['pkce_token_http'])
      self.assertNotIn(locator, rendered)
      self.assertNotIn(handle, rendered)
      self.assertNotIn('authorization_code', rendered)

  def test_callback_gate_selector_is_listed_in_invalid_profile_diagnostic(self):
    import wallet_login_live_e2e as probe
    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'unknown-profile'}):
      with self.assertRaisesRegex(ValueError, 'issue6-postconsume-callback-gate-failure'):
        probe.main()

  def test_callback_gate_profile_dispatches_to_separate_issue6_runner(self):
    import wallet_login_live_e2e as probe

    with patch.dict(os.environ, {'WALLET_IT_PROFILE': 'issue6-postconsume-callback-gate-failure'}):
      with patch.object(probe, 'run_issue6_postconsume_callback_gate_failure_profile',
          return_value='selected', create=True) as runner:
        self.assertEqual('selected', probe.main())
    runner.assert_called_once_with()


class OwnedResourceCleanupFailureTest(unittest.TestCase):
  def run_cleanup(self, cleanup_failures=(), primary_failure=None, cleanup_interrupt=None):
    import tempfile
    from pathlib import Path
    import wallet_login_live_e2e as probe

    cleanup_calls = []
    output = io.StringIO()
    def cleanup(name):
      cleanup_calls.append(name)
      if name == 'registry' and cleanup_interrupt is not None:
        raise cleanup_interrupt
      if name in cleanup_failures:
        raise RuntimeError(f'sensitive cleanup detail for {name}')

    with tempfile.TemporaryDirectory() as scratch:
      cid_dir = Path(scratch) / 'cids'
      cid_dir.mkdir()
      cid_file = cid_dir / 'keycloak.cid'
      cid_file.write_text('a' * 64)

      def remove_owned(cid_path):
        cleanup('keycloak')
        Path(cid_path).unlink(missing_ok=True)
        return {'removed': True, 'retained_cid': False}

      with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(probe, 'RUN_CID_DIR', cid_dir))
        stack.enter_context(patch.object(probe, 'stop_registry', side_effect=lambda *_: cleanup('registry')))
        stack.enter_context(patch.object(probe, 'stop_resolver_tools', side_effect=lambda *_: cleanup('resolver')))
        stack.enter_context(patch.object(probe, 'remove_owned_container', side_effect=remove_owned))
        with contextlib.redirect_stdout(output):
          try:
            if primary_failure is not None:
              try:
                raise primary_failure
              except BaseException:
                probe.cleanup_after_failure('registry', 'resolver-tools')
                raise
            probe.finish_owned_cleanup('registry', 'resolver-tools')
          except BaseException as error:
            return error, cleanup_calls, output.getvalue()
    return None, cleanup_calls, output.getvalue()

  def test_cleanup_failure_after_success_fails_and_attempts_all_cleanup(self):
    error, calls, output = self.run_cleanup(
        cleanup_failures=('keycloak', 'registry', 'resolver'))
    self.assertIsInstance(error, RuntimeError)
    self.assertIn('cleanup_error_count=3', str(error))
    self.assertCountEqual(['keycloak', 'registry', 'resolver'], calls)
    self.assertIn('keycloak_cleanup_error', output)
    self.assertIn('registry_log_stream_stop_error', output)
    self.assertIn('resolver_tools_stop_error', output)
    self.assertNotIn('sensitive cleanup detail', output)

  def test_primary_failure_or_interruption_is_preserved_while_all_cleanup_is_attempted(self):
    for primary in (RuntimeError('primary scenario failure'), KeyboardInterrupt()):
      with self.subTest(primary=type(primary).__name__):
        error, calls, output = self.run_cleanup(
            cleanup_failures=('keycloak', 'registry', 'resolver'), primary_failure=primary)
        self.assertIs(error, primary)
        self.assertCountEqual(['keycloak', 'registry', 'resolver'], calls)
        self.assertNotIn('sensitive cleanup detail', output)

  def test_cleanup_interrupt_is_preserved_after_all_cleanup_attempts(self):
    cleanup_interrupt = KeyboardInterrupt('sensitive interrupt detail')
    error, calls, output = self.run_cleanup(cleanup_interrupt=cleanup_interrupt)
    self.assertIs(error, cleanup_interrupt)
    self.assertCountEqual(['keycloak', 'registry', 'resolver'], calls)
    self.assertIn('registry_log_stream_stop_error', output)
    self.assertNotIn('sensitive interrupt detail', output)

    for primary in (RuntimeError('primary scenario failure'), KeyboardInterrupt('primary interrupt')):
      with self.subTest(primary=type(primary).__name__):
        cleanup_interrupt = SystemExit('sensitive cleanup exit detail')
        error, calls, output = self.run_cleanup(
            primary_failure=primary, cleanup_interrupt=cleanup_interrupt)
        self.assertIs(error, primary)
        self.assertCountEqual(['keycloak', 'registry', 'resolver'], calls)
        self.assertNotIn('sensitive cleanup exit detail', output)

  def test_success_without_cleanup_errors_remains_success(self):
    error, calls, output = self.run_cleanup()
    self.assertIsNone(error)
    self.assertCountEqual(['keycloak', 'registry', 'resolver'], calls)
    self.assertNotIn('cleanup_categories=', output)


if __name__ == '__main__':
  unittest.main()
