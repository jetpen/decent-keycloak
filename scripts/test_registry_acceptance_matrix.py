"""Executable Issue #5 behavior tests, independent of live qualification."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('WALLET_IT_NATIVE_LIBS', '/unused-test-library-path')
sys.path.insert(0, str(Path(__file__).parent))

import wallet_login_live_e2e as probe  # noqa: E402
from wallet_login_live_e2e import (  # noqa: E402
    AuthFlowFailure,
    classify_registry_matrix_attempt,
    run_registry_attempts,
    sanitize_live_checkpoint,
)


class RegistryAcceptanceMatrixTest(unittest.TestCase):
  def test_issue5_adversarial_profile_is_allowlisted(self):
    previous = os.environ.get('WALLET_IT_PROFILE')
    os.environ['WALLET_IT_PROFILE'] = 'issue5-adversarial'
    try:
      self.assertEqual('issue5-adversarial', probe.selected_live_profile())
    finally:
      if previous is None:
        os.environ.pop('WALLET_IT_PROFILE', None)
      else:
        os.environ['WALLET_IT_PROFILE'] = previous

  def test_issue5_fixture_exec_provides_pinned_source_paths(self):
    class ExitedProcess:
      returncode = 1

      def poll(self):
        return self.returncode

    commands = []
    with tempfile.TemporaryDirectory() as temp, \
        patch.object(probe.subprocess, 'Popen', side_effect=lambda command, **_kwargs: (
            commands.append(command) or ExitedProcess())):
      fixture = probe.AdversarialPeerFixtureProcess(
          temp, 'resolver-tools', 'malformed_result', 'synthetic@example.invalid')
      with self.assertRaises(probe.AdversarialFixtureFailure):
        fixture.start()

    self.assertEqual(1, len(commands))
    self.assertIn(
        'PYTHONPATH=/opt/decent-resolver/registry-src/src:'
        '/opt/decent-resolver/identity-src/src:'
        '/opt/decent-resolver/venv/lib64/python3.11/site-packages:'
        '/opt/decent-resolver/venv/lib/python3.11/site-packages',
        commands[0])

  def test_issue5_fixture_start_preserves_all_conflicting_peer_bootstraps(self):
    class LiveProcess:
      returncode = None

      def poll(self):
        return self.returncode

      def wait(self, timeout=None):
        self.returncode = 0
        return self.returncode

    addresses = [
        '/ip4/127.0.0.1/tcp/39001/p2p/peer-one',
        '/ip4/127.0.0.1/tcp/39002/p2p/peer-two',
    ]
    commands = []

    def start_process(command, **_kwargs):
      commands.append(command)
      readiness = Path(command[command.index('--ready-file') + 1])
      status = Path(command[command.index('--status-file') + 1])
      readiness.write_text(json.dumps({
          'bootstrap_peers': addresses, 'peer_count': 2}), encoding='utf-8')
      status.write_text(json.dumps({
          'peer_count': 2, 'exact_key_gets': [0, 0]}), encoding='utf-8')
      return LiveProcess()

    with tempfile.TemporaryDirectory() as temp:
      fixture = probe.AdversarialPeerFixtureProcess(
          temp, 'resolver-tools', 'ambiguous_registry_result', 'synthetic@example.invalid')
      with patch.object(probe.subprocess, 'Popen', side_effect=start_process):
        try:
          bootstrap = fixture.start()
        except probe.AdversarialFixtureFailure:
          self.fail('fixture startup must retain every advertised bootstrap peer')
        fixture.close()

    self.assertEqual(','.join(addresses), bootstrap)
    self.assertEqual(2, len(addresses))

  def test_issue5_direct_cli_receives_every_conflicting_peer_bootstrap(self):
    addresses = [
        '/ip4/127.0.0.1/tcp/39001/p2p/peer-one',
        '/ip4/127.0.0.1/tcp/39002/p2p/peer-two',
    ]
    captured = {}

    def capture_cli(_container, args, **_kwargs):
      captured['args'] = args
      raise RuntimeError('stop at direct CLI boundary')

    with tempfile.TemporaryDirectory() as temp, \
        patch.dict(os.environ, {'WALLET_IT_RESOLVER_TOOLS_CONTAINER': 'resolver-tools'}), \
        patch.object(probe, 'run_image_resolver', side_effect=capture_cli):
      with self.assertRaisesRegex(RuntimeError, 'stop at direct CLI boundary'):
        probe.registry_proof_probe(
            temp, 18886, ','.join(addresses), 'immutable-image',
            identity_key=Path(temp) / 'owner.pem',
            identity_id='synthetic@example.invalid',
            fixture_observer=lambda: [0, 0], fixture_peer_count=2)

    args = captured['args']
    actual_bootstraps = [args[index + 1] for index, value in enumerate(args)
        if value == '--bootstrap']
    self.assertEqual(addresses, actual_bootstraps)

  def test_issue5_case_allowlist_is_shared_with_resolver_fixture(self):
    fixture_source = Path(__file__).with_name('test_pinned_adversarial_identity_peer.py').read_text()
    self.assertIn(
        'ISSUE5_ADVERSARIAL_CASE_NAMES as ADVERSARIAL_CASE_NAMES', fixture_source)
    self.assertEqual(
        probe.ISSUE5_ADVERSARIAL_CASE_NAMES,
        frozenset(case for case, _label in probe.ISSUE5_ADVERSARIAL_CASES))
    with tempfile.TemporaryDirectory() as temp:
      fixture = probe.AdversarialPeerFixtureProcess(
          temp, 'resolver-tools', 'malformed_result', 'synthetic@example.invalid')
      source_script = Path(__file__).with_name('test_pinned_adversarial_identity_peer.py').read_bytes()
      source_cases = Path(__file__).with_name('issue5_adversarial_cases.py').read_bytes()
      self.assertEqual(source_script, fixture.script_path.read_bytes())
      self.assertEqual(source_cases, fixture.case_constants_path.read_bytes())
      self.assertEqual(hashlib.sha256(source_script).hexdigest(), fixture.script_sha256)
      self.assertEqual(hashlib.sha256(source_cases).hexdigest(), fixture.case_constants_sha256)

  def test_issue5_adversarial_profile_runs_two_checkpointed_attempts_per_case(self):
    observed = []
    checkpoints = []

    def attempt_runner(case_name, attempt_number, fixture):
      observed.append((case_name, attempt_number, fixture[0]))
      return {
          'fixture': fixture[0], 'fixture_evidence': 'test-only-hostile-peer',
          'direct_resolution': 'unavailable', 'provider_http': 503,
          'status_http': 200,
          'status_pending': True, 'no_acceptance_or_callback': True,
          'no_authorization_code': True, 'fixture_cli_key_observed': True,
          'fixture_provider_key_observed': True,
          'fixture_all_provider_peers_observed': True,
          'fixture_source_sha256': 'a' * 64,
          'fixture_case_constants_sha256': 'b' * 64,
          'outcome': 'adversarial_peer_unavailable',
      }

    matrix = probe.run_issue5_adversarial_profile(attempt_runner, checkpoints.append)

    expected = [
        (case_name, attempt_number, fixture_label)
        for case_name, fixture_label in probe.ISSUE5_ADVERSARIAL_CASES
        for attempt_number in (1, 2)
    ]
    self.assertEqual(expected, observed)
    self.assertEqual(8, len(checkpoints))
    self.assertEqual(4, len(matrix))
    self.assertTrue(all(len(matrix[name]['attempts']) == 2 for name, _ in probe.ISSUE5_ADVERSARIAL_CASES))

  def test_resolver_client_ephemeral_ports_are_unique_and_exclude_configured_listener(self):
    candidates = iter((31000, 31000, 31001, 31002))

    ports = probe.distinct_ephemeral_ports(2, port_factory=lambda: next(candidates),
        excluded_ports={31000})

    self.assertEqual([31001, 31002], ports)
    self.assertEqual(2, len(set(ports)))

  def test_account_denial_probe_uses_a_distinct_ephemeral_cli_listener_and_all_registry_seeds(self):
    source = Path(__file__).with_name('wallet_login_live_e2e.py').read_text()
    flow = source.split('def account_mapping_denial_flow(', 1)[1].split(
        '\ndef account_policy_request_id', 1)[0]
    self.assertIn("distinct_ephemeral_ports(1", flow)
    self.assertIn("excluded_ports={resolver_port}", flow)
    self.assertIn("'--port', str(resolver_client_port)", flow)
    self.assertIn("*identity_bootstrap_arguments(bootstrap)", flow)
    self.assertNotIn("'--port', str(resolver_port)", flow)

  def test_two_attempts_are_ordered_checkpointed_and_use_distinct_fixtures(self):
    fixtures = {1: 'owner-key-alpha', 2: 'owner-key-beta'}
    fixture_ids = {1: 'fixture-alpha', 2: 'fixture-beta'}
    events = []

    def run_attempt(number, identity_fixture):
      events.append(('attempt', number))
      self.assertEqual(f'unpublished-fixture-{number}', identity_fixture[0])
      self.assertEqual(fixtures[number], identity_fixture[1])
      return {
          'fixture': identity_fixture[0],
          'direct_resolution': 'not_found',
          'provider_http': 503,
          'status_http': 200,
          'status_pending': True,
          'outcome': classify_registry_matrix_attempt('not_found', 503,
              status_pending=True, exact_readback=False),
      }

    def provide_fixture(number):
      return (f'unpublished-fixture-{number}', fixtures[number], fixture_ids[number], None)

    result = run_registry_attempts('missing_identity', run_attempt,
        lambda checkpoint: events.append(('checkpoint', checkpoint)),
        fixture_factory=provide_fixture)

    self.assertEqual(['attempt', 'checkpoint', 'attempt', 'checkpoint'],
        [event[0] for event in events])
    self.assertEqual([1, 2], [events[i][1] for i in (0, 2)])
    first_checkpoint = events[1][1]['registry_matrix']['missing_identity']['attempts']
    second_checkpoint = events[3][1]['registry_matrix']['missing_identity']['attempts']
    self.assertEqual(1, len(first_checkpoint))
    self.assertEqual('unpublished-fixture-1', first_checkpoint[0]['fixture'])
    self.assertEqual(2, len(second_checkpoint))
    second = second_checkpoint[1]
    self.assertEqual('provider_registry_inconsistent', second['outcome'])
    self.assertEqual('unpublished-fixture-2', second['fixture'])
    self.assertEqual(503, second['provider_http'])
    self.assertEqual(200, second['status_http'])
    self.assertTrue(second['status_pending'])
    self.assertEqual('missing_identity', result['case'])

  def test_auth_failure_retains_proof_and_status_outcomes(self):
    def fail_after_proof():
      probe.record_auth_flow_outcome('proof_post_http', 503)
      probe.record_auth_flow_outcome('status_poll_http', 200)
      probe.record_auth_flow_outcome('status_pending', True)
      raise RuntimeError('provider proof failed')

    with self.assertRaises(AuthFlowFailure) as caught:
      probe.capture_auth_flow_outcomes(fail_after_proof)

    self.assertEqual(503, caught.exception.outcomes['proof_post_http'])
    self.assertEqual(200, caught.exception.outcomes['status_poll_http'])
    self.assertTrue(caught.exception.outcomes['status_pending'])

  def test_failed_attempt_outcomes_are_checkpointed_before_next_invocation(self):
    events = []

    def failed_attempt(_number):
      events.append('attempt')
      probe.record_auth_flow_outcome('proof_post_http', 503)
      probe.record_auth_flow_outcome('status_poll_http', 200)
      probe.record_auth_flow_outcome('status_pending', True)
      raise RuntimeError('provider proof failed')

    result = run_registry_attempts('missing_identity', failed_attempt, events.append)

    self.assertEqual('attempt', events[0])
    self.assertEqual('attempt', events[2])
    failed = events[1]['registry_matrix']['missing_identity']['attempts'][0]
    self.assertEqual('unqualified', failed['outcome'])
    self.assertEqual(503, failed['proof_post_http'])
    self.assertEqual(200, failed['status_poll_http'])
    self.assertTrue(failed['status_pending'])
    self.assertEqual(2, len(result['attempts']))

  def test_hostile_peer_attempt_requires_provider_path_and_exact_key_witnesses(self):
    evidence = {
        'fixture': 'hostile-peer-ambiguous',
        'fixture_evidence': 'test-only-hostile-peer',
        'direct_resolution': 'unavailable',
        'provider_http': 503,
        'status_http': 200,
        'status_pending': True,
        'no_acceptance_or_callback': True,
        'no_authorization_code': True,
        'fixture_cli_key_observed': True,
        'fixture_provider_key_observed': True,
        'fixture_all_provider_peers_observed': True,
        'fixture_source_sha256': 'a' * 64,
        'fixture_case_constants_sha256': 'b' * 64,
    }
    self.assertEqual('adversarial_peer_unavailable',
        probe.classify_adversarial_peer_attempt(evidence))
    for field in ('fixture_source_sha256', 'fixture_case_constants_sha256'):
      incomplete = dict(evidence)
      incomplete.pop(field)
      self.assertEqual('unqualified', probe.classify_adversarial_peer_attempt(incomplete), field)
      malformed = dict(evidence, **{field: 'not-a-digest'})
      self.assertEqual('unqualified', probe.classify_adversarial_peer_attempt(malformed), field)
    for field in ('fixture_evidence', 'status_http', 'status_pending', 'no_acceptance_or_callback',
        'no_authorization_code', 'fixture_cli_key_observed',
        'fixture_provider_key_observed', 'fixture_all_provider_peers_observed'):
      broken = dict(evidence)
      broken[field] = False
      self.assertEqual('unqualified', probe.classify_adversarial_peer_attempt(broken), field)
    broken = dict(evidence, status_http=503)
    self.assertEqual('unqualified', probe.classify_adversarial_peer_attempt(broken))
    broken = dict(evidence, provider_http=202)
    self.assertEqual('unqualified', probe.classify_adversarial_peer_attempt(broken))

  def test_set_registry_bootstrap_reports_exact_get_put_get_readback(self):
    original = {'attributes': {'decent.wallet.registry.bootstrap': 'old-peer'}}
    overridden = {'attributes': {'decent.wallet.registry.bootstrap': 'new-peer'}}
    admin = patch.object(probe, 'admin_call', side_effect=[
        (200, {}, json.dumps(original).encode()),
        (204, {}, b''),
        (200, {}, json.dumps(overridden).encode()),
    ])
    with admin as admin_call:
      self.assertIs(probe.set_registry_bootstrap(object(), 'token', 'new-peer'), True)
    self.assertEqual(['GET', 'PUT', 'GET'], [call.args[2] for call in admin_call.call_args_list])

  def test_set_registry_bootstrap_readback_mismatch_fails_closed(self):
    original = {'attributes': {'decent.wallet.registry.bootstrap': 'old-peer'}}
    wrong = {'attributes': {'decent.wallet.registry.bootstrap': 'unexpected-peer'}}
    with patch.object(probe, 'admin_call', side_effect=[
        (200, {}, json.dumps(original).encode()),
        (204, {}, b''),
        (200, {}, json.dumps(wrong).encode()),
    ]):
      with self.assertRaisesRegex(RuntimeError, 'persisted exactly'):
        probe.set_registry_bootstrap(object(), 'token', 'new-peer')

  def test_set_registry_bootstrap_admin_error_fails_closed(self):
    with patch.object(probe, 'admin_call', return_value=(403, {}, b'')):
      with self.assertRaises(Exception):
        probe.set_registry_bootstrap(object(), 'token', 'new-peer')

  def test_fixture_peer_request_delta_requires_each_expected_peer(self):
    delta = probe.fixture_peer_request_increments
    self.assertTrue(delta([0, 2], [1, 3], 2))
    self.assertTrue(delta([0, 2], [1, 3], 2, require_all=True))
    self.assertTrue(delta([0, 2], [1, 2], 2))
    self.assertFalse(delta([0, 2], [1, 2], 2, require_all=True))
    self.assertFalse(delta([0], [1], 2))
    self.assertFalse(delta([0], [0], 1))

  def test_classification_keeps_miss_unavailable_and_policy_distinct(self):
    self.assertEqual('provider_registry_inconsistent',
        classify_registry_matrix_attempt('not_found', 503, status_pending=True,
            exact_readback=False))
    self.assertEqual('registry_unavailable',
        classify_registry_matrix_attempt('unavailable', 503, status_pending=True,
            exact_readback=False))
    self.assertEqual('provider_denied_unclassified',
        classify_registry_matrix_attempt('not_found', 401, status_pending=True,
            exact_readback=False))
    self.assertEqual('unexpected_acceptance',
        classify_registry_matrix_attempt('not_found', 202, status_pending=False,
            exact_readback=False))

  def test_malformed_matrix_values_are_rejected_without_crashing_sanitizer(self):
    projected = sanitize_live_checkpoint({'registry_matrix': {
        'missing_identity': {'attempts': [{
            'attempt_number': 1,
            'direct_resolution': [],
            'outcome': {},
            'provider_http': True,
            'status_pending': 'yes',
        }]}}})

    attempt = projected['registry_matrix']['missing_identity']['attempts'][0]
    self.assertEqual({'attempt_number': 1}, attempt)
    self.assertEqual('unqualified', classify_registry_matrix_attempt([], 503,
        status_pending=True, exact_readback=False))

  def test_unavailable_bootstrap_changes_only_the_tcp_port(self):
    bootstrap = '/ip4/127.0.0.1/tcp/4100/p2p/12D3KooWabc'
    self.assertEqual('/ip4/127.0.0.1/tcp/4200/p2p/12D3KooWabc',
        probe.unavailable_bootstrap(bootstrap, 4200))
    self.assertIsNone(probe.unavailable_bootstrap(bootstrap, 4100))

  def test_issue5_profile_checkpoint_keeps_substep_and_allowlisted_failure_category(self):
    stages = (
        'current_identity_direct_lookup_start',
        'current_identity_direct_lookup_complete',
        'current_identity_owner_key_extract_start',
        'current_identity_owner_key_extract_complete',
        'current_identity_exact_readback_start',
        'current_identity_exact_readback_complete',
        'current_identity_classification_start',
        'current_identity_classification_complete',
        'current_identity_provider_flow_start',
        'current_identity_provider_flow_complete',
    )
    for stage in stages:
      with self.subTest(stage=stage):
        projected = sanitize_live_checkpoint({'issue5_profile': {
            'stage': stage, 'failure_category': 'runtime_error',
            'exception_text': 'secret raw details'}})
        self.assertEqual({'stage': stage, 'failure_category': 'runtime_error'},
            projected.get('issue5_profile'))
        invalid_category = sanitize_live_checkpoint({'issue5_profile': {
            'stage': stage, 'failure_category': 'secret raw details'}})
        self.assertEqual({'stage': stage}, invalid_category.get('issue5_profile'))
    invalid_stage = sanitize_live_checkpoint({'issue5_profile': {
        'stage': 'secret raw details', 'failure_category': 'runtime_error'}})
    self.assertNotIn('issue5_profile', invalid_stage)

  def test_checkpoint_sanitizer_preserves_matrix_outcomes_but_discards_private_values(self):
    projected = sanitize_live_checkpoint({'registry_matrix': {
        'missing_identity': {'attempts': [{
            'attempt_number': 1,
            'direct_resolution': 'not_found',
            'provider_http': 503,
            'status_http': 200,
            'status_pending': True,
            'no_acceptance_or_callback': True,
            'outcome': 'provider_registry_inconsistent',
            'identity': 'must-not-survive',
        }]}}})

    self.assertIn('registry_matrix', projected)
    attempt = projected['registry_matrix']['missing_identity']['attempts'][0]
    self.assertEqual(503, attempt['provider_http'])
    self.assertEqual(200, attempt['status_http'])
    self.assertTrue(attempt['status_pending'])
    self.assertNotIn('identity', attempt)

  def test_hostile_peer_attempt_sanitizer_keeps_only_bounded_fixture_and_denial_facts(self):
    candidate = {
        'attempt_number': 1,
        'direct_resolution': 'unavailable',
        'provider_http': 503,
        'status_http': 200,
        'status_pending': True,
        'no_acceptance_or_callback': True,
        'no_authorization_code': True,
        'fixture_cli_key_observed': True,
        'fixture_provider_key_observed': True,
        'fixture_all_provider_peers_observed': True,
        'fixture_source_sha256': 'a' * 64,
        'fixture_case_constants_sha256': 'b' * 64,
        'outcome': 'adversarial_peer_unavailable',
        'fixture': 'hostile-peer-ambiguous',
        'fixture_evidence': 'test-only-hostile-peer',
        'identity': 'private identity',
        'owner_key': 'private key',
        'raw_output': 'sensitive diagnostic',
    }
    projected = sanitize_live_checkpoint({'registry_matrix': {
        'ambiguous_registry_result': {'attempts': [candidate]}}})

    self.assertIn('registry_matrix', projected)
    attempt = projected['registry_matrix']['ambiguous_registry_result']['attempts'][0]
    self.assertEqual('hostile-peer-ambiguous', attempt.get('fixture'))
    self.assertEqual('test-only-hostile-peer', attempt.get('fixture_evidence'))
    self.assertEqual('adversarial_peer_unavailable', attempt.get('outcome'))
    self.assertTrue(attempt.get('status_pending'))
    self.assertTrue(attempt.get('no_acceptance_or_callback'))
    self.assertTrue(attempt.get('no_authorization_code'))
    self.assertTrue(attempt.get('fixture_cli_key_observed'))
    self.assertTrue(attempt.get('fixture_provider_key_observed'))
    self.assertTrue(attempt.get('fixture_all_provider_peers_observed'))
    self.assertEqual('a' * 64, attempt.get('fixture_source_sha256'))
    self.assertEqual('b' * 64, attempt.get('fixture_case_constants_sha256'))
    self.assertNotIn('identity', attempt)
    self.assertNotIn('owner_key', attempt)
    self.assertNotIn('raw_output', attempt)
    malformed = dict(candidate, fixture_source_sha256='z' * 64)
    malformed_projection = sanitize_live_checkpoint({'registry_matrix': {
        'ambiguous_registry_result': {'attempts': [malformed]}}})
    malformed_attempt = malformed_projection['registry_matrix']['ambiguous_registry_result']['attempts'][0]
    self.assertNotIn('fixture_source_sha256', malformed_attempt)

  def test_registry_attempt_code_absence_fails_closed_for_body_location_and_redirects(self):
    checker = getattr(probe, 'registry_no_authorization_code', None)
    if not callable(checker):
      self.fail('registry_no_authorization_code is not callable')
    safe = b'{"status":"pending"}'
    self.assertTrue(checker(safe, safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"code":""}', safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"authorization_code":""}', safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"message":"authorization code=abc"}', safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"message":"code = abc"}', safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"message":"OIDC code: abc"}', safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"message":"callback delivered"}', safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"message":"receipt=abc"}', safe, {}, {}, (), ()))
    self.assertFalse(checker(b'{"receipt":{}}', safe, {}, {}, (), ()))
    self.assertFalse(checker(safe, safe, {'Location': 'https://rp.example/callback?code='}, {}, (), ()))
    self.assertFalse(checker(safe, safe,
        {'Location': 'https://rp.example/status?message=authorization%20code%3Dabc'}, {}, (), ()))
    self.assertFalse(checker(safe, safe, {},
        {'Location': 'https://rp.example/status#message=receipt%3Dabc'}, (), ()))
    self.assertFalse(checker(safe, safe, {}, {}, ({'status': 302},), ()))
    self.assertFalse(checker(b'not-json', safe, {}, {}, (), ()))
    self.assertFalse(checker(safe, safe, {'XAuthorizationCode': 'opaque'}, {}, (), ()))
    self.assertFalse(checker(safe, safe, {'XCallbackUrl': 'opaque'}, {}, (), ()))
    self.assertFalse(checker(safe, safe, {}, {'XReceiptId': 'opaque'}, (), ()))

  def test_issue_guide_records_offline_fixture_evidence_and_live_limits(self):
    guide = Path(__file__).parents[1] / 'docs/acceptance/issue-5-registry-matrix.md'
    text = guide.read_text()
    self.assertIn('test-only fixture supplies malformed bytes', text)
    self.assertIn('inside the resolver-builder', text)
    self.assertIn('Offline receipts still leave live Registry/provider gates `not_run`', text)
    self.assertIn('latest explicitly authorized integrated live result is recorded above', text)
    self.assertIn('The exact candidate passed the complete `issue5-live` lifecycle', text)
    readme = Path(__file__).parents[1] / 'README.md'
    readme_text = readme.read_text()
    self.assertEqual(0, readme_text.count('Twenty-three offline behavior tests'))
    self.assertNotIn('Ten offline behavior tests', readme_text)


if __name__ == '__main__':
  unittest.main()
