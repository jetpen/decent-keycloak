"""Executable Issue #5 behavior tests, independent of live qualification."""

import os
import sys
import unittest
from pathlib import Path

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
  def test_two_attempts_are_ordered_checkpointed_and_use_distinct_fixtures(self):
    events = []
    fixtures = {1: 'owner-key-alpha', 2: 'owner-key-beta'}
    fixture_ids = {1: 'fixture-alpha', 2: 'fixture-beta'}

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

  def test_issue_guide_records_status_without_claiming_readme_is_untouched(self):
    guide = Path(__file__).parents[1] / 'docs/acceptance/issue-5-registry-matrix.md'
    text = guide.read_text()
    self.assertNotIn('remains untouched for its reserved #9 cleanup', text)
    self.assertIn('README', text)


if __name__ == '__main__':
  unittest.main()
