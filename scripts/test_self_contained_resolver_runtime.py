import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class SelfContainedResolverRuntimeTest(unittest.TestCase):
  def test_runtime_provenance_includes_exact_harness_and_lock_hashes(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import _prepare_resolver_runtime

    provenance = _prepare_resolver_runtime()
    self.assertEqual(hashlib.sha256((ROOT / 'scripts/wallet_login_live_e2e.py').read_bytes()).hexdigest(),
        provenance.get('harness_sha256'))
    self.assertEqual(hashlib.sha256((ROOT / 'container/resolver-runtime.lock.json').read_bytes()).hexdigest(),
        provenance.get('runtime_manifest_sha256'))
    self.assertEqual(hashlib.sha256((ROOT / 'container/resolver-requirements.lock.txt').read_bytes()).hexdigest(),
        provenance.get('runtime_lock_sha256'))

  def test_runtime_patcher_finds_helper_when_copied_into_flat_build_context(self):
    import runpy

    with tempfile.TemporaryDirectory() as temporary_directory:
      build_context = Path(temporary_directory)
      patcher_copy = build_context / 'patch_resolver_runtime.py'
      overlay_copy = build_context / 'pinned_lookup_outcomes.py'
      patcher_copy.write_bytes((ROOT / 'container/patch_resolver_runtime.py').read_bytes())
      overlay_copy.write_bytes((ROOT / 'container/pinned_lookup_outcomes.py').read_bytes())

      patcher = runpy.run_path(str(patcher_copy))
      self.assertEqual(overlay_copy.resolve(), patcher['OVERLAY'])
      self.assertEqual(overlay_copy.read_bytes(), patcher['OVERLAY'].read_bytes())

  def test_runtime_lock_pins_wheelhouse_archive_and_exact_size(self):
    lock = json.loads((ROOT / 'container/resolver-runtime.lock.json').read_text())
    wheelhouse = lock.get('wheelhouse')
    self.assertIsInstance(wheelhouse, dict)
    self.assertEqual(67, wheelhouse.get('file_count'))
    archive = ROOT / 'container' / wheelhouse.get('archive', '')
    self.assertTrue(archive.is_file())
    self.assertEqual(wheelhouse.get('archive_sha256'), hashlib.sha256(archive.read_bytes()).hexdigest())

  def test_live_harness_checkpoints_evidence_before_failure(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertIn("evidence_path = Path(temp_dir) / 'live-evidence.json'", harness)
    self.assertIn('def checkpoint(snapshot=None):', harness)
    self.assertIn("except Exception as failure:", harness)
    self.assertIn("print('partial_evidence='", harness)
    self.assertIn("checkpoint()", harness)
    import ast
    main = next(node for node in ast.walk(ast.parse(harness))
        if isinstance(node, ast.FunctionDef) and node.name == 'main')
    local_assignments = [node for node in ast.walk(main)
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'result'
            for target in node.targets)]
    self.assertEqual(1, len(local_assignments), 'scenario receipts must use one projected accumulator')
    self.assertIsInstance(local_assignments[0].value, ast.Dict)
    self.assertTrue(all(isinstance(key, ast.Constant) and isinstance(key.value, str)
        for key in local_assignments[0].value.keys), 'initial checkpoint uses an explicit key allowlist')

  def test_live_harness_persists_per_case_evidence_before_later_failures(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertIn("evidence_path = Path(temp_dir) / 'live-evidence.json'", harness)
    self.assertIn("except Exception as failure:", harness)
    self.assertIn("print('partial_evidence='", harness)
    for case in ('browser_preflight', 'negative_case', 'unmapped_account_case',
        'disabled_account_case', 'signup_case', 'rotated_identity_case', 'ambiguous_account_case', 'missing_identity_case'):
      self.assertIn(f"result['{case}']", harness)
    self.assertGreaterEqual(harness.count('checkpoint()'), 9)
    self.assertIn("current_result = invoke_current_identity_attempt", harness)
    self.assertIn("result['wallet_login'] = current_result.pop('wallet_login')", harness)
    self.assertIn("result['registry_matrix']", harness)
    self.assertNotIn("result.update(auth_flow", harness)
    self.assertIn("json.dumps(sanitize_live_checkpoint(result), sort_keys=True)", harness)
    self.assertNotIn("print('partial_evidence=', result)", harness)
    import ast
    module = ast.parse(harness)
    sanitizer = next(node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == 'sanitize_live_checkpoint')
    allowed_literals = [node for node in ast.walk(sanitizer)
        if isinstance(node, ast.Set) and any(isinstance(item, ast.Constant)
            and item.value == 'resolver_runtime' for item in node.elts)]
    self.assertEqual(1, len(allowed_literals))
    self.assertIn("'runtime_manifest_sha256'", ast.unparse(sanitizer))

  def test_rotation_registry_helper_uses_finalized_envelope_and_independent_fresh_read(self):
    helper = (ROOT / 'scripts/rotation_registry_roundtrip.py').read_text()
    self.assertIn('put_identity(', helper)
    self.assertIn('finalized_envelope_cbor=envelope', helper)
    self.assertIn('get_identity_record(', helper)
    self.assertIn('port=fresh_readback_port()', helper)
    self.assertIn('observed.seq == expected_seq', helper)
    self.assertIn('observed.owner_public_key_hex == expected_key', helper)
  def test_rotation_readback_compares_configured_and_ephemeral_ports_with_same_record(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    flow = harness.split('def rotation_readback_samples(', 1)[1].split('def stale_key_rotation_flow(', 1)[0]
    self.assertIn("for strategy in ('configured', 'ephemeral')", flow)
    self.assertIn("configured_port", flow)
    self.assertIn("packaged_resolver_readback", flow)
    self.assertIn("elif outcome == 'resolved':", flow)
    self.assertIn("outcome = 'unavailable'", flow)
    self.assertIn("range(3)", flow)
    self.assertIn("return samples, resolved", flow)
    rotation_flow = harness.split('def stale_key_rotation_flow(', 1)[1].split('def sanitized_resolver_diagnostic_lines(', 1)[0]
    self.assertIn("expected_key.stdout[-32:].hex()", rotation_flow)
    self.assertIn("'--bootstrap', bootstrap", rotation_flow)
    self.assertIn("free_port,", rotation_flow)
    self.assertIn("'--port', str(port)", rotation_flow)

  def test_rotation_checkpoints_allowlist_both_port_strategies_and_six_samples(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertIn("'configured', 'ephemeral'}", harness)
    self.assertIn("len(value['resolver_samples']) <= 6", harness)
    self.assertIn("'port_strategy': sample['port_strategy']", harness)

  def test_rotation_resolver_sample_keeps_only_allowlisted_diagnostic_categories(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import checkpoint_rotation_stage, sanitize_live_checkpoint

    sample = {'outcome': 'unavailable', 'lookup_ms': 1300, 'peer_handshake': True,
        'unexpected_diagnostic': True, 'json_balanced': False,
        'exact_identity_and_successor_match': False, 'port_strategy': 'configured',
        'diagnostic_categories': ['peer_status', 'peer_handshake', 'other'],
        'raw_output': 'identity private@example.invalid'}
    result = {}
    checkpoint_rotation_stage(result, 'readback', {'resolver_samples': [sample]}, lambda: None)
    projected = sanitize_live_checkpoint(result)
    self.assertEqual({'outcome': 'unavailable', 'lookup_ms': 1300,
        'peer_handshake': True, 'unexpected_diagnostic': True,
        'json_balanced': False, 'exact_identity_and_successor_match': False,
        'port_strategy': 'configured',
        'diagnostic_categories': ['peer_status', 'peer_handshake', 'other']},
        projected['rotated_identity_case']['resolver_samples'][0])
    self.assertNotIn('raw_output', json.dumps(projected))

    invalid = dict(sample, port_strategy='ephemeral', diagnostic_categories=['peer_status', 'password=secret'])
    result = {}
    checkpoint_rotation_stage(result, 'readback', {'resolver_samples': [invalid]}, lambda: None)
    projected = sanitize_live_checkpoint(result)
    self.assertNotIn('diagnostic_categories',
        projected['rotated_identity_case']['resolver_samples'][0])

  def test_checkpoint_reports_current_owner_503_and_status_poll_before_failure(self):
    flow = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    rotation = flow.split('def stale_key_rotation_flow(', 1)[1].split('def classify_oidc_action_error(', 1)[0]
    self.assertIn("progress('current_attempt'", rotation)
    self.assertIn("progress('current_proof', {'current_key_proof_http': current_key_status})", rotation)
    self.assertLess(rotation.index("progress('current_proof'"),
        rotation.index("require(current_key_status == 202"))
    self.assertIn("progress('stale_proof', {'stale_key_proof_http': stale_key_status})", rotation)

  def test_rotation_samples_separate_json_balance_from_exact_successor_match(self):
    from types import SimpleNamespace
    sys.path.insert(0, str(ROOT / 'scripts'))
    import wallet_login_live_e2e as probe
    identity = 'mailto:owner@example.invalid'
    identifier_hex = identity.encode('utf-8').hex()
    expected_key = 'ab' * 32

    def sample_for(public_key, complete=True):
      record = ('{\n  "identifier": "' + identity + '",\n  "owner_name_hex": "'
          + identifier_hex + '",\n  "owner_public_key_hex": "' + public_key
          + '",\n  "seq": 2' + ('\n}' if complete else ''))
      samples, resolved = probe.rotation_readback_samples(identity, expected_key, 8081,
          lambda _port: SimpleNamespace(stdout=record, returncode=0),
          lambda: 8082, lambda _samples: None)
      return samples, resolved

    mismatch, mismatch_resolved = sample_for('cd' * 32)
    malformed, malformed_resolved = sample_for(expected_key, complete=False)
    exact, exact_resolved = sample_for(expected_key)

    self.assertFalse(mismatch_resolved)
    self.assertTrue(all(sample['json_balanced'] for sample in mismatch))
    self.assertTrue(all(not sample['exact_identity_and_successor_match'] for sample in mismatch))
    self.assertTrue(all(sample['outcome'] == 'unavailable' for sample in mismatch))
    self.assertFalse(malformed_resolved)
    self.assertTrue(all(not sample['json_balanced'] for sample in malformed))
    self.assertTrue(all(not sample['exact_identity_and_successor_match'] for sample in malformed))
    self.assertTrue(exact_resolved)
    self.assertTrue(all(sample['json_balanced'] for sample in exact))
    self.assertTrue(all(sample['exact_identity_and_successor_match'] for sample in exact))

  def test_checkpoint_projection_drops_nested_secrets_and_unknown_fields(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import sanitize_live_checkpoint

    candidate = {
        'resolver_runtime': {
            'identity_commit': 'a' * 40, 'registry_commit': 'b' * 40,
            'harness_sha256': 'c' * 64, 'runtime_manifest_sha256': 'd' * 64,
            'runtime_lock_sha256': 'e' * 64, 'image_digest': 'sha256:' + 'f' * 64,
            'host_path': '/sensitive/path',
        },
        'wallet_login': {
            'challenge_get': True, 'proof_post_http': 202, 'callback_code': True,
            'identity_id': 'private-id', 'callback': 'https://issuer/callback?secret',
            'cookies': {'session': 'private-cookie'},
            'callback_replay': {'redirect_http': 302, 'state_preserved': True,
                'error_returned': True, 'authorization_code_returned': False,
                'callback_url': 'https://issuer/callback?secret'},
        },
        'unmapped_account_case': {
            'current_registry_proof_http': 403, 'scenario': 'unmapped-account',
            'registry_lookup_outcome': 'resolved',
            'local_account_mapping_decision_observed': True,
            'registry_unavailable': False, 'no_acceptance_or_callback': True,
            'outcome': 'policy_denied',
        },
        'signup_case': {'stage': 'complete', 'signup_intent_action_http': 200,
            'signup_proof_http': 202, 'exact_mapped_users': 1, 'pkce_token_http': 200,
            'identity_id': 'private-id', 'callback': 'https://issuer/callback?secret'},
        'rotated_identity_case': {'stage': 'complete', 'rotation_publish': 'passed',
            'current_sequence': 2, 'current_key_proof_http': 202,
            'stale_key_proof_http': 401, 'stale_transaction_remains_pending': True,
            'current_transaction_accepted': True, 'local_mapping_persisted': True,
            'resolver_samples': [{'outcome': 'resolved', 'lookup_ms': 240,
                'peer_handshake': False, 'unexpected_diagnostic': False,
                'diagnostic_categories': ['json'], 'port_strategy': 'configured', 'raw': 'private-id'}],
            'identity_id': 'private-id'},
        'rotation_case': {
            'rotation_publish': 'passed', 'current_sequence': 2,
            'current_key_proof_http': 202, 'stale_key_proof_http': 401,
            'stale_transaction_remains_pending': True,
            'current_transaction_accepted': True, 'local_mapping_persisted': True,
        },
        'missing_identity_case': {
            'cli_resolution': 'not_found', 'cli_exit': 1,
            'cli_output_categories': ['registry_miss', 'not_found'],
            'cli_output_shape': ['private-id@example.invalid'],
            'cli_lookup_ms': 120, 'direct_provider_http': 401,
            'direct_provider_lookup_ms': 135, 'status_http': 200,
            'status_pending': True, 'redirects_safe': False,
            'no_acceptance_or_callback': True,
        },
        'negative_case': {'no_acceptance_or_callback': True,
            'invalid_proof_throttle': {'pre_resolution_invalid_http': 401,
                'four_malformed_proofs_http': [400, 400, 400, 400],
                'http_after_five_invalid_attempts': 429, 'no_acceptance_or_callback': True,
                'identity_id': 'private-id'}},
        'unexpected': {'access_token': 'private-token'},
    }

    projected = sanitize_live_checkpoint(candidate)
    self.assertEqual({'resolver_runtime', 'wallet_login', 'unmapped_account_case', 'rotation_case', 'missing_identity_case', 'negative_case', 'signup_case', 'rotated_identity_case'}, set(projected))
    self.assertEqual({'identity_commit', 'registry_commit', 'harness_sha256',
        'runtime_manifest_sha256', 'runtime_lock_sha256', 'image_digest'},
        set(projected['resolver_runtime']))
    self.assertEqual({'stage', 'signup_intent_action_http', 'signup_proof_http',
        'exact_mapped_users', 'pkce_token_http'}, set(projected['signup_case']))
    self.assertEqual({'challenge_get', 'proof_post_http', 'callback_code', 'callback_replay'},
        set(projected['wallet_login']))
    self.assertEqual({'redirect_http', 'state_preserved', 'error_returned',
        'authorization_code_returned'}, set(projected['wallet_login']['callback_replay']))
    self.assertNotIn('callback_url', projected['wallet_login']['callback_replay'])
    self.assertEqual({'current_registry_proof_http', 'scenario', 'registry_lookup_outcome',
        'local_account_mapping_decision_observed', 'registry_unavailable',
        'no_acceptance_or_callback', 'outcome'}, set(projected['unmapped_account_case']))
    self.assertEqual({'rotation_publish', 'current_sequence', 'current_key_proof_http',
        'stale_key_proof_http', 'stale_transaction_remains_pending',
        'current_transaction_accepted', 'local_mapping_persisted'}, set(projected['rotation_case']))
    self.assertEqual({'stage', 'rotation_publish', 'current_sequence',
        'current_key_proof_http', 'stale_key_proof_http', 'resolver_samples',
        'stale_transaction_remains_pending', 'current_transaction_accepted',
        'local_mapping_persisted'}, set(projected['rotated_identity_case']))
    self.assertEqual({'outcome': 'resolved', 'lookup_ms': 240,
        'peer_handshake': False, 'unexpected_diagnostic': False,
        'json_balanced': False, 'exact_identity_and_successor_match': False,
        'port_strategy': 'configured', 'diagnostic_categories': ['json']},
        projected['rotated_identity_case']['resolver_samples'][0])
    self.assertEqual('complete', projected['rotated_identity_case']['stage'])
    self.assertEqual({'cli_resolution', 'cli_exit', 'cli_output_categories', 'cli_lookup_ms',
        'direct_provider_http', 'direct_provider_lookup_ms', 'status_http', 'status_pending',
        'redirects_safe', 'no_acceptance_or_callback'}, set(projected['missing_identity_case']))
    self.assertEqual(['registry_miss', 'not_found'],
        projected['missing_identity_case']['cli_output_categories'])
    self.assertEqual({'no_acceptance_or_callback', 'invalid_proof_throttle'},
        set(projected['negative_case']))
    self.assertEqual({'pre_resolution_invalid_http', 'four_malformed_proofs_http',
        'http_after_five_invalid_attempts', 'no_acceptance_or_callback'},
        set(projected['negative_case']['invalid_proof_throttle']))
    self.assertEqual([400, 400, 400, 400],
        projected['negative_case']['invalid_proof_throttle']['four_malformed_proofs_http'])
    self.assertNotIn('identity_id', json.dumps(projected['negative_case']))
    self.assertNotIn('private-id', json.dumps(projected['negative_case']))
    self.assertNotIn('cli_output_shape', projected['missing_identity_case'])
    self.assertNotIn('private-id', json.dumps(projected))
    self.assertNotIn('private-cookie', json.dumps(projected))
    self.assertNotIn('private-token', json.dumps(projected))
    self.assertNotIn('issuer/callback', json.dumps(projected))
    unsafe_runtime = sanitize_live_checkpoint({
        'resolver_runtime': {
            'identity_commit': 'private-id',
            'harness_sha256': {'password': 'private-password'},
            'runtime_manifest_sha256': ['private-manifest'],
            'image_digest': 'private-image-tag',
        },
    })
    self.assertEqual({}, unsafe_runtime)
    self.assertNotIn('private-password', json.dumps(unsafe_runtime))
    self.assertNotIn('private-id', json.dumps(unsafe_runtime))

  def test_signup_progress_checkpoint_filters_untrusted_fields_and_records_failure_status(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import checkpoint_signup_stage

    result = {'signup_case': {'stage': 'intent', 'signup_intent_action_http': 200}}
    persisted = []
    checkpoint_signup_stage(result, 'proof', {
        'signup_proof_http': 503,
        'identity_id': 'private-id',
        'callback': 'https://issuer/callback?secret',
        'exception': 'private-error',
    }, lambda: persisted.append(json.loads(json.dumps(result))))

    self.assertEqual({'signup_case': {'stage': 'proof', 'signup_intent_action_http': 200,
        'signup_proof_http': 503}}, result)
    self.assertEqual([result], persisted)
    self.assertNotIn('private-id', json.dumps(persisted))
    self.assertNotIn('issuer/callback', json.dumps(persisted))
    self.assertNotIn('private-error', json.dumps(persisted))

  def test_signup_checkpoint_records_http_503_before_the_failure_gate(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertIn("signup_result = signup_wallet_flow", harness)
    self.assertIn("checkpoint()", harness)
    signup_flow = harness.split('def signup_wallet_flow(', 1)[1].split('def missing_identity_flow(', 1)[0]
    proof_position = signup_flow.index("proof_status, _, _ = wallet.request('POST'")
    failure_position = signup_flow.index("require(proof_status == 202")
    self.assertLess(proof_position, failure_position)
    self.assertIn("progress('proof', {'signup_proof_http': proof_status})", signup_flow)
    self.assertNotIn("print('signup_proof_http=", signup_flow)

  def test_account_mapping_checkpoint_reports_unavailable_before_policy_failure(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    main = harness.split('def main():', 1)[1]
    disabled = main.index("disabled_result = account_mapping_denial_flow")
    checkpoint = main.index("result['disabled_account_case'] = disabled_result", disabled)
    decision = main.index("require(account_policy_denial_is_attributed(disabled_result)", disabled)
    self.assertLess(checkpoint, decision)

    self.assertIn("result['disabled_account_case'] = disabled_result", harness)
    self.assertIn("result['ambiguous_account_case'] = ambiguity_result", harness)
    self.assertIn("rotation_result = stale_key_rotation_flow", harness)

  def test_rotation_progress_checkpoint_is_bounded_and_stages_are_allowlisted(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import checkpoint_rotation_stage, sanitize_live_checkpoint

    result = {}
    snapshots = []
    checkpoint_rotation_stage(result, 'current_proof', {
        'current_key_proof_http': 503,
        'identity_id': 'private-id',
        'callback': 'https://issuer/callback?secret',
        'raw_error': 'peer secret detail',
    }, lambda: snapshots.append(sanitize_live_checkpoint(result)))

    self.assertEqual({'rotated_identity_case': {
        'stage': 'current_proof', 'current_key_proof_http': 503}}, snapshots[-1])
    self.assertNotIn('private-id', json.dumps(snapshots))
    self.assertNotIn('issuer/callback', json.dumps(snapshots))
    self.assertNotIn('peer secret detail', json.dumps(snapshots))

  def test_rotation_checkpoints_each_proof_result_before_assertion(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    rotation_flow = harness.split('def stale_key_rotation_flow(', 1)[1].split('def classify_oidc_action_error(', 1)[0]
    self.assertIn("progress('stale_proof', {'stale_key_proof_http': stale_key_status})", rotation_flow)
    self.assertIn("progress('current_proof', {'current_key_proof_http': current_key_status})", rotation_flow)
    self.assertIn("resolver_samples, resolved_fresh_read = rotation_readback_samples(", rotation_flow)
    self.assertIn("'resolver_samples': resolver_samples", rotation_flow)
    self.assertIn("range(3)", harness[harness.index('def rotation_readback_samples('):harness.index('def stale_key_rotation_flow(')])
    self.assertLess(rotation_flow.index("progress('current_proof'"),
        rotation_flow.index("require(current_key_status == 202"))
    main = harness.split('def main():', 1)[1]
    self.assertLess(main.index("rotation_progress = lambda"), main.index("result['rotated_identity_case'] = {"))

  def test_partial_evidence_is_reported_before_temporary_directory_cleanup(self):
    import tempfile
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import report_partial_evidence_on_failure
    from contextlib import redirect_stdout
    from io import StringIO

    scratch = Path(os.environ.get('TMPDIR') or tempfile.gettempdir())
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as directory:
      evidence_path = Path(directory) / 'evidence.json'
      evidence_path.write_text('{"wallet_login":{"proof_post_http":202}}', encoding='utf-8')
      output = StringIO()
      with redirect_stdout(output):
        with self.assertRaisesRegex(RuntimeError, 'synthetic harness failure'):
          with report_partial_evidence_on_failure(evidence_path):
            raise RuntimeError('synthetic harness failure')
      self.assertIn('partial_evidence={"wallet_login":{"proof_post_http":202}}', output.getvalue())

  def test_completed_rotation_snapshot_preserves_earlier_resolver_samples(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    main = harness.split('def main():', 1)[1]
    assignment = main.split("result['rotated_identity_case'] =", 1)[1].split('checkpoint()', 1)[0]
    self.assertIn("result.get('rotated_identity_case', {})", assignment)

  def test_bounded_resolver_attempts_retry_only_503_and_stop_on_first_other_status(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import run_bounded_resolver_attempts

    responses = iter([503, 503, 401])
    calls = []

    def one_fresh_transaction():
      calls.append(len(calls))
      return next(responses)

    outcomes = run_bounded_resolver_attempts(one_fresh_transaction, max_attempts=3)

    self.assertEqual([503, 503, 401], outcomes)
    self.assertEqual([0, 1, 2], calls)

  def test_retry_requires_pending_status_after_a_503_before_resubmitting(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import run_bounded_resolver_attempts

    responses = iter([503, 503, 401])
    pending = iter([True, False])
    calls = []

    def attempt():
      calls.append('proof')
      return next(responses)

    outcomes = run_bounded_resolver_attempts(attempt, max_attempts=3,
        retry_status=503, can_retry=lambda: next(pending), retry_delay_seconds=0)
    self.assertEqual([503, 503], outcomes)
    self.assertEqual(['proof', 'proof'], calls)

  def test_bounded_resolver_attempts_stop_on_success_and_respect_limit(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import run_bounded_resolver_attempts

    responses = iter([503, 202])
    pending_checks = []
    calls = []

    def attempt():
      calls.append('proof')
      return next(responses)

    def still_pending():
      pending_checks.append(True)
      return True

    outcomes = run_bounded_resolver_attempts(attempt, max_attempts=3,
        retry_status=503, can_retry=still_pending, retry_delay_seconds=0)

    self.assertEqual([503, 202], outcomes)
    self.assertEqual(['proof', 'proof'], calls)
    self.assertEqual([True], pending_checks)

  def test_rotation_retries_only_after_same_browser_confirms_pending(self):
    flow = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    flow = flow.split('def stale_key_rotation_flow(', 1)[1].split('def classify_oidc_action_error(', 1)[0]
    for binding in ('rotation_status_url = status_url.group(1)',
        'rotation_csrf = csrf.group(1)', 'current_status_url = status_url.group(1)',
        'current_csrf = csrf.group(1)'):
      self.assertIn(binding, flow)
    self.assertIn("rotation_browser.request('GET', rotation_status_url", flow)
    self.assertIn("'X-Decent-CSRF': rotation_csrf", flow)
    self.assertIn("current_browser.request('GET', current_status_url", flow)
    self.assertIn("'X-Decent-CSRF': current_csrf", flow)
    self.assertIn("status_payload == {'status': 'pending'}", flow)
    self.assertIn('except (json.JSONDecodeError, UnicodeDecodeError):', flow)
    self.assertIn("retry_status=503, can_retry=lambda: stale_retry_status[-1] is not None", flow)
    self.assertIn("retry_status=503, can_retry=lambda: current_retry_status[-1] is not None", flow)

    lock = json.loads((ROOT / 'container/resolver-runtime.lock.json').read_text())
    self.assertEqual({'identity', 'registry'}, set(lock['sources']))
    self.assertEqual('2caec24de52c2dbe241e72fe317281c051d03f89',
        lock['sources']['identity']['commit'])
    self.assertEqual('0fa9a6b631bd77725418e990ae9ea4d974dc546c',
        lock['sources']['registry']['commit'])
    for source in lock['sources'].values():
      self.assertRegex(source['commit'], re.compile(r'^[0-9a-f]{40}$'))
      self.assertRegex(source['archive_sha256'], re.compile(r'^[0-9a-f]{64}$'))
      self.assertTrue(source['url'].startswith('https://github.com/'))
      self.assertTrue(source['requirements_lock'])

    lock = json.loads((ROOT / 'container/resolver-runtime.lock.json').read_text())
    runtime_lock = ROOT / 'container/resolver-requirements.lock.txt'
    constraints = ROOT / 'container/registry-lock-constraints.txt'
    self.assertEqual(lock['runtime_requirements']['lock_sha256'],
        hashlib.sha256(runtime_lock.read_bytes()).hexdigest())
    self.assertEqual(lock['registry_dependency_lock']['registry_lock_constraints_sha256'],
        hashlib.sha256(constraints.read_bytes()).hexdigest())
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    self.assertIn('--require-hashes', dockerfile)
    build_lock = ROOT / 'container/resolver-build-requirements.lock.txt'
    self.assertIn('--require-hashes', dockerfile)
    self.assertIn('wheel==0.45.1', build_lock.read_text())

  def test_builder_uses_locked_extraction_tools_without_mutable_package_install(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    self.assertNotRegex(dockerfile, r'(?m)^RUN dnf\\b')
    self.assertNotRegex(dockerfile, r'(?m)^RUN yum\\b')
    self.assertIn('rpm2cpio gmp-devel.rpm | /usr/bin/cpio -idm', dockerfile)
    self.assertNotIn('curl ', dockerfile)
    self.assertNotIn('openssl', dockerfile)

  def test_container_packages_resolver_and_gmp_without_host_mounts(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    self.assertIn('resolver-runtime.lock.json', dockerfile)
    self.assertIn('libgmp.so.10', dockerfile)
    self.assertIn('decent-identity', dockerfile)
    self.assertIn('/opt/decent-resolver/bin/decent-registry', dockerfile)
    self.assertIn('python-311@sha256:', dockerfile)
    self.assertNotRegex(dockerfile, r'(?i)(/home/|/projects/|\.venv)')
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertNotIn("WALLET_IT_PROJECTS", harness)
    self.assertNotIn("WALLET_IT_NATIVE_LIBS", harness)
    self.assertIn("RESOLVER_WRAPPER = '/opt/decent-resolver/bin/decent-identity'", harness)

  def test_existing_bounded_adapter_still_invokes_exact_identity_get(self):
    resolver = (ROOT / 'src/main/java/org/decentwallet/keycloak/wallet/ProcessIdentityResolver.java').read_text()
    self.assertIn('command.add("get")', resolver)
    self.assertIn('TIMEOUT_SECONDS = 10', resolver)
    self.assertIn('isConfirmedIdentityNotFound(outputText, exactRegistryObjectKeyHex(identityId))', resolver)

  def test_pinned_source_archives_are_bundled_and_checked_before_extraction(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    lock = json.loads((ROOT / 'container/resolver-runtime.lock.json').read_text())
    self.assertIn('COPY container/source-archives/identity.tar.gz container/source-archives/registry.tar.gz ./', dockerfile)
    self.assertIn('COPY container/verify_resolver_runtime_inputs.py ./verify_resolver_runtime_inputs.py', dockerfile)
    self.assertIn('COPY container/patch_resolver_runtime.py container/pinned_lookup_outcomes.py ./', dockerfile)
    self.assertIn('COPY scripts/test_pinned_dht_peer_outcomes.py scripts/test_pinned_registry_lookup_outcomes.py ./scripts/', dockerfile)
    self.assertIn('/resolver-build/scripts/test_pinned_dht_peer_outcomes.py', dockerfile)
    self.assertIn('/resolver-build/scripts/test_pinned_registry_lookup_outcomes.py', dockerfile)
    self.assertNotIn('/tmp/resolver-tests/', dockerfile)
    self.assertIn('python3.11 verify_resolver_runtime_inputs.py', dockerfile)
    self.assertNotIn('ARG IDENTITY_ARCHIVE_SHA256=', dockerfile)
    self.assertNotIn('ARG REGISTRY_ARCHIVE_SHA256=', dockerfile)
    self.assertNotIn('ARG PYTHON_BUILDER=', dockerfile)
    self.assertNotIn('ARG KEYCLOAK_BASE=', dockerfile)
    self.assertIn("FROM quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad", dockerfile)
    self.assertIn("FROM registry.access.redhat.com/ubi9/python-311@sha256:a0bdb55576fc5b8d6704279307817828ef027e1065533ceba133fe9516003a6c", dockerfile)
    self.assertIn('tar -xzf identity.tar.gz --strip-components=1', dockerfile)
    self.assertIn('tar -xzf registry.tar.gz --strip-components=1', dockerfile)
    self.assertNotIn('RUN ./download_resolver_sources.sh', dockerfile)
    for name in ('identity', 'registry'):
      archive = ROOT / 'container/source-archives' / f'{name}.tar.gz'
      self.assertTrue(archive.is_file())
      self.assertEqual(lock['sources'][name]['archive_sha256'],
          hashlib.sha256(archive.read_bytes()).hexdigest())

  def test_container_source_archive_verifier_binds_hashes_and_commits(self):
    import importlib.util
    import tempfile

    path = ROOT / 'container/verify_resolver_runtime_inputs.py'
    spec = importlib.util.spec_from_file_location('verify_resolver_runtime_inputs', path)
    self.assertIsNotNone(spec)
    assert spec is not None and spec.loader is not None
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    original_lock = json.loads((ROOT / 'container/resolver-runtime.lock.json').read_text())
    original_lock.pop('wheelhouse', None)

    with tempfile.TemporaryDirectory() as directory:
      work = Path(directory)
      archives = work / 'archives'
      archives.mkdir()
      manifest_directory = work / 'manifest'
      manifest_directory.mkdir()
      for name in ('identity', 'registry'):
        source = ROOT / 'container/source-archives' / f'{name}.tar.gz'
        (archives / f'{name}.tar.gz').write_bytes(source.read_bytes())
      for name, filename in (
          ('pinned_lookup_outcomes', 'pinned_lookup_outcomes.py'),
          ('runtime_patcher', 'patch_resolver_runtime.py'),
      ):
        source = ROOT / 'container' / filename
        (manifest_directory / filename).write_bytes(source.read_bytes())
        original_lock.setdefault('repo_overlays', {})[name] = {
            'file': filename,
            'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        }
      manifest = manifest_directory / 'resolver-runtime.lock.json'
      manifest.write_text(json.dumps(original_lock))
      verifier.verify_source_archives(archives, manifest)
      overlay_path = manifest_directory / 'pinned_lookup_outcomes.py'
      overlay_bytes = overlay_path.read_bytes()
      overlay_path.write_bytes(overlay_bytes + b'altered')
      with self.assertRaisesRegex(RuntimeError, 'resolver overlay checksum mismatch'):
        verifier.verify_source_archives(archives, manifest)
      overlay_path.write_bytes(overlay_bytes)

      import io
      import tarfile
      wheelhouse_archive = manifest_directory / 'wheelhouse.tar.gz'
      payload = b'pinned-wheel'
      info = tarfile.TarInfo('wheelhouse/example.whl')
      info.size = len(payload)
      info.mode = 0o644
      info.mtime = 0
      with tarfile.open(wheelhouse_archive, 'w:gz') as bundle:
        bundle.addfile(info, io.BytesIO(payload))
      lock_with_wheelhouse = json.loads(manifest.read_text())
      lock_with_wheelhouse['wheelhouse'] = {
          'archive': 'wheelhouse.tar.gz',
          'archive_sha256': hashlib.sha256(wheelhouse_archive.read_bytes()).hexdigest(),
          'file_count': 1,
      }
      manifest.write_text(json.dumps(lock_with_wheelhouse))
      verifier.verify_source_archives(archives, manifest)
      wheelhouse_archive.write_bytes(wheelhouse_archive.read_bytes() + b'altered')
      with self.assertRaisesRegex(RuntimeError, 'wheelhouse archive checksum mismatch'):
        verifier.verify_source_archives(archives, manifest)

      changed_archive = archives / 'identity.tar.gz'
      changed_archive.write_bytes(changed_archive.read_bytes() + b'changed')
      with self.assertRaisesRegex(RuntimeError, 'checksum'):
        verifier.verify_source_archives(archives, manifest)
      source = ROOT / 'container/source-archives/identity.tar.gz'
      changed_archive.write_bytes(source.read_bytes())

      altered_lock = json.loads(manifest.read_text())
      altered_lock['sources']['identity']['commit'] = 'f' * 40
      manifest.write_text(json.dumps(altered_lock))
      with self.assertRaisesRegex(RuntimeError, 'commit'):
        verifier.verify_source_archives(archives, manifest)

  def test_source_archive_extraction_rejects_symlink_destination(self):
    import importlib.util
    import io
    import tarfile
    import tempfile

    path = ROOT / 'container/build_resolver_runtime.py'
    spec = importlib.util.spec_from_file_location('build_resolver_runtime_symlink_test', path)
    self.assertIsNotNone(spec)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    with tempfile.TemporaryDirectory() as directory:
      work = Path(directory)
      outside = work / 'outside'
      outside.mkdir()
      destination = work / 'source-destination'
      destination.symlink_to(outside, target_is_directory=True)
      archive = work / 'source.tar.gz'
      with tarfile.open(archive, 'w:gz') as bundle:
        payload = b'archive payload'
        info = tarfile.TarInfo('repo-abc123/payload.txt')
        info.size = len(payload)
        info.mode = 0o644
        bundle.addfile(info, io.BytesIO(payload))

      with self.assertRaisesRegex(RuntimeError, 'destination must not be a symlink'):
        builder.extract_pinned_archive(archive, destination, 'abc123')

      self.assertFalse((outside / 'payload.txt').exists())

  def test_wheelhouse_verifier_rejects_duplicate_normalized_member_paths(self):
    import importlib.util
    import io
    import tarfile
    import tempfile

    path = ROOT / 'container/verify_resolver_runtime_inputs.py'
    spec = importlib.util.spec_from_file_location('verify_resolver_runtime_inputs_duplicates', path)
    self.assertIsNotNone(spec)
    assert spec is not None and spec.loader is not None
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    with tempfile.TemporaryDirectory() as directory:
      work = Path(directory)
      archive = work / 'wheelhouse.tar.gz'
      with tarfile.open(archive, 'w:gz') as bundle:
        for name, payload in (('./wheelhouse/example.whl', b'first'),
            ('wheelhouse/example.whl', b'second')):
          info = tarfile.TarInfo(name)
          info.size = len(payload)
          info.mode = 0o644
          info.mtime = 0
          bundle.addfile(info, io.BytesIO(payload))
      manifest = work / 'resolver-runtime.lock.json'
      manifest.write_text(json.dumps({'wheelhouse': {
          'archive': archive.name,
          'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
          'file_count': 2}}))
      with self.assertRaisesRegex(RuntimeError, 'duplicate normalized path'):
        verifier.verify_wheelhouse_archive(work, manifest)

  def test_each_dockerfile_run_step_is_network_isolated(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    run_lines = [line for line in dockerfile.splitlines() if line.startswith('RUN ')]

    self.assertTrue(run_lines)
    self.assertTrue(all(line.startswith('RUN --network=none ') for line in run_lines), run_lines)

  def test_build_downloads_no_unpinned_sources(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    download_script = ROOT / 'container/download_resolver_sources.sh'
    self.assertFalse(download_script.exists())
    self.assertNotIn('curl ', dockerfile)
    self.assertIn('COPY container/source-archives/identity.tar.gz container/source-archives/registry.tar.gz ./', dockerfile)

  def test_gmp_layer_does_not_continue_into_source_download_run(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    lines = dockerfile.splitlines()
    link_index = next(index for index, line in enumerate(lines)
        if 'ln -s libgmp.so.10.4.0 /opt/decent-resolver/lib/libgmp.so.10' in line)
    self.assertTrue(lines[link_index].rstrip().endswith(chr(92)))
    self.assertEqual('RUN --network=none python3.11 verify_resolver_runtime_inputs.py --archives . --manifest resolver-runtime.lock.json \\', lines[link_index + 3])

  def test_runtime_target_installs_provider_and_builds_keycloak(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    runtime_stage = dockerfile.split('FROM keycloak-with-resolver AS runtime', 1)[1]
    self.assertIn('COPY target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/', runtime_stage)
    self.assertIn('RUN --network=none /opt/keycloak/bin/kc.sh build', runtime_stage)
    self.assertIn('--db=dev-file', runtime_stage)
    self.assertIn('--cache=local', runtime_stage)
    self.assertIn('--spi-single-use-object--provider-default=infinispan', runtime_stage)
    startup = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text().split('def start_keycloak(', 1)[1].split('def admin_token', 1)[0]
    self.assertIn("'--cache=local'", startup)

  def test_resolver_image_tag_is_resolved_once_to_an_immutable_id_before_containers_start(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from types import SimpleNamespace
    from unittest.mock import patch
    import wallet_login_live_e2e as harness

    digest = 'sha256:' + 'a' * 64
    image_id = 'sha256:' + 'b' * 64
    with patch.object(harness, 'run', return_value=SimpleNamespace(
        returncode=0, stdout=image_id + '|' + digest + '\n')) as inspect:
      resolved_id, resolved_digest = harness.resolve_immutable_image('mutable:test-tag')

    self.assertEqual(image_id, resolved_id)
    self.assertEqual(digest, resolved_digest)
    self.assertEqual(['podman', 'image', 'inspect', 'mutable:test-tag',
        '--format', '{{.Id}}|{{.Digest}}'], inspect.call_args.args[0])
    main = harness.__file__ and (ROOT / 'scripts/wallet_login_live_e2e.py').read_text().split('def main():', 1)[1]
    self.assertLess(main.index('IMAGE, image_digest = resolve_immutable_image(IMAGE)'),
        main.index('start_resolver_tools(temp, IMAGE,'))

  def test_resolver_tools_container_mounts_only_the_run_temporary_directory(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    start = harness.split('def start_resolver_tools(temp, image, lifetime=300):', 1)[1].split('def run_image_resolver(', 1)[0]
    self.assertIn("temp = Path(temp)", start)
    self.assertIn("f'{temp}:{temp}:rw'", start)
    self.assertNotIn("f'{SCRATCH}:{SCRATCH}:rw'", start)

  def test_live_harness_requires_digest_pinned_image_for_all_containers(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertIn('def resolve_immutable_image(', harness)
    self.assertIn("runtime_provenance['image_digest']", harness)
    self.assertNotIn("IMAGE = os.environ.get('WALLET_IT_IMAGE', 'localhost/", harness)
    self.assertIn("--format", harness)
    self.assertIn("IMAGE = os.environ.get('WALLET_IT_IMAGE')", harness)

  def test_full_live_harness_uses_the_selected_immutable_image_for_each_container(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    for function_name, end_name in (('start_registry', 'start_resolver_tools'),
        ('start_resolver_tools', 'run_image_resolver'), ('start_keycloak', 'def admin_token')):
      body = harness.split(f'def {function_name}(', 1)[1].split(f'def {end_name}', 1)[0]
      self.assertIn('image', body)
      self.assertIn('image,', body)
    self.assertIn('IMAGE, image_digest = resolve_immutable_image(IMAGE)', harness)
    self.assertNotIn("podman', 'image', 'inspect', IMAGE, '--format', '{{.Digest}}'", harness)
    self.assertIn("def run_image_resolver(container, args, timeout=45, image=None):", harness)
    self.assertIn("if image is None:\n    image = IMAGE", harness)

  def test_owner_key_signing_inputs_remain_private_even_when_parent_is_world_readable(self):
    import os
    import tempfile
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import write_private_signing_input

    with tempfile.TemporaryDirectory() as scratch:
      parent = Path(scratch) / 'shared'
      parent.mkdir(mode=0o755)
      os.chmod(parent, 0o755)
      path = write_private_signing_input(parent, 'signing-test', b'fixture challenge')
      try:
        self.assertEqual(b'fixture challenge', path.read_bytes())
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
      finally:
        path.unlink(missing_ok=True)

    source = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertIn('def write_private_signing_input(', source)
    helper = source.split('def write_private_signing_input(', 1)[1].split('def ', 1)[0]
    self.assertIn('os.open(', helper)
    self.assertIn('0o600', helper)
    self.assertIn('os.fchmod(', helper)
    self.assertIn('with tempfile.TemporaryDirectory', source)
    self.assertNotIn("Path(SCRATCH) / f'wallet-login-", source)
    self.assertNotIn("Path(SCRATCH) / f'signup-signing-", source)

    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    runtime_stage = dockerfile.split('FROM quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad AS keycloak-with-resolver', 1)[1]
    self.assertIn('USER 1000', runtime_stage)
    self.assertLess(runtime_stage.index('USER 0'), runtime_stage.index('USER 1000'))

  def test_exact_registry_readback_rejects_peer_handshake_diagnostics_around_valid_json(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import (
        classify_identity_lookup, exact_registry_lookup_outcome,
        packaged_resolver_readback, parse_exact_identity_result,
    )

    record = '{\n  "identifier": "alice@example.org",\n  "owner_name_hex": "616c696365406578616d706c652e6f7267",\n  "owner_public_key_hex": "' + ('ab' * 32) + '",\n  "seq": 1\n}'
    handshake = ('failed to upgrade security for peer 12D3Koo' + ('1' * 45)
        + ': handshake failed when upgrading to secure connection')
    for mixed in (handshake + '\n' + record, record + '\n' + handshake):
      with self.subTest(prefix=mixed.startswith('failed')):
        self.assertEqual('unavailable', classify_identity_lookup(mixed, 0)[0])
        self.assertIsNone(parse_exact_identity_result(mixed, 'alice@example.org'))
        self.assertFalse(packaged_resolver_readback(mixed, 0,
            'alice@example.org', 'ab' * 32))
        self.assertEqual('unavailable', exact_registry_lookup_outcome(
            mixed, 0, 'alice@example.org'))

    self.assertIn("resolver_samples, resolved_fresh_read = rotation_readback_samples(", harness)
    self.assertIn("provider_lookup = run_image_resolver", harness)
    self.assertIn("lambda port: run_image_resolver", harness)

  def test_classifier_requires_every_registry_miss_to_match_exact_requested_identity(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import classify_identity_lookup
    identifier = 'mailto:alice@example.org'
    expected_key = '4aa8889aa1e3f193844b32d36e58b50a8817304b9e15d798d460d00bff828a29'
    expected_miss = 'Value not found for key /decent-registry/identity/' + expected_key
    wrong_miss = 'Value not found for key /decent-registry/identity/' + 'ab' * 32

    clean_summary = (
        'DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=1 failed=0 timeouts=0 incomplete=0' + chr(10)
        + 'DHT_LOOKUP_SUMMARY stage=remote_identity attempts=1 empty=1 failed=0 timeouts=0 incomplete=0' + chr(10)
    )

    self.assertEqual('not_found', classify_identity_lookup(
        clean_summary + expected_miss + chr(10) + 'not found', 1, identifier)[0])
    self.assertEqual('unavailable', classify_identity_lookup(
        clean_summary + wrong_miss + chr(10) + 'not found', 1, identifier)[0])
    self.assertEqual('unavailable', classify_identity_lookup(
        clean_summary + expected_miss + chr(10) + wrong_miss + chr(10) + 'not found', 1, identifier)[0])
    self.assertEqual('unavailable', classify_identity_lookup(
        clean_summary + expected_miss + chr(10) + 'not found', 1)[0])

  def test_rotation_helper_uses_a_real_ephemeral_port_for_independent_reads(self):
    helper = (ROOT / 'scripts/rotation_registry_roundtrip.py').read_text()
    self.assertIn('def fresh_readback_port() -> int:', helper)
    self.assertIn('port=fresh_readback_port()', helper)
    self.assertNotIn('port=0,', helper)

  def test_rotation_helper_is_packaged_and_registry_cli_smoke_runs_in_builder_stage(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    builder_stage = dockerfile.split('FROM quay.io/keycloak/keycloak@', 1)[0]
    keycloak_stage = dockerfile.split('FROM quay.io/keycloak/keycloak@', 1)[1].split(
        'FROM keycloak-with-resolver AS runtime', 1)[0]
    runtime_stage = dockerfile.split('FROM keycloak-with-resolver AS runtime', 1)[1].split(
        'FROM runtime AS issue7-user-readback-test-runtime', 1)[0]
    self.assertIn('COPY container/rotation_registry_roundtrip.py ./rotation_registry_roundtrip.py', dockerfile)
    self.assertIn('/opt/decent-resolver/bin/decent-registry --help', builder_stage)
    self.assertNotIn('decent-registry --help', keycloak_stage)
    self.assertNotIn('decent-registry --help', runtime_stage)
    self.assertIn('cp rotation_registry_roundtrip.py /opt/decent-resolver/rotation_registry_roundtrip.py', dockerfile)

  def test_stale_key_rotation_uses_packaged_tools_and_confirms_exact_successor_key(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    flow = harness.split('def stale_key_rotation_flow(', 1)[1].split('def missing_identity_flow(', 1)[0]
    self.assertIn("'/opt/decent-resolver/rotation_registry_roundtrip.py'", flow)
    self.assertIn("'--new-key', str(new_key_in_tools)", flow)
    self.assertIn('readback[1] == expected_key.stdout[-32:].hex()', flow)
    self.assertIn('run_image_resolver(os.environ[\'WALLET_IT_RESOLVER_TOOLS_CONTAINER\']', flow)
    self.assertNotIn("PROJECTS / 'decent-registry/.venv/bin/python'", flow)
    self.assertNotIn('helper_env', flow)

  def test_registry_node_mounts_its_ephemeral_datastore(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    registry_start = harness.split('def start_registry(temp, image, run_seconds=300):', 1)[1].split('def start_resolver_tools(', 1)[0]
    self.assertIn("datastore = temp / 'registry-lmdb'", registry_start)
    self.assertIn('datastore.mkdir(', registry_start)
    self.assertIn("host: 127.0.0.1", registry_start)
    self.assertNotIn("host: 0.0.0.0", registry_start)
    self.assertIn("'--volume', f'{datastore}:{datastore}:rw'", registry_start)
    self.assertNotIn("path: /tmp/registry-lmdb", registry_start)

  def test_mapping_checkpoint_is_written_before_later_scenarios(self):
    source = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    main = source.split('def main():', 1)[1]
    mapping_check = main.index("rotation_progress('mapping', {'local_mapping_persisted': local_mapping_persisted})")
    require_mapping = main.index("require(local_mapping_persisted, 'rotated account Identity mapping persisted exactly')")
    ambiguity = main.index('ambiguity_result = account_mapping_denial_flow', require_mapping)
    checkpoint_after = main.index('checkpoint()', require_mapping)
    self.assertLess(mapping_check, require_mapping)
    self.assertLess(require_mapping, checkpoint_after)
    self.assertLess(checkpoint_after, ambiguity)

  def test_refreshes_realm_admin_token_before_late_rotation_readback(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    main = harness.split('def main():', 1)[1]
    check = main.index("rotated_user = json.loads(admin_call(client, token, 'GET',")
    refresh = main.rfind('token = admin_token(client, AdminPassword(password))', 0, check)
    self.assertGreater(refresh, main.index("rotation_result = stale_key_rotation_flow("))
    self.assertLess(refresh, check)
  def test_packaged_resolver_readback_rejects_transport_diagnostics_and_requires_exact_identity_and_key(self):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from wallet_login_live_e2e import packaged_resolver_readback, parse_exact_identity_result
    output = '{\n  "identifier": "alice@example.org",\n  "owner_name_hex": "616c696365406578616d706c652e6f7267",\n  "owner_public_key_hex": "' + ('ab' * 32) + '",\n  "seq": 1\n}'
    handshake = 'failed to upgrade security for peer 12D3Koo' + ('1' * 44) + ': handshake failed when upgrading to secure connection'
    self.assertIsNone(parse_exact_identity_result(handshake + '\n' + output,
        'alice@example.org'))
    self.assertIsNone(parse_exact_identity_result(output + '\n' + handshake,
        'alice@example.org'))
    self.assertFalse(packaged_resolver_readback(handshake + '\n' + output,
        0, 'alice@example.org', 'ab' * 32))
    self.assertFalse(packaged_resolver_readback(output + '\n' + handshake,
        0, 'alice@example.org', 'ab' * 32))
    self.assertTrue(packaged_resolver_readback(output, 0, 'alice@example.org', 'ab' * 32))
    self.assertFalse(packaged_resolver_readback(output, 0, 'alice@example.org', 'cd' * 32))
    self.assertFalse(packaged_resolver_readback(output, 0, 'alice@example.net', 'ab' * 32))
    self.assertFalse(packaged_resolver_readback('not found', 1, 'alice@example.org', 'ab' * 32))

  def test_runtime_build_installs_hash_locked_dependencies_offline_from_wheelhouse(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    self.assertIn('COPY container/resolver-wheelhouse.tar.gz ./resolver-wheelhouse.tar.gz', dockerfile)
    self.assertIn('--no-index', dockerfile)
    self.assertIn('--find-links=/resolver-build/wheelhouse', dockerfile)
    self.assertIn('--require-hashes', dockerfile)

  def test_pinned_resolver_tests_run_in_builder_and_are_absent_from_runtime_layers(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    builder_stage = dockerfile.split('FROM quay.io/keycloak/keycloak@', 1)[0]
    peer_test = '/resolver-build/scripts/test_pinned_dht_peer_outcomes.py'
    registry_test = '/resolver-build/scripts/test_pinned_registry_lookup_outcomes.py'
    self.assertIn('RUN --network=none if [ ! -e /etc/resolv.conf ]', builder_stage)
    self.assertIn('LD_LIBRARY_PATH=/opt/decent-resolver/lib /opt/decent-resolver/venv/bin/python ' + peer_test, builder_stage)
    self.assertIn('RESOLVER_TEST_REGISTRY_SOURCE=/opt/decent-resolver/registry-src/src LD_LIBRARY_PATH=/opt/decent-resolver/lib /opt/decent-resolver/venv/bin/python ' + registry_test, builder_stage)
    self.assertIn("/opt/decent-resolver/bin/decent-identity --help", builder_stage)
    self.assertIn("/opt/decent-resolver/bin/decent-registry --help", builder_stage)
    self.assertIn('rm -f /etc/resolv.conf', builder_stage)
    self.assertLess(builder_stage.index('if [ ! -e /etc/resolv.conf ]'), builder_stage.index(peer_test))
    self.assertLess(builder_stage.index(registry_test), builder_stage.index('rm -f /etc/resolv.conf'))
    keycloak_stage = dockerfile.split('FROM quay.io/keycloak/keycloak@', 1)[1].split(
        'FROM keycloak-with-resolver AS runtime', 1)[0]
    runtime_stage = dockerfile.split('FROM keycloak-with-resolver AS runtime', 1)[1].split(
        'FROM runtime AS issue7-user-readback-test-runtime', 1)[0]
    for stage in (keycloak_stage, runtime_stage):
      self.assertNotIn('test_pinned_', stage)
      self.assertNotIn('/tmp/resolver-tests', stage)
      self.assertNotIn('/etc/resolv.conf', stage)

  def test_live_harness_uses_the_pinned_image_for_registry_node_and_seed_resolver(self):
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    self.assertIn("def run_image_resolver", harness)
    self.assertIn("runtime_provenance['image_digest']", harness)
    self.assertIn("'--network', 'host'", harness)
    self.assertIn("packaged_resolver_readback", harness)
    self.assertIn("RESOLVER_WRAPPER, *args", harness)
    self.assertNotIn("[REGISTRY_CLI, '-v', 'node'", harness)
    self.assertIn("'/opt/decent-resolver/bin/decent-registry'", harness)

  def test_runtime_uses_bundled_registry_rotation_helper(self):
    dockerfile = (ROOT / 'container/Dockerfile').read_text()
    self.assertIn('COPY container/rotation_registry_roundtrip.py ./rotation_registry_roundtrip.py', dockerfile)
    harness = (ROOT / 'scripts/wallet_login_live_e2e.py').read_text()
    helper = ROOT / 'scripts/rotation_registry_roundtrip.py'
    bundled_helper = ROOT / 'container/rotation_registry_roundtrip.py'
    self.assertTrue(helper.is_file())
    self.assertEqual(hashlib.sha256(helper.read_bytes()).digest(),
        hashlib.sha256(bundled_helper.read_bytes()).digest())
    self.assertIn("'/opt/decent-resolver/rotation_registry_roundtrip.py'", harness)
    self.assertNotIn('WALLET_IT_IDENTITY_CLI', harness)
    self.assertNotIn('WALLET_IT_REGISTRY_CLI', harness)

  def test_runtime_input_verifier_does_not_advertise_bundle_building(self):
    builder = ROOT / 'container/build_resolver_runtime.py'
    help_result = subprocess.run([sys.executable, str(builder), '--help'], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=30)
    self.assertEqual(0, help_result.returncode, help_result.stdout)
    self.assertNotIn('--bundle', help_result.stdout)
    self.assertIn('--materialize-sources', help_result.stdout)
    result = subprocess.run([sys.executable, str(builder)], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=30)
    self.assertEqual(0, result.returncode, result.stdout)
    self.assertIn('"status": "resolver_inputs_verified"', result.stdout)
    self.assertIn('"builder": "container/Dockerfile"', result.stdout)
    lock = json.loads((ROOT / 'container/resolver-runtime.lock.json').read_text())
    self.assertIn(lock['sources']['identity']['commit'], result.stdout)
    self.assertIn(lock['sources']['registry']['commit'], result.stdout)



if __name__ == '__main__':
  unittest.main()
