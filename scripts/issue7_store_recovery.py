"""Single-node store fault/recovery coordinator, shared lifecycle owned by main.

The decorator is a test-only operation-boundary wrapper, not a distributed race.
Only allowlisted facts cross the checkpoint boundary; subjects/locators stay local.
"""
import hashlib
import re
import urllib.parse

PROFILES = {
    'issue7-consume-loss-recovery': 'consume-loss',
    'issue7-accepted-receipt-write-recovery': 'accepted-receipt-write',
    'issue7-accepted-receipt-write-false-recovery': 'accepted-receipt-write-false',
}
MARKERS = {
    'consume-loss': 'pending consume committed then threw',
    'accepted-receipt-write': 'accepted receipt write committed then threw',
    'accepted-receipt-write-false': 'accepted receipt write returned false before commit',
}
FAILURE_STAGES = {'signup_flow', 'signup_proof', 'user_readback'}
FAILURE_GATES = {'unclassified', 'proof_http_status', 'account_readback', 'proof_post',
    'identical_retry', 'changed_retry', 'proof_status', 'callback', 'callback_replay',
    'status_after_callback', 'pkce', 'store_correlation'}
FAILURE_CATEGORIES = {'runtime_error', 'assertion_failed'}
FAILURE_CONTEXTS = {
    'post-create UserProvider readback fault returns empty 503 without redirect, callback, or code':
        ('signup_proof', 'proof_http_status'),
    'post-create readback failure retains one exact enabled account':
        ('user_readback', 'account_readback'),
}


def checkpoint_signup_failure(checkpoint, failure, *, mode_field, mode):
  evidence = {
      'stage': 'faulted_signup', 'scope': 'one-keycloak-node', mode_field: mode,
      'failure_stage': getattr(failure, 'failure_stage', 'signup_flow'),
      'failure_gate': getattr(failure, 'failure_gate', 'unclassified'),
      'failure_category': getattr(failure, 'failure_category', 'runtime_error'),
  }
  status = getattr(failure, 'failure_http_status', None)
  if type(status) is int and 100 <= status <= 599:
    status_field = ('signup_proof_http' if evidence['failure_gate'] == 'proof_http_status'
        else 'failure_http_status')
    evidence[status_field] = status
  diagnostics = getattr(failure, 'issue7_diagnostics', None)
  if isinstance(diagnostics, dict):
    read_status = diagnostics.get('store_diagnostic_read_status')
    if read_status in {'observed', 'unavailable'}:
      evidence['store_diagnostic_read_status'] = read_status
    selected = diagnostics.get('store_provider_selected')
    if type(selected) is bool:
      evidence['store_provider_selected'] = selected
    for field in ('store_fault_count', 'correlated_store_failure_count'):
      count = diagnostics.get(field)
      if type(count) is int and 0 <= count <= 5:
        evidence[field] = count
  try:
    checkpoint(evidence)
  except Exception:
    failure.add_note('Issue #7 failure checkpoint could not be written')


def diagnostics(logs, mode, request_id):
  if mode not in MARKERS or not re.fullmatch(r'[a-f0-9]{32}', request_id):
    return {'store_fault_count': 0, 'correlated_store_failure_count': 0,
        'store_provider_selected': False}
  cause = ('Wallet pending transaction unavailable (request=' + request_id
      + ', reason=consume-unavailable)' if mode == 'consume-loss' else
      'Wallet proof acceptance unavailable (request=' + request_id + ', outcome=not_accepted)')
  operation = 'transaction_remove' if mode == 'consume-loss' else 'accepted_replace'
  provider_witness = (f'ISSUE7_TEST_PROVIDER_OPERATION: operation={operation} '
      f'request={request_id}')
  fault_witness = f'ISSUE7_TEST_FAULT: {MARKERS[mode]} request={request_id}'
  return {
      'store_fault_count': min(5, logs.count(fault_witness)),
      'correlated_store_failure_count': min(5, logs.count(cause)),
      'store_provider_selected': logs.count(provider_witness) == 1,
  }


def failure_diagnostic_snapshot(api, *, container, log_cursor, mode, locator):
  """Read only allowlisted failure facts; raw log text never leaves this helper."""
  try:
    handle = urllib.parse.urlsplit(locator).path.rsplit('/', 1)[-1]
    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    logs = api.read_provider_fault_log_window(container, log_cursor, strict=True)
    if not isinstance(logs, str):
      raise ValueError('diagnostic log result unavailable')
  except Exception:
    return {'store_diagnostic_read_status': 'unavailable',
        'store_provider_selected': False, 'store_fault_count': 0,
        'correlated_store_failure_count': 0}
  return {'store_diagnostic_read_status': 'observed',
      **diagnostics(logs, mode, request_id)}


def attach_failure_diagnostics(failure, api, *, container, log_cursor, mode, locator):
  try:
    failure.issue7_diagnostics = failure_diagnostic_snapshot(api, container=container,
        log_cursor=log_cursor, mode=mode, locator=locator)
  except Exception:
    # Diagnostic collection must never replace the signup failure.
    failure.issue7_diagnostics = {'store_diagnostic_read_status': 'unavailable',
        'store_provider_selected': False, 'store_fault_count': 0,
        'correlated_store_failure_count': 0}


def failure_flow(api, *, mode, wallet, browser, locator, status_url, csrf, proof,
    proof_response, proof_redirects, container, log_cursor, admin_client, token, identifier):
  """Validate original failure AND old status/retry; do not start recovery here."""
  status, headers, body = proof_response
  api.require(status == 503 and api.failure_response_has_no_callback_or_code(
      body, headers, proof_redirects), 'store fault denies proof without body, redirect, callback or code',
      status, failure_stage='signup_proof', failure_gate='proof_http_status', http_status=status)
  browser_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf}
  for requester, method, url, data, request_headers, gate in (
      (browser, 'GET', status_url, None, browser_headers, 'proof_status'),
      (wallet, 'POST', locator, proof, {'Content-Type': 'application/json'}, 'identical_retry')):
    before = len(requester.redirects)
    try:
      polled, response_headers, raw = requester.request(method, url, data, headers=request_headers)
    except Exception as failure:
      setattr(failure, 'failure_stage', 'signup_proof')
      setattr(failure, 'failure_gate', gate)
      setattr(failure, 'failure_category', 'runtime_error')
      raise
    api.require(polled == 404 and api.failure_response_has_no_callback_or_code(
        raw, response_headers, requester.redirects[before:]),
        'consumed transaction status and retry deny all receipt/callback/code disclosure',
        polled, failure_stage='signup_proof', failure_gate=gate, http_status=polled)
  facts = failure_diagnostic_snapshot(api, container=container,
      log_cursor=log_cursor, mode=mode, locator=locator)
  api.require(facts['store_provider_selected'] and facts['store_fault_count'] == 1
      and facts['correlated_store_failure_count'] >= 1,
      'one-shot store fixture and production failure branch correlate to this request',
      failure_stage='signup_proof', failure_gate='store_correlation')
  import json
  users = json.loads(api.admin_call(admin_client, token, 'GET',
      f'/auth/admin/realms/{api.REALM}/users?q=decent_identity_id:{urllib.parse.quote(identifier)}&max=10')[2])
  matched = [user for user in users
      if user.get('attributes', {}).get('decent_identity_id') == [identifier]]
  api.require(len(matched) == 1 and matched[0].get('enabled') is True and matched[0].get('id'),
      'failed signup retains exactly one enabled exact local account')
  return {**facts, 'signup_proof_http': status, 'browser_status_http': 404,
      'retry_http': 404, 'failure_responses_no_callback_or_code': True,
      'account_retained_after_failure': True, 'exact_mapped_users': 1,
      'expected_existing_subject': matched[0]['id'], 'prior_locator': locator}


def run(api, client, key, identifier, container, admin_client, image, progress, checkpoint, profile):
  mode = PROFILES[profile]
  try:
    failed = api.signup_wallet_flow(client, key, identifier, container, admin_client,
        progress, image, store_fault_mode=mode)
  except Exception as failure:
    checkpoint_signup_failure(checkpoint, failure, mode_field='store_fault_mode', mode=mode)
    raise
  # Defense in depth at the coordinator seam, before another ceremony is possible.
  api.require(failed.get('failure_responses_no_callback_or_code') is True
      and failed.get('account_retained_after_failure') is True
      and failed.get('signup_proof_http') == 503 and failed.get('browser_status_http') == 404
      and failed.get('retry_http') == 404 and failed.get('exact_mapped_users') == 1
      and failed.get('store_fault_count') == 1 and failed.get('store_provider_selected') is True
      and failed.get('correlated_store_failure_count', 0) >= 1
      and bool(failed.get('expected_existing_subject')) and bool(failed.get('prior_locator')),
      'complete safe failed signup evidence required before recovery')
  evidence = {field: value for field, value in failed.items()
      if field not in {'expected_existing_subject', 'prior_locator'}}
  evidence.update({'stage': 'recovery', 'scope': 'one-keycloak-node',
      'store_fault_mode': mode, 'fault_evidence_provenance': 'wrapper-mediated-application-path',
      'keycloak_node_count': 1, 'fresh_explicit_signup_transactions': 1,
      'fresh_login_transactions': 0})
  checkpoint(evidence)
  api.wait_for_identity_lookup_cooldown()
  receipt = mode != 'consume-loss'
  if receipt:
    recovered = api.auth_flow(api.Client(), key, identifier, container, image,
        prior_locator=failed['prior_locator'], expected_subject=failed['expected_existing_subject'])
    valid = (recovered.get('proof_post_http') == 202
        and recovered.get('fresh_locator_distinct') is True
        and recovered.get('callback_replay_denied_safely') is True
        and recovered.get('callback_state_preserved') is True
        and recovered.get('callback_code_returned') is True)
  else:
    recovered = api.signup_wallet_flow(api.Client(), key, identifier, container,
        admin_client, progress, image, reuse_existing=True)
    valid = recovered.get('signup_proof_http') == 202 and recovered.get('exact_mapped_users') == 1
  same_subject = recovered.get('local_subject') == failed['expected_existing_subject']
  api.require(valid and same_subject and recovered.get('callback_http') in {302, 303}
      and recovered.get('pkce_token_http') == 200,
      'fresh recovery completes callback and PKCE for the retained exact subject')
  evidence = {key: value for key, value in failed.items()
      if key not in {'expected_existing_subject', 'prior_locator'}}
  evidence.update({'stage': 'complete', 'scope': 'one-keycloak-node',
      'store_fault_mode': mode, 'fault_evidence_provenance': 'wrapper-mediated-application-path',
      'keycloak_node_count': 1, 'same_local_subject': same_subject,
      'fresh_explicit_signup_transactions': 1 if receipt else 2,
      'fresh_login_transactions': 1 if receipt else 0,
      'recovery_intent': 'login' if receipt else 'signup',
      'callback_http': recovered['callback_http'], 'pkce_token_http': recovered['pkce_token_http']})
  checkpoint(evidence)
  return evidence


def sanitize(value):
  if not isinstance(value, dict):
    return {}
  enums = {'stage': {'setup', 'faulted_signup', 'recovery', 'complete'},
      'scope': {'one-keycloak-node'}, 'store_fault_mode': set(PROFILES.values()),
      'recovery_intent': {'signup', 'login'},
      'fault_evidence_provenance': {'wrapper-mediated-application-path'},
      'failure_stage': FAILURE_STAGES, 'failure_gate': FAILURE_GATES,
      'failure_category': FAILURE_CATEGORIES,
      'store_diagnostic_read_status': {'observed', 'unavailable'}}
  booleans = {'same_local_subject', 'failure_responses_no_callback_or_code',
      'account_retained_after_failure', 'store_provider_selected'}
  counts = {'store_fault_count', 'correlated_store_failure_count', 'exact_mapped_users',
      'keycloak_node_count', 'fresh_explicit_signup_transactions', 'fresh_login_transactions'}
  statuses = {'signup_proof_http', 'failure_http_status', 'browser_status_http',
      'retry_http', 'callback_http', 'pkce_token_http', 'signup_intent_action_http'}
  safe = {}
  for field, item in value.items():
    if field in enums and isinstance(item, str) and item in enums[field]:
      safe[field] = item
    elif field in booleans and type(item) is bool:
      safe[field] = item
    elif field == 'fresh_explicit_signup_transactions':
      allowed = {1, 2} if value.get('store_fault_mode') == 'consume-loss' else {1}
      if type(item) is int and item in allowed:
        safe[field] = item
    elif field == 'fresh_login_transactions':
      allowed = {0, 1} if value.get('store_fault_mode') in {
          'accepted-receipt-write', 'accepted-receipt-write-false'} else {0}
      if type(item) is int and item in allowed:
        safe[field] = item
    elif field in counts and type(item) is int and 0 <= item <= 5:
      safe[field] = item
    elif field in statuses and type(item) is int and 100 <= item <= 599:
      safe[field] = item
  return safe
