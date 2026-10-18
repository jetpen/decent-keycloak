"""Disposable local integration probe; not cluster/TLS/wallet-client qualification."""
import base64
import hashlib
import html.parser
import json
import os
import re
import secrets
import select
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
SCRATCH = os.environ.get('TMPDIR', str(Path.home() / '.hermes/cache/scratch'))
RESOLVER_WRAPPER = '/opt/decent-resolver/bin/decent-identity'


def _prepare_resolver_runtime():
  lock_path = PROJECT_DIR / 'container/resolver-runtime.lock.json'
  runtime_lock_path = PROJECT_DIR / 'container/resolver-requirements.lock.txt'
  harness_path = PROJECT_DIR / 'scripts/wallet_login_live_e2e.py'
  lock = json.loads(lock_path.read_text())
  return {
      'identity_commit': lock['sources']['identity']['commit'],
      'registry_commit': lock['sources']['registry']['commit'],
      'harness_sha256': hashlib.sha256(harness_path.read_bytes()).hexdigest(),
      'runtime_manifest_sha256': hashlib.sha256(lock_path.read_bytes()).hexdigest(),
      'runtime_lock_sha256': hashlib.sha256(runtime_lock_path.read_bytes()).hexdigest(),
  }

from contextlib import contextmanager


@contextmanager
def report_partial_evidence_on_failure(evidence_path, diagnostic_provider=None):
  try:
    yield
  except Exception as failure:
    if diagnostic_provider is not None:
      try:
        evidence = sanitize_live_checkpoint(diagnostic_provider())
        if evidence:
          print('partial_evidence=' + json.dumps(evidence, sort_keys=True))
      except Exception:
        print('resolver_diagnostic_status=unavailable')
    if evidence_path.exists():
      print('partial_evidence=' + evidence_path.read_text(encoding='utf-8'))
    print('harness_status=failed; failure_type=' + type(failure).__name__)
    raise


def checkpoint_signup_stage(result, stage, fields, checkpoint):
  """Persist one bounded signup phase before its next failure gate."""
  if stage not in {'intent', 'proof', 'account', 'callback', 'token'}:
    return
  allowed = {
      'signup_intent_action_http', 'signup_proof_http', 'exact_mapped_users',
      'pkce_token_http', 'callback_http', 'callback_replay', 'oidc_state_preserved',
  }
  safe = {}
  for name, value in fields.items():
    if name not in allowed:
      continue
    if name in {'exact_mapped_users'}:
      if type(value) is int and 0 <= value <= 2:
        safe[name] = value
    elif name in {'callback_replay', 'oidc_state_preserved'}:
      if type(value) is bool:
        safe[name] = value
    elif name.endswith('_http') and type(value) is int and 100 <= value <= 599:
      safe[name] = value
  result['signup_case'] = {**result.get('signup_case', {}), 'stage': stage, **safe}
  checkpoint()


def checkpoint_live_case(result, case_name, fields, checkpoint):
  if case_name not in {
      'rotated_identity_case', 'ambiguous_account_case', 'unmapped_account_case',
      'disabled_account_case', 'wallet_login', 'browser_preflight', 'negative_case',
  }:
    return
  result[case_name] = sanitize_live_checkpoint({case_name: fields}).get(case_name, {})
  checkpoint()


def checkpoint_rotation_stage(result, stage, fields, checkpoint):
  if stage not in {'publish', 'readback', 'stale_proof', 'stale_pending',
      'stale_attempt', 'stale_proof_pending', 'current_proof', 'current_attempt', 'current_accepted', 'callback',
      'mapping'}:
    return
  allowed = {
      'rotation_publish', 'current_sequence', 'stale_key_proof_http',
      'stale_transaction_remains_pending', 'current_key_proof_http',
      'current_transaction_accepted', 'callback_available', 'resolver_samples',
      'attempt_number', 'status_http', 'status_pending', 'local_mapping_persisted',
      'port_strategy'}
  enums = {'rotation_publish': {'published', 'read_back_exact', 'passed', 'failed'},
      'port_strategy': {'configured', 'ephemeral'}}
  http_fields = {'stale_key_proof_http', 'current_key_proof_http'}
  boolean_fields = {'stale_transaction_remains_pending', 'current_transaction_accepted',
      'callback_available', 'status_pending', 'local_mapping_persisted'}
  safe = {}
  for key, value in fields.items():
    if key not in allowed:
      continue
    if key in enums and isinstance(value, str) and value in enums[key]:
      safe[key] = value
    elif key in http_fields and type(value) is int and 100 <= value <= 599:
      safe[key] = value
    elif key == 'status_http' and type(value) is int and 100 <= value <= 599:
      safe[key] = value
    elif key in boolean_fields and type(value) is bool:
      safe[key] = value
    elif key == 'port_strategy' and isinstance(value, str) and value in enums['port_strategy']:
      safe[key] = value
    elif key == 'current_sequence' and type(value) is int and 0 <= value <= 60000:
      safe[key] = value
    elif key == 'attempt_number' and type(value) is int and 1 <= value <= 5:
      safe[key] = value
    elif key == 'resolver_samples' and isinstance(value, list) and len(value) <= 6:
      safe[key] = [{
          'outcome': sample['outcome'],
          'lookup_ms': sample['lookup_ms'],
          'peer_handshake': sample['peer_handshake'],
          'unexpected_diagnostic': sample['unexpected_diagnostic'],
          'json_balanced': sample['json_balanced'],
          'exact_identity_and_successor_match': sample['exact_identity_and_successor_match'],
          'port_strategy': sample['port_strategy'],
          **({'diagnostic_categories': sample['diagnostic_categories']}
              if isinstance(sample.get('diagnostic_categories'), list)
              and len(sample['diagnostic_categories']) <= 12
              and all(category in {'json','registry_miss','not_found','dial_warning',
                  'peer_status','peer_handshake','peer_error','history_unavailable','traceback','other'}
                  for category in sample['diagnostic_categories']) else {}),
      } for sample in value if isinstance(sample, dict)
          and sample.get('outcome') in {'resolved', 'not_found', 'unavailable'}
          and type(sample.get('lookup_ms')) is int and 0 <= sample['lookup_ms'] <= 60000
          and type(sample.get('peer_handshake')) is bool
          and type(sample.get('unexpected_diagnostic')) is bool
          and sample.get('port_strategy') in {'configured', 'ephemeral'}]
  result['rotated_identity_case'] = {
      **result.get('rotated_identity_case', {}), 'stage': stage, **safe}
  checkpoint()


def sanitize_live_checkpoint(candidate):
  """Project live outcomes into a fixed, non-sensitive evidence schema."""
  if not isinstance(candidate, dict):
    return {}
  runtime_fields = {
      'identity_commit', 'registry_commit', 'harness_sha256',
      'runtime_manifest_sha256', 'runtime_lock_sha256', 'image_digest', 'diagnostic_categories',
  }
  scalar_fields = {
      'proof_post_http', 'status_poll_http',
      'invalid_proof_http', 'pkce_token_http', 'current_key_proof_http',
      'stale_key_proof_http', 'current_sequence', 'cli_exit', 'cli_lookup_ms',
      'provider_http', 'direct_provider_http', 'provider_lookup_ms',
      'direct_provider_lookup_ms', 'exact_mapped_users',
      'signup_intent_action_http', 'signup_proof_http', 'scenario',
      'rotation_publish', 'callback_code', 'id_token_claims_checked', 'jwks_signature_verified',
      'identical_retry_accepted', 'changed_retry_denied', 'alien_status_denied',
      'state_preserved', 'error_returned', 'authorization_code_returned',
      'callback_replay', 'local_mapping_persisted', 'credentialed', 'wrong_origin_denied',
      'signature_rejected_by_verifier', 'no_acceptance_or_callback',
      'registry_unavailable', 'local_account_mapping_decision_observed',
      'pending_after_negative_http', 'current_registry_proof_http',
      'http_after_five_invalid_attempts',
      'pre_resolution_invalid_http', 'four_malformed_proofs_http',
      'browser_challenge_http', 'browser_proof_http',
      'missing_csrf_http', 'extra_header_http', 'wrong_origin_http',
      'redirect_http', 'challenge_get', 'challenge_post', 'status_poll_http',
      'get_http', 'post_http', 'redirect_http', 'invalid_proof_http',
      'stale_transaction_remains_pending', 'current_transaction_accepted',
      'cli_resolution', 'provider_resolution_outcome', 'registry_lookup_outcome', 'cli_output_categories',
      'cli_output_shape', 'outcome', 'wallet_locator',
  }
  sequence_fields = {'current_sequence'}
  exit_fields = {'cli_exit'}
  allowed = {
      'resolver_runtime', 'wallet_login', 'browser_preflight', 'negative_case',
      'unmapped_account_case', 'disabled_account_case', 'signup_case', 'rotation_case',
      'rotated_identity_case', 'ambiguous_account_case', 'missing_identity_case',
  }
  signup_stages = {'intent', 'proof', 'account', 'callback', 'token', 'complete'}
  rotation_stages = {'publish', 'readback', 'stale_proof', 'stale_pending', 'stale_attempt',
      'stale_proof_pending', 'current_proof', 'current_attempt', 'current_accepted', 'callback', 'complete', 'mapping'}
  bool_fields = {
      'id_token_claims_checked', 'jwks_signature_verified', 'callback_code', 'identical_retry_accepted',
      'local_mapping_persisted',
      'changed_retry_denied', 'alien_status_denied', 'state_preserved', 'error_returned',
      'challenge_get', 'wrong_origin_denied', 'credentialed',
      'authorization_code_returned', 'callback_replay', 'credentialed',
      'wrong_origin_denied', 'signature_rejected_by_verifier', 'no_acceptance_or_callback',
      'registry_unavailable', 'local_account_mapping_decision_observed',
      'stale_transaction_remains_pending', 'current_transaction_accepted', 'status_pending',
  }
  http_fields = {
      'proof_post_http', 'status_poll_http', 'pkce_token_http', 'current_key_proof_http', 'stale_key_proof_http',
      'provider_http', 'direct_provider_http',
      'signup_intent_action_http', 'signup_proof_http', 'callback_http',
      'pending_after_negative_http', 'current_registry_proof_http',
      'http_after_five_invalid_attempts', 'four_malformed_proofs_http',
      'pre_resolution_invalid_http',
      'browser_challenge_http', 'browser_proof_http', 'missing_csrf_http',
      'extra_header_http', 'wrong_origin_http', 'redirect_http',
      'challenge_post', 'get_http', 'post_http', 'four_malformed_proofs_http',
      'status_http',
  }
  time_fields = {'cli_lookup_ms', 'provider_lookup_ms', 'direct_provider_lookup_ms'}
  digest_fields = {'identity_commit', 'registry_commit'}
  enums = {
      'scenario': {'login', 'signup', 'unmapped-account', 'disabled-account', 'rotation', 'ambiguous-account', 'account-mapping-denial'},
      'registry_lookup_outcome': {'resolved', 'present', 'not_found', 'unavailable'},
      'cli_resolution': {'not_found', 'unavailable', 'inconsistent'},
      'provider_resolution_outcome': {'unavailable', 'provider_denied_unclassified', 'unexpected_status'},
      'rotation_publish': {'passed', 'published', 'read_back_exact', 'failed'},
      'outcome': {'accepted', 'denied', 'unavailable', 'pending', 'not_found', 'inconsistent',
          'policy_denied', 'provider_denied_unclassified', 'registry_unavailable',
          'provider_registry_inconsistent', 'account_mapping_unavailable', 'provider_unavailable',
          'unexpected_acceptance', 'unexpected_status', 'unqualified', 'policy_denied',
          'provider_denied_unclassified', 'registry_unavailable', 'provider_registry_inconsistent',
          'account_mapping_unavailable', 'provider_unavailable'},
  }

  runtime_string_fields = {
      'harness_sha256', 'runtime_manifest_sha256', 'runtime_lock_sha256', 'image_digest',
  }
  resolver_diagnostic_reasons = {
      'registry_miss', 'dial_warning', 'peer_handshake', 'peer_error',
      'history_unavailable', 'traceback', 'process_start', 'nonzero_exit',
      'unknown', 'success', 'timeout', 'interrupted', 'termination_interrupted',
      'output_overflow',
  }

  def safe_diagnostic_category(value):
    if isinstance(value, str) and value in {'unavailable', 'invalid'}:
      return True
    if not isinstance(value, str) or not value.startswith('ok:'):
      return False
    categories = value[3:].split('|')
    return bool(categories) and len(categories) <= 8 and len(categories) == len(set(categories)) \
        and all(category in resolver_diagnostic_reasons for category in categories)

  def safe_scalar(field, value):
    if field == 'diagnostic_categories':
      return isinstance(value, list) and len(value) <= 32 and all(
          safe_diagnostic_category(item) for item in value)
    if field in runtime_string_fields:
      if field == 'image_digest':
        return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None
      return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None
    if field in bool_fields:
      return type(value) is bool
    if field in http_fields:
      return type(value) is int and 100 <= value <= 599
    if field in sequence_fields or field in time_fields:
      return type(value) is int and 0 <= value <= 60000
    if field in exit_fields:
      return type(value) is int and -1 <= value <= 255
    if field in digest_fields:
      return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value) is not None
    if field == 'cli_output_categories':
      return isinstance(value, list) and len(value) <= 16 and all(item in {
          'not_found', 'registry_miss', 'dial_warning', 'peer_handshake', 'peer_error',
          'peer_status', 'json', 'history_unavailable', 'traceback', 'other',
          'ok:registry_miss', 'ok:registry_miss|dial_warning|unknown', 'unavailable', 'invalid'}
          for item in value)
    if field == 'diagnostic_categories':
      return isinstance(value, list) and len(value) <= 32 and all(
          safe_diagnostic_category(item) for item in value)
    if field == 'cli_output_shape':
      return isinstance(value, list) and len(value) <= 16 and all(
          item in {'object', 'nested_object', 'array', 'scalar'} for item in value)
    if field in enums:
      return isinstance(value, str) and value in enums[field]
    if field == 'exact_mapped_users':
      return type(value) is int and 0 <= value <= 2
    if field == 'wallet_locator':
      return value is True
    return False

  projected = {}
  for key, value in candidate.items():
    if key not in allowed or not isinstance(value, dict):
      continue
    if key == 'rotated_identity_case' and isinstance(value, dict):
      stage = value.get('stage')
      if stage not in rotation_stages and stage != 'diagnostic_probe':
        continue
      fields = {'rotation_publish', 'current_sequence', 'current_key_proof_http',
          'stale_key_proof_http', 'stale_transaction_remains_pending',
          'current_transaction_accepted', 'callback_available', 'local_mapping_persisted',
          'attempt_number', 'status_http', 'status_pending', 'diagnostic_categories',
          'port_strategy'}
      safe = {'stage': stage}
      safe.update({field: item for field, item in value.items()
          if field in fields and safe_scalar(field, item)})
      if type(value.get('attempt_number')) is int and 1 <= value['attempt_number'] <= 5:
        safe['attempt_number'] = value['attempt_number']
      if type(value.get('status_http')) is int and 100 <= value['status_http'] <= 599:
        safe['status_http'] = value['status_http']
      if isinstance(value.get('resolver_samples'), list) and len(value['resolver_samples']) <= 6:
        safe['resolver_samples'] = [{
            'outcome': sample['outcome'], 'lookup_ms': sample['lookup_ms'],
            'peer_handshake': sample['peer_handshake'],
            'unexpected_diagnostic': sample['unexpected_diagnostic'],
            'json_balanced': sample.get('json_balanced') is True,
            'exact_identity_and_successor_match': sample.get('exact_identity_and_successor_match') is True,
            'port_strategy': sample['port_strategy'],
            **({'diagnostic_categories': sample['diagnostic_categories']}
                if isinstance(sample.get('diagnostic_categories'), list)
                and len(sample['diagnostic_categories']) <= 12
                and all(category in {'json','registry_miss','not_found','dial_warning',
                    'peer_status','peer_handshake','peer_error','history_unavailable','traceback','other'}
                    for category in sample['diagnostic_categories']) else {}),
        } for sample in value['resolver_samples'] if isinstance(sample, dict)
            and sample.get('outcome') in {'resolved', 'not_found', 'unavailable'}
            and type(sample.get('lookup_ms')) is int and 0 <= sample['lookup_ms'] <= 60000
            and type(sample.get('peer_handshake')) is bool
            and type(sample.get('unexpected_diagnostic')) is bool
            and sample.get('port_strategy') in {'configured', 'ephemeral'}]
      if stage == 'diagnostic_probe' and isinstance(value.get('diagnostic_categories'), list):
        categories = value['diagnostic_categories']
        if len(categories) <= 32 and all(safe_diagnostic_category(category) for category in categories):
          safe['diagnostic_categories'] = categories
      if safe:
        projected[key] = safe
      continue
    if key == 'signup_case' and isinstance(value, dict):
      stage = value.get('stage')
      if stage not in signup_stages:
        continue
      safe = {'stage': stage}
      safe.update({field: item for field, item in value.items()
          if field in {'signup_intent_action_http', 'signup_proof_http',
              'callback_http', 'pkce_token_http'} and safe_scalar(field, item)})
      if type(value.get('exact_mapped_users')) is int and 0 <= value['exact_mapped_users'] <= 2:
        safe['exact_mapped_users'] = value['exact_mapped_users']
      if safe:
        projected[key] = safe
      continue
    if key == 'resolver_runtime' and isinstance(value, dict):
      safe = {field: item for field, item in value.items()
          if field in runtime_fields and safe_scalar(field, item)}
      if safe:
        projected[key] = safe
      continue
    fields = scalar_fields
    original_value = value
    if key == 'negative_case' and isinstance(value.get('invalid_proof_throttle'), dict):
      value = {field: item for field, item in value.items() if field != 'invalid_proof_throttle'}
    safe = {field: item for field, item in value.items()
        if field in fields and (field in runtime_fields and key == 'resolver_runtime'
            or safe_scalar(field, item))}
    if key == 'wallet_login' and isinstance(value.get('callback_replay'), dict):
      callback_fields = {'redirect_http', 'state_preserved', 'error_returned',
          'authorization_code_returned'}
      callback = value['callback_replay']
      safe['callback_replay'] = {field: item for field, item in callback.items()
          if field in callback_fields and safe_scalar(field, item)}
    if key == 'negative_case' and isinstance(original_value.get('invalid_proof_throttle'), dict):
      throttle_fields = {'pre_resolution_invalid_http', 'four_malformed_proofs_http',
          'http_after_five_invalid_attempts', 'no_acceptance_or_callback'}
      throttle = original_value['invalid_proof_throttle']
      sanitized_throttle = {}
      for field, item in throttle.items():
        if field not in throttle_fields:
          continue
        if field == 'four_malformed_proofs_http' and isinstance(item, list):
          if len(item) <= 16 and all(type(status) is int and 100 <= status <= 599 for status in item):
            sanitized_throttle[field] = item
        elif safe_scalar(field, item):
          sanitized_throttle[field] = item
      safe['invalid_proof_throttle'] = sanitized_throttle
    if safe:
      projected[key] = safe
  return projected


def resolve_immutable_image(image):
  if not isinstance(image, str) or not image:
    raise RuntimeError('an explicit resolver image is required')
  inspected = run(['podman', 'image', 'inspect', image, '--format', '{{.Id}}|{{.Digest}}'], timeout=15)
  if inspected.returncode != 0:
    raise RuntimeError('resolver image inspect failed')
  fields = inspected.stdout.strip().split('|')
  if len(fields) != 2 or re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', fields[0]) is None or re.fullmatch(r'sha256:[0-9a-f]{64}', fields[1]) is None:
    raise RuntimeError('resolver image inspect did not return immutable image ID and digest')
  return fields[0], fields[1]


IMAGE = os.environ.get('WALLET_IT_IMAGE')
KC_PORT = 18886
IDP_ORIGIN = 'https://idp.example'
WALLET_ORIGIN = 'https://wallet.example'
REALM = 'wallet-e2e'
CLIENT = 'wallet-e2e-client'
REDIRECT = 'https://rp.example/callback'
class AdminPassword:
  def __init__(self, value):
    if value is None:
      raise RuntimeError("disposable admin credential is unavailable")
    self._value = value

  def __str__(self):
    return self._value

  def __repr__(self):
    return "AdminPassword([REDACTED])"



def free_port():
  with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    return sock.getsockname()[1]


def run(args, timeout=60, env=None):
  return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=timeout, env=env, check=False)


def b64url(data):
  return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def write_private_signing_input(parent, prefix, payload):
  """Write short-lived challenge signing bytes without shared-temp exposure."""
  parent = Path(parent)
  parent.mkdir(mode=0o700, parents=True, exist_ok=True)
  path = parent / (prefix + '-' + uuid.uuid4().hex + '.bin')
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
  try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as stream:
      stream.write(payload)
  except BaseException:
    try:
      os.close(fd)
    except OSError:
      pass
    path.unlink(missing_ok=True)
    raise
  return path


class LoginPageParser(html.parser.HTMLParser):
  def __init__(self):
    super().__init__()
    self.in_locator = False
    self.locator_parts = []

  def handle_starttag(self, tag, attrs):
    if tag == 'p' and dict(attrs).get('id') == 'wallet-locator':
      self.in_locator = True

  def handle_endtag(self, tag):
    if tag == 'p' and self.in_locator:
      self.in_locator = False

  def handle_data(self, data):
    if self.in_locator:
      self.locator_parts.append(data)


REDIRECT_DIAGNOSTICS = []


class LocalKeycloakRedirects(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    parsed = urllib.parse.urlsplit(newurl)
    if parsed.hostname in ('idp.example', '127.0.0.1'):
      REDIRECT_DIAGNOSTICS.append({
          'status': int(code),
          'source_method': req.get_method(),
          'source_path': urllib.parse.urlsplit(req.full_url).path,
          'target_path': parsed.path,
          'target_query_names': sorted(set(urllib.parse.parse_qs(parsed.query).keys()))[:32],
      })
      if len(REDIRECT_DIAGNOSTICS) > 20:
        del REDIRECT_DIAGNOSTICS[:-20]
      local = f'http://127.0.0.1:{KC_PORT}{parsed.path}'
      if parsed.query:
        local += '?' + parsed.query
      forwarded = dict(req.header_items())
      forwarded.update({'Host': 'idp.example', 'X-Forwarded-Host': 'idp.example',
                        'X-Forwarded-Proto': 'https', 'X-Forwarded-Port': '443'})
      return urllib.request.Request(local, headers=forwarded, method='GET')
    return None


class Client:
  def __init__(self):
    self.redirects = []
    self.privateClientAdminCredential: str | None = None
    self.opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(), LocalKeycloakRedirects())
    redirect_handler = next(handler for handler in self.opener.handlers
        if isinstance(handler, LocalKeycloakRedirects))
    original_redirect = redirect_handler.redirect_request
    def capture_redirect(req, fp, code, msg, headers, newurl):
      parsed_source = urllib.parse.urlsplit(req.full_url)
      parsed_target = urllib.parse.urlsplit(newurl)
      self.redirects.append({'status': int(code), 'method': req.get_method(),
          'source_path': parsed_source.path, 'target_path': parsed_target.path,
          'target_query_names': sorted(set(urllib.parse.parse_qs(parsed_target.query).keys()))[:32]})
      return original_redirect(req, fp, code, msg, headers, newurl)
    redirect_handler.redirect_request = capture_redirect
    self.forward_headers = {
        'Host': 'idp.example', 'X-Forwarded-Host': 'idp.example',
        'X-Forwarded-Proto': 'https', 'X-Forwarded-Port': '443',
    }

  def url(self, path_or_url):
    parsed = urllib.parse.urlsplit(path_or_url)
    path = parsed.path if parsed.scheme else path_or_url
    query = parsed.query if parsed.scheme else ''
    if not path.startswith('/'):
      path = '/' + path
    result = f'http://127.0.0.1:{KC_PORT}{path}'
    return result + ('?' + query if query else '')

  def request(self, method, path, data=None, headers=None, timeout=10):
    merged = dict(self.forward_headers)
    if headers:
      merged.update(headers)
    # This harness simulates TLS termination over loopback. Secure cookies
    # belong to the asserted HTTPS public origin, never the wallet client.
    cookies = [c for h in self.opener.handlers
               if isinstance(h, urllib.request.HTTPCookieProcessor) for c in h.cookiejar
               if urllib.parse.urlsplit(self.url(path)).path.startswith(c.path)]
    if cookies:
      merged['Cookie'] = '; '.join(c.name + '=' + str(c.value or '') for c in cookies)
    req = urllib.request.Request(self.url(path), data=data, headers=merged, method=method)
    try:
      with self.opener.open(req, timeout=timeout) as response:
        return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
      return error.code, error.headers, error.read()


class BareLocalClient(Client):
  def __init__(self):
    super().__init__()
    self.opener = urllib.request.build_opener(LocalKeycloakRedirects())

  def request(self, method, path, data=None, headers=None, timeout=10):
    req = urllib.request.Request(self.url(path), data=data, headers=headers or {}, method=method)
    try:
      with self.opener.open(req, timeout=timeout) as response:
        return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
      return error.code, error.headers, error.read()


def require(condition, stage, code=None):
  if not condition:
    raise RuntimeError(f'acceptance probe failed at {stage}' + (f' (HTTP {code})' if code else ''))


def start_registry(temp, image):
  port = free_port()
  config = temp / 'registry.yaml'
  datastore = temp / 'registry-lmdb'
  datastore.mkdir(mode=0o700)
  config.write_text(
      f"network:\n  host: 127.0.0.1\n  port: {port}\n  bootstrap: []\n"
      f"datastore:\n  path: {datastore}\nlogging:\n  verbosity: 0\n",
      encoding='utf-8')
  container = f'wallet-login-registry-{os.getpid()}'
  node = None
  try:
    node = subprocess.Popen(
        ['podman', 'run', '--rm', '--user', '0', '--name', container, '--network', 'host',
         '--volume', f'{config}:/tmp/registry.yaml:ro',
         '--volume', f'{datastore}:{datastore}:rw', '--entrypoint',
         '/opt/decent-resolver/bin/decent-registry', image,
         '-v', 'node', '--config', '/tmp/registry.yaml', '--run-seconds', '300'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    require(node.stdout is not None, 'packaged Registry log stream is available')
    bootstrap = None
    output = bytearray()
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
      ready, _, _ = select.select([node.stdout], [], [], 0.5)
      if ready:
        output.extend(os.read(node.stdout.fileno(), 4096))
        for line in output.decode('utf-8', errors='replace').splitlines():
          if '[BOOTSTRAP]' in line:
            bootstrap = line.split('[BOOTSTRAP]', 1)[1].strip().split()[0]
            break
      if bootstrap is not None:
        break
      if node.poll() is not None:
        break
    if bootstrap is None:
      process_state = 'exited' if node.poll() is not None else 'timeout'
      output_categories = []
      for line in output.decode('utf-8', errors='replace').splitlines():
        if len(output_categories) == 8:
          break
        output_categories.append('bootstrap-marker' if '[BOOTSTRAP]' in line else 'other-log-line')
      print('registry-startup-diagnostics:', json.dumps({
          'process_state': process_state, 'output_categories': output_categories}, sort_keys=True))
    require(bootstrap is not None, 'ephemeral packaged Registry startup')
    return node, bootstrap, port
  except BaseException:
    stop_registry(node, container)
    raise


def start_resolver_tools(temp, image):
  container = f'wallet-login-resolver-tools-{os.getpid()}'
  temp = Path(temp)
  started = run(['podman', 'run', '--detach', '--rm', '--user', '0', '--name', container,
      '--network', 'host', '--volume', f'{temp}:{temp}:rw',
      '--entrypoint', '/bin/sh', image, '-lc', 'sleep 300'], timeout=30)
  require(started.returncode == 0, 'start pinned resolver tools container')
  os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = container
  return container


def run_image_resolver(container, args, timeout=45, image=None):
  if image is None:
    image = IMAGE
  if image is None:
    raise RuntimeError('immutable resolver image is required')
  return run(['podman', 'exec', container,
      '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'LANG=C.UTF-8',
      RESOLVER_WRAPPER, *args], timeout=timeout)


def run_image_registry(container, args, timeout=45, image=None):
  if image is None:
    image = IMAGE
  if image is None:
    raise RuntimeError('immutable resolver image is required')
  return run(['podman', 'exec', container,
      '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'LANG=C.UTF-8',
      '/opt/decent-resolver/bin/decent-registry', *args], timeout=timeout)


def stop_resolver_tools(container):
  if container:
    run(['podman', 'rm', '--force', container], timeout=20)


def stop_registry(node, container):
  run(['podman', 'rm', '--force', container], timeout=20)
  if node is not None and node.poll() is None:
    node.terminate()
    try:
      node.wait(timeout=8)
    except subprocess.TimeoutExpired:
      node.kill()
      node.wait(timeout=5)


def identity_lookup_category(line):
  if line == 'not found':
    return 'not_found'
  miss_prefix = 'Value not found for key /decent-registry/identity/'
  if line.startswith(miss_prefix):
    object_key = line[len(miss_prefix):]
    if len(object_key) == 64 and all(character in '0123456789abcdefABCDEF' for character in object_key):
      return 'registry_miss'
  warning_prefix = 'Failed to open TCP stream: all attempts to connect to '
  if line.startswith(warning_prefix):
    endpoint = line[len(warning_prefix):].removesuffix(' failed')
    if endpoint and not any(character.isspace() for character in endpoint):
      return 'dial_warning'
  prefix = 'failed to upgrade security for peer '
  suffix = ': handshake failed when upgrading to secure connection'
  short_suffix = ': handshake failed'
  if line.startswith(prefix) and (line.endswith(suffix) or line.endswith(short_suffix)):
    peer = line[len(prefix):]
    peer = peer[:-len(suffix)] if peer.endswith(suffix) else peer[:-len(short_suffix)]
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if peer.startswith('12D3Koo') and len(peer) == 52 and all(character in alphabet for character in peer):
      return 'peer_handshake'
  if line.startswith('Failed to send request to peer: ') or line.startswith('Failed to connect to peer: '):
    return 'peer_error'
  if line.startswith('Dialing ') or line.startswith('Connected to '):
    value = line.split(' ', 1)[1]
    return 'peer_status' if value.strip() else 'other'
  if line.startswith('{') or line.startswith('  "') or line.startswith('    "') or line.strip() == '}':
    return 'json'
  if line.startswith('history unavailable:'):
    return 'history_unavailable'
  if line.startswith('Traceback') or line.startswith('File ') or 'Error:' in line:
    return 'traceback'
  return 'other'


def classify_identity_lookup(stdout, exit_code, expected_identifier=None):
  def category(line):
    if line == 'not found':
      return 'not_found'
    if line.startswith('Value not found for key /decent-registry/identity/'):
      key = line.rsplit('/', 1)[-1]
      return 'registry_miss' if len(key) == 64 and all(ch in '0123456789abcdefABCDEF' for ch in key) else 'other'
    if line.startswith('Failed to open TCP stream: all attempts to connect to '):
      endpoint = line.removeprefix('Failed to open TCP stream: all attempts to connect to ').removesuffix(' failed')
      return 'dial_warning' if endpoint and not any(ch.isspace() for ch in endpoint) else 'other'
    if line.startswith('failed to upgrade security for peer '):
      suffix = ': handshake failed when upgrading to secure connection'
      short_suffix = ': handshake failed'
      peer = line.removeprefix('failed to upgrade security for peer ')
      if peer.endswith(suffix):
        peer = peer[:-len(suffix)]
      elif peer.endswith(short_suffix):
        peer = peer[:-len(short_suffix)]
      else:
        return 'other'
      alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
      return 'peer_handshake' if peer.startswith('12D3Koo') and len(peer) == 52 and all(c in alphabet for c in peer) else 'other'
    if line.startswith('Dialing ') or line.startswith('Connected to '):
      value = line.split(' ', 1)[1]
      return 'peer_status' if value and not any(character.isspace() for character in value) else 'other'
    if line.startswith('Failed to send request to peer: ') or line.startswith('Failed to connect to peer: '):
      return 'peer_error'
    if line.startswith('history unavailable:'):
      return 'history_unavailable'
    if line.startswith('Traceback') or line.startswith('File ') or 'Error:' in line:
      return 'traceback'
    if line.startswith('{') or (line.strip().startswith('"') and ':' in line) or line.strip() == '}':
      return 'json'
    return 'other'
  lines = stdout.splitlines()
  categories = [category(line.strip()) for line in lines if line.strip()]
  peer_handshake_or_error = any(category in {'peer_handshake', 'peer_error'} for category in categories)
  if peer_handshake_or_error:
    return 'unavailable', categories
  json_start = next((index for index, line in enumerate(lines)
      if line.strip().startswith('{')), None)
  if any(category in {'traceback', 'history_unavailable'} for category in categories):
    return 'unavailable', categories
  if json_start is not None:
    json_end = None
    depth = 0
    in_string = False
    escaped = False
    for index in range(json_start, len(lines)):
      for character in lines[index]:
        if in_string:
          if escaped:
            escaped = False
          elif character == '\\':
            escaped = True
          elif character == '"':
            in_string = False
        elif character == '"':
          in_string = True
        elif character == '{':
          depth += 1
        elif character == '}':
          depth -= 1
          if depth < 0:
            return 'unavailable', categories
      if depth == 0 and not in_string:
        json_end = index
        break
    if json_end is None or exit_code != 0:
      return 'unavailable', categories
    for index, line in enumerate(lines):
      if index < json_start or index > json_end:
        if line.strip() and identity_lookup_category(line.strip()) not in {
            'dial_warning', 'registry_miss', 'peer_status'}:
          return 'unavailable', categories
    if any(category in {'registry_miss', 'not_found'} for category in categories):
      return 'unavailable', categories
    return 'resolved', categories
  if peer_handshake_or_error:
    return 'unavailable', categories
  explicit_terminal_miss = exit_code == 1 and categories[-1:] == ['not_found']
  absence_only = explicit_terminal_miss and all(
      item in ('registry_miss', 'not_found') for item in categories)
  if expected_identifier is None:
    absence_only = False
  if (exit_code == 1 and explicit_terminal_miss and absence_only
      and expected_identifier is not None):
    expected_key = hashlib.sha256(expected_identifier.encode('utf-8')).hexdigest()
    expected_miss = 'Value not found for key /decent-registry/identity/' + expected_key
    registry_miss_lines = [line.strip() for line in lines
        if line.strip().startswith('Value not found for key /decent-registry/identity/')]
    absence_only = absence_only and bool(registry_miss_lines) and all(
        line == expected_miss for line in registry_miss_lines)
    matching_miss = any(line.strip() == expected_miss for line in lines)
    absence_only = absence_only and matching_miss
  return ('not_found' if absence_only else 'unavailable'), categories


def parse_exact_identity_result(stdout, identifier):
  lines = stdout.splitlines()
  result_start = None
  diagnostics = []
  recognized_diagnostics = {'dial_warning', 'registry_miss', 'peer_handshake', 'peer_error', 'peer_status'}
  def json_structural(line):
    stripped = line.strip()
    return (stripped.startswith(('"', '{')) or stripped in ('}', '},', '[', '],')
        or stripped.endswith((' {', ' [', '{', '[')))
  for index, line in enumerate(lines):
    if line.strip().startswith('{'):
      category = 'json_start'
    elif identity_lookup_category(line.strip()) == 'json':
      category = 'json'
    else:
      category = identity_lookup_category(line.strip())
    if not line.strip():
      continue
    if category == 'json_start':
      result_start = index
      break
    if category in recognized_diagnostics:
      diagnostics.append(category)
      continue
    if not json_structural(line):
      return None
  if result_start is None:
    return None
  depth = 0
  in_string = False
  escaped = False
  result_end = None
  for index in range(result_start, len(lines)):
    for character in lines[index]:
      if in_string:
        if escaped:
          escaped = False
        elif character == '\\':
          escaped = True
        elif character == '"':
          in_string = False
      elif character == '"':
        in_string = True
      elif character == '{':
        depth += 1
      elif character == '}':
        depth -= 1
        if depth < 0:
          return None
    if depth == 0 and not in_string:
      result_end = index
      break
  if result_end is None:
    return None
  for line in lines[result_end + 1:]:
    if not line.strip():
      continue
    category = identity_lookup_category(line.strip())
    if category in recognized_diagnostics:
      diagnostics.append(category)
      continue
    if not json_structural(line):
      return None
  if not any('"identifier"' in line and ':' in line
      for line in lines[result_start:result_end + 1]):
    return None
  if any(category in {'peer_handshake', 'peer_error'} for category in diagnostics):
    return None
  def unique_object(pairs):
    result = {}
    for key, value in pairs:
      if key in result:
        raise ValueError('duplicate JSON member')
      result[key] = value
    return result
  try:
    result = json.loads('\n'.join(lines[result_start:result_end + 1]), object_pairs_hook=unique_object)
  except (ValueError, TypeError):
    return None
  if not isinstance(result, dict) or result.get('identifier') != identifier:
    return None
  if result.get('owner_name_hex') != identifier.encode('utf-8').hex():
    return None
  if isinstance(result.get('seq'), bool) or not isinstance(result.get('seq'), int) or result['seq'] < 0:
    return None
  key = result.get('owner_public_key_hex')
  if not isinstance(key, str) or re.fullmatch(r'[0-9a-fA-F]{64}', key) is None:
    return None
  try:
    raw_key = bytes.fromhex(key)
  except ValueError:
    return None
  if len(raw_key) != 32:
    return None
  return result


def packaged_resolver_readback(stdout, exit_code, identifier, expected_public_key_hex):
  if exit_code != 0:
    return False
  outcome, _ = classify_identity_lookup(stdout, exit_code)
  if outcome != 'resolved':
    return False
  result = parse_exact_identity_result(stdout, identifier)
  return result is not None and result.get('owner_public_key_hex', '').lower() == expected_public_key_hex.lower()


def json_object_is_balanced(stdout):
  if not isinstance(stdout, str):
    return False
  lines = stdout.splitlines()
  json_start = next((index for index, line in enumerate(lines)
      if line.strip().startswith('{')), None)
  if json_start is None:
    return False
  depth = 0
  in_string = False
  escaped = False
  json_end = None
  for index in range(json_start, len(lines)):
    for character in lines[index]:
      if in_string:
        if escaped:
          escaped = False
        elif character == '\\':
          escaped = True
        elif character == '"':
          in_string = False
      elif character == '"':
        in_string = True
      elif character == '{':
        depth += 1
      elif character == '}':
        depth -= 1
        if depth < 0:
          return False
    if depth == 0 and not in_string:
      json_end = index
      break
  if json_end is None:
    return False
  try:
    json.loads('\n'.join(lines[json_start:json_end + 1]))
  except (json.JSONDecodeError, TypeError):
    return False
  return True


def classify_and_parse_result(stdout, exit_code, identifier, expected_public_key_hex):
  outcome, categories = classify_identity_lookup(stdout, exit_code, identifier)
  exact = packaged_resolver_readback(stdout, exit_code, identifier, expected_public_key_hex)
  return ('resolved' if outcome == 'resolved' and exact else 'unavailable', exact, categories)


def exact_registry_lookup_succeeded(stdout, exit_code, identifier):
  outcome, _ = classify_identity_lookup(stdout, exit_code, identifier)
  return outcome == 'resolved' and parse_exact_identity_result(stdout, identifier) is not None


def exact_registry_lookup_outcome(stdout, exit_code, identifier):
  if exact_registry_lookup_succeeded(stdout, exit_code, identifier):
    return 'resolved'
  resolution, _ = classify_identity_lookup(stdout, exit_code, identifier)
  return 'not_found' if resolution == 'not_found' else 'unavailable'


def generate_owner_key(temp, label, image):
  key = temp / (label + '-identity.pem')
  key_in_container = str(key)
  generated = run_image_registry(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
      ['keygen', '--output', key_in_container], image=image)
  require(generated.returncode == 0 and key.exists(), 'successor owner-key generation')
  return key


def write_identity(temp, bootstrap, image, label='wallet-login-e2e'):
  key = generate_owner_key(temp, label, image)
  identifier = label + '-' + uuid.uuid4().hex + '@example.invalid'
  pub = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
  require(pub.returncode == 0 and len(pub.stdout) >= 32, 'extract test public key')
  expected_public_key_hex = pub.stdout[-32:].hex()
  put = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'], ['put', '--identifier', identifier,
             '--owner-privkey', str(key), '--seq', '1', '--host', '127.0.0.1',
             '--port', str(free_port()), '--bootstrap', bootstrap], timeout=60, image=image)
  require(put.returncode == 0, 'publish test identity to ephemeral Registry')
  observed = False
  for _ in range(10):
    lookup = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'], ['get', '--identifier', identifier,
                  '--host', '127.0.0.1', '--port', str(free_port()),
                  '--bootstrap', bootstrap], timeout=25, image=image)
    if lookup.returncode == 0 and '"identifier"' in lookup.stdout:
      observed = True
      break
    time.sleep(1)
  require(observed, 'separate client Registry read-back')
  lookup = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'], ['get', '--identifier', identifier,
                '--host', '127.0.0.1', '--port', str(free_port()),
                '--bootstrap', bootstrap], timeout=25, image=image)
  require(packaged_resolver_readback(lookup.stdout, lookup.returncode, identifier, expected_public_key_hex),
      'pinned Registry resolver returns exact Identity ID and current owner key')
  return key, Path(RESOLVER_WRAPPER), identifier


def start_keycloak(container, password, wrapper_path, resolver_port, bootstrap, image):
  check = run(['ss', '-ltn', f'( sport = :{KC_PORT} )'], timeout=5)
  require('LISTEN' not in check.stdout, 'disposable Keycloak port available')
  env_fd, env_path = tempfile.mkstemp(prefix='wallet-login-admin-', suffix='.env', dir=SCRATCH)
  env_file = Path(env_path)
  try:
    os.fchmod(env_fd, 0o600)
    with os.fdopen(env_fd, 'w', encoding='utf-8') as env_stream:
      env_stream.write('KC_BOOTSTRAP_ADMIN_PASSWORD=' + password + '\n')
    cmd = [
        'podman', 'run', '--detach', '--rm', '--name', container, '--network', 'host',
        '--env-file', str(env_file),
        '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=wallet-admin',
        image, 'start-dev', '--http-enabled=true', f'--http-port={KC_PORT}',
        '--http-relative-path=/auth', f'--hostname=https://idp.example:{KC_PORT}/auth',
        '--proxy-headers=xforwarded', '--proxy-trusted-addresses=127.0.0.1', '--db=dev-file',
        '--log-level=org.decentwallet.keycloak.wallet:DEBUG'
    ]
    started = run(cmd, timeout=40)
  finally:
    env_file.unlink(missing_ok=True)
  if started.returncode != 0:
    raise RuntimeError("acceptance probe failed at start disposable Keycloak")
  if not isinstance(started, subprocess.CompletedProcess):
    raise RuntimeError("Keycloak start returned no result")
  client = Client()
  client.privateClientAdminCredential = password
  discovery = None
  last_connection_error = None
  for _ in range(90):
    try:
      status, _, body = client.request('GET', '/auth/realms/master/.well-known/openid-configuration', timeout=2)
    except urllib.error.URLError as error:
      last_connection_error = error
      time.sleep(1)
      continue
    if status == 200:
      discovery = json.loads(body)
      break
    time.sleep(1)
  if discovery is None:
    logs = run(['podman', 'logs', '--tail', '80', container], timeout=15)
    for line in logs.stdout.splitlines():
      if any(word in line.lower() for word in ('error', 'exception', 'failed', 'listening', 'started')):
        print('keycloak-log:', line[:500])
    print('last_connection_error=', type(last_connection_error).__name__ if last_connection_error else 'none')
    require(False, 'Keycloak OIDC discovery startup')
  require(discovery is not None, 'Keycloak OIDC discovery startup')
  require(discovery.get('issuer') == f'https://idp.example:{KC_PORT}/auth/realms/master',
          'trusted HTTPS issuer')
  return client


def admin_token(client, password):
  form = urllib.parse.urlencode({
      'client_id': 'admin-cli', 'grant_type': 'password',
      'username': 'wallet-admin', 'password': password,
  }).encode()
  status, _, body = client.request('POST', '/auth/realms/master/protocol/openid-connect/token', form,
      {'Content-Type': 'application/x-www-form-urlencoded'})
  require(status == 200, 'temporary admin token', status)
  return json.loads(body)['access_token']


def admin_call(client, token, method, path, value=None, expected=(200, 201, 204)):
  data = None if value is None else json.dumps(value, separators=(',', ':')).encode()
  headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
  if data is not None:
    headers['Content-Type'] = 'application/json'
  status, response_headers, body = client.request(method, path, data, headers)
  if status not in expected:
    message = body.decode('utf-8', errors='replace')[:500]
    raise RuntimeError(f'Keycloak test-realm configuration failed HTTP {status}: {message}')
  return status, response_headers, body



def provision_identity_attribute(client, token, username, identity_id):
  _, _, user_raw = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/users?username={urllib.parse.quote(username)}&exact=true')
  users = json.loads(user_raw)
  if users:
    require(len(users) == 1, f'{username} fixture user is unique')
    user = users[0]
  else:
    admin_call(client, token, 'POST', f'/auth/admin/realms/{REALM}/users', {
        'username': username, 'enabled': True,
    }, expected=(201,))
    _, _, user_raw = admin_call(client, token, 'GET',
        f'/auth/admin/realms/{REALM}/users?username={urllib.parse.quote(username)}&exact=true')
    users = json.loads(user_raw)
    require(len(users) == 1, f'{username} fixture user exists')
    user = users[0]
  attributes = dict(user.get('attributes', {}))
  attributes['decent_identity_id'] = [identity_id]
  user['attributes'] = attributes
  admin_call(client, token, 'PUT', f'/auth/admin/realms/{REALM}/users/{user["id"]}',
      user, expected=(204,))
  _, _, user_raw = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/users/{user["id"]}')
  verified = json.loads(user_raw)
  require(verified.get('attributes', {}).get('decent_identity_id') == [identity_id],
      f'{username} exact Identity attribute persisted')


def configure_identity_profile(client, token):
  _, _, profile_raw = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/users/profile')
  profile = json.loads(profile_raw)
  attributes = profile.get('attributes')
  require(isinstance(attributes, list), 'realm user-profile attributes available')
  matches = [attribute for attribute in attributes if attribute.get('name') == 'decent_identity_id']
  if not matches:
    attributes.append({
        'name': 'decent_identity_id',
        'displayName': 'Decent Identity ID',
        'multivalued': False,
        'permissions': {'view': ['admin'], 'edit': ['admin']},
    })
  else:
    require(len(matches) == 1, 'exactly one Identity attribute in realm user profile')
    matches[0]['permissions'] = {'view': ['admin'], 'edit': ['admin']}
  profile['unmanagedAttributePolicy'] = 'ADMIN_EDIT'
  admin_call(client, token, 'PUT', f'/auth/admin/realms/{REALM}/users/profile',
      profile, expected=(200, 204))
  _, _, verified_raw = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/users/profile')
  verified = json.loads(verified_raw)
  configured = [attribute for attribute in verified.get('attributes', [])
      if attribute.get('name') == 'decent_identity_id']
  require(len(configured) == 1
      and configured[0].get('permissions') == {'view': ['admin'], 'edit': ['admin']},
      'managed Identity attribute is admin-only and persisted')


def enable_keycloak_login_events(client, token):
  _, _, settings_raw = admin_call(client, token, 'GET', f'/auth/admin/realms/{REALM}')
  settings = json.loads(settings_raw)
  settings['eventsEnabled'] = True
  settings['eventsListeners'] = ['jboss-logging']
  settings['enabledEventTypes'] = ['LOGIN_ERROR']
  admin_call(client, token, 'PUT', f'/auth/admin/realms/{REALM}', settings)
  _, _, verified_raw = admin_call(client, token, 'GET', f'/auth/admin/realms/{REALM}')
  verified = json.loads(verified_raw)
  require(verified.get('eventsEnabled') is True
      and 'jboss-logging' in verified.get('eventsListeners', [])
      and 'LOGIN_ERROR' in verified.get('enabledEventTypes', []),
      'sanitized disposable Keycloak login-error events enabled')


def recent_login_error_categories(client, token):
  _, _, body = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/events?type=LOGIN_ERROR&max=20')
  return sanitize_keycloak_events(body.decode('utf-8', errors='replace'))


def configure_realm(client, token, identifier, resolver_port, wrapper_path, bootstrap):
  realm_rep = {
      'realm': REALM, 'enabled': True, 'registrationAllowed': True, 'verifyEmail': False,
      'loginWithEmailAllowed': True, 'duplicateEmailsAllowed': False,
      'sslRequired': 'none',
      'attributes': {
          'decent.wallet.browser-origin': WALLET_ORIGIN,
          'decent.wallet.trusted-origins': 'https://wallet.example',
          'decent.wallet.site-name': 'Example Wallet Demo Site',
          'decent.wallet.registry.bootstrap': bootstrap,
          'decent.wallet.registry.client-port': str(resolver_port),
          'decent.wallet.identity.executable': RESOLVER_WRAPPER,
          'decent.wallet.idp-origin': f'https://idp.example:{KC_PORT}',
      },
      'clients': [{
          'clientId': CLIENT, 'enabled': True, 'protocol': 'openid-connect',
          'publicClient': True, 'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
          'redirectUris': [REDIRECT], 'webOrigins': [WALLET_ORIGIN],
          'protocolMappers': [{
              'name': 'decent_identity_id',
              'protocol': 'openid-connect',
              'protocolMapper': 'oidc-usermodel-attribute-mapper',
              'consentRequired': False,
              'config': {
                  'user.attribute': 'decent_identity_id',
                  'claim.name': 'decent_identity_id',
                  'jsonType.label': 'String',
                  'id.token.claim': 'true',
                  'access.token.claim': 'false',
                  'userinfo.token.claim': 'false',
                  'multivalued': 'false',
              },
          }],
      }],
      'users': [{
          'username': 'wallet-owner', 'enabled': True,
          'email': identifier, 'emailVerified': True, 'firstName': 'Synthetic', 'lastName': 'Wallet',
          'attributes': {'decent_identity_id': [identifier]},
      }],
  }
  admin_call(client, token, 'POST', '/auth/admin/realms', realm_rep, expected=(201,))
  duplicate_rep = {'username': 'wallet-owner-duplicate', 'enabled': True}
  duplicate_status, _, _ = admin_call(client, token, 'POST',
      f'/auth/admin/realms/{REALM}/users', duplicate_rep, expected=(201,))
  require(duplicate_status == 201, 'seed second user for duplicate mapping fixture')
  _, _, realm_raw = admin_call(client, token, 'GET', f'/auth/admin/realms/{REALM}', expected=(200,))
  created_realm = json.loads(realm_raw)
  require(created_realm.get('realm') == REALM and created_realm.get('enabled'),
          'disposable realm persisted')
  for lookup_key, lookup_value in realm_rep['attributes'].items():
    require(created_realm.get('attributes', {}).get(lookup_key) == lookup_value,
        'realm runtime attribute persisted: ' + lookup_key)
  configure_identity_profile(client, token)
  alias = f'{REALM}-browser-wallet'
  admin_call(client, token, 'POST', f'/auth/admin/realms/{REALM}/authentication/flows/browser/copy',
      {'newName': alias}, expected=(201,))
  _, _, flows_raw = admin_call(client, token, 'GET', f'/auth/admin/realms/{REALM}/authentication/flows')
  browser = next((f for f in json.loads(flows_raw) if f.get('alias') == alias), None)
  require(browser is not None, 'copied disposable browser flow')
  browser_id = browser['id']
  _, _, execution_paths_raw = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/authentication/flows/{alias}/executions')
  execution_paths = json.loads(execution_paths_raw)
  path = next((item for item in execution_paths
               if item.get('authenticator') == 'auth-cookie'
               or item.get('authenticator') == 'identity-provider-redirector'), None)
  if path is not None:
    path['requirement'] = 'DISABLED'
    for auth in ('auth-cookie', 'identity-provider-redirector'):
      for item in execution_paths:
        if item.get('authenticator') == auth:
          item['requirement'] = 'DISABLED'
    admin_call(client, token, 'PUT',
        f'/auth/admin/realms/{REALM}/authentication/flows/{alias}/executions',
        {'authenticationExecutions': execution_paths}, expected=(204,))
  admin_call(client, token, 'POST',
      f'/auth/admin/realms/{REALM}/authentication/flows/{alias}/executions/execution',
      {'provider': 'decent-wallet-challenge'}, expected=(201,))
  _, _, exec_raw = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/authentication/flows/{alias}/executions')
  exec_list = json.loads(exec_raw)
  execution = next((item for item in exec_list if item.get('providerId') == 'decent-wallet-challenge'), None)
  require(execution is not None, 'registered wallet authenticator execution')
  execution_id = execution['id']
  admin_call(client, token, 'POST',
      f'/auth/admin/realms/{REALM}/authentication/executions/{execution_id}/config',
      {'alias': 'wallet-login-e2e-trusted-origin', 'config': {
          'trusted-origins': f'https://idp.example:{KC_PORT}',
      }}, expected=(201,))
  _, _, execution_after_config = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/authentication/executions/{execution_id}')
  execution_after_config = json.loads(execution_after_config)
  config_id = execution_after_config.get('authenticatorConfig')
  require(bool(config_id), 'authenticator config attached')
  _, _, config_raw = admin_call(client, token, 'GET',
      f'/auth/admin/realms/{REALM}/authentication/config/{config_id}')
  config = json.loads(config_raw).get('config', {})
  require(config.get('trusted-origins') == f'https://idp.example:{KC_PORT}'
      and 'site-name' not in config, 'authenticator config values')
  admin_call(client, token, 'PUT',
      f'/auth/admin/realms/{REALM}/authentication/flows/{alias}/executions',
      {'id': execution_id, 'requirement': 'REQUIRED'}, expected=(204,))
  admin_call(client, token, 'PUT', f'/auth/admin/realms/{REALM}', {
      'browserFlow': alias, 'loginWithEmailAllowed': True,
      'duplicateEmailsAllowed': False,
  }, expected=(204,))


def der(tag, value):
  length = len(value)
  encoded_length = bytes([length]) if length < 128 else bytes([0x80 + (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8, 'big')
  return bytes([tag]) + encoded_length + value


def verify_id_token(client, token, temp):
  header_segment, payload_segment, signature_segment = token.split('.')
  decode = lambda value: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
  header = json.loads(decode(header_segment))
  require(header.get('alg') == 'RS256', 'pinned ID token algorithm')
  status, _, raw = client.request('GET', f'/auth/realms/{REALM}/protocol/openid-connect/certs')
  require(status == 200, 'realm JWKS read')
  keys = [key for key in json.loads(raw)['keys'] if key.get('kid') == header.get('kid')
          and key.get('kty') == 'RSA' and key.get('alg') == 'RS256' and key.get('use') == 'sig']
  require(len(keys) == 1, 'unique realm signing key')
  def integer(value):
    data = decode(value).lstrip(b'\x00')
    if data[0] & 0x80:
      data = b'\x00' + data
    return der(2, data)
  rsa = der(0x30, integer(keys[0]['n']) + integer(keys[0]['e']))
  spki = der(0x30, bytes.fromhex('300d06092a864886f70d0101010500') + der(3, b'\x00' + rsa))
  public = temp / 'realm-public.der'
  public.write_bytes(spki)
  pem = temp / 'realm-public.pem'
  converted = run(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', str(public), '-out', str(pem)])
  require(converted.returncode == 0, 'realm public key conversion')
  signature = temp / 'id-token-signature'
  signature.write_bytes(decode(signature_segment))
  verified = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(pem), '-signature', str(signature)],
      input=(header_segment + '.' + payload_segment).encode('ascii'), capture_output=True, timeout=10)
  require(verified.returncode == 0, 'ID token signature verified against realm JWKS')
  return json.loads(decode(payload_segment))


def auth_flow(client, key, identifier, container, image):
  verifier = b64url(secrets.token_bytes(32))
  challenge = b64url(hashlib.sha256(verifier.encode('ascii')).digest())
  state = b64url(secrets.token_bytes(24))
  nonce = b64url(secrets.token_bytes(24))
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': state, 'nonce': nonce,
      'code_challenge': challenge, 'code_challenge_method': 'S256',
  })
  status, _, page = client.request('GET', f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(status == 200, 'wallet authenticator challenge page', status)
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  if not locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'):
    print('diagnostic=', json.dumps({
        'wallet_page_title': re.findall(r'<title[^>]*>(.*?)</title>', text, flags=re.I|re.S)[:1],
        'execution_configured': True,
        'response_contains_provider_id': 'decent-wallet-challenge' in text,
        'response_contains_setup': 'SETUP_REQUIRED' in text or 'setup' in text.lower(),
        'response_has_auth_error': 'authentication' in text.lower() and 'error' in text.lower(),
    }))
    require(False, 'provider-owned HTTPS QR locator')
  handle = locator.rsplit('/', 1)[1]
  csrf_match = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', text)
  status_match = re.search(r'const statusUrl = "([^"]+)";', text)
  require(csrf_match is not None and status_match is not None, 'browser-bound status inputs')
  if csrf_match is None or status_match is None:
    raise RuntimeError('acceptance probe failed at browser-bound status inputs')
  browser_csrf = csrf_match.group(1)
  status_url = status_match.group(1)
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': browser_csrf}
  status_parts = urllib.parse.urlsplit(status_url)
  status_query = urllib.parse.parse_qs(status_parts.query)
  wrong_client_query = dict(status_query)
  wrong_client_query['client_id'] = ['not-the-wallet-client']
  wrong_tab_query = dict(status_query)
  wrong_tab_query['tab_id'] = ['not-the-initiating-tab']
  wrong_client_url = urllib.parse.urlunsplit(status_parts._replace(
      query=urllib.parse.urlencode(wrong_client_query, doseq=True)))
  wrong_tab_url = urllib.parse.urlunsplit(status_parts._replace(
      query=urllib.parse.urlencode(wrong_tab_query, doseq=True)))
  wrong_realm_url = status_url.replace(f'/realms/{REALM}/', '/realms/not-the-wallet-realm/', 1)
  wrong_binding_statuses = {
      'alien_browser': Client().request('GET', status_url, headers=status_headers)[0],
      'wrong_client': client.request('GET', wrong_client_url, headers=status_headers)[0],
      'wrong_tab': client.request('GET', wrong_tab_url, headers=status_headers)[0],
      'wrong_realm': client.request('GET', wrong_realm_url, headers=status_headers)[0],
  }
  require(all(status == 404 for status in wrong_binding_statuses.values()),
      'wrong realm/client/session/tab cannot poll wallet status')
  require('Example Wallet Demo Site' in text,
      'provider login page displays configured site label')
  wallet = Client()
  wallet_status, wallet_headers, envelope_raw = wallet.request('GET', locator)
  require(wallet_status == 200, 'native challenge GET', wallet_status)
  envelope = json.loads(envelope_raw)
  require(set(envelope) == {'profile', 'challenge', 'csrf_token'}, 'challenge response exact contract fields')
  require(envelope['profile'] == 'decent-wallet-login-v1', 'challenge profile')
  require(envelope['csrf_token'] == browser_csrf, 'transaction CSRF binding')
  require_transport_security_headers(wallet_headers, 'native challenge security headers')
  pub = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
  require(pub.returncode == 0 and len(pub.stdout) >= 32, 'extract test public key')
  expected_public_key_hex = pub.stdout[-32:].hex()
  signed = json.dumps({'challenge': envelope['challenge'], 'identity_id': identifier,
      'profile': envelope['profile']}, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
  with tempfile.TemporaryDirectory(prefix='wallet-signing-', dir=key.parent) as signing_dir:
    payload = write_private_signing_input(signing_dir, 'proof', signed)
    try:
      sig = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(payload)],
          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    finally:
      payload.unlink(missing_ok=True)
  require(sig.returncode == 0 and len(sig.stdout) == 64, 'Ed25519 RFC8785 proof signature')
  proof = json.dumps({'profile': envelope['profile'], 'challenge': envelope['challenge'],
      'identity_id': identifier, 'signature': b64url(sig.stdout)},
      ensure_ascii=False, separators=(',', ':')).encode('utf-8')
  submitted, proof_headers, accepted = wallet.request('POST', locator, proof, {'Content-Type': 'application/json'})
  require_transport_security_headers(proof_headers, 'native proof security headers')
  require(submitted == 202 and json.loads(accepted).get('status') == 'pending',
      'valid wallet proof POST', submitted)
  diagnostic = run(['podman', 'logs', '--tail', '80', container], timeout=15)
  print('diagnostic-log-lines:', len(diagnostic.stdout.splitlines()))
  for line in diagnostic.stdout.splitlines():
    if '[WALLET-RESOLVER-DIAG]' in line:
      print('resolver-diagnostic:', 'Identity resolver failure')
  retried, _, retry_raw = wallet.request('POST', locator, proof, {'Content-Type': 'application/json'})
  require(retried == 202 and json.loads(retry_raw).get('status') == 'accepted', 'identical native proof retry')
  accepted_by_browser, _, browser_retry_body = client.request('POST', locator, proof,
      {'Content-Type': 'application/json', 'X-Decent-CSRF': browser_csrf,
       'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
       'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty'})
  require(accepted_by_browser == 202 and json.loads(browser_retry_body).get('status') == 'accepted',
      'identical browser proof retry preserves the initiating session')
  changed, _, _ = wallet.request('POST', locator, proof + b' ', {'Content-Type': 'application/json'})
  require(changed == 409, 'changed proof replay denied')
  oversized_status, oversized_headers, _ = wallet.request('POST', locator,
      b' ' * 8193, {'Content-Type': 'application/json'})
  require_transport_security_headers(oversized_headers, 'oversized native proof security headers')
  require(oversized_status == 413, 'native proof body over 8 KiB is rejected', oversized_status)
  poll_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': browser_csrf}
  alien_poll, _, _ = wallet.request('GET', status_url, headers=poll_headers)
  require(alien_poll == 404, 'wallet cannot poll initiating browser status')
  polled, status_headers_out, status_raw = client.request('GET', status_url, headers=poll_headers)
  require_transport_security_headers(status_headers_out, 'valid accepted status security headers')
  require(polled == 200, 'initiating-browser status poll', polled)
  status_obj = json.loads(status_raw)
  require(status_obj.get('status') == 'accepted', 'accepted receipt')
  callback = status_obj.get('callback')
  require(callback and callback.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/'),
      'same-issuer callback')
  callback_status, response_headers, callback_body = client.request('GET', callback)
  location = response_headers.get('Location', '')
  require(urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get('state') == [state], 'OIDC redirect state binding')
  code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get('code', [None])[0]
  require(code is not None, 'Keycloak callback authorization code')
  repeated_status, repeated_headers, _ = client.request('GET', callback)
  repeated_location = repeated_headers.get('Location', '')
  repeated_location_parts = urllib.parse.urlsplit(repeated_location)
  repeated_query = urllib.parse.parse_qs(repeated_location_parts.query)
  repeated_code = repeated_query.get('code', [None])[0]
  require(repeated_status == 302, 'consumed callback replay redirects without authenticating')
  require(repeated_location_parts.path == '/callback'
      and repeated_query.get('state') == [state]
      and repeated_query.get('error') is not None
      and repeated_code is None,
      'consumed callback replay preserves OIDC state but returns error instead of code')
  callback_replay = {'redirect_http': repeated_status, 'state_preserved': True,
      'error_returned': True, 'authorization_code_returned': False}
  status_after_callback, _, status_after_callback_raw = client.request(
      'GET', status_url, headers=poll_headers)
  require(status_after_callback == 404, 'consumed callback is no longer advertised by browser status')
  require(b'callback' not in status_after_callback_raw.lower(),
      'post-callback status discloses no callback URL')
  form = urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': CLIENT,
      'code': code, 'redirect_uri': REDIRECT, 'code_verifier': verifier}).encode()
  token_status, _, token_raw = client.request('POST',
      f'/auth/realms/{REALM}/protocol/openid-connect/token', form,
      {'Content-Type': 'application/x-www-form-urlencoded'})
  require(token_status == 200, 'OIDC Code+PKCE token exchange', token_status)
  id_token = json.loads(token_raw)['id_token']
  pieces = id_token.split('.')
  require(len(pieces) == 3, 'ID token shape')
  claims = verify_id_token(client, id_token, key.parent)
  require(claims.get('exp', 0) > time.time(), 'unexpired ID token')
  require(claims.get('iss') == f'https://idp.example:{KC_PORT}/auth/realms/' + REALM, 'signed issuer claim')
  aud = claims.get('aud')
  require(CLIENT in (aud if isinstance(aud, list) else [aud]), 'ID token audience')
  require(claims.get('nonce') == nonce, 'OIDC nonce binding')
  require(claims.get('sub') and claims.get('sub') != identifier, 'opaque local Keycloak subject')
  return {'wallet_locator': True, 'challenge_get': True, 'proof_post_http': submitted,
      'status_poll_http': polled, 'callback_code': True, 'callback_replay': callback_replay,
      'pkce_token_http': token_status,
      'id_token_claims_checked': True, 'jwks_signature_verified': True,
      'identical_retry_accepted': True, 'changed_retry_denied': True, 'alien_status_denied': True}


def require_transport_security_headers(headers, stage, *, expect_no_store=True):
  expected = {'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff'}
  if expect_no_store:
    expected['Cache-Control'] = 'no-store'
  missing_or_wrong = {name: headers.get(name) for name, value in expected.items()
      if headers.get(name) != value}
  require(not missing_or_wrong, stage, missing_or_wrong)
  require(headers.get('Vary') is not None and 'origin' in {
      item.strip().lower() for item in headers.get('Vary', '').split(',')},
      stage + ' varies by Origin')


def browser_preflight_flow(image):
  browser = Client()
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(secrets.token_bytes(32)).digest()),
      'code_challenge_method': 'S256',
  })
  status, _, page = browser.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(status == 200, 'CORS preflight browser login page')
  parser = LoginPageParser()
  parser.feed(page.decode('utf-8', errors='strict'))
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'CORS preflight transaction locator')
  path = urllib.parse.urlsplit(locator).path
  common = {'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
      'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty'}
  get_headers = {**common, 'Access-Control-Request-Method': 'GET'}
  get_status, get_response_headers, get_body = browser.request('OPTIONS', path,
      headers=get_headers)
  require_transport_security_headers(get_response_headers, 'GET preflight security headers',
      expect_no_store=False)
  require(get_status == 204, 'simple challenge GET browser preflight', get_status)
  require(get_response_headers.get('Access-Control-Allow-Origin') == WALLET_ORIGIN,
      'GET preflight echoes exact allowed Origin')
  require(get_response_headers.get('Access-Control-Allow-Credentials') == 'false',
      'GET preflight does not authorize credentials')
  get_allow_headers = get_response_headers.get('Access-Control-Allow-Headers')
  require(get_allow_headers is None or not get_allow_headers.strip(),
      'GET preflight requires no non-safelisted request headers')
  post_headers = {**common,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type,x-decent-csrf'}
  post_status, post_response_headers, _ = browser.request('OPTIONS', path,
      headers=post_headers)
  require_transport_security_headers(post_response_headers, 'POST preflight security headers',
      expect_no_store=False)
  require(post_status == 204, 'JSON and CSRF proof POST browser preflight', post_status)
  require(post_response_headers.get('Access-Control-Allow-Origin') == WALLET_ORIGIN
      and post_response_headers.get('Access-Control-Allow-Credentials') == 'false',
      'POST preflight echoes only the configured non-credentialed Origin')
  require(set(value.strip().lower() for value in
      post_response_headers.get('Access-Control-Allow-Headers', '').split(','))
      == {'content-type', 'x-decent-csrf'}, 'POST preflight allows only JSON and CSRF headers')
  forbidden_headers = {**common,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'authorization,content-type,x-decent-csrf'}
  rejected_status, rejected_headers, _ = browser.request('OPTIONS', path,
      headers=forbidden_headers)
  require(rejected_status == 403, 'proof preflight rejects an extra Authorization header', rejected_status)
  require(rejected_headers.get('Cache-Control') == 'no-store', 'rejected preflight is not cached')
  wrong_origin_headers = {**common, 'Origin': 'https://attacker.example',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type,x-decent-csrf'}
  wrong_origin_status, _, _ = browser.request('OPTIONS', path,
      headers=wrong_origin_headers)
  require(wrong_origin_status == 403, 'preflight rejects unconfigured Origin', wrong_origin_status)
  browser_challenge_status, browser_challenge_headers, challenge_body = browser.request(
      'GET', locator, headers={'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
          'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty'})
  require_transport_security_headers(browser_challenge_headers, 'browser challenge security headers')
  require(browser_challenge_status == 200, 'browser challenge fetch succeeds', browser_challenge_status)
  require(browser_challenge_headers.get('Access-Control-Allow-Origin') == WALLET_ORIGIN,
      'browser challenge response exposes only the configured Origin')
  require(browser_challenge_headers.get('Cache-Control') == 'no-store',
      'browser challenge response is not cacheable')
  challenge_envelope = json.loads(challenge_body)
  challenge_csrf = challenge_envelope.get('csrf_token')
  require(isinstance(challenge_csrf, str) and challenge_csrf,
      'browser challenge returns a CSRF token')
  challenge_envelope['challenge'] = b64url(bytes([255]) * 32)
  require(challenge_envelope['challenge'] != json.loads(challenge_body)['challenge'],
      'browser proof uses an invalid challenge')
  missing_csrf_status, missing_csrf_headers, _ = browser.request('POST', locator,
      json.dumps({'profile': challenge_envelope['profile'],
          'challenge': challenge_envelope['challenge'], 'identity_id': 'cors-probe',
          'signature': b64url(bytes(64))}, separators=(',', ':')).encode('utf-8'),
      {'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
       'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
       'Content-Type': 'application/json'})
  require_transport_security_headers(missing_csrf_headers, 'missing-CSRF response security headers')
  require(missing_csrf_status == 403, 'browser proof POST without CSRF is denied', missing_csrf_status)
  wrong_challenge = b64url(bytes([255]) * 32)
  if wrong_challenge == challenge_envelope['challenge']:
    wrong_challenge = b64url(bytes([254]) * 32)
  proof_payload = json.dumps({'profile': challenge_envelope['profile'],
      'challenge': wrong_challenge, 'identity_id': 'cors-probe',
      'signature': b64url(bytes(64))}, separators=(',', ':')).encode('utf-8')
  browser_proof_status, browser_proof_headers, _ = browser.request('POST', locator, proof_payload,
      {'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
       'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
       'Content-Type': 'application/json', 'X-Decent-CSRF': challenge_csrf})
  require_transport_security_headers(browser_proof_headers, 'browser proof response security headers')
  require(browser_proof_status == 401,
      'browser proof POST with CSRF reaches challenge validation', browser_proof_status)
  oversized_status, oversized_headers, _ = browser.request('POST', locator,
      b' ' * 8193, {'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
       'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
       'Content-Type': 'application/json', 'X-Decent-CSRF': challenge_csrf})
  require_transport_security_headers(oversized_headers, 'oversized proof response security headers')
  require(oversized_status == 413, 'proof body over 8 KiB is rejected', oversized_status)
  page_text = page.decode('utf-8', errors='strict')
  csrf_match = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', page_text)
  status_match = re.search(r'const statusUrl = "([^"]+)";', page_text)
  require(csrf_match is not None and status_match is not None,
      'browser login status binding for CORS negative requests')
  if csrf_match is None or status_match is None:
    raise RuntimeError('acceptance probe failed at browser status binding')
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf_match.group(1)}
  status, status_response_headers, status_raw = browser.request('GET', status_match.group(1), headers=status_headers)
  require_transport_security_headers(status_response_headers, 'status response security headers')
  require(status == 200 and json.loads(status_raw) == {'status': 'pending'},
      'CORS negative browser requests do not accept or callback')
  return {'get_http': get_status, 'post_http': post_status,
      'browser_challenge_http': browser_challenge_status,
      'missing_csrf_http': missing_csrf_status, 'browser_proof_http': browser_proof_status,
      'extra_header_http': rejected_status, 'wrong_origin_http': wrong_origin_status,
      'pending_after_negative_http': status, 'credentialed': False}


def negative_proof_flow(identifier, image):
  browser = Client()
  verifier = b64url(secrets.token_bytes(32))
  code_challenge = b64url(hashlib.sha256(verifier.encode('ascii')).digest())
  state = b64url(secrets.token_bytes(24))
  nonce = b64url(secrets.token_bytes(24))
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': state, 'nonce': nonce,
      'code_challenge': code_challenge, 'code_challenge_method': 'S256',
  })
  status, _, page = browser.request('GET', f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(status == 200, 'negative-case browser login page', status)
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'negative-case transaction locator')
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', text)
  status_url = re.search(r'const statusUrl = "([^"]+)";', text)
  require(csrf is not None and status_url is not None, 'negative-case browser status binding')
  wallet = Client()
  lookup_client = BareLocalClient()
  throttle_client = BareLocalClient()
  hostile_origin, _, _ = wallet.request('GET', locator, headers={
      'Origin': 'https://attacker.example', 'Sec-Fetch-Site': 'cross-site',
      'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty'})
  require(hostile_origin == 403, 'wrong-origin challenge disclosure denied')
  challenge_status, _, challenge_raw = wallet.request('GET', locator)
  require(challenge_status == 200, 'negative-case native challenge GET')
  envelope = json.loads(challenge_raw)
  wrong_challenge = b64url(bytes([1]) * 32)
  if wrong_challenge == envelope['challenge']:
    wrong_challenge = b64url(bytes([2]) * 32)
  invalid_proof = json.dumps({
      'profile': envelope['profile'], 'challenge': wrong_challenge,
      'identity_id': identifier, 'signature': b64url(bytes(64)),
  }, separators=(',', ':')).encode('utf-8')
  rejected, _, _ = wallet.request('POST', locator, invalid_proof,
      {'Content-Type': 'application/json'})
  require(rejected == 401, 'wrong-challenge proof is denied before Registry resolution')
  assert csrf is not None and status_url is not None
  poll_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  polled, _, status_raw = browser.request('GET', status_url.group(1), headers=poll_headers)
  require(polled == 200, 'invalid-proof initiating-browser status')
  status_body = json.loads(status_raw)
  require(status_body == {'status': 'pending'}, 'invalid proof did not accept or expose callback')
  return {'wrong_origin_denied': True, 'invalid_proof_http': rejected,
      'signature_rejected_by_verifier': rejected == 401,
      'no_acceptance_or_callback': True}


def invalid_proof_throttle_flow(image):
  browser = Client()
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(secrets.token_bytes(32)).digest()),
      'code_challenge_method': 'S256',
  })
  status, _, page = browser.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(status == 200, 'throttle browser login page')
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'throttle transaction locator')
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', text)
  status_url = re.search(r'const statusUrl = "([^"]+)";', text)
  require(csrf is not None and status_url is not None, 'throttle browser status binding')
  wallet = BareLocalClient()
  challenge_status, _, challenge_raw = wallet.request('GET', locator)
  require(challenge_status == 200, 'throttle native challenge GET')
  envelope = json.loads(challenge_raw)
  wrong_challenge = b64url(bytes([1]) * 32)
  require(wrong_challenge != envelope['challenge'], 'throttle challenge differs from issued challenge')
  pre_resolution_invalid = json.dumps({
      'profile': envelope['profile'], 'challenge': wrong_challenge,
      'identity_id': 'throttle-probe', 'signature': b64url(bytes(64)),
  }, separators=(',', ':')).encode('utf-8')
  first_invalid, _, _ = wallet.request('POST', locator, pre_resolution_invalid,
      {'Content-Type': 'application/json'})
  require(first_invalid == 401, 'first invalid challenge is rejected before Registry lookup')
  malformed_results = []
  for _ in range(4):
    response, _, _ = wallet.request('POST', locator, b'{"profile":',
        {'Content-Type': 'application/json'})
    malformed_results.append(response)
  require(malformed_results == [400, 400, 400, 400],
      'four malformed proofs are rejected', malformed_results)
  throttled, _, _ = wallet.request('POST', locator, pre_resolution_invalid,
      {'Content-Type': 'application/json'})
  require(throttled == 429, 'proof after five invalid attempts is throttled')
  poll_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  polled, _, status_raw = browser.request('GET', status_url.group(1), headers=poll_headers)
  require(polled == 200 and json.loads(status_raw) == {'status': 'pending'},
      'throttled transaction remains pending with no callback')
  return {'pre_resolution_invalid_http': first_invalid,
      'four_malformed_proofs_http': malformed_results,
      'http_after_five_invalid_attempts': throttled, 'no_acceptance_or_callback': True}

def account_mapping_denial_flow(client, key, identity_id, scenario, container, resolver_port, bootstrap, wrapper_path_name, image):
  token = admin_token(client, AdminPassword(client.privateClientAdminCredential))
  browser = Client()
  poll_browser = browser
  verifier = b64url(secrets.token_bytes(32))
  code_challenge = b64url(hashlib.sha256(verifier.encode('ascii')).digest())
  state = b64url(secrets.token_bytes(24))
  nonce = b64url(secrets.token_bytes(24))
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': state, 'nonce': nonce,
      'code_challenge': code_challenge, 'code_challenge_method': 'S256',
  })
  status, _, page = browser.request('GET', f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(status == 200, f'{scenario} browser login page', status)
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      f'{scenario} transaction locator')
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', text)
  status_url = re.search(r'const statusUrl = "([^"]+)";', text)
  assert csrf is not None and status_url is not None
  wallet = Client()
  challenge_status, _, challenge_raw = wallet.request('GET', locator)
  require(challenge_status == 200, f'{scenario} native challenge GET')
  envelope = json.loads(challenge_raw)
  signing_input = json.dumps({
      'challenge': envelope['challenge'], 'identity_id': identity_id,
      'profile': envelope['profile'],
  }, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
  with tempfile.TemporaryDirectory(prefix='wallet-signing-', dir=key.parent) as signing_dir:
    payload = write_private_signing_input(signing_dir, scenario, signing_input)
    try:
      signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key),
          '-in', str(payload)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    finally:
      payload.unlink(missing_ok=True)
  require(signature.returncode == 0 and len(signature.stdout) == 64,
      f'sign valid proof for {scenario} Registry identity')
  direct_started = time.monotonic()
  registry_lookup_outcome = 'unavailable'
  try:
    direct_probe = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
        ['get', '--identifier', identity_id,
        '--host', '127.0.0.1', '--port', str(resolver_port), '--bootstrap', bootstrap], timeout=20, image=image)
    registry_lookup_outcome = exact_registry_lookup_outcome(
        direct_probe.stdout, direct_probe.returncode, identity_id)
    if registry_lookup_outcome == 'resolved':
      print(f'{scenario} direct Registry lookup completed in {int((time.monotonic()-direct_started)*1000)} ms')
    else:
      print(f'{scenario} direct Registry lookup {registry_lookup_outcome}')
  except (subprocess.TimeoutExpired, RuntimeError) as resolver_failure:
    print(f'{scenario} direct Registry lookup unavailable: {type(resolver_failure).__name__}')
  logs_before = run(['podman', 'logs', '--tail', '120', container], timeout=15)
  previous_log_lines = logs_before.stdout.splitlines() if logs_before.returncode == 0 else None
  expected_request_id = account_policy_request_id(locator)
  require(expected_request_id is not None, f'{scenario} opaque log correlation token')
  proof = json.dumps({
      'profile': envelope['profile'], 'challenge': envelope['challenge'],
      'identity_id': identity_id, 'signature': b64url(signature.stdout),
  }, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
  logs_before = run(['podman', 'logs', '--tail', '120', container], timeout=15)
  previous_log_lines = logs_before.stdout.splitlines() if logs_before.returncode == 0 else None
  direct_http, _, response_body = browser.request('POST', locator, proof,
      {'Content-Type': 'application/json', 'X-Decent-CSRF': csrf.group(1),
       'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
       'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty'})
  poll_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  polled, _, status_raw = poll_browser.request('GET', status_url.group(1), headers=poll_headers)
  require(polled == 200, f'{scenario} browser remains pending')
  require(json.loads(status_raw) == {'status': 'pending'},
      f'{scenario} proof yielded no accepted receipt or callback')
  server_diagnostics = run(['podman', 'logs', '--tail', '120', container], timeout=15)
  current_log_lines = server_diagnostics.stdout.splitlines() if server_diagnostics.returncode == 0 else []
  expected_request_id = account_policy_request_id(locator)
  safe_categories = new_account_mapping_log_categories(
      previous_log_lines, current_log_lines, expected_request_id)
  if safe_categories:
    print(f'{scenario} provider-failure-categories:', json.dumps(safe_categories))
  result = account_mapping_denial_result(direct_http, registry_lookup_outcome, safe_categories)
  if result['outcome'] in ('unexpected_acceptance', 'unexpected_status'):
    raise RuntimeError(f'acceptance probe failed at {scenario} expected account denial (HTTP {direct_http})')
  if result['outcome'] == 'provider_denied_unclassified':
    print(f'{scenario} HTTP 403 denied; provider-side account-policy attribution unavailable')
  return result


def account_policy_request_id(locator):
  handle = urllib.parse.urlsplit(locator).path.rsplit('/', 1)[-1]
  return hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]


def new_account_mapping_log_categories(previous_lines, current_lines, expected_request_id):
  if previous_lines is None:
    return []
  maximum_overlap = min(len(previous_lines), len(current_lines))
  overlap = 0
  for size in range(maximum_overlap, 0, -1):
    if previous_lines[-size:] == current_lines[:size]:
      overlap = size
      break
  if previous_lines and overlap == 0:
    return []
  if not re.fullmatch(r'[0-9a-f]{32}', expected_request_id):
    return []
  categories = []
  for line in current_lines[overlap:]:
    policy_match = re.search(r'Wallet account policy rejected proof \(request=([0-9a-f]{32}),', line)
    resolver_match = re.search(r'Wallet Identity resolver unavailable \(request=([0-9a-f]{32}),', line)
    mapping_match = re.search(r'Wallet account mapping lookup unavailable \(request=([0-9a-f]{32}),', line)
    matched = policy_match or resolver_match or mapping_match
    if matched is None:
      continue
    request_id = matched.group(1)
    if request_id != expected_request_id:
      continue
    if policy_match:
      categories.append('account-policy-rejected')
    elif resolver_match:
      categories.append('identity-resolver-unavailable')
    elif mapping_match:
      categories.append('account-mapping-unavailable')
  return categories


def account_mapping_denial_result(status, registry_lookup_outcome, safe_categories):
  if status == 403:
    policy_trace = 'account-policy-rejected' in safe_categories
    resolver_failed = any(category == 'identity-resolver-unavailable' for category in safe_categories)
    mapping_failed = any(category == 'account-mapping-unavailable' for category in safe_categories)
    if registry_lookup_outcome == 'resolved' and policy_trace and not resolver_failed and not mapping_failed:
      return {'current_registry_proof_http': status, 'scenario': 'account-mapping-denial',
          'registry_lookup_outcome': registry_lookup_outcome,
          'local_account_mapping_decision_observed': True, 'registry_unavailable': False,
          'no_acceptance_or_callback': True, 'outcome': 'policy_denied'}
    return {'current_registry_proof_http': status, 'scenario': 'account-mapping-denial',
        'registry_lookup_outcome': registry_lookup_outcome,
        'local_account_mapping_decision_observed': False,
        'registry_unavailable': registry_lookup_outcome == 'unavailable',
        'no_acceptance_or_callback': True, 'outcome': 'provider_denied_unclassified'}
  if status == 503:
    if registry_lookup_outcome == 'unavailable':
      outcome = 'registry_unavailable'
    elif registry_lookup_outcome == 'not_found':
      outcome = 'provider_registry_inconsistent'
    elif 'account-mapping-unavailable' in safe_categories:
      outcome = 'account_mapping_unavailable'
    else:
      outcome = 'provider_unavailable'
    return {'current_registry_proof_http': status, 'scenario': 'account-mapping-denial',
        'registry_lookup_outcome': registry_lookup_outcome,
        'local_account_mapping_decision_observed': False,
        'registry_unavailable': outcome == 'registry_unavailable',
        'no_acceptance_or_callback': True, 'outcome': outcome}
  if status == 202:
    return {'current_registry_proof_http': status, 'scenario': 'account-mapping-denial',
        'registry_lookup_outcome': registry_lookup_outcome,
        'local_account_mapping_decision_observed': False, 'registry_unavailable': False,
        'no_acceptance_or_callback': False, 'outcome': 'unexpected_acceptance'}
  return {'current_registry_proof_http': status, 'scenario': 'account-mapping-denial',
      'registry_lookup_outcome': registry_lookup_outcome,
      'local_account_mapping_decision_observed': False, 'registry_unavailable': False,
      'no_acceptance_or_callback': False, 'outcome': 'unexpected_status'}


def unmapped_account_case_evidence(result):
  if result.get('outcome') == 'policy_denied':
    return result
  return {'outcome': result.get('outcome', 'unqualified'),
      'current_registry_proof_http': result.get('current_registry_proof_http'),
      'registry_lookup_outcome': result.get('registry_lookup_outcome', 'unavailable'),
      'local_account_mapping_decision_observed': False,
      'registry_unavailable': result.get('registry_unavailable', False),
      'no_acceptance_or_callback': result.get('no_acceptance_or_callback', False),
      'scenario': 'unmapped-account'}


def account_policy_denial_is_attributed(result):
  return (result.get('current_registry_proof_http') == 403
      and result.get('outcome') == 'policy_denied'
      and result.get('local_account_mapping_decision_observed') is True
      and result.get('no_acceptance_or_callback') is True)


def run_bounded_resolver_attempts(attempt, max_attempts=3, *, retry_status=503,
    can_retry=lambda: True, retry_delay_seconds=0.0):
  if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
    raise ValueError('resolver retry count must be between one and five')
  if type(retry_status) is not int or not 100 <= retry_status <= 599:
    raise ValueError('retry status must be an HTTP status')
  if not callable(can_retry):
    raise ValueError('retry state predicate must be callable')
  if not isinstance(retry_delay_seconds, (int, float)) or not 0 <= retry_delay_seconds <= 5:
    raise ValueError('retry delay must be between zero and five seconds')
  outcomes = []
  for attempt_number in range(max_attempts):
    status = attempt()
    outcomes.append(status)
    if status != retry_status or attempt_number + 1 >= max_attempts:
      break
    if not can_retry():
      break
    if retry_delay_seconds:
      time.sleep(retry_delay_seconds)
  return outcomes




def rotation_readback_samples(identifier, expected_public_key_hex, configured_port,
    lookup_at_port, fresh_port, progress):
  samples = []
  resolved = False
  for _ in range(3):
    for strategy in ('configured', 'ephemeral'):
      port = configured_port
      if strategy == 'ephemeral':
        port = fresh_port()
        if port == configured_port:
          port = fresh_port()
        require(port != configured_port, 'ephemeral resolver port differs from configured port')
      started = time.monotonic()
      lookup = lookup_at_port(port)
      lookup_ms = int((time.monotonic() - started) * 1000)
      outcome, categories = classify_identity_lookup(lookup.stdout, lookup.returncode, identifier)
      lookup_ms = int((time.monotonic() - started) * 1000)
      exact = packaged_resolver_readback(
          lookup.stdout, lookup.returncode, identifier, expected_public_key_hex)
      if exact:
        outcome = 'resolved'
        resolved = True
      elif outcome == 'resolved':
        outcome = 'unavailable'
      samples.append({
          'outcome': outcome,
          'lookup_ms': lookup_ms,
          'peer_handshake': 'peer_handshake' in categories,
          'unexpected_diagnostic': any(category == 'other' for category in categories),
          'diagnostic_categories': categories[:12],
          'json_balanced': json_object_is_balanced(lookup.stdout),
          'exact_identity_and_successor_match': exact,
          'port_strategy': strategy,
      })
      progress(samples)
  return samples, resolved

def stale_key_rotation_flow(client, old_key, new_key, identifier, container,
    resolver_port, bootstrap, wrapper_name, progress, image, rotation_root):
  def start_rotation_transaction():
    fresh_browser = Client()
    verifier = b64url(secrets.token_bytes(32))
    query = urllib.parse.urlencode({
        'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
        'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
        'nonce': b64url(secrets.token_bytes(24)),
        'code_challenge': b64url(hashlib.sha256(verifier.encode('ascii')).digest()),
        'code_challenge_method': 'S256',
    })
    status, _, page = fresh_browser.request('GET',
        f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
    return fresh_browser, status, page

  rotation_browser, status, page = start_rotation_transaction()
  require(status == 200, 'rotation initiating browser login page')
  parser = LoginPageParser()
  parser.feed(page.decode('utf-8', errors='strict'))
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'rotation transaction locator')
  status_url = re.search(r'const statusUrl = "([^"]+)";', page.decode('utf-8'))
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', page.decode('utf-8'))
  require(status_url is not None and csrf is not None, 'rotation browser status binding')
  if status_url is None or csrf is None:
    raise RuntimeError('acceptance probe failed at rotation browser status binding')
  rotation_status_url = status_url.group(1)
  rotation_csrf = csrf.group(1)
  wallet = Client()
  challenge_status, _, challenge_body = wallet.request('GET', locator)
  require(challenge_status == 200, 'rotation native challenge GET')
  envelope = json.loads(challenge_body)

  def submit_signed(key, label, proof_envelope, transaction_locator, browser=None, csrf_token=None):
    signing_input = json.dumps({'challenge': proof_envelope['challenge'],
        'identity_id': identifier, 'profile': proof_envelope['profile']},
        ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
    with tempfile.TemporaryDirectory(prefix='wallet-signing-', dir=rotation_root) as signing_dir:
      payload = write_private_signing_input(signing_dir, label, signing_input)
      try:
        signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin',
            '-inkey', str(key), '-in', str(payload)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
      finally:
        payload.unlink(missing_ok=True)
    require(signature.returncode == 0 and len(signature.stdout) == 64,
        f'{label} Ed25519 proof signature')
    proof = json.dumps({'profile': proof_envelope['profile'],
        'challenge': proof_envelope['challenge'], 'identity_id': identifier,
        'signature': b64url(signature.stdout)}, separators=(',', ':')).encode()
    if browser is not None:
      headers = {'Content-Type': 'application/json', 'X-Decent-CSRF': csrf_token,
          'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
          'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty'}
      return browser.request('POST', transaction_locator, proof, headers)[0]
    return wallet.request('POST', transaction_locator, proof, {'Content-Type': 'application/json'})[0]

  project = Path(__file__).parents[1]
  helper = project / 'scripts/rotation_registry_roundtrip.py'
  require(helper.is_file(), 'rotation helper source exists before packaged execution')
  with tempfile.TemporaryDirectory(prefix='wallet-rotation-', dir=rotation_root) as rotation_temp:
    rotation_dir = Path(rotation_temp)
    rotation_in_tools = rotation_dir
    old_key_in_tools = old_key
    new_key_in_tools = new_key
    envelope_path = rotation_in_tools / 'rotation-envelope.cbor'
    readback_path = rotation_in_tools / 'rotation-readback.txt'
    completed = run(['podman', 'exec', os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
        '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'LANG=C.UTF-8',
        'PYTHONPATH=/opt/decent-resolver/registry-src/src:/opt/decent-resolver/identity-src/src:'
        '/opt/decent-resolver/venv/lib64/python3.11/site-packages:/opt/decent-resolver/venv/lib/python3.11/site-packages',
        'LD_LIBRARY_PATH=/opt/decent-resolver/lib', '/usr/bin/python3.11',
        '/opt/decent-resolver/rotation_registry_roundtrip.py',
        '--identifier', identifier, '--old-key', str(old_key_in_tools),
        '--new-key', str(new_key_in_tools), '--host', '127.0.0.1',
        '--port', str(free_port()), '--bootstrap', bootstrap,
        '--datastore', str(rotation_in_tools / 'writer-lmdb'),
        '--envelope', str(envelope_path), '--readback', str(readback_path)], timeout=60)
    progress('publish', {'rotation_publish': 'passed' if completed.returncode == 0 else 'failed'})
    require(completed.returncode == 0, 'packaged Registry owner-key rotation', completed.returncode)
    envelope_path = rotation_dir / 'rotation-envelope.cbor'
    readback_path = rotation_dir / 'rotation-readback.txt'
    require(envelope_path.is_file() and readback_path.is_file(),
        'packaged rotation outputs visible in scratch mount')
    expected_key = subprocess.run(['openssl', 'pkey', '-in', str(new_key),
        '-pubout', '-outform', 'DER'], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10, check=False)
    require(expected_key.returncode == 0 and len(expected_key.stdout) >= 32,
        'derive expected post-rotation owner key')
    readback = readback_path.read_text(encoding='ascii').splitlines()
    require(len(readback) == 2 and readback[0] == '2'
        and readback[1] == expected_key.stdout[-32:].hex(),
        'separate Identity resolver confirms seq 2 and exact successor key')
    progress('readback', {'rotation_publish': 'read_back_exact', 'current_sequence': 2})
    provider_lookup = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
        ['get', '--identifier', identifier, '--host', '127.0.0.1',
         '--port', str(resolver_port), '--bootstrap', bootstrap], timeout=30, image=image)
    provider_categories = classify_identity_lookup(
        provider_lookup.stdout, provider_lookup.returncode, identifier)[1]
    require(provider_lookup.returncode == 0 and '"identifier"' in provider_lookup.stdout,
        'production-container resolver reads the rotated Identity', provider_lookup.returncode)

  resolver_samples, resolved_fresh_read = rotation_readback_samples(
      identifier,
      expected_key.stdout[-32:].hex(),
      resolver_port,
      lambda port: run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
          ['get', '--identifier', identifier, '--host', '127.0.0.1',
           '--port', str(port), '--bootstrap', bootstrap], timeout=30, image=image),
      free_port,
      lambda samples: progress('readback', {
          'rotation_publish': 'read_back_exact', 'current_sequence': 2,
          'resolver_samples': samples}),
  )
  progress('readback', {'rotation_publish': 'read_back_exact', 'current_sequence': 2,
      'resolver_samples': resolver_samples})
  require(resolved_fresh_read,
      'at least one fresh production-container read confirms the exact successor key before proofs',
      'unavailable')
  progress('stale_proof_pending', {})
  stale_retry_status = []
  def stale_attempt():
    observed_status = submit_signed(old_key, 'rotated-stale-key', envelope, locator,
        rotation_browser, rotation_csrf)
    pending_status = None
    if observed_status == 503:
      status_code, _, status_body = rotation_browser.request('GET', rotation_status_url,
          headers={'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
              'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': rotation_csrf})
      status_payload = None
      if status_code == 200:
        try:
          status_payload = json.loads(status_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
          pass
      pending_status = {'status_http': status_code,
          'status_pending': status_payload == {'status': 'pending'}}
    stale_retry_status.append(pending_status)
    return observed_status
  stale_attempts = run_bounded_resolver_attempts(stale_attempt, max_attempts=3,
      retry_status=503, can_retry=lambda: stale_retry_status[-1] is not None
          and stale_retry_status[-1]['status_pending'], retry_delay_seconds=1)
  for attempt_number, observed_status in enumerate(stale_attempts, start=1):
    progress('stale_attempt', {'attempt_number': attempt_number,
        'stale_key_proof_http': observed_status,
        **(stale_retry_status[attempt_number - 1] or {})})
  stale_key_status = stale_attempts[-1]
  progress('stale_proof', {'stale_key_proof_http': stale_key_status})
  require(stale_key_status == 401, 'proof signed by pre-rotation owner is rejected', stale_key_status)
  stale_poll_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': rotation_csrf}
  stale_status, _, stale_body = rotation_browser.request('GET', rotation_status_url,
      headers=stale_poll_headers)
  progress('stale_pending', {'stale_transaction_remains_pending':
      stale_status == 200 and json.loads(stale_body) == {'status': 'pending'}})
  require(stale_status == 200 and json.loads(stale_body) == {'status': 'pending'},
      'stale-key rejection leaves its transaction pending without callback')

  current_browser, status, page = start_rotation_transaction()
  require(status == 200, 'fresh current-key proof browser login page', status)
  parser = LoginPageParser()
  parser.feed(page.decode('utf-8', errors='strict'))
  current_locator = ''.join(parser.locator_parts).strip()
  status_url = re.search(r'const statusUrl = "([^"]+)";', page.decode('utf-8'))
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', page.decode('utf-8'))
  require(status_url is not None and csrf is not None, 'fresh current-key browser binding')
  if status_url is None or csrf is None:
    raise RuntimeError('acceptance probe failed at current-key browser binding')
  current_status_url = status_url.group(1)
  current_csrf = csrf.group(1)
  wallet = Client()
  challenge_status, _, challenge_body = wallet.request('GET', current_locator)
  require(challenge_status == 200, 'fresh current-key wallet challenge')
  envelope = json.loads(challenge_body)
  current_retry_status = []
  def current_attempt():
    observed_status = submit_signed(new_key, 'rotated-current-key', envelope,
        current_locator, current_browser, current_csrf)
    pending_status = None
    if observed_status == 503:
      status_code, _, status_body = current_browser.request('GET', current_status_url,
          headers={'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
              'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': current_csrf})
      status_payload = None
      if status_code == 200:
        try:
          status_payload = json.loads(status_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
          pass
      pending_status = {'status_http': status_code,
          'status_pending': status_payload == {'status': 'pending'}}
    current_retry_status.append(pending_status)
    return observed_status
  current_attempts = run_bounded_resolver_attempts(current_attempt, max_attempts=3,
      retry_status=503, can_retry=lambda: current_retry_status[-1] is not None
          and current_retry_status[-1]['status_pending'], retry_delay_seconds=1)
  for attempt_number, observed_status in enumerate(current_attempts, start=1):
    progress('current_attempt', {'attempt_number': attempt_number,
        'current_key_proof_http': observed_status,
        **(current_retry_status[attempt_number - 1] or {})})
    progress('current_proof', {'current_key_proof_http': observed_status})
    if observed_status == 202 or observed_status != 503:
      break
  current_key_status = current_attempts[-1]
  progress('current_proof', {'current_key_proof_http': current_key_status})
  if current_key_status != 202:
    diagnostic = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
        ['get', '--identifier', identifier,
        '--host', '127.0.0.1', '--port', str(resolver_port), '--bootstrap', bootstrap], timeout=30, image=image)
    safe_categories = []
    for line in diagnostic.stdout.splitlines():
      category = identity_lookup_category(line)
      if category in ('peer_status', 'dial_warning', 'registry_miss', 'peer_handshake', 'peer_error', 'history_unavailable'):
        safe_categories.append(category)
      elif line.strip():
        safe_categories.append('json-line' if category == 'json' else 'unclassified-line')
    print('current-key-provider-resolver-categories:', json.dumps(safe_categories[:40]))
  require(current_key_status == 202,
      'proof signed by post-rotation current owner is accepted', current_key_status)
  current_poll_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': current_csrf}
  current_status, _, current_body = current_browser.request('GET', current_status_url,
      headers=current_poll_headers)
  progress('current_accepted', {'current_transaction_accepted':
      current_status == 200 and json.loads(current_body).get('status') == 'accepted'})
  require(current_status == 200 and json.loads(current_body).get('status') == 'accepted',
      'current-key proof is visible only to the initiating browser')
  callback = json.loads(current_body).get('callback')
  progress('callback', {'callback_available': isinstance(callback, str)
      and callback.startswith(f'https://idp.example:{KC_PORT}/auth/')})
  require(isinstance(callback, str) and callback.startswith(f'https://idp.example:{KC_PORT}/auth/'),
      'current-key accepted status returns the Keycloak execution callback')
  return {'rotation_publish': 'passed', 'current_sequence': 2,
      'current_key_proof_http': current_key_status, 'stale_key_proof_http': stale_key_status,
      'stale_transaction_remains_pending': True, 'current_transaction_accepted': True}




def sanitized_resolver_diagnostic_lines(text):
  if not isinstance(text, str):
    return []
  allowed = {'registry_miss', 'dial_warning', 'peer_handshake', 'peer_error',
      'history_unavailable', 'traceback', 'process_start', 'nonzero_exit', 'unknown', 'success',
      'timeout', 'interrupted', 'termination_interrupted', 'output_overflow'}
  output = []
  for line in text.splitlines()[-300:]:
    if len(line) > 2048:
      continue
    marker = '[WALLET-RESOLVER-DIAG]'
    if marker not in line:
      continue
    suffix = line.split(marker, 1)[1].strip()
    match = re.fullmatch(r'exit=(-?\d+), reason=([a-z_|]+), lines=(\d+), capped=(true|false)', suffix)
    if not match:
      output.append('invalid')
      continue
    exit_code, reason, count, _ = match.groups()
    cats = reason.split('|')
    if (int(exit_code) < -1 or int(exit_code) > 255 or int(count) > 64
        or not cats or any(cat not in allowed for cat in cats)
        or len(cats) != len(set(cats))):
      output.append('invalid')
      continue
    output.append('ok:' + '|'.join(cats))
  return output[:32]


def record_resolver_diagnostics(container):
  logs = run(['podman', 'logs', '--tail', '300', container], timeout=15)
  if logs.returncode != 0:
    return ['unavailable']
  return sanitized_resolver_diagnostic_lines(logs.stdout)


def safe_resolver_diagnostic_snapshot(container):
  logs = run(['podman', 'logs', '--tail', '300', container], timeout=15)
  if logs.returncode != 0:
    return ['unavailable']
  return sanitized_resolver_diagnostic_lines(logs.stdout)


def capture_live_resolver_diagnostics(container, result, checkpoint):
  categories = safe_resolver_diagnostic_snapshot(container)
  result.setdefault('resolver_runtime', {})['diagnostic_categories'] = categories
  checkpoint()
  return categories


def classify_oidc_action_error(body):
  try:
    payload = json.loads(body)
  except (TypeError, ValueError):
    return 'non-json-error'
  if not isinstance(payload, dict):
    return 'non-object-error'
  name = payload.get('error')
  known = {'invalid_grant', 'expired_code', 'invalid_code', 'invalid_token', 'invalid_request',
      'invalid_session', 'session_not_found', 'authentication_expired'}
  safe_name = name if isinstance(name, str) and name in known else 'other-error'
  description = payload.get('error_description')
  if not isinstance(description, str):
    return safe_name + ':no-description'
  folded = description.casefold()
  if folded.strip() in ('internal server error', 'internal error'):
    return safe_name + ':internal-error'
  clues = (
      ('restart-path', ('login restart', 'restart authentication', 'restart page',
          'restart login', 'login restarted')),
      ('session-code', ('session code', 'session_code', 'client session code')),
      ('execution', ('execution',)),
      ('tab', ('tab id', 'tab_id')),
      ('client-data', ('client data', 'client_data')),
      ('csrf-or-cookie', ('csrf', 'cookie', 'authenticator session')),
      ('flow-reset', ('flow', 'reset')),
      ('expired', ('expired', 'expiration')),
      ('invalid', ('invalid', 'not valid')),
  )
  matched = [label for label, phrases in clues if any(phrase in folded for phrase in phrases)]
  return safe_name + ':' + ('+'.join(matched) if matched else 'unclassified-description')

def sanitize_keycloak_events(response_body):
  try:
    events = json.loads(response_body)
  except (TypeError, ValueError):
    return []
  if not isinstance(events, list):
    return []
  output = []
  for event in events[:20]:
    if not isinstance(event, dict):
      continue
    event_type = event.get('type')
    error = event.get('error')
    details = event.get('details')
    if not isinstance(event_type, str) or not re.fullmatch(r'[A-Z_]{1,40}', event_type):
      continue
    if not isinstance(error, str) or not re.fullmatch(r'[a-z_]{1,48}', error):
      error = 'unclassified'
    names = sorted(key for key in details if isinstance(key, str)
        and re.fullmatch(r'[a-z_]{1,48}', key)) if isinstance(details, dict) else []
    output.append({'type': event_type, 'error': error, 'detail_names': names[:32]})
  return output


def sanitize_signup_action_diagnostics(response_body, server_logs):
  result = {'error': classify_oidc_action_error(response_body),
      'exceptions': [], 'frames': [], 'stack_frames': [], 'server_error_categories': []}
  exception_pattern = re.compile(r'(?:Caused by: )?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:Exception|Error))(?::|$)')
  frame_pattern = re.compile(r'^\s*at ([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\(([^:()]+):(\d+)\)$')
  for line in server_logs.splitlines():
    exception = exception_pattern.search(line)
    if exception:
      name = exception.group(1).rsplit('.', 1)[-1]
      if name not in result['exceptions'] and len(result['exceptions']) < 20:
        result['exceptions'].append(name)
    frame = frame_pattern.match(line)
    if frame:
      qualified = frame.group(1)
      package = qualified.rpartition('.')[0]
      allowed = package.startswith(('org.keycloak.', 'org.decentwallet.keycloak.wallet',
          'org.jboss.', 'jakarta.', 'java.', 'io.quarkus.'))
      if allowed and qualified not in result['frames'] and len(result['frames']) < 100:
        result['frames'].append(qualified)
        result['stack_frames'].append({'method': qualified, 'line': int(frame.group(3))})
  folded = response_body.casefold()
  category_markers = (
      ('invalid_session_code', ('invalid session code', 'invalid code')),
      ('expired_session_code', ('expired session code', 'code expired')),
      ('invalid_redirect_uri', ('invalid redirect uri', 'redirect uri is invalid')),
  )
  for category, markers in category_markers:
    if any(marker in folded for marker in markers):
      result['server_error_categories'].append(category)
  return result


def signup_profile_submission(html_body, idp_origin, realm, profile_values):
  match = re.search(r'<form\b([^>]*)>(.*?)</form>', html_body, re.I | re.S)
  if match is None:
    raise ValueError('signup profile form is missing')
  attrs, contents = match.groups()
  method = re.search(r'\bmethod=["\']([^"\']+)["\']', attrs, re.I)
  action = re.search(r'\baction=["\']([^"\']+)["\']', attrs, re.I)
  if method is None or method.group(1).lower() != 'post' or action is None:
    raise ValueError('signup profile form is not a POST action')
  url = urllib.parse.urljoin(idp_origin.rstrip('/') + '/', html.unescape(action.group(1)))
  parsed = urllib.parse.urlsplit(url)
  expected = urllib.parse.urlsplit(idp_origin)
  expected_path = f"{expected.path.rstrip('/')}/realms/{realm}/login-actions/required-action"
  if (parsed.scheme != 'https' or parsed.netloc != expected.netloc or parsed.path != expected_path
      or parsed.fragment or parsed.username is not None or parsed.password is not None):
    raise ValueError('signup profile action origin or path is invalid')
  query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
  required_query = {'session_code', 'execution', 'client_id', 'tab_id', 'client_data'}
  if any(len(query.get(name, [])) != 1 or not query[name][0] for name in required_query):
    raise ValueError('signup profile Keycloak parameters are invalid')
  names = set(re.findall(r'<input\b[^>]*\bname=["\']([^"\']+)["\']', contents, re.I))
  if not names.issubset(set(profile_values) | {'stateChecker'}) or not set(profile_values).issubset(names):
    raise ValueError('signup profile fields do not match the local profile allowlist')
  fields = {}
  for name in re.findall(r'<input\b([^>]*)>', contents, re.I | re.S):
    field_name = re.search(r'\bname=["\']([^"\']+)["\']', name, re.I)
    field_value = re.search(r'\bvalue=["\']([^"\']*)["\']', name, re.I)
    if field_name is not None and field_name.group(1) == 'stateChecker' and field_value:
      fields['stateChecker'] = html.unescape(field_value.group(1))
  fields.update(profile_values)
  return url, urllib.parse.urlencode(fields).encode('utf-8')


def signup_contact_email(identity_id):
  digest = hashlib.sha256(identity_id.encode('utf-8')).hexdigest()[:32]
  return f'wallet-{digest}@example.com'


def sanitize_signup_callback_response(status, headers, body, server_logs=""):
  content_type = headers.get('Content-Type', '').split(';', 1)[0].strip().lower() or 'unknown'
  location = headers.get('Location', '')
  parsed_location = urllib.parse.urlsplit(location)
  forms = []
  for match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', body, re.I | re.S):
    attrs, content = match.groups()
    action_match = re.search(r'\baction=["\']([^"\']*)["\']', attrs, re.I)
    method_match = re.search(r'\bmethod=["\']([^"\']*)["\']', attrs, re.I)
    action = urllib.parse.urlsplit(html.unescape(action_match.group(1))) if action_match else None
    fields = []
    for input_match in re.finditer(r'<input\b([^>]*)>', content, re.I | re.S):
      input_attrs = input_match.group(1)
      name_match = re.search(r'\bname=["\']([^"\']+)["\']', input_attrs, re.I)
      if name_match is None:
        continue
      field_name = name_match.group(1)
      invalid_match = re.search(r'\baria-invalid=["\']([^"\']*)["\']', input_attrs, re.I)
      fields.append({'name': field_name,
          'invalid': invalid_match is not None and invalid_match.group(1).lower() == 'true'})
    forms.append({'method': method_match.group(1).upper() if method_match else 'GET',
        'action_path': action.path if action else '',
        'query_names': sorted(set(urllib.parse.parse_qs(action.query).keys()))[:32] if action else [],
        'input_fields': fields[:32]})
  field_errors = []
  for field in ('email', 'firstName', 'lastName'):
    candidates = re.findall(rf'<[^>]*\bid=["\'](?:input-error-|error-){field}["\'][^>]*>(.*?)</[^>]+>',
        body, re.I | re.S)
    text = ' '.join(re.sub(r'<[^>]+>', ' ', html.unescape(value)) for value in candidates).lower()
    if text:
      category = ('required' if 'required' in text else
          'duplicate' if 'already' in text or 'exists' in text else
          'invalid' if 'invalid' in text or 'valid' in text or 'format' in text else 'other')
      field_errors.append({'field': field, 'category': category})
  diagnostics = sanitize_signup_action_diagnostics(body, server_logs)
  diagnostics.update({'status': int(status), 'content_type': content_type,
      'location_path': parsed_location.path,
      'location_query_names': sorted(set(urllib.parse.parse_qs(parsed_location.query).keys()))[:32],
      'forms': forms[:8], 'field_errors': field_errors})
  return diagnostics



def signup_callback_from_status(status_body, idp_origin, realm):
  if not isinstance(status_body, dict) or status_body.get('status') != 'accepted':
    raise ValueError('signup status is not accepted')
  callback = status_body.get('callback')
  if status_body.get('status') == 'accepted' and callback is None:
    return None
  if not isinstance(callback, str) or not callback:
    raise ValueError('signup callback is missing')
  parsed = urllib.parse.urlsplit(callback)
  expected = urllib.parse.urlsplit(idp_origin)
  expected_path = f"{expected.path.rstrip('/')}/realms/{realm}/login-actions/authenticate"
  query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
  if (parsed.scheme != 'https' or parsed.netloc != expected.netloc
      or parsed.path != expected_path or parsed.fragment or parsed.username is not None
      or parsed.password is not None):
    raise ValueError('signup callback origin or path is invalid')
  required = {'session_code', 'execution', 'client_id', 'tab_id', 'client_data'}
  if set(query) < required or any(len(query.get(name, [])) != 1 or not query[name][0] for name in required):
    raise ValueError('signup callback Keycloak fields are invalid')
  return callback


def signup_callback_submission(status_body, idp_origin, realm):
  callback = signup_callback_from_status(status_body, idp_origin, realm)
  if callback is None:
    raise ValueError('signup callback is missing')
  parsed = urllib.parse.urlsplit(callback)
  path = parsed.path + '?' + parsed.query
  return 'GET', path, b''


def signup_action_path(action, base_url):
  return urllib.parse.urljoin(base_url.rstrip('/') + '/', html.unescape(action))


def signup_resume_action_path(action, base_url, realm):
  status = {'status': 'accepted', 'callback': action}
  _, path, _ = signup_callback_submission(status, base_url, realm)
  return urllib.parse.urljoin(base_url.rstrip('/') + '/', path)


def signup_form_action(html_body, idp_origin, realm, required_action=False, profile_values=None):
  match = re.search(r'<form([^>]*)>(.*?)</form>', html_body, re.I | re.S)
  if match is None:
    raise ValueError('signup form is missing')
  attrs, contents = match.groups()
  method_match = re.search(r'method="([^"]+)"', attrs, re.I)
  action_match = re.search(r'action="([^"]+)"', attrs, re.I)
  if method_match is None or method_match.group(1).lower() != 'post' or action_match is None:
    raise ValueError('signup form is not a POST action')
  url = urllib.parse.urljoin(idp_origin.rstrip('/') + '/', html.unescape(action_match.group(1)))
  parsed = urllib.parse.urlsplit(url)
  expected = urllib.parse.urlsplit(idp_origin)
  action_name = 'required-action' if required_action else 'authenticate'
  expected_path = f"{expected.path.rstrip('/')}/realms/{realm}/login-actions/{action_name}"
  query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
  required = {'session_code', 'execution', 'client_id', 'tab_id', 'client_data'}
  if (parsed.scheme != 'https' or parsed.netloc != expected.netloc or parsed.path != expected_path
      or parsed.fragment or parsed.username is not None or parsed.password is not None
      or not required.issubset(query)
      or any(len(query.get(name, [])) != 1 or not query[name][0] for name in required)):
    raise ValueError('signup form action is not a valid Keycloak action URL')
  allowed = {'email', 'firstName', 'lastName', 'stateChecker'} if required_action else {'wallet_intent'}
  fields = {}
  for attrs in re.findall(r'<input([^>]*)>', contents, re.I | re.S):
    name_match = re.search(r'name="([^"]+)"', attrs, re.I)
    value_match = re.search(r'value="([^"]*)"', attrs, re.I)
    if name_match is None:
      continue
    name = name_match.group(1)
    if name not in allowed:
      raise ValueError('signup form contains unsupported fields')
    if name == 'wallet_intent':
      if value_match is None or html.unescape(value_match.group(1)) != 'signup':
        raise ValueError('signup intent form value is invalid')
      fields[name] = 'signup'
    elif name == 'stateChecker' and value_match is not None:
      fields[name] = html.unescape(value_match.group(1))
  if required_action:
    if profile_values is None:
      raise ValueError('signup profile fields are incomplete')
    fields.update(profile_values)
  elif fields.get('wallet_intent') != 'signup':
    raise ValueError('signup intent form field missing')
  return parsed.path + '?' + parsed.query, urllib.parse.urlencode(fields).encode('utf-8')



def signup_wallet_flow(client, key, identifier, container, admin_client, progress, image):
  verifier = b64url(secrets.token_bytes(32))
  code_challenge = b64url(hashlib.sha256(verifier.encode('ascii')).digest())
  state = b64url(secrets.token_bytes(24))
  nonce = b64url(secrets.token_bytes(24))
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': state, 'nonce': nonce,
      'code_challenge': code_challenge, 'code_challenge_method': 'S256',
  })
  status, _, page = client.request('GET', f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(status == 200, 'signup login page', status)
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser(); parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'login wallet page locator before signup choice')
  action_match = re.search(r'<form method="post" action="([^"]+)"[^>]*>\s*<input type="hidden" name="wallet_intent" value="signup"', text)
  require(action_match is not None, 'wallet signup choice posts explicit intent to Keycloak execution')
  if action_match is None:
    raise RuntimeError('acceptance probe failed at wallet signup action')
  action_url = signup_action_path(action_match.group(1), f'https://idp.example:{KC_PORT}/auth/')
  parsed_action = urllib.parse.urlsplit(action_url)
  action_path = parsed_action.path + ('?' + parsed_action.query if parsed_action.query else '')
  action_data = urllib.parse.urlencode({'wallet_intent': 'signup'}).encode()
  auth_cookie = ''
  if hasattr(client, 'opener') and hasattr(client, 'forward_headers'):
    auth_cookie = '; '.join(c.name + '=' + str(c.value or '') for handler in client.opener.handlers
        if isinstance(handler, urllib.request.HTTPCookieProcessor) for c in handler.cookiejar
        if urllib.parse.urlsplit(client.url(action_path)).path.startswith(c.path))
  print('signup-route-form-shape:', json.dumps({
      'action_path': urllib.parse.urlsplit(action_path).path,
      'query_names': sorted(urllib.parse.parse_qs(parsed_action.query).keys()),
      'has_session_cookie': bool(auth_cookie), 'cookie_count': len(auth_cookie.split(';')) if auth_cookie else 0}))
  action_status, action_response_headers, signup_page = client.request('POST', action_path, action_data,
      {'Content-Type': 'application/x-www-form-urlencoded'})
  if action_status != 200:
    logs = run(['podman', 'logs', '--tail', '100', container], timeout=15)
    print('signup-action-diagnostics:', json.dumps(
        sanitize_signup_action_diagnostics(signup_page, logs.stdout), sort_keys=True))
  progress('intent', {'signup_intent_action_http': action_status})
  require(action_status == 200, 'Keycloak action records signup intent and restarts wallet flow', action_status)
  signup_text = signup_page.decode('utf-8', errors='strict')
  require('Creating a new account with this wallet identity.' in signup_text,
      'fresh wallet transaction is bound to signup intent')
  parser = LoginPageParser(); parser.feed(signup_text)
  signup_locator = ''.join(parser.locator_parts).strip()
  status_url = re.search(r'const statusUrl = "([^"]+)";', signup_text)
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', signup_text)
  require(status_url is not None and csrf is not None, 'signup transaction browser binding')
  if status_url is None or csrf is None:
    raise RuntimeError('acceptance probe failed at signup transaction binding')
  wallet = Client()
  challenge_status, _, challenge_raw = wallet.request('GET', signup_locator)
  require(challenge_status == 200, 'signup native challenge GET')
  envelope = json.loads(challenge_raw)
  signing_input = json.dumps({'challenge': envelope['challenge'], 'identity_id': identifier,
      'profile': envelope['profile']}, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
  with tempfile.TemporaryDirectory(prefix='wallet-signing-', dir=key.parent) as signing_dir:
    payload = write_private_signing_input(signing_dir, 'signup', signing_input)
    try:
      signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(payload)],
          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    finally:
      payload.unlink(missing_ok=True)
  require(signature.returncode == 0 and len(signature.stdout) == 64, 'signup Ed25519 proof signed')
  proof = json.dumps({'profile': envelope['profile'], 'challenge': envelope['challenge'],
      'identity_id': identifier, 'signature': b64url(signature.stdout)}, separators=(',', ':')).encode()
  admin = admin_token(admin_client, AdminPassword(admin_client.privateClientAdminCredential))
  exact_users_before_proof = json.loads(admin_call(admin_client, admin, 'GET',
      f'/auth/admin/realms/{REALM}/users?q=decent_identity_id:{urllib.parse.quote(identifier)}&max=10')[2])
  existing_exact_users = [user for user in exact_users_before_proof
      if user.get('attributes', {}).get('decent_identity_id') == [identifier]]
  require(not existing_exact_users, 'no exact Keycloak account exists before signup proof')
  proof_status, _, _ = wallet.request('POST', signup_locator, proof, {'Content-Type': 'application/json'})
  progress('proof', {'signup_proof_http': proof_status})
  require(proof_status == 202, 'signup proof provisions exact account before pending consume', proof_status)
  exact_users = json.loads(admin_call(admin_client, admin, 'GET',
      f'/auth/admin/realms/{REALM}/users?q=decent_identity_id:{urllib.parse.quote(identifier)}&max=10')[2])
  matched = [user for user in exact_users
      if user.get('attributes', {}).get('decent_identity_id') == [identifier]]
  progress('account', {'exact_mapped_users': len(matched)})
  require(len(matched) == 1 and matched[0].get('enabled'),
      'signup provisioned exactly one enabled account with exact identity before consume')
  browser_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  polled, _, polled_raw = client.request('GET', status_url.group(1), headers=browser_headers)
  require(polled == 200, 'signup initiating browser observes bound acceptance', polled)
  status_body = json.loads(polled_raw)
  require(status_body.get('status') == 'accepted',
      'signup browser acceptance is bound to the initiating session')
  status_callback = signup_callback_from_status(status_body,
      f'https://idp.example:{KC_PORT}/auth', REALM)
  if status_callback is None:
    raise RuntimeError('signup acceptance lacks callback URL')
  callback_method, callback_path, callback_data = signup_callback_submission(
      status_body, f'https://idp.example:{KC_PORT}/auth', REALM)
  callback_status, headers, callback_body = client.request(callback_method, callback_path,
      callback_data, {'Content-Type': 'application/x-www-form-urlencoded'})
  if callback_status == 200:
    callback_html = callback_body.decode('utf-8', errors='replace')
    profile_values = {'email': signup_contact_email(identifier),
        'firstName': 'Wallet', 'lastName': 'Account'}
    profile_path, profile_data = signup_form_action(callback_html,
        f'https://idp.example:{KC_PORT}/auth', REALM, True, profile_values)
    callback_status, headers, callback_body = client.request('POST', profile_path, profile_data,
        {'Content-Type': 'application/x-www-form-urlencoded'})
  callback_html = callback_body.decode('utf-8', errors='replace')
  debug_logs = None
  if callback_status == 400:
    debug_logs = run(['podman', 'logs', '--tail', '100', container], timeout=15)
    safe_response = sanitize_signup_action_diagnostics(callback_html, debug_logs.stdout)
    print('signup-callback-error-diagnostics:', json.dumps(safe_response, sort_keys=True))
    admin_password = AdminPassword(admin_client.privateClientAdminCredential)
    safe_token = admin_token(admin_client, admin_password)
    safe_events = recent_login_error_categories(admin_client, safe_token)
    print('signup-keycloak-event-categories:', json.dumps(safe_events, sort_keys=True))
  diagnostics = sanitize_signup_callback_response(callback_status, headers, callback_html,
      debug_logs.stdout if debug_logs is not None else '')
  location = headers.get('Location', '')
  code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get('code', [None])[0]
  if callback_status not in (302, 303) or not code:
    logs = run(['podman', 'logs', '--tail', '140', container], timeout=15)
    print('signup-callback-diagnostics:', json.dumps({
        key: value for key, value in sanitize_signup_callback_response(callback_status, headers,
            callback_body.decode('utf-8', errors='replace'), logs.stdout).items()
        if key in ('error', 'exceptions', 'frames', 'stack_frames', 'server_error_categories',
            'status', 'content_type', 'location_path', 'forms', 'field_errors')}, sort_keys=True))
  progress('callback', {'callback_http': callback_status})
  require(callback_status in (302, 303) and code,
      'callback, OIDC state, and no-code replay', callback_status)
  location_query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
  require(location_query.get('state') == [state], 'signup callback preserves OIDC state')
  replay_status, replay_headers, _ = client.request('GET', status_callback)
  replay_location = urllib.parse.urlsplit(replay_headers.get('Location', ''))
  replay_query = urllib.parse.parse_qs(replay_location.query)
  require(replay_status == 302 and replay_location.path == urllib.parse.urlsplit(REDIRECT).path
      and replay_query.get('state') == [state] and replay_query.get('error')
      and 'code' not in replay_query,
      'signup callback replay returns no second authorization code')
  token_status, _, token_raw = client.request('POST', f'/auth/realms/{REALM}/protocol/openid-connect/token',
      urllib.parse.urlencode({'grant_type':'authorization_code','client_id':CLIENT,'code':code,
          'redirect_uri':REDIRECT,'code_verifier':verifier}).encode(),
      {'Content-Type':'application/x-www-form-urlencoded'})
  progress('token', {'pkce_token_http': token_status})
  require(token_status == 200, 'signup authorization code exchanges with PKCE', token_status)
  claims = verify_id_token(client, json.loads(token_raw)['id_token'], key.parent)
  require(claims.get('sub') == matched[0].get('id'), 'signup returns created opaque Keycloak subject')
  require(claims.get('decent_identity_id') == identifier,
      'signup ID token contains exact signed wallet Identity claim')
  return {'signup_intent_action_http': action_status, 'signup_proof_http': proof_status,
      'exact_mapped_users': len(matched), 'pkce_token_http': token_status}


def classify_provider_identity_outcome(provider_http):
  """Classify only the provider request status; a separate CLI miss is not authority."""
  if provider_http == 503:
    return 'unavailable'
  if provider_http == 401:
    return 'provider_denied_unclassified'
  return 'unexpected_status'


def missing_identity_flow(container, wrapper, resolver_port, bootstrap, image):
  browser = Client()
  verifier = b64url(secrets.token_bytes(32))
  code_challenge = b64url(hashlib.sha256(verifier.encode('ascii')).digest())
  state = b64url(secrets.token_bytes(24))
  nonce = b64url(secrets.token_bytes(24))
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': state, 'nonce': nonce,
      'code_challenge': code_challenge, 'code_challenge_method': 'S256',
  })
  status, _, page = browser.request('GET', f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(status == 200, 'missing-Identity browser login page', status)
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'missing-Identity transaction locator')
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', text)
  status_url = re.search(r'const statusUrl = "([^"]+)";', text)
  assert csrf is not None and status_url is not None
  missing_id = 'wallet-login-unpublished-' + uuid.uuid4().hex + '@example.invalid'
  direct_lookup_id = 'wallet-login-unpublished-direct-' + uuid.uuid4().hex + '@example.invalid'
  lookup_started = time.monotonic()
  registry_lookup = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
      ['get', '--identifier', direct_lookup_id,
      '--host', '127.0.0.1', '--port', str(resolver_port), '--bootstrap', bootstrap], timeout=20, image=image)
  lookup_ms = int((time.monotonic() - lookup_started) * 1000)
  resolution_category, result_categories = classify_identity_lookup(
      registry_lookup.stdout, registry_lookup.returncode, direct_lookup_id)
  safe_lines = ['object' for category in result_categories if category == 'json']
  if resolution_category == 'not_found' and result_categories[-1:] == ['not_found']:
    safe_lines.append('terminal-not-found')
  # Start a separate transaction for the production provider path; its resolver
  # admission cooldown is per browser/client, so reusing one handle after a
  # direct lookup would return 429 without exercising Registry resolution.
  provider_browser = Client()
  provider_query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(secrets.token_bytes(32)).digest()),
      'code_challenge_method': 'S256',
  })
  provider_status, _, provider_page = provider_browser.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{provider_query}')
  require(provider_status == 200, 'fresh provider unknown-Identity login page')
  provider_parser = LoginPageParser()
  provider_parser.feed(provider_page.decode('utf-8', errors='strict'))
  provider_locator = ''.join(provider_parser.locator_parts).strip()
  require(provider_locator.startswith(
      f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'fresh provider unknown-Identity transaction locator')
  provider_status_url = re.search(r'const statusUrl = "([^"]+)";', provider_page.decode('utf-8'))
  provider_csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', provider_page.decode('utf-8'))
  require(provider_status_url is not None and provider_csrf is not None,
      'fresh provider browser status binding')
  if provider_status_url is None or provider_csrf is None:
    raise RuntimeError('acceptance probe failed at fresh provider browser status binding')
  provider_status_url_value = provider_status_url.group(1)
  provider_csrf_value = provider_csrf.group(1)
  provider_wallet = Client()
  challenge_status, _, challenge_raw = provider_wallet.request('GET', provider_locator)
  require(challenge_status == 200, 'fresh provider unknown-Identity challenge GET')
  challenge_envelope = json.loads(challenge_raw)
  provider_proof = json.dumps({
      'profile': challenge_envelope['profile'], 'challenge': challenge_envelope['challenge'],
      'identity_id': direct_lookup_id, 'signature': b64url(bytes(64)),
  }, separators=(',', ':')).encode('utf-8')
  provider_started = time.monotonic()
  direct_http, _, _ = provider_wallet.request('POST', provider_locator, provider_proof,
      {'Content-Type': 'application/json'})
  direct_provider_ms = int((time.monotonic() - provider_started) * 1000)
  provider_resolution_outcome = classify_provider_identity_outcome(direct_http)
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': provider_csrf_value}
  status_poll, _, status_raw = provider_browser.request('GET', provider_status_url_value,
      headers=status_headers)
  require(status_poll == 200 and json.loads(status_raw) == {'status': 'pending'},
      'unknown identity produced no accepted receipt or callback')
  return {'cli_resolution': resolution_category, 'cli_exit': registry_lookup.returncode,
      'cli_output_categories': result_categories, 'cli_output_shape': safe_lines,
      'cli_lookup_ms': lookup_ms, 'provider_resolution_outcome': provider_resolution_outcome,
      'direct_provider_http': direct_http,
      'direct_provider_lookup_ms': direct_provider_ms,
      'no_acceptance_or_callback': True}


def main():
  global IMAGE
  IMAGE, image_digest = resolve_immutable_image(IMAGE)
  runtime_provenance = _prepare_resolver_runtime()
  runtime_provenance['image_digest'] = image_digest
  container = f'wallet-login-live-e2e-{os.getpid()}'
  password = secrets.token_urlsafe(32)
  registry = None
  resolver_tools = None
  try:
    with tempfile.TemporaryDirectory(prefix='wallet-login-e2e-',
        dir=SCRATCH) as temp_dir:
      evidence_path = Path(temp_dir) / 'live-evidence.json'
      result = {'resolver_runtime': runtime_provenance}
      def checkpoint():
        evidence_path.write_text(
            json.dumps(sanitize_live_checkpoint(result), sort_keys=True), encoding='utf-8')
      def latest_resolver_diagnostics():
        if resolver_tools is None:
          return {'resolver_runtime': runtime_provenance,
              'rotated_identity_case': {'stage': 'probe_not_started'}}
        return {'resolver_runtime': runtime_provenance,
            'rotated_identity_case': {'stage': 'diagnostic_probe',
                'diagnostic_categories': record_resolver_diagnostics(container)}}
      temp = Path(temp_dir)
      with report_partial_evidence_on_failure(evidence_path, latest_resolver_diagnostics):
        resolver_tools = start_resolver_tools(temp, IMAGE)
        os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = resolver_tools
        registry, bootstrap, registry_port = start_registry(temp, IMAGE)
        os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = resolver_tools
        resolver_port = free_port()
        key, wrapper, identifier = write_identity(temp, bootstrap, IMAGE)
        unmapped_key, wrapper, unmapped_identifier = write_identity(
            temp, bootstrap, IMAGE, label='wallet-login-unmapped')
        replay_key, _, replay_identifier = write_identity(
            temp, bootstrap, IMAGE, label='wallet-login-replay')
        client = start_keycloak(container, password, wrapper, resolver_port, bootstrap, IMAGE)
        client.privateClientAdminCredential = password
        token = admin_token(client, password)
        configure_realm(client, token, identifier, resolver_port, wrapper, bootstrap)
        enable_keycloak_login_events(client, token)
        provision_identity_attribute(client, token, 'wallet-owner-duplicate', replay_identifier)
        probe = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
            ['get', '--identifier', identifier,
            '--host', '127.0.0.1', '--port', str(resolver_port), '--bootstrap', bootstrap], timeout=20, image=IMAGE)
        require(probe.returncode == 0, 'sanitized container Identity CLI lookup')
        auth_browser = Client()
        result['wallet_login'] = auth_flow(auth_browser, key, identifier, container, IMAGE)
        checkpoint()
        result['browser_preflight'] = browser_preflight_flow(IMAGE)
        checkpoint()
        result['negative_case'] = negative_proof_flow(identifier, IMAGE)
        checkpoint()
        result['negative_case']['invalid_proof_throttle'] = invalid_proof_throttle_flow(IMAGE)
        checkpoint()
        unmapped_status, _, _ = admin_call(client, token, 'POST', f'/auth/admin/realms/{REALM}/users', {
            'username': 'wallet-unmapped-fixture', 'enabled': True,
        }, expected=(201,))
        require(unmapped_status == 201, 'create pre-provisioned user without wallet Identity mapping')
        provision_identity_attribute(client, token, 'wallet-unmapped-fixture', replay_identifier)
        unmapped_result = account_mapping_denial_flow(
            client, unmapped_key, unmapped_identifier, 'unmapped-account',
            container, resolver_port, bootstrap, wrapper.name, IMAGE)
        result['unmapped_account_case'] = unmapped_account_case_evidence(unmapped_result)
        checkpoint()
        require(account_policy_denial_is_attributed(result['unmapped_account_case']),
            'unmapped account denial has fresh provider policy evidence',
            result['unmapped_account_case'].get('outcome'))

        rotated_old_key, rotated_wrapper, rotated_identifier = write_identity(
            temp, bootstrap, IMAGE, label='wallet-login-rotated')
        rotated_key = generate_owner_key(temp, 'wallet-login-rotated-successor', IMAGE)
        rotation_progress = lambda stage, fields: checkpoint_rotation_stage(
            result, stage, fields, checkpoint)
        rotated_status, _, _ = admin_call(client, token, 'POST', f'/auth/admin/realms/{REALM}/users', {
            'username': 'wallet-rotated-owner', 'enabled': True,
            'attributes': {'decent_identity_id': [rotated_identifier]},
        }, expected=(201,))
        require(rotated_status == 201, 'preprovision rotated-Identity local mapping')
        provision_identity_attribute(client, token, 'wallet-rotated-owner', rotated_identifier)
        replay_status, _, _ = admin_call(client, token, 'POST', f'/auth/admin/realms/{REALM}/users', {
            'username': 'wallet-replay-owner', 'enabled': True,
            'attributes': {'decent_identity_id': [replay_identifier]},
        }, expected=(201,))
        require(replay_status == 201, 'replay owner account was provisioned exactly once')
        replay_users = json.loads(admin_call(client, token, 'GET',
            f'/auth/admin/realms/{REALM}/users?username=wallet-replay-owner&exact=true')[2])
        require(len(replay_users) == 1, 'replay owner fixture exists exactly once')
        replay_user = replay_users[0]
        replay_user['attributes'] = {'decent_identity_id': [replay_identifier]}
        replay_status, _, _ = admin_call(client, token, 'PUT',
            f'/auth/admin/realms/{REALM}/users/{replay_user["id"]}', replay_user, expected=(204,))
        require(replay_status == 204, 'set replay owner Identity mapping')
        duplicate_users = json.loads(admin_call(client, token, 'GET',
            f'/auth/admin/realms/{REALM}/users?username=wallet-owner-duplicate&exact=true')[2])
        require(len(duplicate_users) == 1, 'duplicate fixture account exists exactly once')
        duplicate_user = duplicate_users[0]
        duplicate_user['attributes'] = {'decent_identity_id': [replay_identifier]}
        duplicate_status, _, _ = admin_call(client, token, 'PUT',
            f'/auth/admin/realms/{REALM}/users/{duplicate_user["id"]}', duplicate_user, expected=(204,))
        require(duplicate_status == 204, 'reset duplicate account to same Registry Identity')
        disabled_key, _, disabled_identifier = write_identity(
            temp, bootstrap, IMAGE, label='wallet-login-disabled')
        disabled_status, _, _ = admin_call(client, token, 'POST', f'/auth/admin/realms/{REALM}/users', {
            'username': 'wallet-disabled-fixture', 'enabled': True,
        }, expected=(201,))
        require(disabled_status == 201, 'create distinct disabled-account fixture')
        provision_identity_attribute(client, token, 'wallet-disabled-fixture', disabled_identifier)
        disabled_users = json.loads(admin_call(client, token, 'GET',
            f'/auth/admin/realms/{REALM}/users?username=wallet-disabled-fixture&exact=true')[2])
        require(len(disabled_users) == 1, 'disabled account fixture is unique')
        disabled_user = disabled_users[0]
        disabled_user['enabled'] = False
        admin_call(client, token, 'PUT',
            f'/auth/admin/realms/{REALM}/users/{disabled_user["id"]}', disabled_user,
            expected=(204,))
        verified_disabled_user = json.loads(admin_call(client, token, 'GET',
            f'/auth/admin/realms/{REALM}/users/{disabled_user["id"]}')[2])
        require(verified_disabled_user.get('enabled') is False
            and verified_disabled_user.get('attributes', {}).get('decent_identity_id') == [disabled_identifier],
            'distinct disabled account has exact Registry Identity mapping and disabled status')
        disabled_result = account_mapping_denial_flow(
            client, disabled_key, disabled_identifier, 'disabled-account',
            container, resolver_port, bootstrap, wrapper.name, IMAGE)
        result['disabled_account_case'] = disabled_result
        checkpoint()
        require(account_policy_denial_is_attributed(disabled_result),
            'disabled mapped account denial has fresh provider policy evidence',
            disabled_result.get('outcome'))
        signup_key, _, signup_identifier = write_identity(
            temp, bootstrap, IMAGE, label='wallet-login-signup')
        signup_browser = Client()
        signup_result = signup_wallet_flow(signup_browser, signup_key, signup_identifier,
            container, client, lambda stage, fields: checkpoint_signup_stage(result, stage, fields, checkpoint), IMAGE)
        result['signup_case'] = {'stage': 'complete', **signup_result}
        checkpoint()
        rotation_result = stale_key_rotation_flow(
            client, rotated_old_key, rotated_key, rotated_identifier, container,
            resolver_port, bootstrap, rotated_wrapper.name, rotation_progress, IMAGE, temp)
        token = admin_token(client, AdminPassword(password))
        rotated_user = json.loads(admin_call(client, token, 'GET',
            f'/auth/admin/realms/{REALM}/users?username=wallet-rotated-owner&exact=true')[2])
        local_mapping_persisted = (len(rotated_user) == 1
            and rotated_user[0].get('attributes', {}).get('decent_identity_id') == [rotated_identifier])
        rotation_progress('mapping', {'local_mapping_persisted': local_mapping_persisted})
        require(local_mapping_persisted, 'rotated account Identity mapping persisted exactly')
        result['rotated_identity_case'] = {
            **result.get('rotated_identity_case', {}), 'stage': 'complete', **rotation_result,
            'local_mapping_persisted': True}
        checkpoint()
        provision_identity_attribute(client, token, 'wallet-owner-duplicate', identifier)
        ambiguity_result = account_mapping_denial_flow(
            client, key, identifier, 'ambiguous-account', container,
            resolver_port, bootstrap, wrapper.name, IMAGE)
        require(account_policy_denial_is_attributed(ambiguity_result),
            'ambiguous account denial has fresh provider policy evidence',
            ambiguity_result.get('outcome'))
        result['ambiguous_account_case'] = ambiguity_result
        checkpoint()
        result['missing_identity_case'] = missing_identity_flow(container, wrapper, resolver_port, bootstrap, IMAGE)
        checkpoint()
        print('E2E_SCENARIOS_COMPLETE: inspect per-case outcomes; overall provider qualification remains limited')
        runtime_provenance['diagnostic_categories'] = capture_live_resolver_diagnostics(
            container, result, checkpoint)
        print('evidence=', json.dumps(sanitize_live_checkpoint(result), sort_keys=True))
  finally:
    run(['podman', 'rm', '--force', container], timeout=25)
    stop_registry(registry, f'wallet-login-registry-{os.getpid()}')
    stop_resolver_tools(resolver_tools)


if __name__ == '__main__':
  main()
