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
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
import issue7_store_recovery


PROJECT_DIR = Path(__file__).resolve().parents[1]
SCRATCH = os.environ.get('TMPDIR', str(Path.home() / '.hermes/cache/scratch'))
RESOLVER_WRAPPER = '/opt/decent-resolver/bin/decent-identity'
ISSUE7_USER_READBACK_PROFILE = 'issue7-user-readback-empty'
ISSUE7_USER_READBACK_OVERCAP_PROFILE = 'issue7-user-readback-overcap'
ISSUE7_USER_READBACK_THROW_PROFILE = 'issue7-user-readback-throw'
ISSUE7_USER_READBACK_FAULT_MODES = {
    ISSUE7_USER_READBACK_PROFILE: 'empty',
    ISSUE7_USER_READBACK_OVERCAP_PROFILE: 'over-cap',
    ISSUE7_USER_READBACK_THROW_PROFILE: 'throw',
}
SUPPORTED_LIVE_PROFILES = {
    'default', 'expiry', 'provider-not-found-diagnostic',
    'issue6-single-node', 'issue6-auth-flow', 'issue7-signup-success',
    'issue6-postconsume-receipt-failure', 'issue6-postconsume-callback-gate-failure',
    *ISSUE7_USER_READBACK_FAULT_MODES,
    *issue7_store_recovery.PROFILES,
}


def selected_live_profile():
  profile = os.environ.get('WALLET_IT_PROFILE', 'default')
  if profile not in SUPPORTED_LIVE_PROFILES:
    raise ValueError('unsupported WALLET_IT_PROFILE value; supported values: '
        + ', '.join(sorted(SUPPORTED_LIVE_PROFILES)))
  return profile


def dispatch_live_profile(profile, handlers):
  """Select exactly one explicitly allowlisted live branch; unknown values fail closed."""
  if profile not in SUPPORTED_LIVE_PROFILES or profile not in handlers:
    raise ValueError('unsupported WALLET_IT_PROFILE value; supported values: '
        + ', '.join(sorted(SUPPORTED_LIVE_PROFILES)))
  return handlers[profile]()


def user_readback_fault_mode(profile):
  try:
    return ISSUE7_USER_READBACK_FAULT_MODES[profile]
  except KeyError as error:
    raise ValueError('profile has no UserProvider fault mode') from error


def add_test_user_readback_fault_args(command, image, mode):
  if mode not in {'empty', 'throw', 'over-cap'}:
    raise ValueError('unsupported UserProvider fault mode')
  command.extend(['--env', 'ISSUE7_USER_READBACK_FAULT_MODE=' + mode, image, 'start-dev'])


def utc_log_cursor():
  return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _bounded_command_tail(args, timeout: float = 15, max_bytes=65536):
  """Drain a child fully while retaining only a strict byte-bounded output tail."""
  if timeout <= 0 or max_bytes < 1:
    raise ValueError('timeout and max_bytes must be positive')
  process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
  if process.stdout is None:
    process.kill()
    process.wait()
    raise RuntimeError('subprocess output pipe is unavailable')
  fd = process.stdout.fileno()
  os.set_blocking(fd, False)
  retained = bytearray()
  deadline = time.monotonic() + timeout
  try:
    while True:
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        raise subprocess.TimeoutExpired(args, timeout)
      readable, _, _ = select.select([fd], [], [], min(remaining, 0.2))
      if readable:
        chunk = os.read(fd, 8192)
        if not chunk:
          break
        retained.extend(chunk)
        if len(retained) > max_bytes:
          del retained[:-max_bytes]
      elif process.poll() is not None:
        break
    return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    return subprocess.CompletedProcess(args, return_code,
        retained.decode('utf-8', errors='replace'))
  except BaseException:
    if process.poll() is None:
      process.kill()
    process.wait()
    raise
  finally:
    process.stdout.close()


def read_provider_fault_log_tail(container_id):
  if not isinstance(container_id, str) or re.fullmatch(r'[0-9a-f]{64}', container_id) is None:
    raise ValueError('container ID is invalid')
  logs = _bounded_command_tail(['podman', 'logs', '--tail', '160', container_id])
  return logs.stdout if logs.returncode == 0 else ''


def read_provider_fault_log_window(container_id, cursor, *, strict=False):
  """Read a bounded per-run log window; do not serialize raw lines or identifiers."""
  if not isinstance(container_id, str) or re.fullmatch(r'[0-9a-f]{64}', container_id) is None:
    raise ValueError('container ID is invalid')
  if not isinstance(cursor, str) or not re.fullmatch(
      r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z', cursor):
    raise ValueError('invalid UTC log cursor')
  logs = _bounded_command_tail(
      ['podman', 'logs', '--since', cursor, '--tail', '160', container_id])
  if logs.returncode != 0:
    if strict:
      raise RuntimeError('provider fault log window unavailable')
    return ''
  return logs.stdout


def sanitize_success_provider_witness(logs, expected_request_id):
  """Return one allowlisted selected-provider ID only for an exact request marker."""
  if (not isinstance(logs, str) or not isinstance(expected_request_id, str)
      or re.fullmatch(r'[0-9a-f]{32}', expected_request_id) is None):
    return None
  pattern = re.compile(r'^[^\r\n]*Wallet proof transaction consumed \(request=([0-9a-f]{32}), provider=(infinispan|jpa|remote|unknown)\)$', re.MULTILINE)
  matches = pattern.findall(logs)
  correlated = [provider for request_id, provider in matches if request_id == expected_request_id]
  if len(matches) != 1 or len(correlated) != 1 or correlated[0] == 'unknown':
    return None
  return correlated[0]


def read_provider_success_log_window(container_id, cursor):
  """Bounded production success-marker log window; preserve no raw output downstream."""
  return read_provider_fault_log_window(container_id, cursor)


def sanitize_user_readback_fault_diagnostics(logs, expected_request_id=None):
  """Project a byte-bounded log window into allowlisted counts and fault-mode enum."""
  if not isinstance(logs, str):
    logs = ''
  factory = 'ISSUE7_USER_READBACK_PROVIDER: factory selected' in logs
  modes = [mode for mode in {'empty', 'throw', 'over-cap'}
      if f'ISSUE7_USER_READBACK_PROVIDER: fault mode={mode}' in logs]
  effective_mode = modes[0] if len(modes) == 1 else None
  fault_count = logs.count('ISSUE7_USER_READBACK_FAULT: post-create exact attribute read intercepted')
  failure_count = 0
  if expected_request_id and re.fullmatch(r'[0-9a-f]{32}', expected_request_id):
    needle = (f'Wallet account mapping lookup unavailable (request={expected_request_id}, '
        'IdentityMappingUnavailableException)')
    failure_count = min(5, logs.count(needle))
  return {'factory_selected': factory,
      'effective_fault_mode': effective_mode,
      'post_create_read_fault_count': min(5, fault_count),
      'correlated_mapping_failure_count': min(5, failure_count)}


def failure_response_has_no_callback_or_code(body, headers, redirects=()):
  if body not in (b'', '') or redirects is None or bool(redirects):
    return False
  normalized = {str(name).lower(): value for name, value in headers.items()}
  return not normalized.get('location') and not any(
      name in {'callback', 'code', 'authorization'} for name in normalized)


def browser_status_is_pending(status, body):
  try:
    data = json.loads(body)
  except (TypeError, ValueError):
    return False
  return (status == 200 and isinstance(data, dict) and data.get('status') == 'pending'
      and not any(key in data for key in ('callback', 'callback_url', 'code', 'authorization_code')))
REQUIRED_SINGLE_USE_OBJECT_PROVIDER_ID = 'infinispan'
ISSUE6_POSTCONSUME_TEST_PROVIDER_ID = 'issue6-postconsume-receipt-failure'
ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID = 'issue6-postconsume-callback-gate-failure'
ISSUE6_TEST_PROVIDER_IDS = frozenset({ISSUE6_POSTCONSUME_TEST_PROVIDER_ID,
    ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID})
EXPIRY_WAIT_MARGIN_SECONDS = 5
EXPIRY_CONTAINER_LIFETIME_SECONDS = 1200
IDENTITY_LOOKUP_COOLDOWN_SECONDS = 2
IDENTITY_LOOKUP_COOLDOWN_MARGIN_SECONDS = 1


def parse_keycloak_show_config(output):
  """Extract only allowlisted Keycloak values, ignoring source annotations."""
  allowed = {'kc.db': 'database_mode_effective', 'kc.cache': 'cache_mode_effective',
      'kc.cache-stack': 'cache_stack_effective',
      'kc.spi-single-use-object--provider-default': 'single_use_object_provider_configured'}
  values = {}
  duplicates = set()
  for line in output.splitlines() if isinstance(output, str) else ():
    match = re.fullmatch(
        r'\s*(kc\.(?:db|cache|cache-stack|spi-single-use-object--provider-default))'
        r'\s*=\s*([A-Za-z0-9_.-]{1,96})'
        r'(?:\s+\([A-Za-z0-9_. -]{1,128}\))?\s*', line)
    if match is None:
      continue
    key, value = match.groups()
    if key in values:
      duplicates.add(key)
    else:
      values[key] = value
  return {result_name: values[key] for key, result_name in allowed.items()
      if key in values and key not in duplicates}


def parse_infinispan_runtime_cache_mode(log_text):
  """Recognize a single applied Keycloak cache configuration with local caches only."""
  marker = 'Infinispan configuration:'
  if not isinstance(log_text, str) or log_text.count(marker) != 1:
    return None
  config = log_text.split(marker, 1)[1]
  local = len(re.findall(r'<local-cache\b', config))
  clustered = sum(len(re.findall(r'<' + tag + r'\b', config))
      for tag in ('distributed-cache', 'replicated-cache', 'invalidation-cache'))
  return 'local' if local > 0 and clustered == 0 else None


def parse_keycloak_runtime_command(arguments):
  """Read explicit database/cache/provider flags from a Podman-inspected argv vector."""
  allowed = {'--db': 'database_mode_configured', '--cache': 'cache_mode_configured',
      '--spi-single-use-object--provider-default': 'single_use_object_provider_configured'}
  values = {}
  duplicates = set()
  for argument in arguments if isinstance(arguments, list) else ():
    if not isinstance(argument, str):
      continue
    key, separator, value = argument.partition('=')
    if key not in allowed or not separator or re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', value) is None:
      continue
    if key in values:
      duplicates.add(key)
    else:
      values[key] = value
  return {result_name: values[key] for key, result_name in allowed.items()
      if key in values and key not in duplicates}


def runtime_baseline_is_verified(facts):
  return (facts.get('keycloak_version') == '26.8.0'
      and facts.get('keycloak_nodes') == 'one')


def wait_for_identity_lookup_cooldown():
  """Let the two-second shared resolver admission key expire before fresh login."""
  time.sleep(IDENTITY_LOOKUP_COOLDOWN_SECONDS + IDENTITY_LOOKUP_COOLDOWN_MARGIN_SECONDS)


def issue6_test_provider_selection_is_verified(log_text, provider_id, request_id):
  """Require one provider witness for the exact pending transaction handle."""
  if provider_id not in ISSUE6_TEST_PROVIDER_IDS or not re.fullmatch(r'[0-9a-f]{32}', request_id):
    return False
  marker = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={provider_id} '
      f'operation=transaction_put_if_absent request={request_id}')
  return isinstance(log_text, str) and log_text.count(marker) == 1


def issue6_postconsume_provider_is_registered(facts):
  provider_ids = facts.get('single_use_object_provider_ids')
  return (isinstance(provider_ids, list)
      and ISSUE6_POSTCONSUME_TEST_PROVIDER_ID in provider_ids)


def runtime_qualification_is_verified(facts):
  provider = facts.get('single_use_object_provider_path')
  configured_database = facts.get('database_mode_configured', 'unavailable')
  configured_cache = facts.get('cache_mode_configured', 'unavailable')
  return (runtime_baseline_is_verified(facts)
      and facts.get('database_mode_effective') == 'dev-file'
      and configured_database in {'unavailable', 'dev-file'}
      and facts.get('cache_mode_effective') == 'local'
      and configured_cache in {'unavailable', 'local'}
      and provider == REQUIRED_SINGLE_USE_OBJECT_PROVIDER_ID
      and provider in facts.get('single_use_object_provider_ids', []))


def keycloak_runtime_provenance(client, token, keycloak_container_id=None):
  """Capture allowlisted server facts; never infer provider selection from availability."""
  facts = {
      'keycloak_version': 'unavailable', 'keycloak_nodes': 'unknown',
      'database_mode_configured': 'unavailable', 'database_mode_effective': 'unavailable',
      'cache_mode_configured': 'unavailable', 'cache_mode_effective': 'unavailable', 'cache_mode_effective_evidence': 'unavailable',
      'cache_stack_effective': None,
      'single_use_object_provider_configured': 'unavailable',
      'single_use_object_provider_path': 'unavailable', 'single_use_object_provider_ids': [],
      'runtime_command_fields_present': [],
      'keycloak_config_read_status': 'container_id_unverified',
      'keycloak_config_fields_present': [],
      'runtime_qualification_status': 'open_runtime_facts_unavailable',
  }
  try:
    status, _, raw = client.request('GET', '/auth/admin/serverinfo',
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}, timeout=5)
    info = json.loads(raw) if status == 200 else {}
    version = info.get('systemInfo', {}).get('version') if isinstance(info, dict) else None
    if isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
      facts['keycloak_version'] = version
    providers = info.get('providers', {}) if isinstance(info, dict) else {}
    single = providers.get('single-use-object', providers.get('singleUseObject')) \
        if isinstance(providers, dict) else None
    configured_providers = single.get('providers') if isinstance(single, dict) else None
    if isinstance(configured_providers, dict):
      facts['single_use_object_provider_ids'] = sorted(provider_id
          for provider_id, details in configured_providers.items()
          if isinstance(provider_id, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', provider_id)
          and isinstance(details, dict))
  except (OSError, ValueError, TypeError, AttributeError, urllib.error.URLError):
    pass
  if isinstance(keycloak_container_id, str) and re.fullmatch(r'[0-9a-f]{64}', keycloak_container_id):
    try:
      inspected = run(['podman', 'inspect', '--format', '{{.Id}}|{{json .Config.Cmd}}',
          keycloak_container_id], timeout=8)
    except subprocess.TimeoutExpired:
      facts['keycloak_config_read_status'] = 'container_inspect_timeout'
    except OSError:
      facts['keycloak_config_read_status'] = 'container_inspect_error'
    else:
      inspected_fields = inspected.stdout.strip().split('|', 1)
      if (inspected.returncode != 0 or len(inspected_fields) != 2
          or inspected_fields[0] != keycloak_container_id):
        facts['keycloak_config_read_status'] = 'container_id_unverified'
      else:
        facts['keycloak_nodes'] = 'one'
        try:
          command_argv = json.loads(inspected_fields[1])
        except (TypeError, ValueError):
          command_argv = None
        command_values = parse_keycloak_runtime_command(command_argv)
        facts.update(command_values)
        facts['runtime_command_fields_present'] = sorted(command_values)
        show_config_args = ['/opt/keycloak/bin/kc.sh', 'show-config']
        for option, field in (('--db', 'database_mode_configured'),
            ('--cache', 'cache_mode_configured'),
            ('--spi-single-use-object--provider-default', 'single_use_object_provider_configured')):
          if field in command_values:
            show_config_args.append(f'{option}={command_values[field]}')
        try:
          shown = run(['podman', 'exec', keycloak_container_id,
              *show_config_args], timeout=8)
        except subprocess.TimeoutExpired:
          facts['keycloak_config_read_status'] = 'show_config_timeout'
        except OSError:
          facts['keycloak_config_read_status'] = 'show_config_error'
        else:
          if shown.returncode != 0:
            facts['keycloak_config_read_status'] = 'show_config_nonzero'
          else:
            parsed = parse_keycloak_show_config(shown.stdout)
            effective_for_configured = {
                'database_mode_effective': 'database_mode_configured',
                'cache_mode_effective': 'cache_mode_configured',
                'single_use_object_provider_configured': 'single_use_object_provider_configured',
            }
            conflicts = {field for field, value in parsed.items()
                if field in effective_for_configured
                and facts[effective_for_configured[field]] != 'unavailable'
                and facts[effective_for_configured[field]] != value}
            for field, value in parsed.items():
              facts[field] = 'unavailable' if field in conflicts else value
              if field == 'cache_mode_effective' and field not in conflicts:
                facts['cache_mode_effective_evidence'] = 'show_config'
            present = sorted(parsed)
            facts['keycloak_config_fields_present'] = present
            required = {'database_mode_effective', 'cache_mode_effective',
                'single_use_object_provider_configured'}
            facts['keycloak_config_read_status'] = (
                'show_config_conflict' if conflicts else
                'show_config_fields_complete' if required.issubset(present)
                else 'show_config_fields_missing')
        try:
          logs = run(['podman', 'logs', keycloak_container_id], timeout=8)
        except (subprocess.TimeoutExpired, OSError):
          pass
        else:
          if logs.returncode == 0:
            observed_cache_mode = parse_infinispan_runtime_cache_mode(subprocess_output_text(logs))
            if observed_cache_mode is not None:
              effective_cache_mode = facts['cache_mode_effective']
              if effective_cache_mode in {'unavailable', observed_cache_mode}:
                facts['cache_mode_effective'] = observed_cache_mode
                facts['cache_mode_effective_evidence'] = 'infinispan_configuration_log'
              else:
                facts['cache_mode_effective'] = 'unavailable'
                facts['cache_mode_effective_evidence'] = 'unavailable'
                facts['keycloak_config_read_status'] = 'runtime_log_conflict'
  facts['runtime_qualification_status'] = ('runtime_facts_verified'
      if runtime_qualification_is_verified(facts)
      else 'open_runtime_facts_unavailable')
  return facts

def configured_transaction_lifetime_seconds():
  store_source = PROJECT_DIR / 'src/main/java/org/decentwallet/keycloak/wallet/WalletLoginTransactionStore.java'
  match = re.search(r'TRANSACTION_LIFESPAN_SECONDS\s*=\s*(\d+)\s*;',
      store_source.read_text(encoding='utf-8'))
  if match is None:
    raise RuntimeError('configured wallet transaction lifetime is unavailable')
  return int(match.group(1))

TRANSACTION_LIFESPAN_SECONDS = configured_transaction_lifetime_seconds()
ACCEPTANCE_PROFILES = {'full', 'expiry', 'issue6-single-node', 'issue6-auth-flow'}


def selected_acceptance_profile(environ=None):
  source = os.environ if environ is None else environ
  profile = source.get('WALLET_IT_PROFILE', 'full')
  if profile not in ACCEPTANCE_PROFILES:
    raise ValueError('WALLET_IT_PROFILE must be full, expiry, issue6-single-node, or issue6-auth-flow')
  return profile


def run_acceptance_profile(profile, expiry_runner, auth_flow_runner, checkpoint=None):
  """Dispatch only the explicitly bounded profiles supported by this harness."""
  if profile not in ACCEPTANCE_PROFILES:
    raise ValueError('unsupported wallet acceptance profile')
  if profile == 'expiry':
    return {'expiry_case': expiry_runner()}
  if profile in {'issue6-single-node', 'issue6-auth-flow'}:
    result = {
        'profile': profile,
        'broad_matrix_started': False,
        'issue6_single_node_case': {
            'stage': 'auth_flow_complete', 'auth_flow_complete': True,
            'expiry_flow_complete': False, 'phase_order': ['auth_flow'],
        },
        **(auth_flow_runner() or {}),
    }
    if checkpoint is not None:
      checkpoint(result)
    if profile == 'issue6-auth-flow':
      return result
    result['expiry_case'] = expiry_runner()
    result['issue6_single_node_case'] = {
        'stage': 'complete', 'auth_flow_complete': True,
        'expiry_flow_complete': True, 'phase_order': ['auth_flow', 'expiry_flow'],
    }
    if checkpoint is not None:
      checkpoint(result)
    return result
  return auth_flow_runner()


def expiry_acceptance_flow(key, identifier, *, client_factory=None,
    wait=time.sleep, signer=None, progress=None):
  """Exercise real five-minute expiry, then prove a fresh login can be started.

  Production uses the regular Client, openssl signer, and an actual 301-second
  wait. The injected wait/signer seams are solely for offline orchestration tests.
  """
  client_factory = client_factory or Client
  progress = progress or (lambda _stage, _fields: None)
  browser = client_factory()
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(secrets.token_bytes(32)).digest()),
      'code_challenge_method': 'S256',
  })
  login_status, _, page = browser.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  progress('transaction_issued', {'stage': 'transaction_issued', 'profile': 'expiry',
      'login_page_http': login_status})
  require(login_status == 200, 'expiry profile initial login page', login_status)
  parser = LoginPageParser()
  parser.feed(page.decode('utf-8', errors='strict'))
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(
      f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'expiry profile pending transaction locator')
  page_text = page.decode('utf-8', errors='strict')
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', page_text)
  status_url = re.search(r'const statusUrl = "([^"]+)";', page_text)
  require(csrf is not None and status_url is not None,
      'expiry profile initiating-browser status binding')
  if csrf is None or status_url is None:
    raise RuntimeError('expiry profile status binding unavailable')
  wallet = client_factory()
  challenge_status, _, envelope_raw = wallet.request('GET', locator)
  progress('challenge_fetched', {'stage': 'challenge_fetched', 'profile': 'expiry',
      'login_page_http': login_status, 'challenge_http': challenge_status})
  require(challenge_status == 200, 'expiry profile challenge GET', challenge_status)
  envelope = json.loads(envelope_raw)
  require(set(envelope) == {'profile', 'challenge', 'csrf_token'}
      and envelope.get('profile') == 'decent-wallet-login-v1'
      and envelope.get('csrf_token') == csrf.group(1),
      'expiry profile uses the pending transaction challenge')

  if signer is None:
    public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    require(public.returncode == 0 and len(public.stdout) >= 32,
        'expiry profile proof public key')
    signed = json.dumps({'challenge': envelope['challenge'], 'identity_id': identifier,
        'profile': envelope['profile']}, ensure_ascii=False, separators=(',', ':'),
        sort_keys=True).encode('utf-8')
    with tempfile.TemporaryDirectory(prefix='wallet-expiry-signing-', dir=key.parent) as signing_dir:
      payload = write_private_signing_input(signing_dir, 'proof', signed)
      try:
        signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin',
            '-inkey', str(key), '-in', str(payload)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
      finally:
        payload.unlink(missing_ok=True)
    require(signature.returncode == 0 and len(signature.stdout) == 64,
        'expiry profile correctly signed proof')
    proof = json.dumps({'profile': envelope['profile'], 'challenge': envelope['challenge'],
        'identity_id': identifier, 'signature': b64url(signature.stdout)},
        ensure_ascii=False, separators=(',', ':')).encode('utf-8')
  else:
    proof = signer(envelope, identifier)
  require(isinstance(proof, bytes) and proof, 'expiry profile signed proof bytes')

  wait(TRANSACTION_LIFESPAN_SECONDS + 1)
  wallet_redirect_count = len(wallet.redirects)
  proof_status, proof_headers, proof_body = wallet.request('POST', locator, proof,
      {'Content-Type': 'application/json'})
  proof_location = proof_headers.get('Location')
  progress('proof_submitted', {'stage': 'proof_submitted', 'profile': 'expiry',
      'lifetime_seconds': TRANSACTION_LIFESPAN_SECONDS,
      'wait_seconds': TRANSACTION_LIFESPAN_SECONDS + 1, 'proof_http': proof_status,
      'proof_body_empty': not proof_body, 'proof_location_present': proof_location is not None,
      'proof_redirect_followed': len(wallet.redirects) != wallet_redirect_count})
  proof_redirect_followed = len(wallet.redirects) != wallet_redirect_count
  require(not proof_redirect_followed, 'expired proof response redirected', proof_status)
  require(proof_status == 404 and not proof_body and proof_location is None,
      'expired proof fails closed with empty HTTP 404 and no Location', proof_status)
  poll_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  status_redirect_count = len(browser.redirects)
  status_response, status_headers, status_body = browser.request(
      'GET', status_url.group(1), headers=poll_headers)
  status_redirect_followed = len(browser.redirects) != status_redirect_count
  progress('expired_denied', {'stage': 'expired_denied', 'profile': 'expiry',
      'lifetime_seconds': TRANSACTION_LIFESPAN_SECONDS,
      'wait_seconds': TRANSACTION_LIFESPAN_SECONDS + 1, 'proof_http': proof_status,
      'proof_body_empty': not proof_body, 'proof_location_present': proof_location is not None,
      'proof_redirect_followed': proof_redirect_followed,
      'status_http': status_response, 'status_body_empty': not status_body,
      'status_callback_exposed': b'callback' in status_body.lower(),
      'status_redirect_followed': status_redirect_followed,
      'accepted_status': False, 'oidc_code_exposed': False})
  require(not status_redirect_followed, 'expired status response redirected', status_response)
  require(status_response == 404 and not status_body and status_headers.get('Location') is None,
      'expired initiating-browser status has no accepted receipt or callback', status_response)

  recovery_browser = browser
  recovery_query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(secrets.token_bytes(32)).digest()),
      'code_challenge_method': 'S256',
  })
  recovery_status, _, recovery_page = recovery_browser.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{recovery_query}')
  progress('fresh_login', {'stage': 'fresh_login', 'profile': 'expiry',
      'proof_http': proof_status, 'status_http': status_response,
      'fresh_login_http': recovery_status})
  require(recovery_status == 200, 'new login required after transaction expiry', recovery_status)
  recovery_parser = LoginPageParser()
  recovery_parser.feed(recovery_page.decode('utf-8', errors='strict'))
  recovery_locator = ''.join(recovery_parser.locator_parts).strip()
  require(recovery_locator != locator and recovery_locator.startswith(
      f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'expiry recovery starts a distinct fresh transaction')
  recovery_wallet = client_factory()
  recovery_challenge_status, _, _ = recovery_wallet.request('GET', recovery_locator)
  recovery_locator_distinct = recovery_locator != locator
  fresh_login_transaction_available = recovery_challenge_status == 200 and recovery_locator_distinct
  progress('fresh_login', {'stage': 'fresh_login', 'profile': 'expiry',
      'lifetime_seconds': TRANSACTION_LIFESPAN_SECONDS,
      'wait_seconds': TRANSACTION_LIFESPAN_SECONDS + 1, 'proof_http': proof_status,
      'proof_body_empty': not proof_body, 'proof_location_present': proof_location is not None,
      'proof_redirect_followed': proof_redirect_followed,
      'status_http': status_response, 'status_body_empty': not status_body,
      'status_location_present': status_headers.get('Location') is not None,
      'status_callback_exposed': b'callback' in status_body.lower(),
      'status_redirect_followed': status_redirect_followed,
      'accepted_status': False, 'oidc_code_exposed': False,
      'fresh_login_http': recovery_status, 'fresh_challenge_http': recovery_challenge_status,
      'fresh_locator_distinct': recovery_locator_distinct,
      'fresh_login_transaction_available': fresh_login_transaction_available})
  require(fresh_login_transaction_available,
      'fresh transaction is available after expired login', recovery_challenge_status)
  return {
      'stage': 'complete', 'profile': 'expiry',
      'lifetime_seconds': TRANSACTION_LIFESPAN_SECONDS,
      'wait_seconds': TRANSACTION_LIFESPAN_SECONDS + 1,
      'proof_http': proof_status, 'proof_body_empty': not proof_body,
      'proof_location_present': proof_location is not None,
      'proof_redirect_followed': proof_redirect_followed,
      'status_http': status_response, 'status_body_empty': not status_body,
      'status_location_present': status_headers.get('Location') is not None,
      'status_callback_exposed': b'callback' in status_body.lower(),
      'status_redirect_followed': status_redirect_followed,
      'accepted_status': False, 'oidc_code_exposed': False,
      'fresh_login_http': recovery_status, 'fresh_challenge_http': recovery_challenge_status,
      'fresh_locator_distinct': recovery_locator_distinct,
      'fresh_login_transaction_available': fresh_login_transaction_available,
  }



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


def merge_issue7_checkpoint(result, evidence_key, evidence, checkpoint):
  current = dict(result.get(evidence_key, {}))
  current.update(evidence)
  result[evidence_key] = current
  checkpoint()


def checkpoint_live_case(result, case_name, fields, checkpoint):
  if case_name not in {
      'rotated_identity_case', 'ambiguous_account_case', 'unmapped_account_case',
      'disabled_account_case', 'wallet_login', 'browser_preflight', 'negative_case',
      'expiry_case',
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


def pinned_keycloak_version():
  """Read the runtime version from the Maven dependency pin, not a duplicate constant."""
  pom = Path(__file__).resolve().parents[1] / 'pom.xml'
  try:
    root = ET.parse(pom).getroot()
  except (OSError, ET.ParseError):
    raise RuntimeError('Keycloak project version pin unavailable') from None
  version = next((node.text for node in root.iter()
      if node.tag.rsplit('}', 1)[-1] == 'keycloak.version'), None)
  if not isinstance(version, str) or re.fullmatch(r'\d+\.\d+\.\d+', version) is None:
    raise RuntimeError('Keycloak project version pin invalid')
  return version


def sanitize_live_checkpoint(candidate):
  """Project live outcomes into a fixed, non-sensitive evidence schema."""
  if not isinstance(candidate, dict):
    return {}
  runtime_fields = {
      'identity_commit', 'registry_commit', 'harness_sha256',
      'runtime_manifest_sha256', 'runtime_lock_sha256', 'image_digest', 'diagnostic_categories',
      'keycloak_version', 'keycloak_nodes', 'database_mode_configured',
      'database_mode_effective', 'cache_mode_configured', 'cache_mode_effective',
      'cache_mode_effective_evidence', 'cache_stack_effective', 'single_use_object_provider_configured',
      'single_use_object_provider_path', 'single_use_object_provider_ids', 'runtime_command_fields_present',
      'keycloak_config_read_status',
      'keycloak_config_fields_present', 'runtime_qualification_status',
      'profile', 'node_count', 'database', 'cache',
      'single_use_object_provider_evidence', 'credential_file_retained',
  }
  scalar_fields = {
      'proof_post_http', 'status_poll_http',
      'proof_http', 'login_page_http', 'challenge_http', 'fresh_login_http', 'fresh_challenge_http',
      'lifetime_seconds', 'wait_seconds', 'profile',
      'invalid_proof_http', 'pkce_token_http', 'current_key_proof_http',
      'stale_key_proof_http', 'current_sequence', 'cli_exit', 'cli_lookup_ms',
      'provider_http', 'direct_provider_http', 'provider_lookup_ms',
      'direct_provider_lookup_ms', 'exact_mapped_users',
      'signup_intent_action_http', 'signup_proof_http', 'scenario',
      'rotation_publish', 'callback_code', 'id_token_claims_checked', 'jwks_signature_verified',
      'identical_retry_accepted', 'changed_retry_denied', 'alien_status_denied',
      'state_preserved', 'error_returned', 'authorization_code_returned',
      'callback_replay', 'oidc_state_preserved', 'local_mapping_persisted', 'credentialed', 'wrong_origin_denied',
      'callback_replay_internal_error_page', 'callback_replay_internal_error_reason',
      'callback_replay_internal_error_hostname_matches',
      'callback_replay_internal_error_port_matches',
      'callback_replay_guard_log_read', 'callback_replay_guard_reached',
      'callback_replay_login_error_log_read',
      'callback_replay_authenticator_entry_reached',
      'callback_replay_authenticator_entry_completed',
      'callback_top_flow_rearm_reached', 'callback_top_flow_rearm_execution_id_present',
      'callback_replay_state_present', 'callback_replay_redirect_uri_present',
      'callback_replay_redirect_uri_registered', 'callback_replay_protocol_openid_connect',
      'callback_replay_guard_marker_count', 'callback_replay_guard_unavailable_marker_count',
      'callback_replay_guard_other_marker_count',
      'callback_replay_login_error_count',
      'callback_replay_login_error_category', 'failure_category',
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
      'rotated_identity_case', 'ambiguous_account_case', 'missing_identity_case', 'expiry_case',
      'issue6_single_node', 'issue6_postconsume_receipt_failure_case',
      'issue6_postconsume_receipt_recovery',
      'issue6_postconsume_callback_gate_failure_case',
      'issue6_postconsume_callback_gate_recovery', 'issue6_single_node_case', 'registry_matrix',
      'issue7_single_node_signup_recovery', 'issue7_store_recovery',
  }
  signup_stages = {'intent', 'proof', 'account', 'callback', 'token', 'complete'}
  rotation_stages = {'publish', 'readback', 'stale_proof', 'stale_pending', 'stale_attempt',
      'stale_proof_pending', 'current_proof', 'current_attempt', 'current_accepted', 'callback', 'complete', 'mapping'}
  expiry_stages = {'started', 'transaction_created', 'expired_proof_submitted',
      'fresh_login_started', 'fresh_login_verified', 'transaction_issued',
      'challenge_fetched', 'proof_submitted', 'expired_denied', 'fresh_login', 'complete'}
  bool_fields = {
      'status_callback_exposed', 'oidc_code_exposed', 'fresh_locator_distinct',
      'fresh_login_transaction_available', 'proof_body_empty', 'proof_location_present',
      'proof_redirect_followed', 'status_body_empty', 'status_location_present',
      'status_redirect_followed', 'accepted_status',
      'id_token_claims_checked', 'jwks_signature_verified', 'callback_code', 'identical_retry_accepted',
      'local_mapping_persisted',
      'changed_retry_denied', 'alien_status_denied', 'state_preserved', 'error_returned',
      'challenge_get', 'wrong_origin_denied', 'credentialed',
      'authorization_code_returned', 'callback_replay', 'oidc_state_preserved', 'credentialed',
      'callback_replay_redirect_uri_matches', 'callback_redirect_uri_matches',
      'initial_status_accepted', 'callback_state_preserved', 'callback_error_returned',
      'callback_code_returned', 'callback_replay_state_preserved',
      'callback_replay_error_returned', 'callback_replay_code_returned',
      'callback_replay_denied_safely', 'callback_replay_internal_error_page',
      'callback_replay_internal_error_hostname_matches',
      'callback_replay_internal_error_port_matches',
      'callback_replay_guard_log_read', 'callback_replay_guard_reached',
      'callback_replay_login_error_log_read',
      'callback_replay_authenticator_entry_reached',
      'callback_replay_authenticator_entry_completed',
      'callback_top_flow_rearm_reached', 'callback_top_flow_rearm_execution_id_present',
      'callback_replay_state_present', 'callback_replay_redirect_uri_present',
      'callback_replay_redirect_uri_registered', 'callback_replay_protocol_openid_connect',
      'status_after_callback_safe',
      'wrong_origin_denied', 'signature_rejected_by_verifier', 'no_acceptance_or_callback',
      'registry_unavailable', 'local_account_mapping_decision_observed',
      'stale_transaction_remains_pending', 'current_transaction_accepted', 'status_pending',
      'proof_denied', 'status_denied', 'no_accepted_receipt', 'no_callback',
      'no_authorization_code', 'request_correlated_denial', 'response_body_safe',
      'location_safe', 'redirects_safe', 'fresh_locator_distinct',
      'fresh_login_transaction_available', 'proof_body_empty',
      'proof_location_present', 'proof_redirect_followed', 'status_body_empty',
      'status_location_present', 'status_redirect_followed', 'callback_exposed',
      'oidc_code_exposed', 'fault_signal_correlated', 'delegate_commit_then_throw',
      'test_provider_selected',
      'retry_redirect_followed', 'callback_replay_denied',
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
      'status_http', 'login_page_http', 'challenge_get_http',
      'fresh_login_http', 'fresh_challenge_http', 'fresh_proof_http', 'fresh_retry_http',
      'fresh_changed_retry_http', 'fresh_status_http', 'fresh_challenge_http',
      'initial_status_http',
      'identical_retry_http', 'changed_retry_http', 'callback_http',
      'callback_replay_http', 'status_after_callback_http', 'proof_http',
      'retry_http', 'challenge_http',
  }
  time_fields = {'cli_lookup_ms', 'provider_lookup_ms', 'direct_provider_lookup_ms',
      'lifetime_seconds', 'wait_seconds'}
  digest_fields = {'identity_commit', 'registry_commit'}
  enums = {
      'profile': {'full', 'expiry', 'issue6-single-node'},
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
      'runtime_qualification_status': {'runtime_facts_verified', 'open_runtime_facts_unavailable'},
      'callback_replay_internal_error_reason': {
          'callback_url_unavailable', 'callback_origin_invalid', 'redirect_scheme_mismatch',
          'redirect_origin_mismatch',
          'redirect_path_untrusted', 'authorization_code_present', 'error_parameter_invalid',
          'same_origin_error_without_code', 'loopback_keycloak_error_without_code',
          'url_parse_error'},
      'callback_replay_login_error_category': {
          'none', 'unavailable', 'multiple', 'other', 'invalid_code', 'expired_code',
          'already_logged_in', 'cookie_not_found', 'invalid_request', 'invalid_redirect_uri',
          'access_denied', 'user_not_found'},
      'failure_category': {'runtime_error', 'timeout', 'value_error', 'other'},
      'single_use_object_provider_path': {'infinispan', 'jpa', 'remote', 'unavailable',
          'issue6-postconsume-receipt-failure', 'issue6-postconsume-callback-gate-failure'},
      'selected_provider_path': {'issue6-postconsume-receipt-failure',
          'issue6-postconsume-callback-gate-failure'},
      'keycloak_config_read_status': {
          'container_id_unverified', 'container_inspect_timeout', 'container_inspect_error',
          'show_config_timeout', 'show_config_error', 'show_config_nonzero',
          'show_config_fields_complete', 'show_config_fields_missing', 'show_config_conflict',
          'runtime_log_conflict'},
      'failure_gate': issue7_store_recovery.FAILURE_GATES,
  }

  runtime_string_fields = {
      'harness_sha256', 'runtime_manifest_sha256', 'runtime_lock_sha256', 'image_digest',
  }
  resolver_diagnostic_reasons = {
      'registry_miss', 'dial_warning', 'peer_handshake', 'peer_error',
      'history_unavailable', 'dht_lookup_unavailable', 'traceback', 'process_start', 'nonzero_exit',
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
    if field == 'keycloak_version':
      return isinstance(value, str) and value == pinned_keycloak_version()
    if field == 'keycloak_nodes':
      return value in {'one', 'unknown'}
    if field == 'cache_mode_effective_evidence':
      return value in {'show_config', 'infinispan_configuration_log', 'unavailable'}
    if field in {'database_mode_configured', 'database_mode_effective',
        'cache_mode_configured', 'cache_mode_effective', 'cache_stack_effective'}:
      return value is None or (isinstance(value, str)
          and re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', value) is not None)
    if field == 'single_use_object_provider_ids':
      return isinstance(value, list) and len(value) <= 32 and all(
          isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', item) is not None
          for item in value) and value == sorted(set(value))
    if field == 'runtime_command_fields_present':
      allowed_command_fields = {'database_mode_configured', 'cache_mode_configured',
          'single_use_object_provider_configured'}
      return (isinstance(value, list) and len(value) <= 3
          and all(item in allowed_command_fields for item in value)
          and value == sorted(set(value)))
    if field == 'single_use_object_provider_configured':
      return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', value) is not None
    if field == 'single_use_object_provider_path':
      return value in {'infinispan', 'jpa', 'remote', 'unavailable',
          'issue6-postconsume-receipt-failure', 'issue6-postconsume-callback-gate-failure'}
    if field == 'keycloak_config_fields_present':
      allowed_config_fields = {'database_mode_effective', 'cache_mode_effective',
          'cache_stack_effective', 'single_use_object_provider_configured'}
      return (isinstance(value, list) and len(value) <= 4
          and all(item in allowed_config_fields for item in value)
          and value == sorted(set(value)))
    if field == 'node_count':
      return type(value) is int and value == 1
    if field == 'database':
      return value == 'dev-file'
    if field == 'cache':
      return value == 'local'
    if field == 'single_use_object_provider_evidence':
      return value == 'not_observed'
    if field == 'credential_file_retained':
      return type(value) is bool
    if field in bool_fields:
      return type(value) is bool
    if field in http_fields:
      return type(value) is int and 100 <= value <= 599
    if field in {'ttl_seconds', 'wait_seconds'}:
      return type(value) is int and 1 <= value <= 7200
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
    if field in {'callback_replay_guard_marker_count',
        'callback_replay_guard_unavailable_marker_count',
        'callback_replay_guard_other_marker_count',
        'callback_replay_login_error_count',
        'callback_replay_authenticator_entry_marker_count',
        'callback_replay_authenticator_entry_unavailable_marker_count',
        'callback_replay_authenticator_entry_other_marker_count',
        'callback_replay_authenticator_entry_completed_true_marker_count',
        'callback_replay_authenticator_entry_completed_false_marker_count',
        'callback_top_flow_rearm_marker_count',
        'callback_top_flow_rearm_unavailable_marker_count',
        'callback_top_flow_rearm_other_marker_count'}:
      return type(value) is int and 0 <= value <= 10
    if field == 'wallet_locator':
      return value is True
    return False

  projected = {}
  for key, value in candidate.items():
    if key not in allowed or not isinstance(value, dict):
      continue
    if key == 'registry_matrix':
      case_names = {'current_identity', 'missing_identity', 'unavailable_registry',
          'history_incomplete', 'malformed_result', 'ambiguous_registry_result', 'rotation'}
      matrix_outcomes = {'current_accepted', 'provider_registry_inconsistent',
          'registry_unavailable', 'provider_unavailable', 'provider_denied_unclassified',
          'unexpected_acceptance', 'unexpected_status', 'unqualified'}
      safe_matrix = {}
      for case_name, case_value in value.items():
        if case_name not in case_names or not isinstance(case_value, dict):
          continue
        attempts = case_value.get('attempts')
        if not isinstance(attempts, list) or len(attempts) > 5:
          continue
        safe_attempts = []
        for attempt in attempts:
          if not isinstance(attempt, dict):
            continue
          safe_attempt = {}
          number = attempt.get('attempt_number')
          if type(number) is int and 1 <= number <= 5:
            safe_attempt['attempt_number'] = number
          direct = attempt.get('direct_resolution')
          if isinstance(direct, str) and direct in {'resolved', 'not_found', 'unavailable'}:
            safe_attempt['direct_resolution'] = direct
          for field in {'provider_http', 'status_http', 'proof_post_http',
              'status_poll_http', 'stale_key_proof_http', 'current_key_proof_http'}:
            status = attempt.get(field)
            if type(status) is int and 100 <= status <= 599:
              safe_attempt[field] = status
          for field in {'exact_readback', 'status_pending', 'no_acceptance_or_callback',
              'stale_transaction_remains_pending', 'current_transaction_accepted'}:
            flag = attempt.get(field)
            if type(flag) is bool:
              safe_attempt[field] = flag
          outcome = attempt.get('outcome')
          if isinstance(outcome, str) and outcome in matrix_outcomes:
            safe_attempt['outcome'] = outcome
          fixture = attempt.get('fixture')
          if isinstance(fixture, str) and re.fullmatch(r'unpublished-fixture-[1-5]', fixture):
            safe_attempt['fixture'] = fixture
          sequence = attempt.get('current_sequence')
          if type(sequence) is int and 0 <= sequence <= 60000:
            safe_attempt['current_sequence'] = sequence
          if safe_attempt:
            safe_attempts.append(safe_attempt)
        safe_matrix[case_name] = {'attempts': safe_attempts}
      if safe_matrix:
        projected[key] = safe_matrix
    if key == 'issue7_store_recovery':
      safe = issue7_store_recovery.sanitize(value)
      if safe:
        projected[key] = safe
      continue
    if key == 'issue7_single_node_signup_recovery':
      stages = {'setup', 'resolver_tools_starting', 'resolver_tools_started',
          'registry_starting', 'registry_started', 'identity_writing', 'identity_ready',
          'keycloak_starting', 'keycloak_started', 'runtime_verifying', 'runtime_verified',
          'realm_configuring', 'realm_configured', 'events_configuring', 'events_configured',
          'faulted_signup', 'fresh_signup', 'complete'}
      enums = {
          'scope': {'one-keycloak-node'},
          'stage': stages,
          'user_readback_fault_mode': {'empty', 'throw', 'over-cap'},
          'effective_user_readback_fault_mode': {'empty', 'throw', 'over-cap'},
          'fault_evidence_provenance': {'wrapper-mediated-application-path'},
      'failure_stage': issue7_store_recovery.FAILURE_STAGES,
      'failure_gate': issue7_store_recovery.FAILURE_GATES,
      'failure_category': issue7_store_recovery.FAILURE_CATEGORIES,
      }
      booleans = {'same_local_subject', 'browser_status_pending',
          'failure_responses_no_callback_or_code', 'account_retained_after_failure',
          'user_readback_factory_selected', 'post_create_read_fault_observed',
          'fresh_signup_reused_account'}
      statuses = {'provider_fault_http', 'browser_status_http', 'fresh_signup_proof_http',
          'fresh_signup_callback_http', 'fresh_signup_pkce_token_http',
          'signup_intent_action_http', 'signup_proof_http', 'failure_http_status',
          'callback_http', 'pkce_token_http'}
      safe = {}
      for field, item in value.items():
        if field in enums and isinstance(item, str) and item in enums[field]:
          safe[field] = item
        elif field in booleans and type(item) is bool:
          safe[field] = item
        elif field in statuses and type(item) is int and 100 <= item <= 599:
          safe[field] = item
        elif field == 'synthetic_candidate_count' and type(item) is int and 0 <= item <= 65:
          safe[field] = item
        elif (
            field in {'correlated_mapping_failure_count', 'post_create_read_fault_count'}
            and type(item) is int and 0 <= item <= 5):
          safe[field] = item
        elif field in {'keycloak_node_count', 'fresh_explicit_signup_transactions',
            'exact_enabled_local_users', 'exact_mapped_users'} and type(item) is int and 0 <= item <= 2:
          safe[field] = item
        elif (field == 'exact_enabled_local_accounts_after_each_signup'
            and isinstance(item, list) and len(item) == 2
            and all(type(count) is int and 0 <= count <= 2 for count in item)):
          safe[field] = item
      if safe:
        projected[key] = safe
      continue
    if key == 'missing_identity_case' and isinstance(value, dict):
      fields = {'cli_resolution', 'cli_exit', 'cli_output_categories', 'cli_output_shape',
          'cli_lookup_ms', 'provider_resolution_outcome', 'direct_provider_http',
          'status_http', 'status_pending', 'redirects_safe', 'direct_provider_lookup_ms',
          'no_acceptance_or_callback'}
      safe = {field: item for field, item in value.items()
          if field in fields and safe_scalar(field, item)}
      if safe:
        projected[key] = safe
      continue
    if key == 'expiry_case':
      stage = value.get('stage')
      if stage not in expiry_stages:
        continue
      fields = {
          'ttl_seconds', 'lifetime_seconds', 'wait_seconds', 'profile', 'login_page_http', 'challenge_get_http',
          'challenge_http', 'proof_http', 'proof_post_http', 'status_http', 'proof_denied', 'status_denied',
          'no_accepted_receipt', 'no_callback', 'no_authorization_code',
          'request_correlated_denial', 'response_body_safe', 'location_safe',
          'redirects_safe', 'proof_body_empty', 'proof_location_present',
          'proof_redirect_followed', 'status_body_empty', 'status_location_present',
          'status_redirect_followed', 'accepted_status', 'oidc_code_exposed',
          'status_callback_exposed', 'runtime_qualification_status',
          'single_use_object_provider_path', 'fresh_login_http', 'fresh_challenge_http',
          'fresh_locator_distinct', 'fresh_login_transaction_available'}
      safe = {'stage': stage}
      safe.update({field: item for field, item in value.items()
          if field in fields and safe_scalar(field, item)})
      if safe:
        projected[key] = safe
      continue
    if key == 'issue6_single_node' and isinstance(value, dict):
      issue6_stages = {
          'preflight', 'resolver_setup', 'registry_setup', 'identity_setup',
          'keycloak_setup', 'realm_setup', 'auth_flow', 'auth_flow_failed', 'complete'}
      stage = value.get('stage')
      if stage not in issue6_stages:
        continue
      issue6_fields = {
          'node_count', 'keycloak_version', 'keycloak_nodes',
          'database_mode_configured', 'database_mode_effective',
          'cache_mode_configured', 'cache_mode_effective',
          'single_use_object_provider_configured', 'single_use_object_provider_path',
          'proof_post_http', 'initial_status_http',
          'initial_status_accepted', 'identical_retry_http', 'changed_retry_http',
          'callback_http', 'callback_redirect_uri_matches', 'callback_state_preserved',
          'callback_code_returned', 'callback_error_returned', 'callback_replay_http',
          'callback_replay_redirect_uri_matches', 'callback_replay_state_preserved',
          'callback_replay_error_returned', 'callback_replay_code_returned',
          'callback_replay_denied_safely', 'callback_replay_internal_error_page',
          'callback_replay_internal_error_reason',
          'callback_replay_internal_error_hostname_matches',
          'callback_replay_internal_error_port_matches',
          'callback_replay_guard_log_read', 'callback_replay_guard_reached',
          'callback_replay_state_present', 'callback_replay_redirect_uri_present',
          'callback_replay_redirect_uri_registered', 'callback_replay_protocol_openid_connect',
          'callback_replay_guard_marker_count', 'callback_replay_guard_unavailable_marker_count',
          'callback_replay_guard_other_marker_count',
          'callback_replay_login_error_log_read', 'callback_replay_login_error_count',
          'callback_replay_login_error_category',
          'callback_replay_authenticator_entry_reached',
          'callback_replay_authenticator_entry_completed',
          'callback_replay_authenticator_entry_marker_count',
          'callback_replay_authenticator_entry_unavailable_marker_count',
          'callback_replay_authenticator_entry_other_marker_count',
        'callback_replay_authenticator_entry_completed_true_marker_count',
        'callback_replay_authenticator_entry_completed_false_marker_count',
          'callback_top_flow_rearm_reached', 'callback_top_flow_rearm_execution_id_present',
          'callback_top_flow_rearm_marker_count',
          'callback_top_flow_rearm_unavailable_marker_count',
          'callback_top_flow_rearm_other_marker_count',
          'status_after_callback_http', 'status_after_callback_safe', 'pkce_token_http',
          'failure_gate'}
      safe = {'stage': stage}
      safe.update({field: item for field, item in value.items()
          if field in issue6_fields and safe_scalar(field, item)})
      if safe:
        projected[key] = safe
      continue
    if key in {'issue6_postconsume_receipt_failure_case',
        'issue6_postconsume_receipt_recovery',
        'issue6_postconsume_callback_gate_failure_case',
        'issue6_postconsume_callback_gate_recovery'} and isinstance(value, dict):
      failure_case = key.endswith('_failure_case')
      failure_fields = {'stage', 'proof_http', 'retry_http', 'status_http',
          'proof_body_empty', 'proof_location_present', 'proof_redirect_followed',
          'status_body_empty', 'status_location_present', 'status_redirect_followed',
          'callback_exposed', 'oidc_code_exposed', 'fault_signal_correlated',
          'delegate_commit_then_throw', 'retry_redirect_followed', 'fault_signal_count',
          'failure_category'}
      recovery_fields = {'stage', 'fresh_login_http', 'fresh_challenge_http',
          'fresh_proof_http', 'fresh_retry_http', 'fresh_changed_retry_http',
          'fresh_status_http', 'fresh_login_transaction_available',
          'callback_http', 'callback_state_preserved', 'callback_code_returned',
          'callback_error_returned', 'callback_code', 'callback_replay_http',
          'callback_replay_state_preserved', 'callback_replay_error_returned',
          'callback_replay_code_returned', 'callback_replay_denied', 'pkce_token_http'}
      recovery_fields.update({
          'callback_replay_guard_log_read', 'callback_replay_guard_reached',
          'callback_replay_guard_marker_count',
          'callback_replay_guard_unavailable_marker_count',
          'callback_replay_guard_other_marker_count',
          'callback_replay_login_error_log_read', 'callback_replay_login_error_count',
          'callback_replay_login_error_category',
          'callback_replay_authenticator_entry_reached',
          'callback_replay_authenticator_entry_completed',
          'callback_replay_authenticator_entry_marker_count',
          'callback_replay_authenticator_entry_unavailable_marker_count',
          'callback_replay_authenticator_entry_other_marker_count',
        'callback_replay_authenticator_entry_completed_true_marker_count',
        'callback_replay_authenticator_entry_completed_false_marker_count',
          'callback_top_flow_rearm_reached', 'callback_top_flow_rearm_execution_id_present',
          'callback_top_flow_rearm_marker_count',
          'callback_top_flow_rearm_unavailable_marker_count',
          'callback_top_flow_rearm_other_marker_count',
          'callback_replay_state_present', 'callback_replay_redirect_uri_present',
          'callback_replay_redirect_uri_registered', 'callback_replay_protocol_openid_connect',
          'failure_category'})
      safe_fields = failure_fields if failure_case else recovery_fields
      safe = {}
      stage = value.get('stage')
      if failure_case and stage in {'preflight', 'resolver_setup', 'registry_setup',
          'identity_setup', 'keycloak_setup', 'runtime_provenance_read',
          'runtime_baseline_verified', 'provider_registration_verified',
          'provider_config_verified', 'configure_realm', 'realm_configured',
          'enable_login_events', 'login_events_enabled', 'provision_identity',
          'realm_setup', 'failed_then_denied', 'complete'}:
        safe['stage'] = stage
      recovery_stages = {'recovery_started', 'fresh_login_page', 'fresh_challenge', 'fresh_proof',
          'fresh_identical_retry', 'fresh_changed_retry', 'fresh_status',
          'fresh_callback', 'fresh_replay', 'fresh_pkce', 'complete'}
      if not failure_case and stage in recovery_stages:
        safe['stage'] = stage
      for field in safe_fields - {'stage'}:
        item = value.get(field)
        if field in bool_fields and type(item) is bool:
          safe[field] = item
        elif field in http_fields and type(item) is int and 100 <= item <= 599:
          safe[field] = item
        elif field == 'failure_category' and item in enums['failure_category']:
          safe[field] = item
        elif field in enums and isinstance(item, str) and item in enums[field]:
          safe[field] = item
        elif field == 'fault_signal_count' and type(item) is int and 0 <= item <= 10:
          safe[field] = item
        elif field in {'callback_replay_guard_marker_count',
            'callback_replay_guard_unavailable_marker_count',
            'callback_replay_guard_other_marker_count',
            'callback_replay_login_error_count',
            'callback_replay_authenticator_entry_marker_count',
            'callback_replay_authenticator_entry_unavailable_marker_count',
            'callback_replay_authenticator_entry_other_marker_count',
        'callback_replay_authenticator_entry_completed_true_marker_count',
        'callback_replay_authenticator_entry_completed_false_marker_count',
            'callback_top_flow_rearm_marker_count',
            'callback_top_flow_rearm_unavailable_marker_count',
            'callback_top_flow_rearm_other_marker_count'} and type(item) is int and 0 <= item <= 10:
          safe[field] = item
      if safe:
        projected[key] = safe
      continue
    if key == 'issue6_single_node_case':
      stage = value.get('stage')
      expected_state = {
          'auth_flow_complete': (['auth_flow'], True, False),
          'complete': (['auth_flow', 'expiry_flow'], True, True),
      }.get(stage)
      if expected_state is None:
        continue
      phase_order, auth_complete, expiry_complete = expected_state
      if (value.get('phase_order') != phase_order
          or value.get('auth_flow_complete') is not auth_complete
          or value.get('expiry_flow_complete') is not expiry_complete):
        continue
      projected[key] = {
          'stage': stage,
          'auth_flow_complete': auth_complete,
          'expiry_flow_complete': expiry_complete,
          'phase_order': phase_order,
      }
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
    if key == 'expiry_case' and isinstance(value, dict):
      if value.get('stage') not in {'transaction_issued', 'challenge_fetched', 'proof_submitted', 'expired_denied', 'fresh_login', 'complete'}:
        continue
      expiry_fields = {
          'profile', 'login_page_http', 'challenge_http', 'lifetime_seconds', 'wait_seconds',
          'proof_http', 'proof_body_empty', 'proof_location_present', 'proof_redirect_followed',
          'status_http', 'status_body_empty', 'status_location_present', 'status_redirect_followed',
          'status_callback_exposed', 'accepted_status', 'oidc_code_exposed',
          'fresh_login_http', 'fresh_challenge_http', 'fresh_locator_distinct',
          'fresh_login_transaction_available',
      }
      safe = {'stage': value['stage']}
      safe.update({field: item for field, item in value.items()
          if field in expiry_fields and safe_scalar(field, item)})
      projected[key] = safe
      continue
    if key == 'signup_case' and isinstance(value, dict):
      stage = value.get('stage')
      if stage not in signup_stages:
        continue
      safe = {'stage': stage}
      if value.get('evidence_provenance') == 'harness-application-path-only':
        safe['evidence_provenance'] = 'harness-application-path-only'
      if (stage == 'complete'
          and value.get('single_use_object_provider_id') in {'infinispan', 'jpa', 'remote'}):
        safe['single_use_object_provider_id'] = value['single_use_object_provider_id']
      safe.update({field: item for field, item in value.items()
          if field in {'signup_intent_action_http', 'signup_proof_http',
              'callback_http', 'pkce_token_http', 'callback_replay',
          'oidc_state_preserved'} and safe_scalar(field, item)})
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


def unavailable_bootstrap(bootstrap, port):
  if not isinstance(bootstrap, str) or type(port) is not int or not 1 <= port <= 65535:
    return None
  match = re.search(r'/tcp/(\d+)(?=/p2p/)', bootstrap)
  if match is None or int(match.group(1)) == port:
    return None
  return bootstrap[:match.start(1)] + str(port) + bootstrap[match.end(1):]


def run(args, timeout=60, env=None):
  return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=timeout, env=env, check=False)


def subprocess_output_text(result):
  """Combine captured text streams while tolerating merged or omitted stderr."""
  return ''.join(value for value in (getattr(result, 'stdout', None),
      getattr(result, 'stderr', None)) if isinstance(value, str))


RUN_CID_DIR = None


def _cid_file(role):
  if RUN_CID_DIR is None:
    raise RuntimeError('run-scoped container ownership directory is unavailable')
  if not isinstance(role, str) or re.fullmatch(r'[a-z-]{1,32}', role) is None:
    raise ValueError('container ownership role is invalid')
  path = Path(RUN_CID_DIR) / (role + '.cid')
  if path.exists():
    raise RuntimeError('run-scoped container CID file already exists')
  return path


def _inspect_cid(cid_file):
  try:
    container_id = Path(cid_file).read_text(encoding='ascii').strip()
  except (OSError, UnicodeError):
    return None
  if re.fullmatch(r'[0-9a-f]{64}', container_id) is None:
    return None
  inspected = run(['podman', 'inspect', '--format', '{{.Id}}', container_id], timeout=15)
  if inspected.returncode != 0 or inspected.stdout.strip() != container_id:
    return None
  return container_id


def remove_owned_container(cid_file):
  """Remove only a CID-file resource whose full ID remains verified."""
  path = Path(cid_file)
  if RUN_CID_DIR is None or path.parent != Path(RUN_CID_DIR):
    return {'removed': False, 'retained_cid': True}
  try:
    container_id = _inspect_cid(cid_file)
    if container_id is None or _inspect_cid(cid_file) != container_id:
      return {'removed': False, 'retained_cid': True}
    try:
      run(['podman', 'rm', '--force', container_id], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
      pass
    try:
      after = run(['podman', 'inspect', '--format', '{{.Id}}', container_id], timeout=15)
    except (OSError, subprocess.TimeoutExpired):
      return {'removed': False, 'retained_cid': True}
    absence_marker = re.compile(
        r'(?:no such (?:container|object)|(?:container|object)\b.*\b'
        r'(?:not found|does not exist)|no (?:container|object)\b.*\bfound)',
        re.IGNORECASE)
    absence_confirmed = (after.returncode != 0 and any(
        container_id in line and absence_marker.search(line) is not None
        for line in subprocess_output_text(after).splitlines()))
    if not absence_confirmed:
      return {'removed': False, 'retained_cid': True}
  except (OSError, RuntimeError, subprocess.TimeoutExpired):
    return {'removed': False, 'retained_cid': True}
  try:
    Path(cid_file).unlink()
  except FileNotFoundError:
    return {'removed': True, 'retained_cid': False}
  except OSError:
    return {'removed': True, 'retained_cid': True}
  if path.exists():
    return {'removed': True, 'retained_cid': True}
  return {'removed': True, 'retained_cid': False}


def start_owned_container(args, cid_file, timeout, stage, ownership_callback=None):
  """Accept container ownership only after the run result and CID agree."""
  container_id = None
  recovery_attempted = False
  returned_id = None
  try:
    started = run(args, timeout=timeout)
    output = getattr(started, 'stdout', None)
    if isinstance(output, bytes):
      output = output.decode('ascii', errors='ignore')
    if isinstance(output, str) and re.fullmatch(r'[0-9a-f]{64}', output.strip()):
      returned_id = output.strip()
    container_id = recover_keycloak_ownership(cid_file, returned_id, ownership_callback)
    recovery_attempted = True
    require(started.returncode == 0, stage)
    if container_id is None:
      raise RuntimeError('container ownership verification failed')
    return started, container_id
  except BaseException:
    if not recovery_attempted:
      try:
        container_id = recover_keycloak_ownership(cid_file, None, ownership_callback)
      except BaseException:
        pass
    if container_id is not None and ownership_callback is None:
      try:
        remove_owned_container(cid_file)
      except BaseException:
        pass
    raise


def cleanup_owned_resources(registry_node, resolver_tools, interruption_collector=None):
  """Attempt every cleanup, preserving interrupts after all owned resources are handled."""
  cleanup_errors = 0
  cleanup_categories = []
  interruptions = []

  def record_failure(category, failure):
    nonlocal cleanup_errors
    cleanup_errors += 1
    cleanup_categories.append(category)
    if isinstance(failure, (KeyboardInterrupt, SystemExit)):
      interruptions.append(failure)

  for category, cleanup in (
      ('registry_log_stream_stop_error', lambda: stop_registry(registry_node)),
      ('resolver_tools_stop_error', lambda: stop_resolver_tools(None))):
    try:
      cleanup()
    except (Exception, KeyboardInterrupt, SystemExit) as failure:
      record_failure(category, failure)
  role_categories = {
      'keycloak': 'keycloak', 'registry': 'registry', 'resolver-tools': 'resolver_tools'}
  if RUN_CID_DIR is not None and RUN_CID_DIR.exists():
    for cid_file in sorted(RUN_CID_DIR.glob('*.cid')):
      role = role_categories.get(cid_file.stem, 'unknown_resource')
      try:
        status = remove_owned_container(cid_file)
        if not status['removed'] or status['retained_cid']:
          cleanup_errors += 1
          cleanup_categories.append(role + '_removal_unconfirmed')
      except (Exception, KeyboardInterrupt, SystemExit) as failure:
        record_failure(role + '_cleanup_error', failure)
    if cleanup_errors:
      print('owned_container_cleanup_status=inconclusive')
    else:
      try:
        RUN_CID_DIR.rmdir()
      except (OSError, KeyboardInterrupt, SystemExit) as failure:
        record_failure('cid_directory_removal_unconfirmed', failure)
  if cleanup_errors:
    print('owned_container_cleanup_categories=' + json.dumps(sorted(set(cleanup_categories))))
  if interruption_collector is not None:
    interruption_collector.extend(interruptions)
  elif interruptions:
    raise interruptions[0]
  return cleanup_errors


def finish_owned_cleanup(registry_node, resolver_tools):
  """Fail successful runs if cleanup is incomplete; cleanup preserves interrupts."""
  cleanup_errors = cleanup_owned_resources(registry_node, resolver_tools)
  if cleanup_errors:
    raise RuntimeError(
        f'owned container cleanup incomplete; cleanup_error_count={cleanup_errors}')
  return cleanup_errors


def cleanup_after_failure(registry_node, resolver_tools):
  """Attempt all cleanup without replacing the scenario's active exception."""
  cleanup_interruptions = []
  return cleanup_owned_resources(registry_node, resolver_tools, cleanup_interruptions)


def _contains_key(value, key):
  if isinstance(value, dict):
    normalized = {str(name).lower() for name in value}
    if key == 'code':
      found = bool(normalized & {'code', 'authorization_code', 'oidc_code'})
    elif key == 'callback':
      found = any(name == 'callback' or name.startswith('callback_') for name in normalized)
    else:
      found = key.lower() in normalized
    return found or any(_contains_key(child, key) for child in value.values())
  if isinstance(value, list):
    return any(_contains_key(child, key) for child in value)
  return False


def _has_accepted_result(value):
  if isinstance(value, str):
    return value.strip().lower() == 'accepted'
  if isinstance(value, dict):
    if any(str(key).lower() in {'receipt', 'receipt_id', 'accepted_receipt'} for key in value):
      return True
    if str(value.get('status', '')).lower() == 'accepted':
      return True
    return any(_has_accepted_result(child) for child in value.values())
  if isinstance(value, list):
    return any(_has_accepted_result(child) for child in value)
  return False


def _expiry_body_is_safe(raw):
  if not raw:
    return True
  try:
    body = json.loads(raw)
  except (json.JSONDecodeError, UnicodeDecodeError):
    return False
  return not (_has_accepted_result(body) or _contains_key(body, 'callback')
      or _contains_key(body, 'code'))


def _expiry_location_is_safe(location):
  if not location:
    return True
  parsed = urllib.parse.urlsplit(location)
  query = urllib.parse.parse_qs(parsed.query)
  fragment = urllib.parse.parse_qs(parsed.fragment)
  keys = {str(key).lower() for key in query} | {str(key).lower() for key in fragment}
  sensitive = {'code', 'authorization_code', 'oidc_code', 'callback', 'receipt',
      'receipt_id', 'accepted_receipt'}
  return not (keys & sensitive
      or any(value.lower() == 'accepted'
          for values in (*query.values(), *fragment.values()) for value in values)
      or any(part in {'callback', 'receipt'} for part in parsed.path.lower().split('/')))


def _expiry_redirects_are_safe(redirects):
  return not bool(redirects)


def expiry_acceptance_passes(evidence):
  return (isinstance(evidence, dict) and evidence.get('stage') == 'complete'
      and evidence.get('login_page_http') == 200 and evidence.get('challenge_get_http') == 200
      and evidence.get('proof_post_http') == 404 and evidence.get('status_http') == 404
      and evidence.get('proof_denied') is True and evidence.get('status_denied') is True
      and evidence.get('no_accepted_receipt') is True and evidence.get('no_callback') is True
      and evidence.get('no_authorization_code') is True
      and evidence.get('fresh_login_http') == 200
      and evidence.get('fresh_challenge_http') == 200
      and evidence.get('fresh_locator_distinct') is True
      and evidence.get('fresh_login_transaction_available') is True
      and evidence.get('request_correlated_denial') is True
      and evidence.get('response_body_safe') is True and evidence.get('location_safe') is True
      and evidence.get('redirects_safe') is True
      and evidence.get('runtime_qualification_status') == 'runtime_facts_verified'
      and evidence.get('single_use_object_provider_path') == REQUIRED_SINGLE_USE_OBJECT_PROVIDER_ID)


def _parse_expiry_denial_provider(line, request_id, available_provider_ids):
  if not isinstance(line, str) or not isinstance(request_id, str):
    return None
  providers = ('infinispan', 'jpa', 'remote')
  provider_pattern = '|'.join(re.escape(provider_id) for provider_id in providers)
  match = re.search(r'Wallet transaction proof rejected \(request=' + re.escape(request_id)
      + r', reason=transaction_unavailable, provider=(' + provider_pattern + r')\)', line)
  if match is None or match.group(1) not in available_provider_ids:
    return None
  return match.group(1)


def _expiry_denial_signal(container_id, cursor, handle, available_provider_ids):
  request_id = hashlib.sha256(handle.encode('ascii')).digest()[:16].hex()
  deadline = time.monotonic() + 5
  while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
      return None
    try:
      logs = run(['podman', 'logs', '--since', str(cursor), container_id],
          timeout=1 if remaining < 2 else 2)
    except subprocess.TimeoutExpired:
      continue
    if logs.returncode == 0:
      output = logs.stdout.decode('utf-8', errors='replace') if isinstance(logs.stdout, bytes) else logs.stdout
      for line in output.splitlines():
        selected = _parse_expiry_denial_provider(line, request_id, available_provider_ids)
        if selected is not None:
          return selected
    time.sleep(min(0.25, max(0, deadline - time.monotonic())))


def transaction_ttl_seconds():
  source = (PROJECT_DIR / 'src/main/java/org/decentwallet/keycloak/wallet/'
      'WalletLoginTransactionStore.java').read_text(encoding='utf-8')
  match = re.search(r'public static final long TRANSACTION_LIFESPAN_SECONDS = ([0-9]+);', source)
  if match is None:
    raise RuntimeError('pending transaction TTL source constant is unavailable')
  ttl = int(match.group(1))
  if not 1 <= ttl <= EXPIRY_CONTAINER_LIFETIME_SECONDS - 120:
    raise RuntimeError('pending transaction TTL exceeds the bounded expiry-profile lifetime')
  return ttl


def expiry_profile_coordinator(client, key, identifier, container, image, checkpoint, runtime_facts):
  """Prove a valid wallet proof is denied after the production pending TTL."""
  ttl_seconds = transaction_ttl_seconds()
  evidence = {'stage': 'started', 'ttl_seconds': ttl_seconds,
      'wait_seconds': ttl_seconds + EXPIRY_WAIT_MARGIN_SECONDS,
      'runtime_qualification_status': runtime_facts.get(
          'runtime_qualification_status', 'open_runtime_facts_unavailable')}
  checkpoint(evidence)
  require(runtime_baseline_is_verified(runtime_facts),
      'expiry Keycloak version and single-node baseline are verified')
  verifier = b64url(secrets.token_bytes(32))
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(verifier.encode('ascii')).digest()),
      'code_challenge_method': 'S256',
  })
  login_http, _, login_page = client.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  evidence['login_page_http'] = login_http
  require(login_http == 200, 'expiry-profile Keycloak wallet login page', login_http)
  parsed_page = login_page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(parsed_page)
  locator = ''.join(parser.locator_parts).strip()
  expected_prefix = (f'{IDP_ORIGIN}:{KC_PORT}/auth/realms/{REALM}/'
      'decent-wallet-login/v1/transactions/')
  require(locator.startswith(expected_prefix), 'expiry-profile provider-owned transaction locator')
  status_match = re.search(r'const statusUrl = \"([^\"]+)\";', parsed_page)
  require(status_match is not None, 'expiry-profile browser-bound status URL')
  if status_match is None:
    raise RuntimeError('expiry-profile browser-bound status URL is unavailable')
  csrf_match = re.search(r'const csrfToken = \"([A-Za-z0-9_-]{43})\";', parsed_page)
  require(csrf_match is not None, 'expiry-profile browser-bound status CSRF')
  if csrf_match is None:
    raise RuntimeError('expiry-profile browser-bound status CSRF is unavailable')
  wallet = Client()
  challenge_http, _, challenge_raw = wallet.request('GET', locator)
  evidence['challenge_get_http'] = challenge_http
  require(challenge_http == 200, 'expiry-profile pending challenge GET', challenge_http)
  envelope = json.loads(challenge_raw)
  require(set(envelope) == {'profile', 'challenge', 'csrf_token'}
      and envelope['profile'] == 'decent-wallet-login-v1',
      'expiry-profile challenge envelope')
  signing_input = json.dumps({'challenge': envelope['challenge'],
      'identity_id': identifier, 'profile': envelope['profile']},
      ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
  with tempfile.TemporaryDirectory(prefix='wallet-expiry-signing-', dir=SCRATCH) as signing_dir:
    payload = write_private_signing_input(Path(signing_dir), 'expiry-proof', signing_input)
    try:
      signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key),
          '-in', str(payload)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
          timeout=10, check=False)
    finally:
      payload.unlink(missing_ok=True)
  require(signature.returncode == 0 and len(signature.stdout) == 64,
      'expiry-profile valid Ed25519 proof signature')
  proof = json.dumps({'profile': envelope['profile'], 'challenge': envelope['challenge'],
      'identity_id': identifier, 'signature': b64url(signature.stdout)},
      ensure_ascii=False, separators=(',', ':')).encode('utf-8')
  evidence['stage'] = 'transaction_created'
  checkpoint(evidence)
  time.sleep(evidence['wait_seconds'])
  handle = urllib.parse.urlsplit(locator).path.rstrip('/').split('/')[-1]
  cursor = time.time()
  wallet_redirect_cursor = len(wallet.redirects)
  client_redirect_cursor = len(client.redirects)
  proof_http, proof_headers, proof_raw = wallet.request('POST', locator, proof,
      {'Content-Type': 'application/json'})
  evidence.update({'stage': 'expired_proof_submitted', 'proof_post_http': proof_http})
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf_match.group(1)}
  status_http, status_response_headers, status_raw = client.request('GET',
      status_match.group(1), headers=status_headers)
  evidence['status_http'] = status_http
  try:
    proof_body = json.loads(proof_raw) if proof_raw else {}
  except (json.JSONDecodeError, UnicodeDecodeError):
    proof_body = {}
  try:
    status_body = json.loads(status_raw) if status_raw else {}
  except (json.JSONDecodeError, UnicodeDecodeError):
    status_body = {}
  locations = [proof_headers.get('Location', ''), status_response_headers.get('Location', '')]
  redirect_records = (wallet.redirects[wallet_redirect_cursor:]
      + client.redirects[client_redirect_cursor:])
  response_body_safe = _expiry_body_is_safe(proof_raw) and _expiry_body_is_safe(status_raw)
  location_safe = all(_expiry_location_is_safe(location) for location in locations)
  redirects_safe = _expiry_redirects_are_safe(redirect_records)
  no_authorization_code = (not _contains_key(proof_body, 'code')
      and not _contains_key(status_body, 'code') and location_safe and redirects_safe)
  no_accepted_receipt = (proof_http != 202 and not _has_accepted_result(proof_body)
      and not _has_accepted_result(status_body) and location_safe and redirects_safe)
  no_callback = (not _contains_key(proof_body, 'callback')
      and not _contains_key(status_body, 'callback') and location_safe and redirects_safe)
  if RUN_CID_DIR is None:
    raise RuntimeError('expiry profile run-owned container directory is unavailable')
  keycloak_cid = RUN_CID_DIR / 'keycloak.cid'
  keycloak_id = _inspect_cid(keycloak_cid)
  selected_provider = (_expiry_denial_signal(keycloak_id, cursor, handle,
      runtime_facts.get('single_use_object_provider_ids', [])) if keycloak_id is not None else None)
  request_correlated_denial = selected_provider is not None
  if selected_provider is not None:
    runtime_facts['single_use_object_provider_path'] = selected_provider
    runtime_facts['runtime_qualification_status'] = (
        'runtime_facts_verified' if runtime_qualification_is_verified(runtime_facts)
        else 'open_runtime_facts_unavailable')
  evidence.update({
      'proof_denied': proof_http == 404,
      'status_denied': status_http == 404,
      'no_accepted_receipt': no_accepted_receipt,
      'no_callback': no_callback,
      'no_authorization_code': no_authorization_code,
      'request_correlated_denial': request_correlated_denial,
      'single_use_object_provider_path': runtime_facts.get(
          'single_use_object_provider_path', 'unavailable'),
      'runtime_qualification_status': runtime_facts.get(
          'runtime_qualification_status', 'open_runtime_facts_unavailable'),
      'response_body_safe': response_body_safe, 'location_safe': location_safe,
      'redirects_safe': redirects_safe,
  })
  checkpoint(evidence)
  require(evidence['proof_denied'], 'expired valid proof is denied', proof_http)
  require(evidence['status_denied'], 'expired transaction status is denied', status_http)
  require(evidence['no_accepted_receipt'], 'expired proof created no accepted receipt')
  require(evidence['no_callback'], 'expired transaction exposes no callback')
  require(evidence['no_authorization_code'], 'expired transaction returned no OIDC authorization code')
  require(evidence['request_correlated_denial'],
      'expired proof has request-correlated production denial signal')

  recovery_verifier = b64url(secrets.token_bytes(32))
  recovery_query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(recovery_verifier.encode('ascii')).digest()),
      'code_challenge_method': 'S256',
  })
  fresh_login_http, _, fresh_login_page = client.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{recovery_query}')
  evidence.update({'stage': 'fresh_login_started', 'fresh_login_http': fresh_login_http})
  checkpoint(evidence)
  require(fresh_login_http == 200, 'new login required after transaction expiry', fresh_login_http)
  fresh_page_text = fresh_login_page.decode('utf-8', errors='strict')
  fresh_parser = LoginPageParser()
  fresh_parser.feed(fresh_page_text)
  fresh_locator = ''.join(fresh_parser.locator_parts).strip()
  fresh_locator_distinct = (fresh_locator != locator and fresh_locator.startswith(expected_prefix))
  evidence['fresh_locator_distinct'] = fresh_locator_distinct
  checkpoint(evidence)
  require(fresh_locator_distinct, 'expiry recovery starts a distinct fresh transaction')
  fresh_csrf = re.search(r'const csrfToken = \"([A-Za-z0-9_-]{43})\";', fresh_page_text)
  require(fresh_csrf is not None, 'fresh login status CSRF is available')
  if fresh_csrf is None:
    raise RuntimeError('fresh login status CSRF is unavailable')
  fresh_wallet = Client()
  fresh_challenge_http, _, fresh_challenge_raw = fresh_wallet.request('GET', fresh_locator)
  try:
    fresh_challenge = json.loads(fresh_challenge_raw) if fresh_challenge_raw else {}
  except (json.JSONDecodeError, UnicodeDecodeError):
    fresh_challenge = {}
  fresh_challenge_valid = (isinstance(fresh_challenge, dict)
      and set(fresh_challenge) == {'profile', 'challenge', 'csrf_token'}
      and fresh_challenge.get('profile') == 'decent-wallet-login-v1'
      and isinstance(fresh_challenge.get('challenge'), str)
      and bool(fresh_challenge['challenge'])
      and fresh_challenge.get('csrf_token') == fresh_csrf.group(1))
  fresh_login_transaction_available = (fresh_challenge_http == 200
      and fresh_locator_distinct and fresh_challenge_valid)
  evidence.update({
      'stage': 'fresh_login_verified', 'fresh_login_http': fresh_login_http,
      'fresh_challenge_http': fresh_challenge_http,
      'fresh_locator_distinct': fresh_locator_distinct,
      'fresh_login_transaction_available': fresh_login_transaction_available,
  })
  checkpoint(evidence)
  require(fresh_login_transaction_available,
      'fresh transaction is available after expired login', fresh_challenge_http)
  evidence['stage'] = 'complete'
  checkpoint(evidence)
  require(expiry_acceptance_passes(evidence), 'expiry profile acceptance gate')
  return evidence


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


class NoRedirects(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    return None


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
                        'X-Forwarded-Proto': 'https', 'X-Forwarded-Port': str(KC_PORT)})
      return urllib.request.Request(local, headers=forwarded, method='GET')
    return None


class Client:
  def __init__(self):
    self.redirects = []
    self.privateClientAdminCredential: str | None = None
    self.wallet_container_id: str | None = None
    cookie_processor = urllib.request.HTTPCookieProcessor()
    self.cookie_jar = cookie_processor.cookiejar
    self.opener = urllib.request.build_opener(
        cookie_processor, LocalKeycloakRedirects())
    self.no_redirect_opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(self.cookie_jar), NoRedirects())
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
        'X-Forwarded-Proto': 'https', 'X-Forwarded-Port': str(KC_PORT),
    }

  def url(self, path_or_url):
    parsed = urllib.parse.urlsplit(path_or_url)
    path = parsed.path if parsed.scheme else path_or_url
    query = parsed.query if parsed.scheme else ''
    if not path.startswith('/'):
      path = '/' + path
    result = f'http://127.0.0.1:{KC_PORT}{path}'
    return result + ('?' + query if query else '')

  def request(self, method, path, data=None, headers=None, timeout=10, *, follow_redirects=True):
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
    opener = self.opener if follow_redirects else self.no_redirect_opener
    try:
      with opener.open(req, timeout=timeout) as response:
        return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
      return error.code, error.headers, error.read()


class BareLocalClient(Client):
  def __init__(self):
    super().__init__()
    self.opener = urllib.request.build_opener(LocalKeycloakRedirects())

  def request(self, method, path, data=None, headers=None, timeout=10, *, follow_redirects=True):
    req = urllib.request.Request(self.url(path), data=data, headers=headers or {}, method=method)
    opener = self.opener if follow_redirects else self.no_redirect_opener
    try:
      with opener.open(req, timeout=timeout) as response:
        return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
      return error.code, error.headers, error.read()


def require(condition, stage, code=None, *, failure_gate=None, failure_stage=None, http_status=None):
  if not condition:
    valid_http_status = type(http_status) is int and 100 <= http_status <= 599
    detail = f' (HTTP {http_status})' if valid_http_status else (
        f' (code {code})' if type(code) is int else '')
    message = f'acceptance probe failed at {stage}' + detail
    active = _ACTIVE_AUTH_FLOW_ATTEMPT
    failure = active.failure(message, gate=failure_gate) if active is not None else RuntimeError(message)
    contextual_stage, contextual_gate = issue7_store_recovery.FAILURE_CONTEXTS.get(
        stage, ('signup_flow', 'unclassified'))
    explicit_gate = failure_gate if failure_gate in issue7_store_recovery.FAILURE_GATES else None
    setattr(failure, 'failure_stage', failure_stage or contextual_stage)
    setattr(failure, 'failure_gate', explicit_gate or contextual_gate)
    setattr(failure, 'failure_category', 'assertion_failed')
    if type(http_status) is int and 100 <= http_status <= 599:
      setattr(failure, 'failure_http_status', http_status)
    raise failure


def start_registry(temp, image, run_seconds=300):
  port = free_port()
  config = temp / 'registry.yaml'
  datastore = temp / 'registry-lmdb'
  datastore.mkdir(mode=0o700)
  config.write_text(
      f"network:\n  host: 127.0.0.1\n  port: {port}\n  bootstrap: []\n"
      f"datastore:\n  path: {datastore}\nlogging:\n  verbosity: 0\n",
      encoding='utf-8')
  container = f'wallet-login-registry-{uuid.uuid4().hex}'
  cid_file = _cid_file('registry')
  node = None
  try:
    _, container_id = start_owned_container(
        ['podman', 'run', '--detach', '--cidfile', str(cid_file), '--user', '0', '--name', container, '--network', 'host',
         '--volume', f'{config}:/tmp/registry.yaml:ro',
         '--volume', f'{datastore}:{datastore}:rw', '--entrypoint',
         '/opt/decent-resolver/bin/decent-registry', image,
         '-v', 'node', '--config', '/tmp/registry.yaml', '--run-seconds', str(run_seconds)],
        cid_file, timeout=30, stage='start packaged Registry')
    node = subprocess.Popen(['podman', 'logs', '--follow', container_id],
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
    cleanup_inconclusive = False
    try:
      stop_registry(node)
    except BaseException:
      cleanup_inconclusive = True
    try:
      removal = remove_owned_container(cid_file)
      cleanup_inconclusive |= (not removal['removed'] or removal['retained_cid'])
    except BaseException:
      cleanup_inconclusive = True
    if cleanup_inconclusive:
      print('registry_startup_cleanup_status=inconclusive')
    raise


def start_resolver_tools(temp, image, lifetime=300):
  container = f'wallet-login-resolver-tools-{uuid.uuid4().hex}'
  temp = Path(temp)
  cid_file = _cid_file('resolver-tools')
  _, container_id = start_owned_container(['podman', 'run', '--detach', '--cidfile', str(cid_file),
      '--user', '0', '--name', container, '--network', 'host', '--volume', f'{temp}:{temp}:rw',
      '--entrypoint', '/bin/sh', image, '-lc', f'sleep {int(lifetime)}'],
      cid_file, timeout=30, stage='start pinned resolver tools container')
  os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = container_id
  return container_id


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
    removed = run(['podman', 'rm', '--force', container], timeout=20)
    if removed.returncode != 0:
      raise RuntimeError('resolver tools container removal failed')


def stop_registry(node):
  """Stop the log follower; container removal is CID-file owned cleanup."""
  if node is not None and node.poll() is None:
    node.terminate()
    try:
      node.wait(timeout=8)
    except subprocess.TimeoutExpired:
      node.kill()
      node.wait(timeout=5)


def parse_dht_lookup_summary_line(line):
  match = re.fullmatch(
      r'DHT_LOOKUP_SUMMARY stage=(get_value|remote_identity) attempts=(\d{1,3}) '
      r'empty=(\d{1,3}) failed=(\d{1,3}) timeouts=(\d{1,3}) incomplete=(\d{1,3})',
      line)
  if not match:
    return None
  stage, *counts = match.groups()
  return stage, *(int(value) for value in counts)


def identity_lookup_category(line):
  if parse_dht_lookup_summary_line(line) is not None:
    return 'dht_lookup_summary'
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
  stripped = line.strip()
  if stripped.startswith('{') or (stripped.startswith('"') and ':' in stripped) or stripped == '}':
    return 'json'
  if line.startswith('history unavailable:'):
    return 'history_unavailable'
  if line.startswith('Traceback') or line.startswith('File ') or 'Error:' in line:
    return 'traceback'
  return 'other'


def classify_identity_lookup(stdout, exit_code, expected_identifier=None):
  lines = stdout.splitlines()
  categories = []
  summaries = {}
  invalid_summary = False
  for line in lines:
    stripped = line.strip()
    if not stripped:
      continue
    summary = parse_dht_lookup_summary_line(stripped)
    if stripped.startswith('DHT_LOOKUP_SUMMARY '):
      if summary is None or summary[0] in summaries:
        invalid_summary = True
      else:
        summaries[summary[0]] = summary[1:]
      continue
    categories.append(identity_lookup_category(stripped))
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
  required_stages = {'get_value', 'remote_identity'}
  summaries_clean = (not invalid_summary and set(summaries) == required_stages
      and all(attempts > 0 and empty == attempts and failed == 0 and timeouts == 0 and incomplete == 0
          for attempts, empty, failed, timeouts, incomplete in summaries.values()))
  absence_only = (explicit_terminal_miss and summaries_clean
      and all(item in ('registry_miss', 'not_found') for item in categories))
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


def verified_container_id(cidfile):
  path = Path(cidfile)
  try:
    value = path.read_text(encoding='ascii').strip()
  except OSError:
    raise RuntimeError('container ownership verification unavailable') from None
  if not re.fullmatch(r'[0-9a-f]{64}', value):
    raise RuntimeError('container ownership verification rejected cid')
  inspected = run(['podman', 'inspect', '--format', '{{.Id}}', value], timeout=15)
  if inspected.returncode != 0 or inspected.stdout.strip() != value:
    raise RuntimeError('container ownership verification failed')
  return value


def unlink_with_retries(path, attempts=3, sleep=time.sleep):
  path = Path(path)
  for attempt in range(attempts):
    try:
      path.unlink(missing_ok=True)
      return not path.exists()
    except OSError:
      if attempt + 1 == attempts:
        return False
      sleep(0.05 * (attempt + 1))
  return not path.exists()


def recover_keycloak_ownership(cidfile, returned_id, ownership_callback):
  """Adopt only an invocation CID whose full inspected ID matches its run result."""
  try:
    container_id = verified_container_id(cidfile)
  except Exception:
    return None
  if returned_id is not None and returned_id != container_id:
    return None
  if ownership_callback is not None:
    ownership_callback(Path(cidfile), container_id)
  return container_id


def start_keycloak(container, password, wrapper_path, resolver_port, bootstrap, image,
    ownership_callback=None, credential_status=None, single_use_object_provider=None,
    user_readback_fault_mode=None, store_fault_mode=None):
  if store_fault_mode is not None and (store_fault_mode not in issue7_store_recovery.PROFILES.values()
      or user_readback_fault_mode is not None or single_use_object_provider is not None):
    raise ValueError('unsupported or conflicting store fault mode')
  check = run(['ss', '-ltn', f'( sport = :{KC_PORT} )'], timeout=5)
  require('LISTEN' not in check.stdout, 'disposable Keycloak port available')
  env_fd, env_path = tempfile.mkstemp(prefix='wallet-login-admin-', suffix='.env', dir=SCRATCH)
  env_file = Path(env_path)
  cid_file = _cid_file('keycloak')
  credential_removed = False
  try:
    os.fchmod(env_fd, 0o600)
    with os.fdopen(env_fd, 'w', encoding='utf-8') as env_stream:
      env_stream.write('KC_BOOTSTRAP_ADMIN_PASSWORD=' + password + '\n')
    cmd = [
        'podman', 'run', '--detach', '--cidfile', str(cid_file), '--name', container, '--network', 'host',
        '--env-file', str(env_file),
        '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=wallet-admin',
    ]
    if store_fault_mode is not None:
      cmd.extend(['--env', 'ISSUE7_TEST_FAULT_MODE=' + store_fault_mode, image, 'start-dev'])
    elif user_readback_fault_mode is not None:
      add_test_user_readback_fault_args(cmd, image, user_readback_fault_mode)
    else:
      cmd.extend([image, 'start-dev'])
    cmd.extend([
        '--http-enabled=true', f'--http-port={KC_PORT}',
        '--http-relative-path=/auth', f'--hostname=https://idp.example:{KC_PORT}/auth',
        '--proxy-headers=xforwarded', '--proxy-trusted-addresses=127.0.0.1', '--db=dev-file', '--cache=local',
        '--log-level=info,org.decentwallet.keycloak.wallet:DEBUG,org.keycloak.connections.infinispan.DefaultInfinispanConnectionProviderFactory:debug'
    ])
    if single_use_object_provider is not None:
      require(single_use_object_provider in ISSUE6_TEST_PROVIDER_IDS,
          'explicit test provider ID is allowlisted')
      cmd.append(f'--spi-single-use-object--provider-default={single_use_object_provider}')
    started, container_id = start_owned_container(
        cmd, cid_file, timeout=40, stage='start disposable Keycloak',
        ownership_callback=ownership_callback)
  finally:
    credential_removed = unlink_with_retries(env_file)
    if credential_status is not None:
      credential_status['credential_file_retained'] = not credential_removed
    if not credential_removed:
      print('credential_file_status=', json.dumps({'credential_file_retained': True}))
  if not credential_removed:
    raise RuntimeError('protected credential file may remain; Keycloak startup stopped')
  if not isinstance(started, subprocess.CompletedProcess):
    raise RuntimeError("Keycloak start returned no result")
  if started.returncode != 0:
    raise RuntimeError("acceptance probe failed at start disposable Keycloak")
  client = Client()
  client.privateClientAdminCredential = password
  client.wallet_container_id = container_id
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
    logs = run(['podman', 'logs', '--tail', '80', container_id], timeout=15)
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


def login_error_event_delta(previous, current):
  if not isinstance(previous, list) or not isinstance(current, list):
    return {'read': False, 'count': 0, 'category': 'unavailable'}
  remaining = list(previous[:20])
  new_errors = []
  for event in current[:20]:
    if not isinstance(event, dict):
      continue
    signature = (event.get('type'), event.get('error'),
        tuple(event.get('detail_names', [])) if isinstance(event.get('detail_names'), list) else ())
    for index, old_event in enumerate(remaining):
      if not isinstance(old_event, dict):
        continue
      old_signature = (old_event.get('type'), old_event.get('error'),
          tuple(old_event.get('detail_names', []))
              if isinstance(old_event.get('detail_names'), list) else ())
      if signature == old_signature:
        del remaining[index]
        break
    else:
      if event.get('type') == 'LOGIN_ERROR':
        raw_error = event.get('error')
        safe_error = raw_error if isinstance(raw_error, str) and raw_error in {
            'invalid_code', 'expired_code', 'already_logged_in', 'cookie_not_found',
            'invalid_request', 'invalid_redirect_uri', 'access_denied', 'user_not_found'} \
            else 'other'
        new_errors.append(safe_error)
  category_set = set(new_errors)
  category = 'none' if not new_errors else (
      next(iter(category_set)) if len(category_set) == 1 else 'multiple')
  return {'read': True, 'count': min(len(new_errors), 20), 'category': category}


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
          # The decentralized Identity ID intentionally remains under .invalid;
          # Keycloak requires its separate email field to be syntactically valid.
          'email': 'wallet-owner@example.com', 'emailVerified': True,
          'firstName': 'Synthetic', 'lastName': 'Wallet',
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


def wallet_transport_log_categories(container_id):
  """Project bounded Keycloak logs to allowlisted failure counters."""
  try:
    result = run(['podman', 'logs', '--tail', '120', container_id], timeout=15)
  except (OSError, subprocess.TimeoutExpired):
    return {'log_read_status': 'error'}
  text = subprocess_output_text(result)
  categories = {
      'identity_resolver_unavailable': 'Wallet Identity resolver unavailable',
      'account_mapping_unavailable': 'Wallet account mapping lookup unavailable',
      'proof_acceptance_unavailable': 'Wallet proof acceptance unavailable',
      'pending_transaction_unavailable': 'Wallet pending transaction unavailable',
      'transaction_proof_rejected': 'Wallet transaction proof rejected',
      'receipt_fault': 'ISSUE6_TEST_FAULT: accepted receipt delegate write committed',
      'callback_gate_fault': 'ISSUE6_TEST_FAULT: callback gate delegate putIfAbsent committed',
  }
  return {'log_read_status': 'ok' if result.returncode == 0 else 'error',
      **{key: text.count(marker) for key, marker in categories.items()}}


def callback_replay_guard_log_outcome(log_text, request_id):
  """Reduce replay-guard log lines to request-correlation facts only."""
  if not isinstance(log_text, str) or not isinstance(request_id, str) \
      or re.fullmatch(r'[0-9a-f]{32}', request_id) is None:
    return {'marker_count': 0, 'unavailable_marker_count': 0,
        'other_marker_count': 0, 'reached': False}
  prefix = 'Wallet callback replay guard entered (request='
  total = min(log_text.count(prefix), 10)
  pattern = re.compile(re.escape(prefix)
      + r'([0-9a-f]{32}|unavailable), state_present=(true|false), '
        r'redirect_uri_present=(true|false), redirect_uri_registered=(true|false), '
        r'protocol_openid_connect=(true|false)\)')
  markers = pattern.findall(log_text)
  expected = [marker for marker in markers if marker[0] == request_id]
  unavailable = sum(marker[0] == 'unavailable' for marker in markers)
  other = sum(marker[0] not in {request_id, 'unavailable'} for marker in markers)
  reached = total == 1 and len(markers) == 1 and len(expected) == 1
  result = {'marker_count': total,
      'unavailable_marker_count': min(unavailable, 10),
      'other_marker_count': min(other, 10), 'reached': reached}
  if reached:
    result.update({
        'state_present': expected[0][1] == 'true',
        'redirect_uri_present': expected[0][2] == 'true',
        'redirect_uri_registered': expected[0][3] == 'true',
        'protocol_openid_connect': expected[0][4] == 'true',
    })
  return result


def callback_authenticator_lifecycle_log_outcome(log_text, request_id):
  """Reduce authenticator-entry and top-flow-rearm logs to bounded request facts."""
  result = {
      'authenticator_entry_marker_count': 0,
      'authenticator_entry_unavailable_marker_count': 0,
      'authenticator_entry_other_marker_count': 0,
      'authenticator_entry_callback_completed_true_marker_count': 0,
      'authenticator_entry_callback_completed_false_marker_count': 0,
      'authenticator_entry_reached': False,
      'authenticator_entry_completed_marker_present': False,
      'callback_flow_rearm_marker_count': 0,
      'callback_flow_rearm_unavailable_marker_count': 0,
      'callback_flow_rearm_other_marker_count': 0,
      'callback_flow_rearmed': False,
      'callback_flow_rearm_execution_id_present': False,
  }
  if not isinstance(log_text, str) or not isinstance(request_id, str) \
      or re.fullmatch(r'[0-9a-f]{32}', request_id) is None:
    return result

  entry_prefix = 'Wallet challenge authenticator entered (request='
  entry_total = min(log_text.count(entry_prefix), 10)
  entry_pattern = re.compile(re.escape(entry_prefix)
      + r'([0-9a-f]{32}|unavailable), callback_completed=(true|false)\)')
  entries = entry_pattern.findall(log_text)
  matching_entries = [entry for entry in entries if entry[0] == request_id]
  result.update({
      'authenticator_entry_marker_count': entry_total,
      'authenticator_entry_unavailable_marker_count': min(
          sum(entry[0] == 'unavailable' for entry in entries), 10),
      'authenticator_entry_other_marker_count': min(
          sum(entry[0] not in {request_id, 'unavailable'} for entry in entries), 10),
      'authenticator_entry_callback_completed_true_marker_count': min(
          sum(entry[1] == 'true' for entry in entries), 10),
      'authenticator_entry_callback_completed_false_marker_count': min(
          sum(entry[1] == 'false' for entry in entries), 10),
      'authenticator_entry_reached': bool(matching_entries),
      'authenticator_entry_completed_marker_present': any(
          entry[1] == 'true' for entry in matching_entries),
  })

  rearm_prefix = 'Wallet callback execution rearmed (request='
  rearm_total = min(log_text.count(rearm_prefix), 10)
  rearm_pattern = re.compile(re.escape(rearm_prefix)
      + r'([0-9a-f]{32}|unavailable), execution_id_present=(true|false)\)')
  rearms = rearm_pattern.findall(log_text)
  matching_rearms = [event for event in rearms if event[0] == request_id]
  result.update({
      'callback_flow_rearm_marker_count': rearm_total,
      'callback_flow_rearm_unavailable_marker_count': min(
          sum(event[0] == 'unavailable' for event in rearms), 10),
      'callback_flow_rearm_other_marker_count': min(
          sum(event[0] not in {request_id, 'unavailable'} for event in rearms), 10),
      'callback_flow_rearmed': any(event[1] == 'true' for event in matching_rearms),
      'callback_flow_rearm_execution_id_present': any(
          event[1] == 'true' for event in matching_rearms),
  })
  return result


def subject_matches_expected(claims, expected_subject):
  """Compare an ID-token subject without returning the private subject value."""
  return claims.get('sub') == expected_subject


def auth_flow(client, key, identifier, container, image, *, prior_locator=None,
    progress_callback=None, admin_access_token=None, expected_subject=None):
  def report_progress(stage, **facts):
    if progress_callback is not None:
      progress_callback(stage, facts)

  verifier = b64url(secrets.token_bytes(32))
  challenge = b64url(hashlib.sha256(verifier.encode('ascii')).digest())
  state = b64url(secrets.token_bytes(24))
  nonce = b64url(secrets.token_bytes(24))
  from datetime import datetime, timezone
  callback_flow_log_cursor = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': state, 'nonce': nonce,
      'code_challenge': challenge, 'code_challenge_method': 'S256',
  })
  status, _, page = client.request('GET', f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  report_progress('fresh_login_page', fresh_login_http=status)
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
  if prior_locator is not None:
    require(locator != prior_locator, 'fresh login creates a distinct transaction locator')
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
  report_progress('fresh_challenge', fresh_challenge_http=wallet_status)
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
  proof_fields = {'profile': envelope['profile'], 'challenge': envelope['challenge'],
      'identity_id': identifier, 'signature': b64url(sig.stdout)}
  proof = json.dumps(proof_fields, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
  submitted, proof_headers, accepted = wallet.request('POST', locator, proof, {'Content-Type': 'application/json'})
  report_progress('fresh_proof', fresh_proof_http=submitted)
  require_transport_security_headers(proof_headers, 'native proof security headers')
  record_auth_flow_outcome('proof_post_http', submitted)
  if submitted != 202:
    print('wallet_proof_failure_categories=' + json.dumps(
        wallet_transport_log_categories(container), sort_keys=True))
  require(submitted == 202 and json.loads(accepted).get('status') == 'pending',
      'valid wallet proof POST', submitted, failure_gate='proof_post', http_status=submitted)
  diagnostic = run(['podman', 'logs', '--tail', '80', container], timeout=15)
  print('diagnostic-log-lines:', len(diagnostic.stdout.splitlines()))
  for line in diagnostic.stdout.splitlines():
    if '[WALLET-RESOLVER-DIAG]' in line:
      print('resolver-diagnostic:', 'Identity resolver failure')
  retried, _, retry_raw = wallet.request('POST', locator, proof, {'Content-Type': 'application/json'})
  report_progress('fresh_identical_retry', fresh_retry_http=retried)
  record_auth_flow_outcome('identical_retry_http', retried)
  require(retried == 202 and json.loads(retry_raw).get('status') == 'accepted',
      'identical native proof retry', retried, failure_gate='identical_retry', http_status=retried)
  accepted_by_browser, _, browser_retry_body = client.request('POST', locator, proof,
      {'Content-Type': 'application/json', 'X-Decent-CSRF': browser_csrf,
       'Origin': WALLET_ORIGIN, 'Sec-Fetch-Site': 'cross-site',
       'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty'})
  require(accepted_by_browser == 202 and json.loads(browser_retry_body).get('status') == 'accepted',
      'identical browser proof retry preserves the initiating session')
  changed_key = key.parent / ('issue6-changed-proof-' + uuid.uuid4().hex + '.pem')
  try:
    changed_key_fd = os.open(changed_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(changed_key_fd)
    changed_key_result = subprocess.run(
        ['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(changed_key)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    require(changed_key_result.returncode == 0, 'generate alternate Ed25519 replay key',
        failure_gate='changed_retry')
    with tempfile.TemporaryDirectory(prefix='issue6-replay-signing-', dir=key.parent) as signing_dir:
      payload = write_private_signing_input(signing_dir, 'changed-proof', signed)
      try:
        changed_signature = subprocess.run(
            ['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(changed_key), '-in', str(payload)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
      finally:
        payload.unlink(missing_ok=True)
    require(changed_signature.returncode == 0 and len(changed_signature.stdout) == 64,
        'alternate Ed25519 signature over identical canonical proof payload',
        failure_gate='changed_retry')
    changed_proof = changed_signed_proof(proof, changed_signature.stdout)
    require(json.loads(changed_proof).get('signature') != json.loads(proof).get('signature'),
        'changed proof has distinct signature bytes', failure_gate='changed_retry')
    changed, _, _ = wallet.request('POST', locator, changed_proof, {'Content-Type': 'application/json'})
  finally:
    changed_key.unlink(missing_ok=True)
  record_auth_flow_outcome('changed_retry_http', changed)
  report_progress('fresh_changed_retry', fresh_changed_retry_http=changed)
  require(changed == 409, 'changed-signature proof replay denied', changed,
      failure_gate='changed_retry', http_status=changed)
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
  record_auth_flow_outcome('initial_status_http', polled)
  initial_status_accepted = accepted_status_payload(polled, status_raw)
  report_progress('fresh_status', fresh_status_http=polled,
      fresh_login_transaction_available=(prior_locator is None or locator != prior_locator)
          and initial_status_accepted)
  record_auth_flow_outcome('initial_status_accepted', initial_status_accepted)
  require(initial_status_accepted, 'initiating browser observes accepted receipt and callback',
      polled, failure_gate='proof_status', http_status=polled)
  status_obj = json.loads(status_raw)
  callback = status_obj.get('callback')
  require(callback and callback.startswith(f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/'),
      'same-issuer callback')
  callback_status, response_headers, callback_body = client.request('GET', callback)
  location = response_headers.get('Location', '')
  callback_outcome = callback_redirect_outcome(location, state, REDIRECT)
  callback_target_matches = callback_outcome['redirect_uri_matches']
  callback_state_matches = callback_outcome['state_preserved']
  callback_code_returned = callback_outcome['single_authorization_code_returned']
  callback_error_returned = callback_outcome['error_parameter_present']
  callback_parts = urllib.parse.urlsplit(location)
  callback_query = urllib.parse.parse_qs(callback_parts.query, keep_blank_values=True)
  code_values = callback_query.get('code', [])
  code = code_values[0] if callback_code_returned else None
  report_progress('fresh_callback', callback_http=callback_status,
      callback_state_preserved=callback_state_matches,
      callback_code_returned=callback_code_returned,
      callback_error_returned=callback_error_returned)
  record_auth_flow_outcome('callback_http', callback_status)
  record_auth_flow_outcome('callback_redirect_uri_matches', callback_target_matches)
  record_auth_flow_outcome('callback_state_preserved', callback_state_matches)
  record_auth_flow_outcome('callback_code_returned', callback_code_returned)
  record_auth_flow_outcome('callback_error_returned', callback_error_returned)
  require(callback_status in {302, 303} and callback_target_matches and callback_state_matches
      and not callback_error_returned,
      'OIDC callback uses registered redirect URI and preserves state', callback_status,
      failure_gate='callback', http_status=callback_status)
  require(code is not None, 'Keycloak callback returns exactly one authorization code', callback_status,
      failure_gate='callback', http_status=callback_status)
  replay_login_errors_before = None
  if admin_access_token is not None:
    try:
      replay_login_errors_before = recent_login_error_categories(Client(), admin_access_token)
    except Exception:
      replay_login_errors_before = None
  callback_replay_log_cursor = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
  repeated_status, repeated_headers, _ = client.request('GET', callback, follow_redirects=False)
  report_progress('fresh_replay', callback_replay_http=repeated_status)
  replay_login_errors_after = None
  if admin_access_token is not None:
    try:
      replay_login_errors_after = recent_login_error_categories(Client(), admin_access_token)
    except Exception:
      replay_login_errors_after = None
  replay_login_error_delta = login_error_event_delta(
      replay_login_errors_before, replay_login_errors_after)
  replay_logs = run(['podman', 'logs', '--since', callback_replay_log_cursor,
      '--timestamps', container], timeout=15)
  flow_logs = run(['podman', 'logs', '--since', callback_flow_log_cursor,
      '--timestamps', container], timeout=15)
  replay_log_read = replay_logs.returncode == 0 and flow_logs.returncode == 0
  replay_log_text = subprocess_output_text(replay_logs) if replay_logs.returncode == 0 else ''
  flow_log_text = subprocess_output_text(flow_logs) if flow_logs.returncode == 0 else ''
  request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
  replay_guard = callback_replay_guard_log_outcome(
      replay_log_text if replay_logs.returncode == 0 else '', request_id)
  lifecycle = callback_authenticator_lifecycle_log_outcome(
      replay_log_text if replay_logs.returncode == 0 else '', request_id)
  flow_lifecycle = callback_authenticator_lifecycle_log_outcome(
      flow_log_text if flow_logs.returncode == 0 else '', request_id)
  for field in ('callback_flow_rearm_marker_count',
      'callback_flow_rearm_unavailable_marker_count', 'callback_flow_rearm_other_marker_count',
      'callback_flow_rearmed', 'callback_flow_rearm_execution_id_present'):
    lifecycle[field] = flow_lifecycle[field]
  marker_count = replay_guard['marker_count']
  replay_guard_reached = replay_guard['reached']
  replay_guard_facts = {
      'callback_replay_guard_log_read': replay_log_read,
      'callback_replay_guard_reached': replay_guard_reached,
      'callback_replay_guard_marker_count': marker_count,
      'callback_replay_guard_unavailable_marker_count': replay_guard['unavailable_marker_count'],
      'callback_replay_guard_other_marker_count': replay_guard['other_marker_count'],
      'callback_replay_authenticator_entry_reached': lifecycle['authenticator_entry_reached'],
      'callback_replay_authenticator_entry_completed': lifecycle[
          'authenticator_entry_completed_marker_present'],
      'callback_replay_authenticator_entry_marker_count': lifecycle[
          'authenticator_entry_marker_count'],
      'callback_replay_authenticator_entry_unavailable_marker_count': lifecycle[
          'authenticator_entry_unavailable_marker_count'],
      'callback_replay_authenticator_entry_other_marker_count': lifecycle[
          'authenticator_entry_other_marker_count'],
      'callback_replay_authenticator_entry_completed_true_marker_count': lifecycle[
          'authenticator_entry_callback_completed_true_marker_count'],
      'callback_replay_authenticator_entry_completed_false_marker_count': lifecycle[
          'authenticator_entry_callback_completed_false_marker_count'],
      'callback_replay_login_error_log_read': replay_login_error_delta['read'],
      'callback_replay_login_error_count': replay_login_error_delta['count'],
      'callback_replay_login_error_category': replay_login_error_delta['category'],
      'callback_top_flow_rearm_reached': lifecycle['callback_flow_rearmed'],
      'callback_top_flow_rearm_execution_id_present': lifecycle[
          'callback_flow_rearm_execution_id_present'],
      'callback_top_flow_rearm_marker_count': lifecycle['callback_flow_rearm_marker_count'],
      'callback_top_flow_rearm_unavailable_marker_count': lifecycle[
          'callback_flow_rearm_unavailable_marker_count'],
      'callback_top_flow_rearm_other_marker_count': lifecycle[
          'callback_flow_rearm_other_marker_count'],
  }
  if replay_guard_reached:
    replay_guard_facts.update({
        'callback_replay_state_present': replay_guard['state_present'],
        'callback_replay_redirect_uri_present': replay_guard['redirect_uri_present'],
        'callback_replay_redirect_uri_registered': replay_guard['redirect_uri_registered'],
        'callback_replay_protocol_openid_connect': replay_guard['protocol_openid_connect'],
    })
  report_progress('fresh_replay', **replay_guard_facts)
  repeated_location = repeated_headers.get('Location', '')
  callback_replay = callback_replay_outcome(
      repeated_status, repeated_location, state, REDIRECT, callback)
  report_progress('fresh_replay', callback_replay_http=repeated_status,
      callback_replay_state_preserved=callback_replay['state_preserved'],
      callback_replay_error_returned=callback_replay['error_returned'],
      callback_replay_code_returned=callback_replay['authorization_code_returned'])
  record_auth_flow_outcome('callback_replay_http', repeated_status)
  record_auth_flow_outcome('callback_replay_redirect_uri_matches', callback_replay['redirect_uri_matches'])
  record_auth_flow_outcome('callback_replay_state_preserved', callback_replay['state_preserved'])
  record_auth_flow_outcome('callback_replay_error_returned', callback_replay['error_returned'])
  record_auth_flow_outcome('callback_replay_code_returned', callback_replay['authorization_code_returned'])
  record_auth_flow_outcome('callback_replay_internal_error_page', callback_replay['internal_error_page'])
  record_auth_flow_outcome('callback_replay_internal_error_reason', callback_replay['internal_error_reason'])
  record_auth_flow_outcome('callback_replay_internal_error_hostname_matches',
      callback_replay['internal_error_hostname_matches'])
  record_auth_flow_outcome('callback_replay_internal_error_port_matches',
      callback_replay['internal_error_port_matches'])
  record_auth_flow_outcome('callback_replay_guard_log_read', replay_log_read)
  record_auth_flow_outcome('callback_replay_guard_reached', replay_guard_reached)
  record_auth_flow_outcome('callback_replay_guard_marker_count', marker_count)
  record_auth_flow_outcome('callback_replay_guard_unavailable_marker_count',
      replay_guard['unavailable_marker_count'])
  record_auth_flow_outcome('callback_replay_guard_other_marker_count',
      replay_guard['other_marker_count'])
  record_auth_flow_outcome('callback_replay_authenticator_entry_reached',
      lifecycle['authenticator_entry_reached'])
  record_auth_flow_outcome('callback_replay_authenticator_entry_completed',
      lifecycle['authenticator_entry_completed_marker_present'])
  record_auth_flow_outcome('callback_replay_authenticator_entry_marker_count',
      lifecycle['authenticator_entry_marker_count'])
  record_auth_flow_outcome('callback_replay_authenticator_entry_unavailable_marker_count',
      lifecycle['authenticator_entry_unavailable_marker_count'])
  record_auth_flow_outcome('callback_replay_authenticator_entry_other_marker_count',
      lifecycle['authenticator_entry_other_marker_count'])
  record_auth_flow_outcome('callback_replay_authenticator_entry_completed_true_marker_count',
      lifecycle['authenticator_entry_callback_completed_true_marker_count'])
  record_auth_flow_outcome('callback_replay_authenticator_entry_completed_false_marker_count',
      lifecycle['authenticator_entry_callback_completed_false_marker_count'])
  record_auth_flow_outcome('callback_replay_login_error_log_read', replay_login_error_delta['read'])
  record_auth_flow_outcome('callback_replay_login_error_count', replay_login_error_delta['count'])
  record_auth_flow_outcome('callback_replay_login_error_category',
      replay_login_error_delta['category'])
  record_auth_flow_outcome('callback_top_flow_rearm_reached', lifecycle['callback_flow_rearmed'])
  record_auth_flow_outcome('callback_top_flow_rearm_execution_id_present',
      lifecycle['callback_flow_rearm_execution_id_present'])
  record_auth_flow_outcome('callback_top_flow_rearm_marker_count',
      lifecycle['callback_flow_rearm_marker_count'])
  record_auth_flow_outcome('callback_top_flow_rearm_unavailable_marker_count',
      lifecycle['callback_flow_rearm_unavailable_marker_count'])
  record_auth_flow_outcome('callback_top_flow_rearm_other_marker_count',
      lifecycle['callback_flow_rearm_other_marker_count'])
  if replay_guard_reached:
    record_auth_flow_outcome('callback_replay_state_present', replay_guard['state_present'])
    record_auth_flow_outcome('callback_replay_redirect_uri_present', replay_guard['redirect_uri_present'])
    record_auth_flow_outcome('callback_replay_redirect_uri_registered', replay_guard['redirect_uri_registered'])
    record_auth_flow_outcome('callback_replay_protocol_openid_connect', replay_guard['protocol_openid_connect'])
  record_auth_flow_outcome('callback_replay_denied_safely', callback_replay['replay_denied_safely'])
  if not callback_replay['replay_denied_safely']:
    safe_replay_fields = {key: callback_replay[key] for key in (
        'redirect_http', 'redirect_uri_matches', 'state_preserved', 'error_returned',
        'authorization_code_returned', 'internal_error_page', 'internal_error_reason',
        'internal_error_hostname_matches', 'internal_error_port_matches')}
    replay_parts = urllib.parse.urlsplit(repeated_location)
    safe_replay_fields.update({
        'redirect_scheme': replay_parts.scheme or 'relative',
        'redirect_path': replay_parts.path or 'unavailable',
        'redirect_query_names': sorted(set(urllib.parse.parse_qs(
            replay_parts.query, keep_blank_values=True)))[:32],
    })
    print('callback_replay_diagnostic=' + json.dumps(safe_replay_fields, sort_keys=True))
  require(callback_replay['replay_denied_safely'],
      'consumed callback replay is denied without an authorization code',
      repeated_status, failure_gate='callback_replay', http_status=repeated_status)
  status_after_callback, _, status_after_callback_raw = client.request(
      'GET', status_url, headers=poll_headers)
  status_after_callback_safe = status_after_callback == 404 and b'callback' not in status_after_callback_raw.lower()
  record_auth_flow_outcome('status_after_callback_http', status_after_callback)
  record_auth_flow_outcome('status_after_callback_safe', status_after_callback_safe)
  require(status_after_callback_safe,
      'consumed callback is no longer advertised by browser status',
      status_after_callback, failure_gate='status_after_callback', http_status=status_after_callback)
  form = urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': CLIENT,
      'code': code, 'redirect_uri': REDIRECT, 'code_verifier': verifier}).encode()
  token_status, _, token_raw = client.request('POST',
      f'/auth/realms/{REALM}/protocol/openid-connect/token', form,
      {'Content-Type': 'application/x-www-form-urlencoded'})
  record_auth_flow_outcome('pkce_token_http', token_status)
  report_progress('fresh_pkce', pkce_token_http=token_status)
  require(token_status == 200, 'OIDC Code+PKCE token exchange', token_status,
      failure_gate='pkce', http_status=token_status)
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
  subject_match = (subject_matches_expected(claims, expected_subject)
      if expected_subject is not None else None)
  if subject_match is not None:
    require(subject_match, 'fresh login returns retained exact account subject')
  auth_result = {
      'login_page_http': status,
      'proof_post_http': submitted, 'initial_status_http': polled,
      'initial_status_accepted': initial_status_accepted,
      'identical_retry_http': retried, 'changed_retry_http': changed,
      'callback_http': callback_status,
      'callback_redirect_uri_matches': callback_target_matches,
      'callback_state_preserved': callback_state_matches,
      'callback_code_returned': bool(code),
      'callback_replay_http': callback_replay['redirect_http'],
      'callback_replay_redirect_uri_matches': callback_replay['redirect_uri_matches'],
      'callback_replay_state_preserved': callback_replay['state_preserved'],
      'callback_replay_error_returned': callback_replay['error_returned'],
      'callback_replay_code_returned': callback_replay['authorization_code_returned'],
      'callback_replay_denied_safely': callback_replay['replay_denied_safely'],
      'callback_replay_guard_log_read': replay_log_read,
      'callback_replay_guard_reached': replay_guard_reached,
      'callback_replay_guard_marker_count': marker_count,
      'callback_replay_guard_unavailable_marker_count': replay_guard['unavailable_marker_count'],
      'callback_replay_guard_other_marker_count': replay_guard['other_marker_count'],
      **({
          'callback_replay_state_present': replay_guard['state_present'],
          'callback_replay_redirect_uri_present': replay_guard['redirect_uri_present'],
          'callback_replay_redirect_uri_registered': replay_guard['redirect_uri_registered'],
          'callback_replay_protocol_openid_connect': replay_guard['protocol_openid_connect'],
      } if replay_guard_reached else {}),
      'status_after_callback_http': status_after_callback,
      'status_after_callback_safe': status_after_callback_safe,
      'pkce_token_http': token_status,
  }
  if prior_locator is not None:
    auth_result['fresh_locator_distinct'] = locator != prior_locator
  if subject_match is not None:
    auth_result['local_subject_matches_expected'] = subject_match
  return auth_result


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
    resolver_port, bootstrap, wrapper_name, progress, image, rotation_root, expected_sequence=2):
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
    require(len(readback) == 2 and readback[0] == str(expected_sequence)
        and readback[1] == expected_key.stdout[-32:].hex(),
        f'separate Identity resolver confirms sequence {expected_sequence} and exact successor key')
    progress('readback', {'rotation_publish': 'read_back_exact', 'current_sequence': expected_sequence})
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
          'rotation_publish': 'read_back_exact', 'current_sequence': expected_sequence,
          'resolver_samples': samples}),
  )
  progress('readback', {'rotation_publish': 'read_back_exact', 'current_sequence': expected_sequence,
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
  return {'rotation_publish': 'passed', 'current_sequence': expected_sequence,
      'current_key_proof_http': current_key_status, 'stale_key_proof_http': stale_key_status,
      'stale_transaction_remains_pending': True, 'current_transaction_accepted': True}




def sanitized_resolver_diagnostic_lines(text):
  if not isinstance(text, str):
    return []
  allowed = {'registry_miss', 'dial_warning', 'peer_handshake', 'peer_error',
      'history_unavailable', 'dht_lookup_unavailable', 'traceback', 'process_start', 'nonzero_exit', 'unknown', 'success',
      'timeout', 'interrupted', 'termination_interrupted', 'output_overflow'}
  dht_count = r'[0-9]{1,3}'
  dht_stage = re.compile(r'(?:get_value|remote_identity):' + '/'.join([dht_count] * 5))
  output = []
  for line in text.splitlines()[-300:]:
    if len(line) > 2048:
      continue
    marker = '[WALLET-RESOLVER-DIAG]'
    if marker not in line:
      continue
    suffix = line.split(marker, 1)[1].strip()
    match = re.fullmatch(
        r'exit=(-?[0-9]+), reason=([a-z_|]+), lines=([0-9]+), capped=(true|false), dht=([^,]+)', suffix)
    if not match:
      output.append('invalid')
      continue
    exit_code, reason, count, _, dht = match.groups()
    stage_summaries = [] if dht == 'none' else dht.split('|')
    parsed_stages = [dht_stage.fullmatch(summary) for summary in stage_summaries]
    if (dht not in {'none', 'invalid'} and (not parsed_stages or any(item is None for item in parsed_stages)
        or len(stage_summaries) > 2
        or len({item.group(0).split(':', 1)[0] for item in parsed_stages if item}) != len(stage_summaries))):
      output.append('invalid')
      continue
    if dht == 'invalid':
      output.append('invalid')
      continue
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



def signup_wallet_flow(client, key, identifier, container, admin_client, progress, image,
    expect_user_readback_fault=False, reuse_existing=False, expected_fault_mode=None,
    store_fault_mode=None):
  if store_fault_mode is not None and (store_fault_mode not in issue7_store_recovery.PROFILES.values()
      or expect_user_readback_fault or reuse_existing):
    raise ValueError('unsupported or conflicting signup store fault mode')
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
  require(status == 200, 'signup login page', status, http_status=status)
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
  require(action_status == 200, 'Keycloak action records signup intent and restarts wallet flow',
      action_status, http_status=action_status)
  signup_text = signup_page.decode('utf-8', errors='strict')
  require('Creating a new account with this wallet identity.' in signup_text,
      'fresh wallet transaction is bound to signup intent')
  parser = LoginPageParser(); parser.feed(signup_text)
  signup_locator = ''.join(parser.locator_parts).strip()
  provider_request_id = account_policy_request_id(signup_locator)
  status_url = re.search(r'const statusUrl = "([^"]+)";', signup_text)
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', signup_text)
  require(status_url is not None and csrf is not None, 'signup transaction browser binding')
  if status_url is None or csrf is None:
    raise RuntimeError('acceptance probe failed at signup transaction binding')
  wallet = Client()
  challenge_status, _, challenge_raw = wallet.request('GET', signup_locator)
  require(challenge_status == 200, 'signup native challenge GET', http_status=challenge_status)
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
  if reuse_existing:
    require(len(existing_exact_users) == 1 and existing_exact_users[0].get('enabled') is True,
        'fresh explicit signup starts with one exact retained enabled account')
    expected_subject = existing_exact_users[0].get('id')
  else:
    require(not existing_exact_users, 'no exact Keycloak account exists before signup proof')
    expected_subject = None
  factory_selected = False
  effective_fault_mode = None
  diagnostics = {'factory_selected': False, 'effective_fault_mode': None,
      'post_create_read_fault_count': 0, 'correlated_mapping_failure_count': 0}
  request_id = ''
  log_cursor = ''
  if expect_user_readback_fault:
    startup_diagnostics = sanitize_user_readback_fault_diagnostics(
        read_provider_fault_log_tail(container))
    factory_selected = startup_diagnostics['factory_selected']
    effective_fault_mode = startup_diagnostics['effective_fault_mode']
    if expected_fault_mode not in {'empty', 'throw', 'over-cap'}:
      raise ValueError('expected UserProvider fault mode is invalid')
    handle = urllib.parse.urlsplit(signup_locator).path.rsplit('/', 1)[-1]
    request_id = hashlib.sha256(handle.encode('ascii')).hexdigest()[:32]
    log_cursor = utc_log_cursor()
  if store_fault_mode is not None:
    log_cursor = utc_log_cursor()
  redirects_before_proof = len(wallet.redirects)
  try:
    proof_status, proof_headers, proof_body = wallet.request('POST', signup_locator, proof,
        {'Content-Type': 'application/json'})
  except Exception as failure:
    if store_fault_mode is not None:
      setattr(failure, 'failure_stage', 'signup_proof')
      setattr(failure, 'failure_gate', 'proof_post')
      setattr(failure, 'failure_category', 'runtime_error')
      issue7_store_recovery.attach_failure_diagnostics(failure, sys.modules[__name__],
          container=container, log_cursor=log_cursor, mode=store_fault_mode,
          locator=signup_locator)
    raise
  redirects_after_proof = list(wallet.redirects[redirects_before_proof:])
  if expect_user_readback_fault:
    fault_logs = read_provider_fault_log_window(container, log_cursor)
    diagnostics = sanitize_user_readback_fault_diagnostics(
        fault_logs, expected_request_id=request_id)
  progress('proof', {'signup_proof_http': proof_status})
  progress('proof', {'provider_request_id': provider_request_id})
  if store_fault_mode is not None:
    try:
      return issue7_store_recovery.failure_flow(sys.modules[__name__], mode=store_fault_mode,
          wallet=wallet, browser=client, locator=signup_locator, status_url=status_url.group(1),
          csrf=csrf.group(1), proof=proof, proof_response=(proof_status, proof_headers, proof_body),
          proof_redirects=redirects_after_proof, container=container, log_cursor=log_cursor,
          admin_client=admin_client, token=admin, identifier=identifier)
    except Exception as failure:
      issue7_store_recovery.attach_failure_diagnostics(failure, sys.modules[__name__],
          container=container, log_cursor=log_cursor, mode=store_fault_mode,
          locator=signup_locator)
      raise
  if expect_user_readback_fault:
    failure_safe = failure_response_has_no_callback_or_code(
        proof_body, proof_headers, redirects_after_proof)
    progress('proof', {'signup_proof_http': proof_status,
        'failure_responses_no_callback_or_code': failure_safe})
    require(proof_status == 503 and failure_safe,
        'post-create UserProvider readback fault returns empty 503 without redirect, callback, or code',
        proof_status, http_status=proof_status)
    exact_users = json.loads(admin_call(admin_client, admin, 'GET',
        f'/auth/admin/realms/{REALM}/users?q=decent_identity_id:{urllib.parse.quote(identifier)}&max=10')[2])
    matched = [user for user in exact_users
        if user.get('attributes', {}).get('decent_identity_id') == [identifier]
        and user.get('enabled') is True and user.get('id')]
    retained_account = len(matched) == 1
    progress('proof', {'exact_mapped_users': len(matched),
        'account_retained_after_failure': retained_account})
    require(retained_account,
        'post-create readback failure retains one exact enabled account')
    status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
    status_redirects_before = len(client.redirects)
    polled, _, status_body = client.request('GET', status_url.group(1), headers=status_headers)
    status_redirects_safe = len(client.redirects) == status_redirects_before
    pending = browser_status_is_pending(polled, status_body) and status_redirects_safe
    progress('proof', {'signup_proof_http': proof_status, 'browser_status_http': polled,
        'browser_status_pending': pending})
    require(pending, 'failed signup browser status remains pending and exposes no callback or code',
        polled, http_status=polled)
    progress('proof', {'user_readback_factory_selected': factory_selected,
        'effective_user_readback_fault_mode': effective_fault_mode,
        'post_create_read_fault_observed': diagnostics['post_create_read_fault_count'] > 0,
        'post_create_read_fault_count': diagnostics['post_create_read_fault_count'],
        'correlated_mapping_failure_count': diagnostics['correlated_mapping_failure_count']})
    require(factory_selected and effective_fault_mode == expected_fault_mode
        and diagnostics['post_create_read_fault_count'] == 1
        and diagnostics['correlated_mapping_failure_count'] >= 1,
        'faulted signup has selected mode, one provider read fault, and request-correlated mapping failure')
    return {'signup_intent_action_http': action_status, 'signup_proof_http': proof_status,
        'exact_mapped_users': len(matched), 'browser_status_http': polled,
        'browser_status_pending': True, 'failure_responses_no_callback_or_code': failure_safe,
        'account_retained_after_failure': True, 'user_readback_factory_selected': True,
        'effective_user_readback_fault_mode': effective_fault_mode,
        'post_create_read_fault_observed': True,
        'post_create_read_fault_count': diagnostics['post_create_read_fault_count'],
        'fresh_signup_reused_account': False,
        'correlated_mapping_failure_count': diagnostics['correlated_mapping_failure_count'],
        'expected_existing_subject': matched[0]['id']}
  require(proof_status == 202, 'signup proof provisions exact account before pending consume',
      proof_status, http_status=proof_status)
  exact_users = json.loads(admin_call(admin_client, admin, 'GET',
      f'/auth/admin/realms/{REALM}/users?q=decent_identity_id:{urllib.parse.quote(identifier)}&max=10')[2])
  matched = [user for user in exact_users
      if user.get('attributes', {}).get('decent_identity_id') == [identifier]]
  progress('account', {'exact_mapped_users': len(matched)})
  require(len(matched) == 1 and matched[0].get('enabled') is True
      and (expected_subject is None or matched[0].get('id') == expected_subject),
      'signup has exactly one enabled exact account and a retry reuses the same subject')
  browser_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  polled, _, polled_raw = client.request('GET', status_url.group(1), headers=browser_headers)
  require(polled == 200, 'signup initiating browser observes bound acceptance',
      polled, http_status=polled)
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
      'callback, OIDC state, and no-code replay', callback_status, http_status=callback_status)
  location_query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
  require(location_query.get('state') == [state], 'signup callback preserves OIDC state')
  replay_status, replay_headers, _ = client.request('GET', status_callback)
  replay_location = urllib.parse.urlsplit(replay_headers.get('Location', ''))
  replay_query = urllib.parse.parse_qs(replay_location.query)
  require(replay_status == 302 and replay_location.path == urllib.parse.urlsplit(REDIRECT).path
      and replay_query.get('state') == [state] and replay_query.get('error')
      and 'code' not in replay_query,
      'signup callback replay returns no second authorization code')
  progress('callback', {'callback_replay': True, 'oidc_state_preserved': location_query.get('state') == [state]})
  token_status, _, token_raw = client.request('POST', f'/auth/realms/{REALM}/protocol/openid-connect/token',
      urllib.parse.urlencode({'grant_type':'authorization_code','client_id':CLIENT,'code':code,
          'redirect_uri':REDIRECT,'code_verifier':verifier}).encode(),
      {'Content-Type':'application/x-www-form-urlencoded'})
  progress('token', {'pkce_token_http': token_status})
  require(token_status == 200, 'signup authorization code exchanges with PKCE', token_status,
      http_status=token_status)
  claims = verify_id_token(client, json.loads(token_raw)['id_token'], key.parent)
  require(claims.get('sub') == matched[0].get('id'), 'signup returns created opaque Keycloak subject')
  require(claims.get('decent_identity_id') == identifier,
      'signup ID token contains exact signed wallet Identity claim')
  result = {'signup_intent_action_http': action_status, 'signup_proof_http': proof_status,
      'provider_request_id': provider_request_id,
      'exact_mapped_users': len(matched), 'pkce_token_http': token_status,
      'callback_http': callback_status, 'callback_replay': True,
      'oidc_state_preserved': location_query.get('state') == [state]}
  if expected_subject is not None:
    result['local_subject_matches_expected'] = subject_matches_expected(
        claims, expected_subject)
  return result


def run_issue7_signup_success_profile(client, key, identifier, container,
    admin_client, image, progress, checkpoint):
  """Run exactly one ordinary explicit-signup success ceremony and checkpoint its safe facts."""
  log_cursor = utc_log_cursor()
  evidence = signup_wallet_flow(client, key, identifier, container, admin_client,
      progress, image)
  request_id = evidence.get('provider_request_id')
  logs = read_provider_success_log_window(container, log_cursor)
  provider_id = sanitize_success_provider_witness(logs, request_id)
  require(provider_id is not None, 'Issue #7 request-correlated selected provider witness')
  require(evidence.get('signup_intent_action_http') == 200
      and evidence.get('signup_proof_http') == 202
      and evidence.get('exact_mapped_users') == 1
      and evidence.get('callback_http') in (302, 303)
      and evidence.get('callback_replay') is True
      and evidence.get('oidc_state_preserved') is True
      and evidence.get('pkce_token_http') == 200,
      'Issue #7 ordinary signup success facts')
  safe = {'stage': 'complete', 'evidence_provenance': 'harness-application-path-only',
      'single_use_object_provider_id': provider_id, **{
      field: evidence[field] for field in ('signup_intent_action_http',
          'signup_proof_http', 'exact_mapped_users', 'callback_http',
          'callback_replay', 'oidc_state_preserved', 'pkce_token_http')}}
  checkpoint(safe)
  return safe


def run_issue7_single_node_signup_recovery_profile(client, key, identifier, container,
    admin_client, image, progress, checkpoint, profile):
  """Inject one post-create readback fault, then prove fresh signup reuses the account."""
  phase = 'faulted_signup'
  def phase_progress(stage, fields):
    progress(phase, fields)
  try:
    failed = signup_wallet_flow(client, key, identifier, container, admin_client,
        phase_progress, image, expect_user_readback_fault=True,
        expected_fault_mode=user_readback_fault_mode(profile))
  except Exception as failure:
    issue7_store_recovery.checkpoint_signup_failure(checkpoint, failure,
        mode_field='user_readback_fault_mode', mode=user_readback_fault_mode(profile))
    raise
  wait_for_identity_lookup_cooldown()
  phase = 'fresh_signup'
  recovered = signup_wallet_flow(Client(), key, identifier, container, admin_client,
      phase_progress, image, reuse_existing=True)
  same_subject = (failed.get('expected_existing_subject') is not None
      and recovered.get('local_subject_matches_expected') is True)
  require(same_subject, 'fresh signup reused the retained exact local account subject')
  evidence = {
      'stage': 'complete',
      'scope': 'one-keycloak-node',
      'keycloak_node_count': 1,
      'fresh_explicit_signup_transactions': 2,
      'exact_enabled_local_users': recovered['exact_mapped_users'],
      'exact_enabled_local_accounts_after_each_signup': [
          failed['exact_mapped_users'], recovered['exact_mapped_users']],
      'same_local_subject': same_subject,
      'user_readback_fault_mode': user_readback_fault_mode(profile),
      'effective_user_readback_fault_mode': failed['effective_user_readback_fault_mode'],
      'user_readback_factory_selected': failed['user_readback_factory_selected'],
      'post_create_read_fault_observed': failed['post_create_read_fault_observed'],
      'post_create_read_fault_count': failed['post_create_read_fault_count'],
      'correlated_mapping_failure_count': failed['correlated_mapping_failure_count'],
      'provider_fault_http': failed['signup_proof_http'],
      'browser_status_http': failed['browser_status_http'],
      'browser_status_pending': failed['browser_status_pending'],
      'failure_responses_no_callback_or_code': failed['failure_responses_no_callback_or_code'],
      'account_retained_after_failure': failed['account_retained_after_failure'],
      'fresh_signup_proof_http': recovered['signup_proof_http'],
      'fresh_signup_callback_http': recovered['callback_http'],
      'fresh_signup_pkce_token_http': recovered['pkce_token_http'],
      'fresh_signup_reused_account': True,
      'synthetic_candidate_count': 65 if user_readback_fault_mode(profile) == 'over-cap' else 0,
      'fault_evidence_provenance': 'wrapper-mediated-application-path',
  }
  checkpoint(evidence)
  return evidence


def provider_missing_identity_is_qualified(evidence):
  """Require a clean exact Registry miss and the provider's terminal denial."""
  if not isinstance(evidence, dict):
    return False
  return (evidence.get('cli_resolution') == 'not_found'
      and evidence.get('cli_output_categories') == ['registry_miss', 'not_found']
      and evidence.get('direct_provider_http') == 401
      and evidence.get('provider_resolution_outcome') == 'provider_denied_unclassified'
      and evidence.get('status_pending') is True
      and evidence.get('redirects_safe') is True
      and evidence.get('no_acceptance_or_callback') is True)


def classify_provider_identity_outcome(provider_http):
  """Classify only the provider request status; a separate CLI miss is not authority."""
  if provider_http == 503:
    return 'unavailable'
  if provider_http == 401:
    return 'provider_denied_unclassified'
  return 'unexpected_status'


def _redirect_count(client):
  redirects = getattr(client, 'redirects', None)
  return len(redirects) if isinstance(redirects, list) else None


def _no_new_redirects(client, previous_count):
  redirects = getattr(client, 'redirects', None)
  return (type(previous_count) is int and isinstance(redirects, list)
      and len(redirects) == previous_count)


def _response_acceptance_category(headers, raw_body, terminal_http_status=None):
  try:
    header_items = list(headers.items())
  except (AttributeError, TypeError, ValueError):
    return 'invalid_headers'
  for name, value in header_items:
    if str(name).lower() != 'location':
      continue
    location = urllib.parse.urlsplit(str(value))
    query = urllib.parse.parse_qs(location.query)
    redirect_path = urllib.parse.urlsplit(REDIRECT).path
    if location.path == redirect_path or 'code' in query or ('state' in query and 'error' in query):
      return 'callback_location'
  if raw_body in (None, b'', ''):
    return 'empty_body'
  try:
    body = json.loads(raw_body)
  except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
    return ('terminal_denial_body' if terminal_http_status in {401, 503}
        else 'opaque_body')
  if (_contains_key(body, 'code') or _contains_key(body, 'callback')
      or _has_accepted_result(body)):
    return 'structured_acceptance'
  return 'structured_no_acceptance'


def _response_has_acceptance_evidence(headers, raw_body, terminal_http_status=None):
  return _response_acceptance_category(headers, raw_body, terminal_http_status) in {
      'callback_location', 'structured_acceptance', 'opaque_body', 'invalid_headers'}


def missing_identity_flow(temp, resolver_port, bootstrap, image):
  missing_label = 'wallet-login-unpublished-' + uuid.uuid4().hex
  missing_id = missing_label + '@example.invalid'
  missing_key = generate_owner_key(Path(temp), missing_label, image)
  lookup_started = time.monotonic()
  registry_lookup = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
      ['get', '--identifier', missing_id,
      '--host', '127.0.0.1', '--port', str(resolver_port), '--bootstrap', bootstrap], timeout=20, image=image)
  lookup_ms = int((time.monotonic() - lookup_started) * 1000)
  resolution_category, result_categories = classify_identity_lookup(
      registry_lookup.stdout, registry_lookup.returncode, missing_id)
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
  challenge_redirect_start = _redirect_count(provider_wallet)
  challenge_status, _, challenge_raw = provider_wallet.request('GET', provider_locator)
  challenge_redirects_safe = _no_new_redirects(provider_wallet, challenge_redirect_start)
  require(challenge_status == 200 and challenge_redirects_safe,
      'fresh provider unknown-Identity challenge GET without redirects')
  challenge_envelope = json.loads(challenge_raw)
  signing_input = json.dumps({
      'challenge': challenge_envelope['challenge'], 'identity_id': missing_id,
      'profile': challenge_envelope['profile'],
  }, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
  with tempfile.TemporaryDirectory(prefix='wallet-signing-', dir=Path(missing_key).parent) as signing_dir:
    payload = write_private_signing_input(signing_dir, 'missing-identity', signing_input)
    try:
      signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin',
          '-inkey', str(missing_key), '-in', str(payload)], stdout=subprocess.PIPE,
          stderr=subprocess.PIPE, timeout=10, check=False)
    finally:
      payload.unlink(missing_ok=True)
  require(signature.returncode == 0 and len(signature.stdout) == 64,
      'sign exact unpublished Identity proof')
  provider_proof = json.dumps({
      'profile': challenge_envelope['profile'], 'challenge': challenge_envelope['challenge'],
      'identity_id': missing_id, 'signature': b64url(signature.stdout),
  }, separators=(',', ':')).encode('utf-8')
  provider_started = time.monotonic()
  proof_redirect_start = _redirect_count(provider_wallet)
  provider_http, provider_headers, provider_body = provider_wallet.request('POST',
      provider_locator, provider_proof, {'Content-Type': 'application/json'})
  proof_redirects_safe = _no_new_redirects(provider_wallet, proof_redirect_start)
  direct_provider_ms = int((time.monotonic() - provider_started) * 1000)
  provider_resolution_outcome = classify_provider_identity_outcome(provider_http)
  require(provider_resolution_outcome in {'unavailable', 'provider_denied_unclassified'},
      'unpublished Identity proof did not succeed or produce an unrelated response',
      provider_http)
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': provider_csrf_value}
  status_redirect_start = _redirect_count(provider_browser)
  status_poll, status_response_headers, status_raw = provider_browser.request(
      'GET', provider_status_url_value, headers=status_headers)
  status_redirects_safe = _no_new_redirects(provider_browser, status_redirect_start)
  status_payload = None
  if status_poll == 200:
    try:
      status_payload = json.loads(status_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
      pass
  status_pending = status_payload == {'status': 'pending'}
  redirects_safe = (challenge_redirects_safe and proof_redirects_safe
      and status_redirects_safe)
  provider_acceptance_category = _response_acceptance_category(
      provider_headers, provider_body, terminal_http_status=provider_http)
  status_acceptance_category = _response_acceptance_category(
      status_response_headers, status_raw)
  provider_acceptance = _response_has_acceptance_evidence(
      provider_headers, provider_body, terminal_http_status=provider_http)
  status_acceptance = _response_has_acceptance_evidence(status_response_headers, status_raw)
  no_acceptance_or_callback = (status_pending and redirects_safe
      and not provider_acceptance and not status_acceptance)
  require(no_acceptance_or_callback,
      'unpublished Identity produced no accepted receipt, callback, or code '
      + '(pending=' + str(status_pending).lower()
      + ', redirects_safe=' + str(redirects_safe).lower()
      + ', provider_evidence=' + provider_acceptance_category
      + ', status_evidence=' + status_acceptance_category + ')')
  return {'cli_resolution': resolution_category, 'cli_exit': registry_lookup.returncode,
      'cli_output_categories': result_categories, 'cli_output_shape': safe_lines,
      'cli_lookup_ms': lookup_ms, 'provider_resolution_outcome': provider_resolution_outcome,
      'direct_provider_http': provider_http, 'status_http': status_poll,
      'status_pending': status_pending, 'direct_provider_lookup_ms': direct_provider_ms,
      'redirects_safe': redirects_safe,
      'no_acceptance_or_callback': no_acceptance_or_callback}


class AuthFlowFailure(RuntimeError):
  """A failure with only allowlisted HTTP/boolean outcomes."""

  def __init__(self, outcomes):
    super().__init__('wallet auth flow failed')
    self.outcomes = dict(outcomes)


class AuthFlowAttempt:
  def __init__(self):
    self.outcomes = {}

  def record(self, name, value):
    if name.endswith('_http') and type(value) is int and 100 <= value <= 599:
      self.outcomes[name] = value
    elif name in {
        'initial_status_accepted', 'callback_state_preserved',
        'callback_error_returned', 'callback_code_returned',
        'callback_redirect_uri_matches', 'callback_replay_state_preserved',
        'callback_replay_error_returned', 'callback_replay_code_returned',
        'callback_replay_redirect_uri_matches', 'callback_replay_denied_safely',
        'callback_replay_internal_error_page',
        'callback_replay_internal_error_hostname_matches',
        'callback_replay_internal_error_port_matches',
        'callback_replay_guard_log_read', 'callback_replay_guard_reached',
        'callback_replay_login_error_log_read',
        'callback_replay_authenticator_entry_reached',
        'callback_replay_authenticator_entry_completed',
        'callback_top_flow_rearm_reached', 'callback_top_flow_rearm_execution_id_present',
        'callback_replay_state_present', 'callback_replay_redirect_uri_present',
        'callback_replay_redirect_uri_registered', 'callback_replay_protocol_openid_connect',
        'status_after_callback_safe', 'status_pending',
    } and type(value) is bool:
      self.outcomes[name] = value
    elif name == 'callback_replay_guard_marker_count' and type(value) is int and 0 <= value <= 10:
      self.outcomes[name] = value
    elif name in {'callback_replay_guard_unavailable_marker_count',
        'callback_replay_guard_other_marker_count',
        'callback_replay_login_error_count',
        'callback_replay_authenticator_entry_marker_count',
        'callback_replay_authenticator_entry_unavailable_marker_count',
        'callback_replay_authenticator_entry_other_marker_count',
        'callback_replay_authenticator_entry_completed_true_marker_count',
        'callback_replay_authenticator_entry_completed_false_marker_count',
        'callback_top_flow_rearm_marker_count',
        'callback_top_flow_rearm_unavailable_marker_count',
        'callback_top_flow_rearm_other_marker_count'} and type(value) is int and 0 <= value <= 10:
      self.outcomes[name] = value
    elif name == 'callback_replay_login_error_category' and isinstance(value, str) and value in {
        'none', 'unavailable', 'multiple', 'other', 'invalid_code', 'expired_code',
        'already_logged_in', 'cookie_not_found', 'invalid_request', 'invalid_redirect_uri',
        'access_denied', 'user_not_found'}:
      self.outcomes[name] = value
    elif name == 'callback_replay_internal_error_reason' and isinstance(value, str) and value in {
        'callback_url_unavailable', 'callback_origin_invalid', 'redirect_scheme_mismatch',
        'redirect_origin_mismatch',
        'redirect_path_untrusted', 'authorization_code_present', 'error_parameter_invalid',
        'same_origin_error_without_code', 'loopback_keycloak_error_without_code',
        'url_parse_error'}:
      self.outcomes[name] = value
    return value

  def failure(self, message=None, *, gate=None):
    del message
    outcomes = dict(self.outcomes)
    if gate in {
        'proof_status', 'proof_post', 'identical_retry', 'changed_retry',
        'callback', 'callback_replay', 'status_after_callback', 'pkce',
    }:
      outcomes['failure_gate'] = gate
    return AuthFlowFailure(outcomes)


_ACTIVE_AUTH_FLOW_ATTEMPT = None


def record_auth_flow_outcome(name, value):
  if _ACTIVE_AUTH_FLOW_ATTEMPT is not None:
    _ACTIVE_AUTH_FLOW_ATTEMPT.record(name, value)
  return value


def capture_auth_flow_outcomes(operation, attempt=None):
  global _ACTIVE_AUTH_FLOW_ATTEMPT
  attempt = attempt or AuthFlowAttempt()
  previous = _ACTIVE_AUTH_FLOW_ATTEMPT
  _ACTIVE_AUTH_FLOW_ATTEMPT = attempt
  try:
    return operation()
  except AuthFlowFailure:
    raise
  except Exception:
    raise attempt.failure() from None
  finally:
    _ACTIVE_AUTH_FLOW_ATTEMPT = previous


def run_registry_attempts(case_name, attempt_runner, checkpoint, *, fixture_factory=None):
  """Run and checkpoint two attempts, retaining failed flow HTTP outcomes."""
  result = {'case': case_name, 'attempts': []}
  for attempt_number in (1, 2):
    attempt_trace = AuthFlowAttempt()
    identity_fixture = fixture_factory(attempt_number) if fixture_factory is not None else None

    def invoke():
      try:
        if fixture_factory is None:
          return attempt_runner(attempt_number)
        return attempt_runner(attempt_number, identity_fixture)
      except AuthFlowFailure:
        raise
      except Exception as failure:
        raise attempt_trace.failure(str(failure)) from failure

    try:
      outcome = capture_auth_flow_outcomes(invoke, attempt_trace)
    except AuthFlowFailure as failure:
      outcome = {'outcome': 'unqualified', **failure.outcomes}
    if outcome is None:
      outcome = {}
    outcome = dict(outcome)
    if identity_fixture is not None:
      outcome.setdefault('fixture', identity_fixture[0])
    attempt = dict(outcome)
    attempt.setdefault('attempt_number', attempt_number)
    result['attempts'].append(attempt)
    checkpoint(sanitize_live_checkpoint({'registry_matrix': {case_name: result}}))
  return result


def classify_registry_matrix_attempt(direct_resolution, provider_http, *, status_pending,
    exact_readback):
  if not isinstance(direct_resolution, str) or direct_resolution not in {
      'resolved', 'not_found', 'unavailable'}:
    return 'unqualified'
  if type(status_pending) is not bool or type(exact_readback) is not bool:
    return 'unqualified'
  if type(provider_http) is not int or not 100 <= provider_http <= 599:
    return 'unqualified'
  if provider_http == 202:
    return ('current_accepted' if direct_resolution == 'resolved' and exact_readback
        and not status_pending else 'unexpected_acceptance')
  if provider_http == 503:
    if not status_pending:
      return 'unexpected_status'
    if direct_resolution == 'not_found':
      return 'provider_registry_inconsistent'
    if direct_resolution == 'unavailable':
      return 'registry_unavailable'
    return 'provider_unavailable'
  if provider_http == 401:
    return 'provider_denied_unclassified'
  return 'unexpected_status'


def set_registry_bootstrap(client, token, bootstrap):
  path = f'/auth/admin/realms/{REALM}'
  _, _, raw = admin_call(client, token, 'GET', path)
  realm = json.loads(raw)
  attributes = dict(realm.get('attributes', {}))
  attributes['decent.wallet.registry.bootstrap'] = bootstrap
  realm['attributes'] = attributes
  admin_call(client, token, 'PUT', path, realm, expected=(204,))
  _, _, verified_raw = admin_call(client, token, 'GET', path)
  verified = json.loads(verified_raw)
  require(verified.get('attributes', {}).get('decent.wallet.registry.bootstrap') == bootstrap,
      'Registry bootstrap fixture configuration persisted exactly')


def registry_proof_probe(temp, resolver_port, bootstrap, image,
    identity_key=None, identity_id=None):
  attempt_suffix = uuid.uuid4().hex
  attempt_label = 'wallet-login-unpublished-' + attempt_suffix
  if identity_key is None:
    missing_key = generate_owner_key(temp, attempt_label, image)
  else:
    missing_key = identity_key
  if identity_id is None:
    missing_id = attempt_label + '@example.invalid'
  else:
    missing_id = identity_id
  lookup_started = time.monotonic()
  registry_lookup = run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
      ['get', '--identifier', missing_id,
      '--host', '127.0.0.1', '--port', str(resolver_port), '--bootstrap', bootstrap], timeout=20, image=image)
  lookup_ms = int((time.monotonic() - lookup_started) * 1000)
  resolution_category, result_categories = classify_identity_lookup(
      registry_lookup.stdout, registry_lookup.returncode, missing_id)
  safe_lines = ['object' for category in result_categories if category == 'json']
  if resolution_category == 'not_found' and result_categories[-1:] == ['not_found']:
    safe_lines.append('terminal-not-found')

  # Use a separate Keycloak transaction so the direct CLI probe cannot trigger
  # the per-browser/client resolver cooldown on the provider request.
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
  provider_text = provider_page.decode('utf-8', errors='strict')
  provider_status_url = re.search(r'const statusUrl = "([^"]+)";', provider_text)
  provider_csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', provider_text)
  require(provider_status_url is not None and provider_csrf is not None,
      'fresh provider browser status binding')
  if provider_status_url is None or provider_csrf is None:
    raise RuntimeError('acceptance probe failed at fresh provider browser status binding')
  provider_wallet = Client()
  challenge_status, _, challenge_raw = provider_wallet.request('GET', provider_locator)
  require(challenge_status == 200, 'fresh provider unknown-Identity challenge GET')
  challenge_envelope = json.loads(challenge_raw)
  signing_input = json.dumps({
      'challenge': challenge_envelope['challenge'], 'identity_id': missing_id,
      'profile': challenge_envelope['profile'],
  }, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
  with tempfile.TemporaryDirectory(prefix='wallet-signing-', dir=missing_key.parent) as signing_dir:
    payload = write_private_signing_input(signing_dir, 'missing-identity', signing_input)
    try:
      signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin',
          '-inkey', str(missing_key), '-in', str(payload)], stdout=subprocess.PIPE,
          stderr=subprocess.PIPE, timeout=10, check=False)
    finally:
      payload.unlink(missing_ok=True)
  require(signature.returncode == 0 and len(signature.stdout) == 64,
      'sign exact unpublished Identity proof')
  provider_proof = json.dumps({
      'profile': challenge_envelope['profile'], 'challenge': challenge_envelope['challenge'],
      'identity_id': missing_id, 'signature': b64url(signature.stdout),
  }, separators=(',', ':')).encode('utf-8')
  provider_started = time.monotonic()
  proof_redirect_cursor = len(provider_wallet.redirects)
  provider_http, proof_headers, proof_raw = provider_wallet.request('POST', provider_locator, provider_proof,
      {'Content-Type': 'application/json'})
  direct_provider_ms = int((time.monotonic() - provider_started) * 1000)
  provider_resolution_outcome = classify_provider_identity_outcome(provider_http)
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': provider_csrf.group(1)}
  status_redirect_cursor = len(provider_browser.redirects)
  status_poll, status_response_headers, status_raw = provider_browser.request(
      'GET', provider_status_url.group(1), headers=status_headers)
  status_payload = None
  try:
    status_payload = json.loads(status_raw) if status_raw else {}
  except (json.JSONDecodeError, UnicodeDecodeError):
    pass
  status_pending = status_payload == {'status': 'pending'}
  locations_safe = (_expiry_location_is_safe(proof_headers.get('Location', ''))
      and _expiry_location_is_safe(status_response_headers.get('Location', '')))
  redirects_safe = _expiry_redirects_are_safe(
      provider_wallet.redirects[proof_redirect_cursor:]
      + provider_browser.redirects[status_redirect_cursor:])
  no_acceptance_or_callback = (provider_http != 202 and status_pending
      and _expiry_body_is_safe(proof_raw) and _expiry_body_is_safe(status_raw)
      and locations_safe and redirects_safe)
  return {'cli_resolution': resolution_category, 'cli_exit': registry_lookup.returncode,
      'cli_output_categories': result_categories, 'cli_output_shape': safe_lines,
      'cli_lookup_ms': lookup_ms, 'provider_resolution_outcome': provider_resolution_outcome,
      'direct_provider_http': provider_http, 'proof_post_http': provider_http,
      'direct_provider_lookup_ms': direct_provider_ms,
      'status_http': status_poll, 'status_pending': status_pending,
      'no_acceptance_or_callback': no_acceptance_or_callback}


def invoke_current_identity_attempt(identifier, key, container, image, attempt_number,
    direct_lookup, auth_flow_runner=auth_flow):
  """Read back one current fixture, then authenticate and retain HTTP outcomes."""
  lookup = direct_lookup(attempt_number)
  public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
  exact_readback = (public.returncode == 0 and len(public.stdout) >= 32
      and packaged_resolver_readback(lookup.stdout, lookup.returncode, identifier,
          public.stdout[-32:].hex()))
  direct_resolution, _ = classify_identity_lookup(lookup.stdout, lookup.returncode, identifier)
  if exact_readback:
    direct_resolution = 'resolved'
  elif direct_resolution == 'resolved':
    direct_resolution = 'unavailable'
  evidence = {'attempt_number': attempt_number, 'direct_resolution': direct_resolution,
      'exact_readback': exact_readback, 'outcome': 'unqualified'}
  if not exact_readback:
    return evidence
  try:
    login_result = capture_auth_flow_outcomes(
        lambda: auth_flow_runner(Client(), key, identifier, container, image))
  except AuthFlowFailure as failure:
    evidence.update(failure.outcomes)
    if 'proof_post_http' in failure.outcomes:
      evidence['provider_http'] = failure.outcomes['proof_post_http']
    if 'status_poll_http' in failure.outcomes:
      evidence['status_http'] = failure.outcomes['status_poll_http']
    return evidence
  evidence.update({
      'provider_http': login_result['proof_post_http'],
      'status_http': login_result['status_poll_http'],
      'status_pending': False,
      'no_acceptance_or_callback': False,
      'outcome': classify_registry_matrix_attempt(direct_resolution,
          login_result['proof_post_http'], status_pending=False, exact_readback=True),
      'wallet_login': login_result,
  })
  return evidence


def changed_signed_proof(proof, signature_bytes):
  if not isinstance(proof, bytes) or not isinstance(signature_bytes, bytes) or len(signature_bytes) != 64:
    raise ValueError('proof and 64-byte signature are required')
  try:
    parsed = json.loads(proof.decode('utf-8'))
  except (UnicodeDecodeError, json.JSONDecodeError):
    raise ValueError('proof is not valid UTF-8 JSON') from None
  if not isinstance(parsed, dict) or not isinstance(parsed.get('signature'), str):
    raise ValueError('proof has no signature field')
  parsed['signature'] = b64url(signature_bytes)
  return json.dumps(parsed, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def accepted_status_payload(status_code, raw_body):
  if status_code != 200:
    return False
  try:
    payload = json.loads(raw_body)
  except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
    return False
  return isinstance(payload, dict) and payload.get('status') == 'accepted' \
      and isinstance(payload.get('callback'), str) and bool(payload['callback'])


def callback_redirect_outcome(location, expected_state, redirect_uri):
  try:
    actual = urllib.parse.urlsplit(location)
    expected = urllib.parse.urlsplit(redirect_uri)
    query = urllib.parse.parse_qs(actual.query, keep_blank_values=True)
    expected_query = urllib.parse.parse_qs(expected.query, keep_blank_values=True)
  except (TypeError, ValueError):
    actual = urllib.parse.urlsplit('')
    expected = urllib.parse.urlsplit('https://invalid.invalid/')
    query = {}
    expected_query = {}
  # OAuth/OIDC response metadata is not part of the registered URI's static
  # query. Keycloak's ALREADY_LOGGED_IN response includes error_description.
  dynamic = {'code', 'state', 'error', 'error_description', 'iss', 'session_state'}
  actual_static_query = {key: value for key, value in query.items() if key not in dynamic}
  redirect_matches = (
      actual.scheme == expected.scheme and actual.netloc == expected.netloc
      and actual.path == expected.path and actual.fragment == expected.fragment
      and actual.username is None and actual.password is None
      and expected.username is None and expected.password is None
      and actual_static_query == {key: value for key, value in expected_query.items() if key not in dynamic})
  state_values = query.get('state', [])
  code_values = query.get('code', [])
  error_values = query.get('error', [])
  return {
      'redirect_uri_matches': redirect_matches,
      'state_preserved': redirect_matches and state_values == [expected_state],
      'authorization_code_returned': 'code' in query,
      'single_authorization_code_returned': len(code_values) == 1 and bool(code_values[0]),
      'error_parameter_present': 'error' in query,
      'error_returned': len(error_values) == 1 and bool(error_values[0]),
  }


def callback_replay_outcome(status_code, location, expected_state, redirect_uri,
    keycloak_callback_url=None):
  outcome = callback_redirect_outcome(location, expected_state, redirect_uri)
  internal_error_page = False
  internal_error_reason = 'callback_url_unavailable'
  internal_error_hostname_matches = False
  internal_error_port_matches = False
  if isinstance(keycloak_callback_url, str):
    try:
      callback_parts = urllib.parse.urlsplit(keycloak_callback_url)
      actual_parts = urllib.parse.urlsplit(urllib.parse.urljoin(keycloak_callback_url, location))
      actual_query = urllib.parse.parse_qs(actual_parts.query, keep_blank_values=True)
      internal_error_hostname_matches = (actual_parts.hostname is not None
          and callback_parts.hostname is not None
          and actual_parts.hostname.lower() == callback_parts.hostname.lower())
      internal_error_port_matches = actual_parts.port == callback_parts.port
      if (callback_parts.scheme not in {'http', 'https'} or not callback_parts.netloc
          or callback_parts.username is not None or callback_parts.password is not None):
        internal_error_reason = 'callback_origin_invalid'
      else:
        expected_origin = (actual_parts.scheme == callback_parts.scheme
            and actual_parts.netloc == callback_parts.netloc
            and actual_parts.username is None and actual_parts.password is None)
        local_keycloak_origin = (actual_parts.scheme == 'http'
            and actual_parts.hostname == '127.0.0.1' and actual_parts.port == KC_PORT
            and actual_parts.username is None and actual_parts.password is None)
        if not expected_origin and not local_keycloak_origin:
          internal_error_reason = ('redirect_scheme_mismatch'
              if actual_parts.scheme != callback_parts.scheme else 'redirect_origin_mismatch')
        elif not actual_parts.path.startswith('/auth/'):
          internal_error_reason = 'redirect_path_untrusted'
        elif 'code' in actual_query:
          internal_error_reason = 'authorization_code_present'
        elif len(actual_query.get('error', [])) != 1 or not actual_query['error'][0]:
          internal_error_reason = 'error_parameter_invalid'
        else:
          internal_error_page = True
          internal_error_reason = ('same_origin_error_without_code' if expected_origin
              else 'loopback_keycloak_error_without_code')
    except (TypeError, ValueError):
      internal_error_reason = 'url_parse_error'
  safe_denial = (status_code in {302, 303} and outcome['error_returned']
      and not outcome['authorization_code_returned']
      and ((outcome['redirect_uri_matches'] and outcome['state_preserved'])
          or internal_error_page))
  return {
      'redirect_http': status_code,
      'redirect_uri_matches': outcome['redirect_uri_matches'],
      'state_preserved': outcome['state_preserved'],
      'error_returned': outcome['error_returned'],
      'authorization_code_returned': outcome['authorization_code_returned'],
      'internal_error_page': internal_error_page,
      'internal_error_reason': internal_error_reason,
      'internal_error_hostname_matches': internal_error_hostname_matches,
      'internal_error_port_matches': internal_error_port_matches,
      'replay_denied_safely': safe_denial,
  }


def pending_status_payload(status_code, raw_body):
  if status_code != 200:
    return False
  try:
    payload = json.loads(raw_body)
  except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
    return False
  return isinstance(payload, dict) and payload.get('status') == 'pending'


def run_issue6_auth_flow(result, attempt, auth_flow_runner, checkpoint):
  try:
    auth_result = capture_auth_flow_outcomes(auth_flow_runner, attempt)
  except Exception as failure:
    profile = dict(result.get('issue6_single_node', {}))
    profile['stage'] = 'auth_flow_failed'
    profile.update(failure.outcomes if isinstance(failure, AuthFlowFailure) else attempt.outcomes)
    result['issue6_single_node'] = profile
    checkpoint()
    raise AuthFlowFailure(profile) from None
  profile = dict(result.get('issue6_single_node', {}))
  profile.update(auth_result)
  profile['stage'] = 'complete'
  result['issue6_single_node'] = profile
  checkpoint()
  return auth_result


def safe_failure_category(failure):
  if isinstance(failure, AuthFlowFailure):
    return 'auth_flow_gate'
  if isinstance(failure, (TimeoutError, subprocess.TimeoutExpired)):
    return 'timeout'
  if isinstance(failure, ValueError):
    return 'value_error'
  if isinstance(failure, RuntimeError):
    return 'runtime_error'
  return 'other'


def run_checkpointed_step(mark_stage, started_stage, completed_stage, operation):
  mark_stage(started_stage)
  try:
    result = operation()
  except Exception as failure:
    mark_stage(started_stage, failure_category=safe_failure_category(failure))
    raise
  mark_stage(completed_stage)
  return result


def postconsume_receipt_failure_flow(key, identifier, container, *, browser_state,
    client_factory=None, signer=None):
  """Trigger the test-image decorator once and verify fail-closed browser state."""
  browser = (client_factory or Client)()
  browser_state['browser'] = browser
  from datetime import datetime, timedelta, timezone
  selection_cursor = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(timespec='milliseconds')
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(secrets.token_bytes(32)).digest()),
      'code_challenge_method': 'S256',
  })
  login_status, _, page = browser.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(login_status == 200, 'post-consume failure profile login page', login_status)
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(
      f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'post-consume failure profile transaction locator')
  browser_state['initial_locator'] = locator
  browser_state['locators'] = [locator]
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', text)
  status_match = re.search(r'const statusUrl = "([^"]+)";', text)
  require(csrf is not None and status_match is not None,
      'post-consume failure profile status binding')
  if csrf is None or status_match is None:
    raise RuntimeError('post-consume failure profile status binding unavailable')
  wallet = (client_factory or Client)()
  challenge_status, _, challenge_raw = wallet.request('GET', locator)
  require(challenge_status == 200, 'post-consume failure challenge GET', challenge_status)
  request_id = hashlib.sha256(locator.rsplit('/', 1)[1].encode('ascii')).hexdigest()[:32]
  selection_logs = run(['podman', 'logs', '--since', selection_cursor,
      '--timestamps', container], timeout=15)
  require(selection_logs.returncode == 0, 'receipt failure provider-selection log cursor')
  selection_text = subprocess_output_text(selection_logs)
  selection_marker_prefix = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={ISSUE6_POSTCONSUME_TEST_PROVIDER_ID} '
      'operation=transaction_put_if_absent request=')
  provider_marker_count = selection_text.count(selection_marker_prefix)
  provider_selected = issue6_test_provider_selection_is_verified(selection_text,
      ISSUE6_POSTCONSUME_TEST_PROVIDER_ID, request_id)
  if not provider_selected:
    print('issue6_provider_selection_diagnostic=' + json.dumps({
        'log_read_status': 'ok' if selection_logs.returncode == 0 else 'error',
        'captured_log_chars': len(selection_text),
        'factory_created_marker_count': selection_text.count('ISSUE6_TEST_PROVIDER_FACTORY_CREATED:'),
        'selection_marker_count': selection_text.count('ISSUE6_TEST_PROVIDER_SELECTED:'),
        'expected_provider_marker_count': provider_marker_count,
        'request_correlated_marker': False}, sort_keys=True))
  require(provider_selected, 'receipt test provider selected for pending transaction')
  envelope = json.loads(challenge_raw)
  signed = json.dumps({'challenge': envelope['challenge'], 'identity_id': identifier,
      'profile': envelope['profile']}, ensure_ascii=False, separators=(',', ':'),
      sort_keys=True).encode('utf-8')
  if signer is None:
    public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    require(public.returncode == 0 and len(public.stdout) >= 32,
        'post-consume failure proof public key')
    with tempfile.TemporaryDirectory(prefix='wallet-receipt-signing-', dir=key.parent) as signing_dir:
      payload = write_private_signing_input(signing_dir, 'proof', signed)
      try:
        signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin',
            '-inkey', str(key), '-in', str(payload)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
      finally:
        payload.unlink(missing_ok=True)
    require(signature.returncode == 0 and len(signature.stdout) == 64,
        'post-consume failure valid Ed25519 proof')
    signature_value = b64url(signature.stdout)
  else:
    signature_value = signer(envelope, identifier)
  proof = json.dumps({'profile': envelope['profile'], 'challenge': envelope['challenge'],
      'identity_id': identifier, 'signature': signature_value},
      ensure_ascii=False, separators=(',', ':')).encode('utf-8')

  log_cursor = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
  redirects_before = len(wallet.redirects)
  proof_status, proof_headers, proof_body = wallet.request('POST', locator, proof,
      {'Content-Type': 'application/json'})
  proof_location = proof_headers.get('Location')
  proof_redirected = len(wallet.redirects) != redirects_before
  require(proof_status == 503 and not proof_body and proof_location is None
      and not proof_redirected, 'accepted receipt failure is empty 503 without redirect', proof_status)
  retry_redirects_before = len(wallet.redirects)
  retry_status, retry_headers, retry_body = wallet.request('POST', locator, proof,
      {'Content-Type': 'application/json'})
  retry_redirected = len(wallet.redirects) != retry_redirects_before
  require(retry_status == 404 and not retry_body and retry_headers.get('Location') is None
      and not retry_redirected, 'identical retry is unavailable after consumed transaction', retry_status)
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  status_redirects_before = len(browser.redirects)
  status_status, status_response_headers, status_body = browser.request(
      'GET', status_match.group(1), headers=status_headers)
  status_redirected = len(browser.redirects) != status_redirects_before
  require(status_status == 404 and not status_body
      and status_response_headers.get('Location') is None and not status_redirected,
      'initiating browser has no accepted receipt or callback', status_status)
  require(b'callback' not in status_body.lower() and b'code' not in status_body.lower(),
      'failure status reveals neither callback nor code')

  logs = run(['podman', 'logs', '--since', log_cursor, '--timestamps', container], timeout=15)
  require(logs.returncode == 0, 'per-run Keycloak failure log cursor')
  request_id = hashlib.sha256(locator.rsplit('/', 1)[1].encode('ascii')).hexdigest()[:32]
  handler_marker = f'Wallet proof acceptance unavailable (request={request_id}, outcome=not_accepted)'
  log_text = subprocess_output_text(logs)
  handler_count = log_text.count(handler_marker)
  decorator_count = log_text.count(
      'ISSUE6_TEST_FAULT: accepted receipt delegate write committed; test decorator threw')
  require(handler_count == 1 and decorator_count == 1,
      'one request-correlated production failure and one decorator commit-then-throw signal')
  return {'stage': 'failed_then_denied', 'proof_http': proof_status,
      'proof_body_empty': not proof_body, 'proof_location_present': proof_location is not None,
      'proof_redirect_followed': proof_redirected, 'retry_redirect_followed': retry_redirected,
      'retry_http': retry_status, 'status_http': status_status,
      'status_body_empty': not status_body,
      'status_location_present': status_response_headers.get('Location') is not None,
      'status_redirect_followed': status_redirected, 'callback_exposed': False,
      'oidc_code_exposed': False, 'fault_signal_correlated': handler_count == 1,
      'fault_signal_count': handler_count,
      'delegate_commit_then_throw': decorator_count == 1,
      'test_provider_selected': provider_selected,
      'selected_provider_path': ISSUE6_POSTCONSUME_TEST_PROVIDER_ID}


def postconsume_callback_gate_failure_flow(key, identifier, container, *, browser_state,
    client_factory=None, signer=None):
  """Exercise the real proof endpoint through a one-shot callback-gate decorator fault."""
  browser = (client_factory or Client)()
  browser_state['browser'] = browser
  from datetime import datetime, timedelta, timezone
  selection_cursor = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(timespec='milliseconds')
  query = urllib.parse.urlencode({
      'client_id': CLIENT, 'redirect_uri': REDIRECT, 'response_type': 'code',
      'scope': 'openid', 'state': b64url(secrets.token_bytes(24)),
      'nonce': b64url(secrets.token_bytes(24)),
      'code_challenge': b64url(hashlib.sha256(secrets.token_bytes(32)).digest()),
      'code_challenge_method': 'S256',
  })
  login_status, _, page = browser.request('GET',
      f'/auth/realms/{REALM}/protocol/openid-connect/auth?{query}')
  require(login_status == 200, 'callback-gate failure profile login page', login_status)
  text = page.decode('utf-8', errors='strict')
  parser = LoginPageParser()
  parser.feed(text)
  locator = ''.join(parser.locator_parts).strip()
  require(locator.startswith(
      f'https://idp.example:{KC_PORT}/auth/realms/{REALM}/decent-wallet-login/v1/transactions/'),
      'callback-gate failure profile transaction locator')
  browser_state['initial_locator'] = locator
  csrf = re.search(r'const csrfToken = "([A-Za-z0-9_-]{43})";', text)
  status_match = re.search(r'const statusUrl = "([^"]+)";', text)
  require(csrf is not None and status_match is not None,
      'callback-gate failure profile status binding')
  if csrf is None or status_match is None:
    raise RuntimeError('callback-gate failure profile status binding unavailable')
  wallet = (client_factory or Client)()
  challenge_status, _, challenge_raw = wallet.request('GET', locator)
  require(challenge_status == 200, 'callback-gate failure challenge GET', challenge_status)
  request_id = hashlib.sha256(locator.rsplit('/', 1)[1].encode('ascii')).hexdigest()[:32]
  selection_logs = run(['podman', 'logs', '--since', selection_cursor,
      '--timestamps', container], timeout=15)
  require(selection_logs.returncode == 0, 'callback-gate provider-selection log cursor')
  selection_text = subprocess_output_text(selection_logs)
  selection_marker_prefix = (f'ISSUE6_TEST_PROVIDER_SELECTED: provider={ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID} '
      'operation=transaction_put_if_absent request=')
  provider_marker_count = selection_text.count(selection_marker_prefix)
  provider_selected = issue6_test_provider_selection_is_verified(selection_text,
      ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID, request_id)
  if not provider_selected:
    print('issue6_provider_selection_diagnostic=' + json.dumps({
        'log_read_status': 'ok' if selection_logs.returncode == 0 else 'error',
        'captured_log_chars': len(selection_text),
        'factory_created_marker_count': selection_text.count('ISSUE6_TEST_PROVIDER_FACTORY_CREATED:'),
        'selection_marker_count': selection_text.count('ISSUE6_TEST_PROVIDER_SELECTED:'),
        'expected_provider_marker_count': provider_marker_count,
        'request_correlated_marker': False}, sort_keys=True))
  require(provider_selected, 'callback-gate test provider selected for pending transaction')
  envelope = json.loads(challenge_raw)
  signed = json.dumps({'challenge': envelope['challenge'], 'identity_id': identifier,
      'profile': envelope['profile']}, ensure_ascii=False, separators=(',', ':'),
      sort_keys=True).encode('utf-8')
  if signer is None:
    public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    require(public.returncode == 0 and len(public.stdout) >= 32,
        'callback-gate failure proof public key')
    with tempfile.TemporaryDirectory(prefix='wallet-callback-signing-', dir=key.parent) as signing_dir:
      payload = write_private_signing_input(signing_dir, 'proof', signed)
      try:
        signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin',
            '-inkey', str(key), '-in', str(payload)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
      finally:
        payload.unlink(missing_ok=True)
    require(signature.returncode == 0 and len(signature.stdout) == 64,
        'callback-gate failure valid Ed25519 proof')
    signature_value = b64url(signature.stdout)
  else:
    signature_value = signer(envelope, identifier)
  proof = json.dumps({'profile': envelope['profile'], 'challenge': envelope['challenge'],
      'identity_id': identifier, 'signature': signature_value},
      ensure_ascii=False, separators=(',', ':')).encode('utf-8')

  log_cursor = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
  redirects_before = len(wallet.redirects)
  proof_status, proof_headers, proof_body = wallet.request('POST', locator, proof,
      {'Content-Type': 'application/json'})
  proof_location = proof_headers.get('Location')
  proof_redirected = len(wallet.redirects) != redirects_before
  require(proof_status == 503 and not proof_body and proof_location is None
      and not proof_redirected, 'callback-gate commit-then-throw is empty 503 without redirect', proof_status)
  retry_redirects_before = len(wallet.redirects)
  retry_status, retry_headers, retry_body = wallet.request('POST', locator, proof,
      {'Content-Type': 'application/json'})
  retry_redirected = len(wallet.redirects) != retry_redirects_before
  require(retry_status == 404 and not retry_body and retry_headers.get('Location') is None
      and not retry_redirected, 'consumed transaction retry is empty 404', retry_status)
  status_headers = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty', 'X-Decent-CSRF': csrf.group(1)}
  status_redirects_before = len(browser.redirects)
  status_status, status_response_headers, status_body = browser.request(
      'GET', status_match.group(1), headers=status_headers)
  status_redirected = len(browser.redirects) != status_redirects_before
  require(status_status == 404 and not status_body
      and status_response_headers.get('Location') is None and not status_redirected,
      'initiating browser sees no callback from failed callback gate', status_status)
  require(b'callback' not in status_body.lower() and b'code' not in status_body.lower(),
      'callback-gate failure reveals neither callback nor code')

  logs = run(['podman', 'logs', '--since', log_cursor, '--timestamps', container], timeout=15)
  require(logs.returncode == 0, 'per-run callback-gate failure log cursor')
  request_id = hashlib.sha256(locator.rsplit('/', 1)[1].encode('ascii')).hexdigest()[:32]
  production_marker = f'Wallet proof acceptance unavailable (request={request_id}, outcome=not_accepted)'
  test_marker = ('ISSUE6_TEST_FAULT: callback gate delegate putIfAbsent committed; '
      'test decorator threw')
  log_text = subprocess_output_text(logs)
  production_count = log_text.count(production_marker)
  test_count = log_text.count(test_marker)
  require(production_count == 1 and test_count == 1,
      'one correlated neutral production failure and one callback-gate commit-then-throw marker')
  receipt_failure_marker = (f'Wallet accepted receipt publication unavailable (request={request_id}, '
      'cause=post_consume_receipt_failure)')
  require(receipt_failure_marker not in log_text,
      'callback-gate failure is not misattributed as receipt publication failure')
  return {'stage': 'failed_then_denied', 'proof_http': proof_status,
      'proof_body_empty': not proof_body, 'proof_location_present': proof_location is not None,
      'proof_redirect_followed': proof_redirected, 'retry_http': retry_status,
      'retry_redirect_followed': retry_redirected, 'status_http': status_status,
      'status_body_empty': not status_body,
      'status_location_present': status_response_headers.get('Location') is not None,
      'status_redirect_followed': status_redirected, 'callback_exposed': False,
      'oidc_code_exposed': False, 'fault_signal_correlated': production_count == 1,
      'fault_signal_count': production_count, 'delegate_commit_then_throw': test_count == 1,
      'test_provider_selected': provider_selected,
      'selected_provider_path': ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID}


def run_issue6_single_node_profile(*, run_expiry=True):
  """Run the one-node auth flow, optionally including its authorized expiry phase."""
  global IMAGE, RUN_CID_DIR
  IMAGE, image_digest = resolve_immutable_image(IMAGE)
  runtime_provenance = _prepare_resolver_runtime()
  runtime_provenance['image_digest'] = image_digest
  run_id = uuid.uuid4().hex
  RUN_CID_DIR = Path(SCRATCH) / ('wallet-login-cids-' + run_id)
  RUN_CID_DIR.mkdir(mode=0o700, parents=True, exist_ok=False)
  container = 'issue6-single-node-' + run_id
  password = secrets.token_urlsafe(32)
  registry = None
  resolver_tools = None
  result = {'resolver_runtime': runtime_provenance,
      'issue6_single_node': {'stage': 'preflight', 'node_count': 1}}
  evidence = None
  try:
    with tempfile.TemporaryDirectory(prefix='issue6-single-node-', dir=SCRATCH) as temp_dir:
      evidence_path = Path(temp_dir) / 'live-evidence.json'

      def checkpoint():
        evidence_path.write_text(json.dumps(sanitize_live_checkpoint(result), sort_keys=True),
            encoding='utf-8')

      def mark_stage(stage):
        profile = dict(result.get('issue6_single_node', {}))
        profile.update({'stage': stage, 'node_count': 1})
        result['issue6_single_node'] = profile
        checkpoint()

      def partial_evidence():
        return sanitize_live_checkpoint(result)

      checkpoint()
      with report_partial_evidence_on_failure(evidence_path, partial_evidence):
        resolver_tools = start_resolver_tools(Path(temp_dir), IMAGE)
        os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = resolver_tools
        mark_stage('resolver_setup')
        registry_node, bootstrap, _ = start_registry(Path(temp_dir), IMAGE)
        registry = registry_node
        mark_stage('registry_setup')
        resolver_port = free_port()
        key, wrapper, identifier = write_identity(
            Path(temp_dir), bootstrap, IMAGE, label='issue6-wallet-login')
        mark_stage('identity_setup')
        client = start_keycloak(container, password, wrapper, resolver_port, bootstrap, IMAGE)
        if not isinstance(client.wallet_container_id, str):
          raise RuntimeError('Keycloak container ID is unavailable')
        mark_stage('keycloak_setup')
        token = admin_token(client, password)
        runtime_provenance.update(keycloak_runtime_provenance(
            client, token, client.wallet_container_id))
        result['resolver_runtime'] = runtime_provenance
        checkpoint()
        if not runtime_baseline_is_verified(runtime_provenance):
          raise RuntimeError('Keycloak version and single-node baseline are not verified')
        configure_realm(client, token, identifier, resolver_port, wrapper, bootstrap)
        enable_keycloak_login_events(client, token)
        provision_identity_attribute(client, token, 'wallet-owner', identifier)
        result['issue6_single_node'] = {
            **result['issue6_single_node'], 'stage': 'realm_setup', 'node_count': 1,
            **{field: runtime_provenance[field] for field in (
                'keycloak_version', 'keycloak_nodes', 'database_mode_configured',
                'database_mode_effective', 'cache_mode_configured', 'cache_mode_effective',
                'single_use_object_provider_configured', 'single_use_object_provider_path')
              if field in runtime_provenance},
        }
        checkpoint()
        def auth_phase():
          auth_result = run_issue6_auth_flow(result, AuthFlowAttempt(),
              lambda: auth_flow(Client(), key, identifier, client.wallet_container_id, IMAGE,
                  admin_access_token=token),
              checkpoint)
          return {'wallet_login': auth_result}

        profile_result = run_acceptance_profile(
            'issue6-single-node' if run_expiry else 'issue6-auth-flow',
            lambda: expiry_profile_coordinator(
                client, key, identifier, client.wallet_container_id, IMAGE,
                lambda snapshot: checkpoint_live_case(
                    result, 'expiry_case', snapshot, checkpoint), runtime_provenance),
            auth_phase,
            checkpoint=lambda snapshot: (result.update(snapshot), checkpoint()))
        result.update(profile_result)
        runtime_provenance['diagnostic_categories'] = capture_live_resolver_diagnostics(
            client.wallet_container_id, result, checkpoint)
        checkpoint()
        evidence = sanitize_live_checkpoint(result)
  except BaseException:
    cleanup_after_failure(registry, resolver_tools)
    raise
  else:
    finish_owned_cleanup(registry, resolver_tools)
    print('issue6_single_node_evidence=' + json.dumps(evidence, sort_keys=True))


def run_issue6_postconsume_receipt_failure_profile():
  """Run a test-image-only one-node receipt failure and fresh-login recovery."""
  global IMAGE, RUN_CID_DIR
  test_image = os.environ.get('WALLET_IT_TEST_IMAGE')
  if not test_image:
    raise RuntimeError('WALLET_IT_TEST_IMAGE must name the isolated Issue #6 test image')
  IMAGE, image_digest = resolve_immutable_image(test_image)
  runtime_provenance = _prepare_resolver_runtime()
  runtime_provenance['image_digest'] = image_digest
  run_id = uuid.uuid4().hex
  RUN_CID_DIR = Path(SCRATCH) / ('wallet-login-cids-' + run_id)
  RUN_CID_DIR.mkdir(mode=0o700, parents=True, exist_ok=False)
  container = 'issue6-postconsume-test-' + run_id
  password = secrets.token_urlsafe(32)
  registry = None
  resolver_tools = None
  result = {'resolver_runtime': runtime_provenance,
      'issue6_postconsume_receipt_failure_case': {'stage': 'preflight'}}
  evidence = None
  try:
    with tempfile.TemporaryDirectory(prefix='issue6-postconsume-', dir=SCRATCH) as temp_dir:
      evidence_path = Path(temp_dir) / 'live-evidence.json'

      def checkpoint():
        evidence_path.write_text(json.dumps(sanitize_live_checkpoint(result), sort_keys=True),
            encoding='utf-8')

      def mark_stage(stage, **facts):
        result['issue6_postconsume_receipt_failure_case'] = {'stage': stage, **facts}
        checkpoint()

      def partial_evidence():
        return sanitize_live_checkpoint(result)

      checkpoint()
      with report_partial_evidence_on_failure(evidence_path, partial_evidence):
        resolver_tools = start_resolver_tools(Path(temp_dir), IMAGE)
        os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = resolver_tools
        mark_stage('resolver_setup')
        registry_node, bootstrap, _ = start_registry(Path(temp_dir), IMAGE)
        registry = registry_node
        mark_stage('registry_setup')
        resolver_port = free_port()
        key, wrapper, identifier = write_identity(
            Path(temp_dir), bootstrap, IMAGE, label='issue6-postconsume-wallet-login')
        mark_stage('identity_setup')
        client = start_keycloak(container, password, wrapper, resolver_port, bootstrap, IMAGE,
            single_use_object_provider=ISSUE6_POSTCONSUME_TEST_PROVIDER_ID)
        if not isinstance(client.wallet_container_id, str):
          raise RuntimeError('Keycloak container ID is unavailable')
        mark_stage('keycloak_setup')
        token = admin_token(client, password)
        runtime_provenance.update(keycloak_runtime_provenance(
            client, token, client.wallet_container_id))
        result['resolver_runtime'] = runtime_provenance
        mark_stage('runtime_provenance_read')
        if not runtime_baseline_is_verified(runtime_provenance):
          raise RuntimeError('Keycloak one-node runtime baseline is not verified')
        mark_stage('runtime_baseline_verified')
        if not issue6_postconsume_provider_is_registered(runtime_provenance):
          raise RuntimeError('Issue #6 test decorator is not registered by Keycloak runtime')
        selected_provider = runtime_provenance.get('single_use_object_provider_path')
        if selected_provider not in {
            'issue6-postconsume-receipt-failure', 'unavailable'}:
          raise RuntimeError('Issue #6 test decorator is not selected by Keycloak runtime config')
        mark_stage('provider_registration_verified')
        run_checkpointed_step(mark_stage, 'configure_realm', 'realm_configured',
            lambda: configure_realm(client, token, identifier, resolver_port, wrapper, bootstrap))
        run_checkpointed_step(mark_stage, 'enable_login_events', 'login_events_enabled',
            lambda: enable_keycloak_login_events(client, token))
        run_checkpointed_step(mark_stage, 'provision_identity', 'realm_setup',
            lambda: provision_identity_attribute(client, token, 'wallet-owner', identifier))

        browser_state = {}
        failure_case = postconsume_receipt_failure_flow(
            key, identifier, client.wallet_container_id, browser_state=browser_state)
        result['issue6_postconsume_receipt_failure_case'] = failure_case
        checkpoint()
        wait_for_identity_lookup_cooldown()
        def recovery_progress(stage, fields):
          recovery_checkpoint = dict(result.get('issue6_postconsume_receipt_recovery', {}))
          recovery_checkpoint.update(fields)
          recovery_checkpoint['stage'] = stage
          result['issue6_postconsume_receipt_recovery'] = recovery_checkpoint
          checkpoint()

        recovery_progress('recovery_started', {})
        try:
          recovery = auth_flow(browser_state['browser'], key, identifier,
              client.wallet_container_id, IMAGE, prior_locator=browser_state['initial_locator'],
              progress_callback=recovery_progress, admin_access_token=token)
        except BaseException as failure:
          current = result.get('issue6_postconsume_receipt_recovery', {})
          recovery_progress(current.get('stage', 'recovery_started'),
              {'failure_category': safe_failure_category(failure)})
          raise
        recovery_case = {
            **result.get('issue6_postconsume_receipt_recovery', {}),
            'stage': 'complete',
            'fresh_login_http': recovery['login_page_http'],
            'fresh_login_transaction_available': (
                recovery['fresh_locator_distinct'] and recovery['initial_status_accepted']),
            'callback_http': recovery['callback_http'],
            'callback_code': recovery['callback_code_returned'],
            'callback_replay_denied': (recovery['callback_replay_error_returned']
                and not recovery['callback_replay_code_returned']),
            'pkce_token_http': recovery['pkce_token_http'],
        }
        require(recovery_case['fresh_login_transaction_available'],
            'fresh login after failed receipt obtains a distinct accepted transaction')
        require(recovery_case['callback_replay_denied'],
            'fresh login callback replay is denied without returning another code')
        result['issue6_postconsume_receipt_recovery'] = recovery_case
        checkpoint()
        evidence = sanitize_live_checkpoint(result)
  except BaseException:
    cleanup_after_failure(registry, resolver_tools)
    raise
  else:
    finish_owned_cleanup(registry, resolver_tools)
    print('issue6_postconsume_receipt_failure_evidence=' + json.dumps(evidence, sort_keys=True))



def run_issue6_postconsume_callback_gate_failure_profile():
  """Run the isolated callback-gate fault and then the ordinary recovery flow."""
  global IMAGE, RUN_CID_DIR
  test_image = os.environ.get('WALLET_IT_TEST_IMAGE')
  if not test_image:
    raise RuntimeError('WALLET_IT_TEST_IMAGE must name the isolated Issue #6 test image')
  IMAGE, image_digest = resolve_immutable_image(test_image)
  runtime_provenance = _prepare_resolver_runtime()
  runtime_provenance['image_digest'] = image_digest
  run_id = uuid.uuid4().hex
  RUN_CID_DIR = Path(SCRATCH) / ('wallet-login-cids-' + run_id)
  RUN_CID_DIR.mkdir(mode=0o700, parents=True, exist_ok=False)
  container = 'issue6-callback-gate-test-' + run_id
  password = secrets.token_urlsafe(32)
  registry = resolver_tools = None
  result = {'resolver_runtime': runtime_provenance,
      'issue6_postconsume_callback_gate_failure_case': {'stage': 'preflight'}}
  evidence = None
  try:
    with tempfile.TemporaryDirectory(prefix='issue6-callback-gate-', dir=SCRATCH) as temp_dir:
      evidence_path = Path(temp_dir) / 'live-evidence.json'

      def checkpoint():
        evidence_path.write_text(json.dumps(sanitize_live_checkpoint(result), sort_keys=True),
            encoding='utf-8')

      def mark_stage(stage, **facts):
        result['issue6_postconsume_callback_gate_failure_case'] = {'stage': stage, **facts}
        checkpoint()

      checkpoint()
      with report_partial_evidence_on_failure(evidence_path, lambda: sanitize_live_checkpoint(result)):
        resolver_tools = start_resolver_tools(Path(temp_dir), IMAGE)
        os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = resolver_tools
        mark_stage('resolver_setup')
        registry_node, bootstrap, _ = start_registry(Path(temp_dir), IMAGE)
        registry = registry_node
        mark_stage('registry_setup')
        resolver_port = free_port()
        key, wrapper, identifier = write_identity(
            Path(temp_dir), bootstrap, IMAGE, label='issue6-callback-gate-wallet-login')
        mark_stage('identity_setup')
        client = start_keycloak(container, password, wrapper, resolver_port, bootstrap, IMAGE,
            single_use_object_provider=ISSUE6_CALLBACK_GATE_TEST_PROVIDER_ID)
        if not isinstance(client.wallet_container_id, str):
          raise RuntimeError('Keycloak container ID is unavailable')
        mark_stage('keycloak_setup')
        token = admin_token(client, password)
        runtime_provenance.update(keycloak_runtime_provenance(
            client, token, client.wallet_container_id))
        result['resolver_runtime'] = runtime_provenance
        mark_stage('runtime_provenance_read')
        if not runtime_baseline_is_verified(runtime_provenance):
          raise RuntimeError('Keycloak one-node runtime baseline is not verified')
        mark_stage('runtime_baseline_verified')
        provider_id = 'issue6-postconsume-callback-gate-failure'
        provider_ids = runtime_provenance.get('single_use_object_provider_ids')
        if not isinstance(provider_ids, list) or provider_id not in provider_ids:
          raise RuntimeError('Issue #6 callback-gate test provider is not registered by Keycloak runtime')
        mark_stage('provider_registration_verified')
        if runtime_provenance.get('single_use_object_provider_path') not in {provider_id, 'unavailable'}:
          raise RuntimeError('Issue #6 callback-gate test provider is not selected by Keycloak runtime config')
        mark_stage('provider_config_verified')
        run_checkpointed_step(mark_stage, 'configure_realm', 'realm_configured',
            lambda: configure_realm(client, token, identifier, resolver_port, wrapper, bootstrap))
        run_checkpointed_step(mark_stage, 'enable_login_events', 'login_events_enabled',
            lambda: enable_keycloak_login_events(client, token))
        run_checkpointed_step(mark_stage, 'provision_identity', 'realm_setup',
            lambda: provision_identity_attribute(client, token, 'wallet-owner', identifier))

        browser_state = {}
        failure_case = postconsume_callback_gate_failure_flow(
            key, identifier, client.wallet_container_id, browser_state=browser_state)
        result['issue6_postconsume_callback_gate_failure_case'] = failure_case
        checkpoint()
        wait_for_identity_lookup_cooldown()
        def recovery_progress(stage, fields):
          recovery_checkpoint = dict(result.get('issue6_postconsume_callback_gate_recovery', {}))
          recovery_checkpoint.update(fields)
          recovery_checkpoint['stage'] = stage
          result['issue6_postconsume_callback_gate_recovery'] = recovery_checkpoint
          checkpoint()

        recovery_progress('recovery_started', {})
        try:
          recovery = auth_flow(browser_state['browser'], key, identifier,
              client.wallet_container_id, IMAGE, prior_locator=browser_state['initial_locator'],
              progress_callback=recovery_progress, admin_access_token=token)
        except BaseException as failure:
          current = result.get('issue6_postconsume_callback_gate_recovery', {})
          recovery_progress(current.get('stage', 'recovery_started'),
              {'failure_category': safe_failure_category(failure)})
          raise
        recovery_case = {
            **result.get('issue6_postconsume_callback_gate_recovery', {}),
            'stage': 'complete',
            'fresh_login_http': recovery['login_page_http'],
            'fresh_login_transaction_available': (
                recovery['fresh_locator_distinct'] and recovery['initial_status_accepted']),
            'callback_http': recovery['callback_http'],
            'callback_code': recovery['callback_code_returned'],
            'callback_replay_denied': (recovery['callback_replay_error_returned']
                and not recovery['callback_replay_code_returned']),
            'pkce_token_http': recovery['pkce_token_http'],
        }
        require(recovery_case['fresh_login_transaction_available'],
            'fresh login after callback-gate failure obtains a distinct accepted transaction')
        require(recovery_case['callback_replay_denied'],
            'recovery callback replay is denied without returning another code')
        result['issue6_postconsume_callback_gate_recovery'] = recovery_case
        checkpoint()
        evidence = sanitize_live_checkpoint(result)
  except BaseException:
    cleanup_after_failure(registry, resolver_tools)
    raise
  else:
    finish_owned_cleanup(registry, resolver_tools)
    print('issue6_postconsume_callback_gate_failure_evidence=' + json.dumps(evidence, sort_keys=True))


def main():
  global IMAGE, RUN_CID_DIR
  profile = selected_live_profile()
  fault_mode = ISSUE7_USER_READBACK_FAULT_MODES.get(profile)
  store_fault_mode = issue7_store_recovery.PROFILES.get(profile)
  if store_fault_mode is not None:
    configured_image = os.environ.get('WALLET_IT_STORE_RECOVERY_IMAGE')
    if not configured_image:
      raise ValueError('WALLET_IT_STORE_RECOVERY_IMAGE is required for the Issue #7 store profile')
    IMAGE = configured_image
  if fault_mode is not None:
    configured_image = os.environ.get('WALLET_IT_USER_READBACK_IMAGE')
    if not configured_image:
      raise ValueError('WALLET_IT_USER_READBACK_IMAGE is required for the Issue #7 test-provider profile')
    IMAGE = configured_image
  if profile == 'issue6-single-node':
    return run_issue6_single_node_profile()
  if profile == 'issue6-auth-flow':
    return run_issue6_single_node_profile(run_expiry=False)
  if profile == 'issue6-postconsume-receipt-failure':
    return run_issue6_postconsume_receipt_failure_profile()
  if profile == 'issue6-postconsume-callback-gate-failure':
    return run_issue6_postconsume_callback_gate_failure_profile()
  IMAGE, image_digest = resolve_immutable_image(IMAGE)
  runtime_provenance = _prepare_resolver_runtime()
  runtime_provenance['image_digest'] = image_digest
  run_id = uuid.uuid4().hex
  RUN_CID_DIR = Path(SCRATCH) / ('wallet-login-cids-' + run_id)
  RUN_CID_DIR.mkdir(mode=0o700, parents=True, exist_ok=False)
  container = f'wallet-login-live-e2e-{run_id}'
  password = secrets.token_urlsafe(32)
  registry = None
  resolver_tools = None
  try:
    with tempfile.TemporaryDirectory(prefix='wallet-login-e2e-',
        dir=SCRATCH) as temp_dir:
      evidence_path = Path(temp_dir) / 'live-evidence.json'
      result = {'resolver_runtime': runtime_provenance}
      def checkpoint(snapshot=None):
        evidence = {**result, **(snapshot or {})}
        evidence_path.write_text(
            json.dumps(sanitize_live_checkpoint(evidence), sort_keys=True), encoding='utf-8')
      if store_fault_mode is not None:
        result['issue7_store_recovery'] = {'stage': 'setup', 'scope': 'one-keycloak-node',
            'store_fault_mode': store_fault_mode,
            'fault_evidence_provenance': 'wrapper-mediated-application-path'}
        checkpoint()
      def issue7_setup_stage(stage):
        if fault_mode is None:
          return
        current = dict(result.get('issue7_single_node_signup_recovery', {}))
        current['stage'] = stage
        if stage == 'runtime_verified':
          current['keycloak_node_count'] = 1
        result['issue7_single_node_signup_recovery'] = current
        checkpoint()
      if fault_mode is not None:
        result['issue7_single_node_signup_recovery'] = {
            'stage': 'setup', 'scope': 'one-keycloak-node',
            'user_readback_fault_mode': fault_mode,
            'fault_evidence_provenance': 'wrapper-mediated-application-path'}
        checkpoint()
      def latest_resolver_diagnostics():
        if resolver_tools is None:
          return {'resolver_runtime': runtime_provenance,
              'rotated_identity_case': {'stage': 'probe_not_started'}}
        return {'resolver_runtime': runtime_provenance,
            'rotated_identity_case': {'stage': 'diagnostic_probe',
                'diagnostic_categories': record_resolver_diagnostics(container)}}
      temp = Path(temp_dir)
      with report_partial_evidence_on_failure(evidence_path, latest_resolver_diagnostics):
        issue7_setup_stage('resolver_tools_starting')
        resolver_tools = start_resolver_tools(temp, IMAGE,
            lifetime=EXPIRY_CONTAINER_LIFETIME_SECONDS if profile == 'expiry' else 300)
        issue7_setup_stage('resolver_tools_started')
        os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = resolver_tools
        issue7_setup_stage('registry_starting')
        registry, bootstrap, registry_port = start_registry(temp, IMAGE,
            run_seconds=EXPIRY_CONTAINER_LIFETIME_SECONDS if profile == 'expiry' else 300)
        issue7_setup_stage('registry_started')
        os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'] = resolver_tools
        issue7_setup_stage('identity_writing')
        resolver_port = free_port()
        key, wrapper, identifier = write_identity(temp, bootstrap, IMAGE)
        issue7_setup_stage('identity_ready')
        if (profile == 'expiry' or profile == 'issue7-signup-success'
            or fault_mode is not None or store_fault_mode is not None):
          unmapped_key = replay_key = None
          unmapped_identifier = replay_identifier = None
        else:
          unmapped_key, wrapper, unmapped_identifier = write_identity(
              temp, bootstrap, IMAGE, label='wallet-login-unmapped')
          replay_key, _, replay_identifier = write_identity(
              temp, bootstrap, IMAGE, label='wallet-login-replay')
        issue7_setup_stage('keycloak_starting')
        start_options = {'user_readback_fault_mode': fault_mode}
        if store_fault_mode is not None:
          start_options['store_fault_mode'] = store_fault_mode
        client = start_keycloak(container, password, wrapper, resolver_port, bootstrap, IMAGE,
            **start_options)
        client.privateClientAdminCredential = password
        if not isinstance(client.wallet_container_id, str):
          raise RuntimeError('Keycloak container ID is unavailable')
        container = client.wallet_container_id
        issue7_setup_stage('keycloak_started')
        issue7_setup_stage('runtime_verifying')
        token = admin_token(client, password)
        runtime_provenance.update(keycloak_runtime_provenance(
            client, token, client.wallet_container_id))
        if (runtime_provenance.get('runtime_qualification_status') == 'runtime_facts_verified'
            and runtime_provenance.get('keycloak_version') == '26.8.0'
            and runtime_provenance.get('keycloak_nodes') == 'one'):
          issue7_setup_stage('runtime_verified')
        else:
          issue7_setup_stage('keycloak_started')
        checkpoint()
        if profile == 'provider-not-found-diagnostic':
          require(runtime_provenance['keycloak_version'] == '26.8.0'
              and runtime_provenance['keycloak_nodes'] == 'one',
              'pinned single-node Keycloak runtime facts verified',
              runtime_provenance['keycloak_version'])
          configure_realm(client, token, identifier, resolver_port, wrapper, bootstrap)
          enable_keycloak_login_events(client, token)
          result['missing_identity_case'] = missing_identity_flow(
              temp, resolver_port, bootstrap, IMAGE)
          checkpoint()
          require(provider_missing_identity_is_qualified(result['missing_identity_case']),
              'additional provider-level missing-Identity terminal not_found diagnostic qualification')
          runtime_provenance['diagnostic_categories'] = capture_live_resolver_diagnostics(
              container, result, checkpoint)
          print('provider-not-found-diagnostic-evidence=', json.dumps(sanitize_live_checkpoint(result), sort_keys=True))
          finish_owned_cleanup(registry, resolver_tools)
          registry = None
          resolver_tools = None
          return
        require(runtime_baseline_is_verified(runtime_provenance),
            'pinned Keycloak version and single-node baseline verified',
            runtime_provenance['keycloak_version'])
        issue7_setup_stage('realm_configuring')
        configure_realm(client, token, identifier, resolver_port, wrapper, bootstrap)
        issue7_setup_stage('realm_configured')
        issue7_setup_stage('events_configuring')
        enable_keycloak_login_events(client, token)
        issue7_setup_stage('events_configured')
        if store_fault_mode is not None:
          require('issue7-fault-injection' in runtime_provenance.get('single_use_object_provider_ids', []),
              'dedicated store fault provider is registered')
          def save_store_checkpoint(evidence):
            merge_issue7_checkpoint(result, 'issue7_store_recovery', evidence, checkpoint)
          def store_progress(stage, fields):
            current = dict(result['issue7_store_recovery'])
            current.update(fields)
            if current.get('stage') != 'recovery':
              current['stage'] = 'faulted_signup'
            save_store_checkpoint(current)
          issue7_store_recovery.run(sys.modules[__name__], Client(), key, identifier, container,
              client, IMAGE, store_progress, save_store_checkpoint, profile)
          print('issue7-store-recovery-evidence=',
              json.dumps(sanitize_live_checkpoint(result), sort_keys=True))
          finish_owned_cleanup(registry, resolver_tools)
          registry = None
          resolver_tools = None
          return
        if fault_mode is not None:
          require(runtime_provenance['keycloak_version'] == '26.8.0'
              and runtime_provenance['keycloak_nodes'] == 'one',
              'pinned single-node Keycloak runtime facts verified',
              runtime_provenance['keycloak_version'])
          def progress(stage, fields):
            if stage not in {'faulted_signup', 'fresh_signup'}:
              return
            current = dict(result.get('issue7_single_node_signup_recovery', {}))
            current['stage'] = stage
            for field, value in fields.items():
              if field.endswith('_http') and type(value) is int and 100 <= value <= 599:
                current[field] = value
              elif field in {'exact_mapped_users', 'post_create_read_fault_count',
                  'correlated_mapping_failure_count'} and type(value) is int and 0 <= value <= 65:
                current[field] = value
              elif field in {'browser_status_pending', 'failure_responses_no_callback_or_code',
                  'account_retained_after_failure', 'user_readback_factory_selected',
                  'post_create_read_fault_observed'} and type(value) is bool:
                current[field] = value
              elif field == 'effective_user_readback_fault_mode' and value in {'empty', 'throw', 'over-cap'}:
                current[field] = value
            result['issue7_single_node_signup_recovery'] = current
            checkpoint()
          def save_issue7_checkpoint(evidence):
            merge_issue7_checkpoint(result, 'issue7_single_node_signup_recovery', evidence, checkpoint)
          handlers = {
              profile_name: lambda profile_name=profile_name: run_issue7_single_node_signup_recovery_profile(
                  Client(), key, identifier, container, client, IMAGE, progress,
                  save_issue7_checkpoint, profile_name)
              for profile_name in ISSUE7_USER_READBACK_FAULT_MODES
          }
          evidence = dispatch_live_profile(profile, handlers)
          print('issue7-user-readback-evidence=',
              json.dumps(sanitize_live_checkpoint(result), sort_keys=True))
          finish_owned_cleanup(registry, resolver_tools)
          registry = None
          resolver_tools = None
          return
        if profile == 'issue7-signup-success':
          def signup_success_progress(stage, fields):
            checkpoint_signup_stage(result, stage, fields, checkpoint)
          handlers = {profile: lambda: run_issue7_signup_success_profile(
              Client(), key, identifier, container, client, IMAGE,
              signup_success_progress,
              lambda evidence: checkpoint_signup_stage(
                  result, 'complete', evidence, checkpoint))}
          evidence = dispatch_live_profile(profile, handlers)
          result['signup_case'] = evidence
          checkpoint()
          print('issue7-signup-success-evidence=',
              json.dumps(sanitize_live_checkpoint(result), sort_keys=True))
          finish_owned_cleanup(registry, resolver_tools)
          registry = None
          resolver_tools = None
          return
        if profile == 'expiry':
          def expiry_checkpoint(snapshot):
            result['expiry_case'] = snapshot
            checkpoint()

          result['expiry_case'] = expiry_profile_coordinator(
              client, key, identifier, container, IMAGE, expiry_checkpoint, runtime_provenance)
          checkpoint()
          print('expiry-evidence=', json.dumps(sanitize_live_checkpoint(result), sort_keys=True))
          finish_owned_cleanup(registry, resolver_tools)
          registry = None
          resolver_tools = None
          return
        provision_identity_attribute(client, token, 'wallet-owner-duplicate', replay_identifier)
        result['registry_matrix'] = {'current_identity': {'attempts': []}}

        def checkpoint_current_attempt(snapshot):
          current = snapshot['registry_matrix']['current_identity']
          result['registry_matrix']['current_identity'] = current
          checkpoint()

        for attempt_number in range(1, 3):
          def current_lookup(_attempt_number):
            return run_image_resolver(os.environ['WALLET_IT_RESOLVER_TOOLS_CONTAINER'],
                ['get', '--identifier', identifier, '--host', '127.0.0.1',
                 '--port', str(free_port()), '--bootstrap', bootstrap], timeout=20, image=IMAGE)

          current_result = invoke_current_identity_attempt(identifier, key, container,
              IMAGE, attempt_number, current_lookup)
          if current_result.get('exact_readback') and 'wallet_login' in current_result:
            if 'wallet_login' not in result:
              result['wallet_login'] = current_result.pop('wallet_login')
            else:
              current_result.pop('wallet_login', None)
          attempts = result['registry_matrix']['current_identity']['attempts']
          attempts.append(current_result)
          checkpoint_current_attempt({'registry_matrix': {'current_identity': {
              'attempts': attempts}}})

        result['registry_matrix']['missing_identity'] = {'attempts': []}
        latest_missing_result = {}

        def run_missing_attempt(attempt_number, identity_fixture):
          del attempt_number
          fixture_name, _, missing_key, missing_id = identity_fixture
          missing_result = registry_proof_probe(temp, resolver_port, bootstrap, IMAGE,
              identity_key=missing_key, identity_id=missing_id)
          latest_missing_result.clear()
          latest_missing_result.update(missing_result)
          missing_outcome = classify_registry_matrix_attempt(
              missing_result['cli_resolution'], missing_result['direct_provider_http'],
              status_pending=missing_result['status_pending'], exact_readback=False)
          return {
              'direct_resolution': missing_result['cli_resolution'],
              'provider_http': missing_result['direct_provider_http'],
              'proof_post_http': missing_result['direct_provider_http'],
              'status_http': missing_result['status_http'],
              'status_poll_http': missing_result['status_http'],
              'status_pending': missing_result['status_pending'],
              'no_acceptance_or_callback': missing_result['no_acceptance_or_callback'],
              'exact_readback': False, 'outcome': missing_outcome,
              'fixture': fixture_name}

        def checkpoint_missing_attempt(snapshot):
          result['registry_matrix']['missing_identity'] = {
              'attempts': snapshot['registry_matrix']['missing_identity']['attempts']}
          checkpoint()

        def fresh_missing_fixture(attempt_number):
          attempt_label = 'wallet-login-unpublished-' + uuid.uuid4().hex
          missing_key = generate_owner_key(temp, attempt_label, IMAGE)
          missing_id = attempt_label + '@example.invalid'
          return f'unpublished-fixture-{attempt_number}', attempt_label, missing_key, missing_id

        missing_attempts = run_registry_attempts('missing_identity', run_missing_attempt,
            checkpoint_missing_attempt, fixture_factory=fresh_missing_fixture)
        result['missing_identity_case'] = latest_missing_result
        result['registry_matrix']['missing_identity'] = {
            'attempts': missing_attempts['attempts']}
        for missing_attempt in missing_attempts['attempts']:
          require(missing_attempt.get('no_acceptance_or_callback') is True,
              'missing-Identity proof produced no accepted receipt or callback',
              missing_attempt.get('provider_http'))
        checkpoint()

        result['registry_matrix']['unavailable_registry'] = {'attempts': []}
        unavailable_port = free_port()
        unavailable_bootstrap_value = unavailable_bootstrap(bootstrap, unavailable_port)
        require(unavailable_bootstrap_value is not None,
            'construct unreachable Registry bootstrap fixture')
        set_registry_bootstrap(client, token, unavailable_bootstrap_value)
        try:
          for attempt_number in range(1, 3):
            unavailable_result = registry_proof_probe(temp, resolver_port,
                unavailable_bootstrap_value, IMAGE, identity_key=key, identity_id=identifier)
            unavailable_outcome = classify_registry_matrix_attempt(
                unavailable_result['cli_resolution'], unavailable_result['direct_provider_http'],
                status_pending=unavailable_result['status_pending'], exact_readback=False)
            result['registry_matrix']['unavailable_registry']['attempts'].append({
                'attempt_number': attempt_number,
                'direct_resolution': unavailable_result['cli_resolution'],
                'provider_http': unavailable_result['direct_provider_http'],
                'status_http': unavailable_result['status_http'],
                'status_pending': unavailable_result['status_pending'],
                'no_acceptance_or_callback': unavailable_result['no_acceptance_or_callback'],
                'exact_readback': False, 'outcome': unavailable_outcome})
            checkpoint()
            require(unavailable_result['no_acceptance_or_callback'],
                'unavailable Registry proof produced no accepted receipt or callback',
                unavailable_result['direct_provider_http'])
        finally:
          set_registry_bootstrap(client, token, bootstrap)
        result['registry_matrix']['history_incomplete'] = {'attempts': []}
        result['registry_matrix']['malformed_result'] = {'attempts': []}
        result['registry_matrix']['ambiguous_registry_result'] = {'attempts': []}
        result['registry_matrix']['rotation'] = {'attempts': []}
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
        first_rotation_outcome = classify_registry_matrix_attempt('resolved',
            rotation_result['current_key_proof_http'], status_pending=False, exact_readback=True)
        result['registry_matrix']['rotation']['attempts'].append({
            'attempt_number': 1, 'direct_resolution': 'resolved', 'exact_readback': True,
            'provider_http': rotation_result['current_key_proof_http'],
            'stale_key_proof_http': rotation_result['stale_key_proof_http'],
            'current_key_proof_http': rotation_result['current_key_proof_http'],
            'current_sequence': rotation_result['current_sequence'],
            'stale_transaction_remains_pending': rotation_result['stale_transaction_remains_pending'],
            'current_transaction_accepted': rotation_result['current_transaction_accepted'],
            'status_pending': False, 'no_acceptance_or_callback': False,
            'outcome': first_rotation_outcome})
        checkpoint()
        rotated_successor = generate_owner_key(
            temp, 'wallet-login-rotated-successor-2', IMAGE)
        rotation_repeat = stale_key_rotation_flow(
            client, rotated_key, rotated_successor, rotated_identifier, container,
            resolver_port, bootstrap, rotated_wrapper.name, rotation_progress, IMAGE, temp,
            expected_sequence=3)
        repeated_rotation_outcome = classify_registry_matrix_attempt('resolved',
            rotation_repeat['current_key_proof_http'], status_pending=False, exact_readback=True)
        result['registry_matrix']['rotation']['attempts'].append({
            'attempt_number': 2, 'direct_resolution': 'resolved', 'exact_readback': True,
            'provider_http': rotation_repeat['current_key_proof_http'],
            'stale_key_proof_http': rotation_repeat['stale_key_proof_http'],
            'current_key_proof_http': rotation_repeat['current_key_proof_http'],
            'current_sequence': rotation_repeat['current_sequence'],
            'stale_transaction_remains_pending': rotation_repeat['stale_transaction_remains_pending'],
            'current_transaction_accepted': rotation_repeat['current_transaction_accepted'],
            'status_pending': False, 'no_acceptance_or_callback': False,
            'outcome': repeated_rotation_outcome})
        token = admin_token(client, AdminPassword(password))
        rotated_user = json.loads(admin_call(client, token, 'GET',
            f'/auth/admin/realms/{REALM}/users?username=wallet-rotated-owner&exact=true')[2])
        local_mapping_persisted = (len(rotated_user) == 1
            and rotated_user[0].get('attributes', {}).get('decent_identity_id') == [rotated_identifier])
        rotation_progress('mapping', {'local_mapping_persisted': local_mapping_persisted})
        require(local_mapping_persisted, 'rotated account Identity mapping persisted exactly')
        result['rotated_identity_case'] = {
            **result.get('rotated_identity_case', {}), 'stage': 'complete', **rotation_repeat,
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
        print('E2E_SCENARIOS_COMPLETE: inspect per-case outcomes; overall provider qualification remains limited')
        runtime_provenance['diagnostic_categories'] = capture_live_resolver_diagnostics(
            container, result, checkpoint)
        print('evidence=', json.dumps(sanitize_live_checkpoint(result), sort_keys=True))
  except BaseException:
    cleanup_after_failure(registry, resolver_tools)
    raise
  else:
    finish_owned_cleanup(registry, resolver_tools)


if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print('harness_status=interrupted')
    raise SystemExit(130) from None
  except SystemExit:
    raise
  except Exception as failure:
    print('harness_status=failed; failure_category=' + safe_failure_category(failure))
    raise SystemExit(1) from None
