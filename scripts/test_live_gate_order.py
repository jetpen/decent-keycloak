"""Disposable live-login probe safety and gate-order regressions."""
from __future__ import annotations

import ast
from pathlib import Path

PROBE = Path(__file__).with_name("wallet_login_live_e2e.py")


def _function_node(name: str) -> ast.FunctionDef:
    tree = ast.parse(PROBE.read_text())
    return next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)


def test_live_account_denial_flow_records_unavailable_direct_probe_as_diagnostic():
  source = PROBE.read_text()
  start = source.index("def account_mapping_denial_flow(")
  end = source.index("\ndef stale_key_rotation_flow", start)
  function = source[start:end]
  assert "except (subprocess.TimeoutExpired, RuntimeError) as resolver_failure" in function
  assert "direct Registry lookup unavailable" in function
  assert "container lookup emitted peer-unavailable diagnostics" in function


def test_live_disabled_account_fixture_has_distinct_identity_and_user_mapping():
  main = PROBE.read_text().split("def main():", 1)[1]
  assert "label='wallet-login-disabled'" in main
  assert "'username': 'wallet-disabled-fixture'" in main
  assert "client, disabled_key, disabled_identifier, 'disabled-account'" in main
  start = main.index("client, disabled_key, disabled_identifier, 'disabled-account'")
  assert "wallet-unmapped-fixture" not in main[start:start + 500]


def test_live_account_denial_flow_uses_initiating_cookie_jar_for_post_and_status():
  source = PROBE.read_text()
  start = source.index("def account_mapping_denial_flow(")
  end = source.index("\ndef stale_key_rotation_flow", start)
  function = source[start:end]
  assert "lookup_client = BareLocalClient()" not in function
  assert "browser.request('POST', locator, proof" in function
  assert "'X-Decent-CSRF': csrf.group(1)" in function
  assert "'Origin': WALLET_ORIGIN" in function
  assert "'Sec-Fetch-Site': 'cross-site'" in function
  assert "browser.request('GET', status_url.group(1)" in function


def test_live_disabled_account_fixture_is_independent_from_unmapped_user():
  source = PROBE.read_text()
  main = source[source.index("def main():"):]
  assert "label='wallet-login-disabled'" in main
  assert "'username': 'wallet-disabled-fixture'" in main
  start = main.index("client, disabled_key, disabled_identifier, 'disabled-account'")
  assert "wallet-unmapped-fixture" not in main[start:start + 500]


def test_live_probe_counts_registry_unavailable_separately_from_policy_denial():
  source = PROBE.read_text()
  start = source.index("def account_mapping_denial_flow(")
  end = source.index("\ndef stale_key_rotation_flow", start)
  body = source[start:end]
  assert "direct_http == 503" in body
  assert "direct_http == 403" in body
  assert "local_account_mapping_decision_observed" in body


def test_latest_e2e_summary_does_not_claim_full_qualification():
  source = PROBE.read_text()
  assert "overall provider qualification remains limited" in source
  assert "PASS: disposable Keycloak" not in source
