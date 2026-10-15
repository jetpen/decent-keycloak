"""Current Keycloak wallet-login qualification ledger, evidence and limits."""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).parents[1] / "README.md"
def test_acceptance_ledger_reports_fresh_signup_evidence_and_remaining_gates():
    text = README.read_text()
    assert "offline Maven clean package passed 119 tests across 12 suites" in text
    assert "Python source/harness group passed 60 tests" in text
    assert "Fresh signup provisioning and callback guard passed bounded single-node simulation" in text
    assert "exact Identity user was absent before proof" in text
    assert "exact signed `decent_identity_id` claim" in text
    assert "signup proof provisions exact account before pending consume" in (README.parents[0] / "scripts/wallet_login_live_e2e.py").read_text()
    assert "Missing-Identity returned 503 because resolver output contained peer-handshake diagnostics" in text
    assert "Two-node shared-store replay" in text
    assert "issue remains open" in text


def test_rotation_section_limits_pass_claim_to_bounded_simulation():
    text = README.read_text()
    assert "Fresh signup provisioning and callback guard passed bounded single-node simulation" in text
    live = (README.parents[0] / "scripts/wallet_login_live_e2e.py").read_text()
    assert "stale_key_status == 401" in live
    assert "current_key_status == 202" in live
    assert "not production qualification" in text


def test_authenticator_preserves_keycloaks_execution_tracking_on_wallet_challenge():
    source = (README.parents[0] / "src/main/java/org/decentwallet/keycloak/wallet/WalletChallengeAuthenticator.java").read_text()
    challenge_start = source.index("public void authenticate(AuthenticationFlowContext context)")
    action_start = source.index("public void action(AuthenticationFlowContext context)", challenge_start)
    body = source[challenge_start:action_start]
    body = body[body.index("String accessCode = context.generateAccessCode();"):]
    assert "CURRENT_AUTHENTICATION_EXECUTION" not in body
    assert "LAST_PROCESSED_EXECUTION" not in body
    assert "context.getActionUrl(accessCode)" in body
