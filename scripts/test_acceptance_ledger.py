"""Current Keycloak wallet-login qualification ledger, evidence and limits."""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).parents[1] / "README.md"


def test_acceptance_ledger_reports_fresh_signup_evidence_and_remaining_gates():
    text = README.read_text()
    assert "offline Maven clean package passed 118 tests across 12 suites" in text
    assert "Python source/harness group passed 59 tests" in text
    assert "Latest integration run" in text
    assert "signup action POST returned 200" in text
    assert "exact signed `decent_identity_id` claim" in text
    assert "pre-provisions the local account before the proof request" in text
    assert "Code + PKCE token exchange returned 200" in text
    assert "Signup and existing-account flows passed the latest disposable run" in text
    assert "missing-Identity resolution returned HTTP 401" in text
    assert "Two-node shared-store replay" in text
    assert "issue remains open" in text


def test_rotation_section_limits_pass_claim_to_bounded_simulation():
    text = README.read_text()
    assert "Latest owner-key rotation run passed its bounded disposable gates" in text
    assert "Registry sequence 2" in text
    assert "Registry-only rotation roundtrip (1 test" not in text
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
