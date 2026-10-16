"""Current Keycloak wallet-login qualification ledger, evidence and limits."""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).parents[1] / "README.md"
def test_acceptance_ledger_reports_fresh_signup_evidence_and_remaining_gates():
    text = README.read_text()
    assert "latest clean Maven package passed 143 tests across 12 suites" in text
    assert "Latest two disposable runs" in text
    assert "462028d4532af88ba30f03632c81cb4d7f8d37823e754e8d4ff9668beb1e3d5e" in text
    assert "The first completed all scenarios (exit 0)" in text
    assert "A repeat on the same image exited 1 at current-key proof HTTP 503" in text
    assert "Registry negative and repeatability remain unqualified" in text

    assert "Still open from Issue #1" in text
    assert "request-correlated reproducible attribution of account-policy denials under concurrent traffic" in text
    assert "self-contained reproducible pinned runtime" in text
    assert "two-node shared-store replay" in text
    assert "Issue #1 remains open" in text
    assert "native challenge GET with browser metadata absent" in text
    assert "no real wallet client has qualified it" in text
    assert "wallet challenge response stays exactly `{profile,challenge,csrf_token}`" in text
    assert "not an additional wallet challenge-response field" in text



def test_rotation_section_reports_bounded_current_image_result():
    text = README.read_text()
    assert "Latest two disposable runs" in text
    assert "current-key proof HTTP 503" in text
    assert "Registry negative and repeatability remain unqualified" in text


def test_live_probe_results_do_not_claim_production_qualification():
    text = README.read_text()
    assert "Both are single-node loopback/synthetic-signer/host-mounted-runtime simulations" in text
    assert "current-key proof HTTP 503" in text
    assert "Registry negative and repeatability remain unqualified" in text
    assert "two-node shared-store replay" in text








def test_admission_cooldown_and_emergency_promotion_are_bounded():
    text = README.read_text()
    assert "The resolver gets a ten-second execution timeout" in text
    assert "two-second forced-termination grace" in text
    assert "The shared admission key expires after two seconds, even if the resolver is still running" in text
    assert "promotion cannot cancel an already-admitted sibling lookup" in text


def test_authenticator_preserves_keycloaks_execution_tracking_on_wallet_challenge():
    source = (README.parents[0] / "src/main/java/org/decentwallet/keycloak/wallet/WalletChallengeAuthenticator.java").read_text()
    challenge_start = source.index("public void authenticate(AuthenticationFlowContext context)")
    action_start = source.index("public void action(AuthenticationFlowContext context)", challenge_start)
    body = source[challenge_start:action_start]
    body = body[body.index("String accessCode = context.generateAccessCode();"):]
    assert "CURRENT_AUTHENTICATION_EXECUTION" not in body
    assert "LAST_PROCESSED_EXECUTION" not in body
    assert "context.getActionUrl(accessCode)" in body
