"""Current Keycloak wallet-login qualification ledger, evidence and limits."""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).parents[1] / "README.md"
def test_acceptance_ledger_reports_fresh_signup_evidence_and_remaining_gates():
    text = README.read_text()
    assert "`mvn -o clean package` passed 122 tests across 12 suites" in text
    assert "Latest repeated disposable runs" in text
    assert "If consumption loses, the losing request publishes no accepted receipt or callback" in text
    assert "a concurrent winner may still succeed" in text
    assert "ef6c0a0a0a59d89a2549493e3b99b54441fbc9c723870da4da6879c958e9be02" in text
    assert "unmapped/disabled policy denial with fresh `account-policy-rejected` events" in text
    assert "bounded log-tail evidence without an explicit request ID" in text
    assert "The first run stopped at stale-owner proof HTTP 503" in text
    assert "The retry passed stale-owner rejection (401/pending) and current-key proof 202/accepted" in text
    assert "Neither run reached missing-Identity" in text
    assert "the harness correctly left the case unclassified" in text
    assert "81 tests and 10 subtests" in text
    assert "host harness SHA-256 `b628838ffb9aa89a73011218e94abdf7d8ac20b873894c4a1bb7f74e9d066398`" in text
    assert "Both exited 1" in text
    assert "An earlier full run on image `sha256:53de80ab84036364b864807ffaca3c564174ff4516535fa7d2a84923e54be648`" in text
    assert "predates the exact challenge-response correction" in text
    assert "WALLET_IT_NATIVE_LIBS=/home/ben/.hermes/cache/scratch/keycloak-ubi9-lib/usr/lib64" in text
    assert "Still open from Issue #1" in text
    assert "request-correlated reproducible attribution of account-policy denials" in text
    assert "self-contained reproducible pinned runtime" in text
    assert "two-node shared-store replay" in text
    assert "Issue #1 remains open" in text
    assert "native challenge GET with browser metadata absent" in text
    assert "no real wallet client has qualified it" in text
    assert "wallet challenge response stays exactly `{profile,challenge,csrf_token}`" in text
    assert "not an additional wallet challenge-response field" in text



def test_rotation_section_reports_bounded_current_image_result():
    text = README.read_text()
    assert "ef6c0a0a0a59d89a2549493e3b99b54441fbc9c723870da4da6879c958e9be02" in text
    assert "The retry passed stale-owner rejection (401/pending) and current-key proof 202/accepted" in text
    assert "repeatable stale/current-key rotation" in text
    assert "earlier full run on image `sha256:53de80ab84036364b864807ffaca3c564174ff4516535fa7d2a84923e54be648`" in text


def test_live_probe_results_do_not_claim_production_qualification():
    text = README.read_text()
    assert "single-node loopback proxy simulation" in text
    assert "no real wallet client has qualified it" in text
    assert "Neither run reached missing-Identity" in text
    assert "both exited 1 before the full scenario sequence completed" in text
    assert "nondeterministic single-node loopback proxy simulations" in text
    assert "shared-store qualification" in text








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
