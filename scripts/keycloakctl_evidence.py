"""Offline validation and sanitized projection of manual qualification metadata.

This validates metadata only; it does not ingest evidence content, execute live
qualification, produce a canonical receipt, or prove referenced files are safe.
The pinned Android component-receipt URL is preserved as a reference only; its
contents are neither fetched nor authenticated by this validator.
"""

from __future__ import annotations

import re


REQUIRED_CASE_IDS = (
    "LOGIN-01", "TLS-01", "TLS-02", "NEG-01", "NEG-02", "NEG-03",
    "NEG-04", "NEG-05", "NEG-06", "NEG-07",
)
STATUSES = frozenset(("pass", "fail", "blocked", "not_run", "non_qualifying"))
RUN_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
OWNER_PATTERN = re.compile(r"owner-[0-9a-f]{16}\Z")
TEAM_OWNERS = frozenset(("team-qa", "team-security"))
HEX_PATTERN = re.compile(r"[0-9a-f]{64}\Z")

ANDROID_IDENTITY = {
    "target": "Pixel_9",
    "package": "org.decentwallet.wallet.client.qualification",
    "apk_sha256": "0db642d3eaca31cc56a7d44b1352b8df70f7df38bef84e6882d85058beb632ba",
    "signer_sha256": "47c24a9850edb62a3c35d0807b85e247b873d1752216536b97908281ace0ef66",
    "component_receipt_url": "https://github.com/jetpen/decent-wallet/releases/download/wallet-android-qualification-issue80/wallet80-component-receipt.json",
}

_TOP_LEVEL_FIELDS = frozenset(("profile", "run_id", "cases", "android"))
_CASE_FIELDS = frozenset((
    "case_id", "run_id", "status", "expected_result", "observed_result",
    "evidence_owner", "evidence_link",
))
_ANDROID_FIELDS = frozenset(ANDROID_IDENTITY)


def _invalid() -> ValueError:
    return ValueError("invalid evidence checkpoint")


def _exact_fields(value: object, fields: frozenset[str]) -> bool:
    return isinstance(value, dict) and set(value) == fields


EXPECTED_RESULTS = {
    "LOGIN-01": "advertised_https_origin_verified_proxy_behavior_verified_assetlinks_served_without_redirect_assetlinks_package_matches_approved_wallet_assetlinks_signing_fingerprint_matches_approved_wallet_real_browser_app_link_success_normally_trusted_public_tls_integrated_browser_native_wallet_handoff_provider_accepted_exact_proof_original_browser_session_state_callback_original_pkce_verifier_redeemed_id_token_issuer_audience_expiry_nonce_jwks_signature_checks_recorded_no_token_or_claims_no_account_profile_disclosure",
    "TLS-01": "matching_san_dedicated_untrusted_ca_integrated_android_rejected_no_proof_post_no_successful_keycloak_authentication_no_authorization_code_no_usable_wallet_callback_material_no_account_profile_disclosure_no_successful_rp_outcome",
    "TLS-02": "normally_trusted_chain_hostname_mismatch_integrated_android_rejected_no_proof_post_no_successful_keycloak_authentication_no_authorization_code_no_usable_wallet_callback_material_no_account_profile_disclosure_no_successful_rp_outcome",
    "NEG-01": "cancelled_before_wallet_approval_no_proof_submission_no_successful_login_no_successful_keycloak_authentication_no_authorization_code_no_usable_wallet_callback_material_no_account_profile_disclosure",
    "NEG-02": "expired_login_transaction_rejected_no_successful_keycloak_authentication_no_authorization_code_no_usable_wallet_callback_material_no_account_profile_disclosure",
    "NEG-03": "unapproved_browser_origin_rejected_no_challenge_disclosure_no_successful_keycloak_authentication_no_authorization_code_no_usable_wallet_callback_material_no_account_profile_disclosure",
    "NEG-04": "invalid_signature_rejected_no_successful_keycloak_authentication_no_authorization_code_no_usable_wallet_callback_material_no_account_profile_disclosure",
    "NEG-05": "replay_rejected_or_recognized_no_second_authentication_no_new_callback_no_new_authorization_code_no_new_authenticated_session_harmless_idempotent_acknowledgement_permitted",
    "NEG-06": "wrong_pkce_verifier_exchange_rejected_no_tokens_no_rp_login_no_rp_session_no_profile_disclosure",
    "NEG-07": "valid_proof_enabled_exactly_mapped_principal_signup_denied_no_successful_keycloak_authentication_no_authorization_code_no_usable_wallet_callback_material_no_new_account_no_account_profile_disclosure",
}
UNEXPECTED_RESULTS = {
    "LOGIN-01": (
        "public_origin_proxy_verification_failed",
        "assetlinks_redirected",
        "assetlinks_package_fingerprint_mismatch",
        "real_browser_app_link_failed",
        "public_tls_platform_trust_failed",
        "chromium_native_wallet_handoff_failed",
        "provider_rejected_exact_proof",
        "callback_original_browser_session_mismatch",
        "callback_state_mismatch",
        "same_transaction_pkce_code_redemption_failed",
        "id_token_issuer_check_failed",
        "id_token_audience_check_failed",
        "id_token_expiry_check_failed",
        "id_token_nonce_check_failed",
        "real_jwks_signature_check_failed",
        "login_successful_keycloak_authentication_after_pre_auth_failure",
        "login_authorization_code_issued_after_pre_auth_failure",
        "login_callback_material_usable_after_pre_auth_failure",
        "login_profile_disclosed_after_pre_auth_failure",
        "profile_disclosed_during_login",
    ),
    "TLS-01": (
        "matching_san_dedicated_untrusted_ca_integrated_android_accepted",
        "matching_san_dedicated_untrusted_ca_proof_posted",
        "matching_san_dedicated_untrusted_ca_successful_keycloak_authentication",
        "matching_san_dedicated_untrusted_ca_authorization_code_issued",
        "matching_san_dedicated_untrusted_ca_callback_material_usable",
        "matching_san_dedicated_untrusted_ca_profile_disclosed",
        "matching_san_dedicated_untrusted_ca_successful_rp_outcome",
    ),
    "TLS-02": (
        "normally_trusted_chain_hostname_mismatch_integrated_android_accepted",
        "normally_trusted_chain_hostname_mismatch_proof_posted",
        "normally_trusted_chain_hostname_mismatch_successful_keycloak_authentication",
        "normally_trusted_chain_hostname_mismatch_authorization_code_issued",
        "normally_trusted_chain_hostname_mismatch_callback_material_usable",
        "normally_trusted_chain_hostname_mismatch_profile_disclosed",
        "normally_trusted_chain_hostname_mismatch_successful_rp_outcome",
    ),
    "NEG-01": (
        "proof_submitted_after_cancel",
        "successful_login_after_cancel",
        "authorization_code_issued_after_cancel",
        "callback_material_usable_after_cancel",
        "profile_disclosed_after_cancel",
    ),
    "NEG-02": (
        "expired_transaction_proof_accepted",
        "expired_transaction_successful_authentication",
        "expired_transaction_authorization_code_issued",
        "expired_transaction_callback_material_usable",
        "expired_transaction_profile_disclosed",
    ),
    "NEG-03": (
        "unapproved_origin_accepted",
        "challenge_disclosed",
        "unapproved_origin_successful_authentication",
        "unapproved_origin_authorization_code_issued",
        "unapproved_origin_callback_material_usable",
        "unapproved_origin_profile_disclosed",
    ),
    "NEG-04": (
        "invalid_signature_proof_accepted",
        "invalid_signature_successful_authentication",
        "invalid_signature_authorization_code_issued",
        "invalid_signature_callback_material_usable",
        "invalid_signature_profile_disclosed",
    ),
    "NEG-05": (
        "replay_new_callback",
        "replay_new_authorization_code",
        "replay_new_authenticated_session",
    ),
    "NEG-06": (
        "wrong_pkce_tokens_issued",
        "wrong_pkce_rp_login_created",
        "wrong_pkce_rp_session_created",
        "wrong_pkce_profile_disclosed",
    ),
    "NEG-07": (
        "signup_authenticated",
        "signup_authorization_code_issued",
        "signup_callback_material_usable",
        "signup_new_account_created",
        "signup_profile_disclosed",
    ),
}


def _valid_owner(value: object) -> bool:
    return (isinstance(value, str)
            and (OWNER_PATTERN.fullmatch(value) is not None or value in TEAM_OWNERS))


def _valid_link(value: object, case_id: str) -> bool:
    return isinstance(value, str) and value == f"evidence/{case_id}.json"


def _valid_results(item: dict, case_id: str) -> bool:
    expected = EXPECTED_RESULTS[case_id]
    status = item["status"]
    observed = item["observed_result"]
    if item["expected_result"] != expected or not isinstance(observed, str):
        return False
    allowed = {
        "pass": expected,
        "fail": UNEXPECTED_RESULTS[case_id],
        "blocked": "blocked",
        "not_run": "not_run",
        "non_qualifying": "non_qualifying",
    }
    expected_observed = allowed[status]
    if status == "fail" and isinstance(expected_observed, tuple):
        return observed in expected_observed
    return observed == expected_observed


def _validate_android(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not _exact_fields(value, _ANDROID_FIELDS):
        raise _invalid()
    for field, expected in ANDROID_IDENTITY.items():
        actual = value.get(field)
        if not isinstance(actual, str) or actual != expected:
            raise _invalid()
    if not HEX_PATTERN.fullmatch(value["apk_sha256"]):
        raise _invalid()
    if not HEX_PATTERN.fullmatch(value["signer_sha256"]):
        raise _invalid()
    return {field: value[field] for field in ANDROID_IDENTITY}


def validate_checkpoint(document: object) -> dict:
    """Validate a fixed ten-case checkpoint and return sanitized metadata only.

    This offline projection does not execute cases, authenticate evidence or
    receipt contents, or certify an Android artifact. A complete result means
    only that all declared case statuses are explicit passes for one shared run
    ID. The pinned component-receipt URL is preserved without fetching it.
    """
    try:
        return _validate_checkpoint(document)
    except ValueError as error:
        if str(error) == "invalid evidence checkpoint":
            raise
        raise _invalid() from None
    except (AttributeError, KeyError, TypeError, OverflowError):
        raise _invalid() from None


def _validate_checkpoint(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != _TOP_LEVEL_FIELDS:
        raise _invalid()
    if document["profile"] != "qualification":
        raise _invalid()
    run_id = document["run_id"]
    if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
        raise _invalid()
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASE_IDS):
        raise _invalid()

    by_id: dict[str, dict] = {}
    for item in cases:
        if not _exact_fields(item, _CASE_FIELDS):
            raise _invalid()
        case_id = item["case_id"]
        if not isinstance(case_id, str) or case_id not in REQUIRED_CASE_IDS or case_id in by_id:
            raise _invalid()
        if item["run_id"] != run_id:
            raise _invalid()
        status = item["status"]
        if not isinstance(status, str) or status not in STATUSES:
            raise _invalid()
        owner = item["evidence_owner"]
        if not _valid_results(item, case_id):
            raise _invalid()
        if not _valid_owner(owner):
            raise _invalid()
        link = item["evidence_link"]
        if not _valid_link(link, case_id):
            raise _invalid()
        by_id[case_id] = {
            "case_id": case_id,
            "run_id": run_id,
            "status": status,
            "expected_result": EXPECTED_RESULTS[case_id],
            "observed_result": item["observed_result"],
            "evidence_owner": owner,
            "evidence_link": link,
        }
    if set(by_id) != set(REQUIRED_CASE_IDS):
        raise _invalid()

    projection = {
        "profile": "qualification",
        "run_id": run_id,
        "complete": all(by_id[case_id]["status"] == "pass" for case_id in REQUIRED_CASE_IDS),
        "cases": [by_id[case_id] for case_id in REQUIRED_CASE_IDS],
    }
    projection["android"] = _validate_android(document["android"])
    return projection
