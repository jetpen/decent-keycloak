"""Offline tests for the strict manual qualification evidence checkpoint."""

from __future__ import annotations

import copy
import ast
import importlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CASES = (
    "LOGIN-01", "TLS-01", "TLS-02", "NEG-01", "NEG-02", "NEG-03",
    "NEG-04", "NEG-05", "NEG-06", "NEG-07",
)
RUN_ID = "a" * 32
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
    "NEG-05": ("replay_new_callback", "replay_new_authorization_code", "replay_new_authenticated_session"),
    "NEG-06": ("wrong_pkce_tokens_issued", "wrong_pkce_rp_login_created", "wrong_pkce_rp_session_created", "wrong_pkce_profile_disclosed"),
    "NEG-07": ("signup_authenticated", "signup_authorization_code_issued", "signup_callback_material_usable", "signup_new_account_created", "signup_profile_disclosed"),
}

ANDROID = {
    "target": "Pixel_9",
    "package": "org.decentwallet.wallet.client.qualification",
    "apk_sha256": "0db642d3eaca31cc56a7d44b1352b8df70f7df38bef84e6882d85058beb632ba",
    "signer_sha256": "47c24a9850edb62a3c35d0807b85e247b873d1752216536b97908281ace0ef66",
    "component_receipt_url": "https://github.com/jetpen/decent-wallet/releases/download/wallet-android-qualification-issue80/wallet80-component-receipt.json",
}


def checkpoint(status="pass"):
    return {
        "profile": "qualification",
        "run_id": RUN_ID,
        "cases": [
            {
                "case_id": case_id,
                "run_id": RUN_ID,
                "status": status,
                "expected_result": EXPECTED_RESULTS[case_id],
                "observed_result": EXPECTED_RESULTS[case_id] if status == "pass" else status,
                "evidence_owner": "owner-0123456789abcdef",
                "evidence_link": f"evidence/{case_id}.json",
            }
            for case_id in REQUIRED_CASES
        ],
        "android": dict(ANDROID),
    }


class KeycloakctlEvidenceTest(unittest.TestCase):
    def validate(self, data):
        try:
            module = importlib.import_module("scripts.keycloakctl_evidence")
        except ModuleNotFoundError:
            self.fail("evidence checkpoint validator is not implemented")
        return module.validate_checkpoint(data)

    def assert_invalid(self, data):
        try:
            self.validate(data)
        except ValueError as error:
            self.assertEqual("invalid evidence checkpoint", str(error))
        else:
            self.fail("malformed evidence checkpoint was accepted")

    def test_all_ten_required_passes_from_one_run_complete_checkpoint(self):
        result = self.validate(checkpoint())

        self.assertEqual("qualification", result["profile"])
        self.assertEqual(RUN_ID, result["run_id"])
        self.assertTrue(result["complete"])
        self.assertEqual(list(REQUIRED_CASES), [case["case_id"] for case in result["cases"]])
        self.assertEqual(10, len(result["cases"]))
        self.assertTrue(all(case["status"] == "pass" and case["run_id"] == RUN_ID
                            and case["expected_result"] == case["observed_result"]
                            for case in result["cases"]))

    def test_fixed_required_case_inventory_is_exact_and_signup_is_not_required_coverage(self):
        result = self.validate(checkpoint())
        self.assertEqual(set(REQUIRED_CASES), {case["case_id"] for case in result["cases"]})

        for signup_id in ("SIGNUP-01", "SIGNUP-02", "SIGNUP-03", "SIGNUP-04"):
            with self.subTest(optional_case=signup_id):
                optional = checkpoint()
                optional["cases"] = [case for case in optional["cases"]
                                     if case["case_id"] != "NEG-07"]
                optional["cases"].append({
                    "case_id": signup_id, "run_id": RUN_ID, "status": "pass",
                    "expected_result": "authenticated", "observed_result": "authenticated",
                    "evidence_owner": "owner-0123456789abcdef",
                    "evidence_link": f"evidence/{signup_id}.json",
                })
                self.assert_invalid(optional)

    def test_missing_duplicate_and_unknown_cases_are_rejected(self):
        missing = checkpoint()
        missing["cases"].pop()
        duplicate = checkpoint()
        duplicate["cases"][-1]["case_id"] = "NEG-06"
        unknown = checkpoint()
        unknown["cases"][-1]["case_id"] = "NEG-08"
        for malformed in (missing, duplicate, unknown):
            with self.subTest(case_count=len(malformed["cases"])):
                self.assert_invalid(malformed)

    def test_mixed_case_run_ids_are_rejected(self):
        data = checkpoint()
        data["cases"][4]["run_id"] = "b" * 32
        self.assert_invalid(data)

    def test_expected_and_unexpected_result_table_matches_issue_66_case_definitions(self):
        expected = {
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
        unexpected = {
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
            "NEG-05": ("replay_new_callback", "replay_new_authorization_code", "replay_new_authenticated_session"),
            "NEG-06": ("wrong_pkce_tokens_issued", "wrong_pkce_rp_login_created", "wrong_pkce_rp_session_created", "wrong_pkce_profile_disclosed"),
            "NEG-07": ("signup_authenticated", "signup_authorization_code_issued", "signup_callback_material_usable", "signup_new_account_created", "signup_profile_disclosed"),
        }
        self.assertEqual(expected, EXPECTED_RESULTS)
        self.assertEqual(unexpected, UNEXPECTED_RESULTS)
        module = importlib.import_module("scripts.keycloakctl_evidence")
        self.assertEqual(expected, module.EXPECTED_RESULTS)
        self.assertEqual(unexpected, module.UNEXPECTED_RESULTS)

    def test_tls_expected_results_encode_conditions_android_rejection_and_forbidden_outcomes(self):
        required_dimensions = {
            "TLS-01": (
                "matching_san", "dedicated_untrusted_ca", "integrated_android_rejected",
                "no_proof_post", "no_successful_keycloak_authentication", "no_successful_rp_outcome",
            ),
            "TLS-02": (
                "normally_trusted_chain", "hostname_mismatch", "integrated_android_rejected",
                "no_proof_post", "no_successful_keycloak_authentication", "no_successful_rp_outcome",
            ),
        }
        less_detailed_aliases = {
            "TLS-01": "untrusted_test_ca_rejected",
            "TLS-02": "trusted_chain_hostname_mismatch_rejected",
        }
        for case_id, dimensions in required_dimensions.items():
            with self.subTest(case_id=case_id):
                for dimension in dimensions:
                    self.assertIn(dimension, EXPECTED_RESULTS[case_id])
                self.assertEqual(EXPECTED_RESULTS[case_id], checkpoint()["cases"][REQUIRED_CASES.index(case_id)]["observed_result"])
                passed = self.validate(checkpoint())["cases"][REQUIRED_CASES.index(case_id)]
                self.assertEqual(EXPECTED_RESULTS[case_id], passed["observed_result"])

                for field in ("expected_result", "observed_result"):
                    with self.subTest(field=field):
                        data = checkpoint()
                        data["cases"][REQUIRED_CASES.index(case_id)][field] = less_detailed_aliases[case_id]
                        self.assert_invalid(data)

                for forbidden_event in UNEXPECTED_RESULTS[case_id]:
                    failed = checkpoint()
                    failed_case = failed["cases"][REQUIRED_CASES.index(case_id)]
                    failed_case["status"] = "fail"
                    failed_case["observed_result"] = forbidden_event
                    projected = self.validate(failed)["cases"][REQUIRED_CASES.index(case_id)]
                    self.assertEqual(forbidden_event, projected["observed_result"])
                combined_alias = checkpoint()
                combined_case = combined_alias["cases"][REQUIRED_CASES.index(case_id)]
                combined_case["status"] = "fail"
                combined_case["observed_result"] = "android_accepted_or_proof_post_or_successful_authentication"
                self.assert_invalid(combined_alias)

    def test_required_pass_outcomes_encode_all_live_issue_observations(self):
        no_success_dimensions = (
            "no_successful_keycloak_authentication",
            "no_authorization_code",
            "no_usable_wallet_callback_material",
            "no_account_profile_disclosure",
        )
        required_dimensions = {
            "LOGIN-01": (
                "advertised_https_origin_verified",
                "proxy_behavior_verified",
                "assetlinks_served_without_redirect",
                "assetlinks_package_matches_approved_wallet",
                "assetlinks_signing_fingerprint_matches_approved_wallet",
            ),
            "TLS-01": no_success_dimensions,
            "TLS-02": no_success_dimensions,
            "NEG-01": no_success_dimensions,
            "NEG-02": no_success_dimensions,
            "NEG-03": no_success_dimensions,
            "NEG-04": no_success_dimensions,
            "NEG-07": no_success_dimensions,
        }
        old_success_aliases = {
            "LOGIN-01": "real_browser_app_link_success_normally_trusted_public_tls_integrated_browser_native_wallet_handoff_provider_accepted_exact_proof_original_browser_session_state_callback_original_pkce_verifier_redeemed_id_token_issuer_audience_expiry_nonce_jwks_signature_checks_recorded_no_token_or_claims",
            "TLS-01": "matching_san_dedicated_untrusted_ca_integrated_android_rejected_no_proof_post_no_successful_keycloak_authentication_no_successful_rp_outcome",
            "TLS-02": "normally_trusted_chain_hostname_mismatch_integrated_android_rejected_no_proof_post_no_successful_keycloak_authentication_no_successful_rp_outcome",
            "NEG-01": "cancelled_before_wallet_approval_no_proof_submission_no_successful_login",
            "NEG-02": "expired_login_transaction_rejected",
            "NEG-03": "unapproved_browser_origin_rejected_no_challenge_disclosure",
            "NEG-04": "invalid_signature_rejected",
            "NEG-07": "valid_proof_enabled_exactly_mapped_principal_signup_denied_no_auth_code_callback_new_account_or_profile_disclosure",
        }

        for case_id, dimensions in required_dimensions.items():
            index = REQUIRED_CASES.index(case_id)
            with self.subTest(case_id=case_id):
                observed = checkpoint()["cases"][index]["observed_result"]
                for dimension in dimensions:
                    with self.subTest(dimension=dimension):
                        self.assertIn(dimension, observed)
                stale = checkpoint()
                stale_case = stale["cases"][index]
                stale_case["expected_result"] = old_success_aliases[case_id]
                stale_case["observed_result"] = old_success_aliases[case_id]
                self.assert_invalid(stale)

    def test_login_success_projection_requires_every_integrated_protocol_stage(self):
        expected_login = (
            "advertised_https_origin_verified_proxy_behavior_verified_"
            "assetlinks_served_without_redirect_assetlinks_package_matches_approved_wallet_"
            "assetlinks_signing_fingerprint_matches_approved_wallet_"
            "real_browser_app_link_success_normally_trusted_public_tls_"
            "integrated_browser_native_wallet_handoff_provider_accepted_exact_proof_"
            "original_browser_session_state_callback_original_pkce_verifier_redeemed_"
            "id_token_issuer_audience_expiry_nonce_jwks_signature_checks_recorded_"
            "no_token_or_claims_no_account_profile_disclosure"
        )
        required_stages = (
            "advertised_https_origin_verified",
            "proxy_behavior_verified",
            "assetlinks_served_without_redirect",
            "assetlinks_package_matches_approved_wallet",
            "assetlinks_signing_fingerprint_matches_approved_wallet",
            "real_browser_app_link_success",
            "normally_trusted_public_tls",
            "integrated_browser_native_wallet_handoff",
            "provider_accepted_exact_proof",
            "original_browser_session_state_callback",
            "original_pkce_verifier_redeemed",
            "id_token_issuer_audience_expiry_nonce_jwks_signature_checks_recorded",
            "no_token_or_claims",
            "no_account_profile_disclosure",
        )
        result = self.validate(checkpoint())
        login = result["cases"][0]
        self.assertEqual(expected_login, login["expected_result"])
        self.assertEqual(expected_login, login["observed_result"])
        for stage in required_stages:
            self.assertIn(stage, login["observed_result"])

        for alias in ("login_completed", "login_succeeded", "browser_login_completed"):
            with self.subTest(alias=alias):
                for field in ("expected_result", "observed_result"):
                    data = checkpoint()
                    data["cases"][0][field] = alias
                    self.assert_invalid(data)
        failed = checkpoint()
        failed["cases"][0]["status"] = "fail"
        failed["cases"][0]["observed_result"] = "login_failed"
        self.assert_invalid(failed)

    def test_failure_outcomes_are_stage_specific_and_fail_only(self):
        failure_outcomes = {
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
        legacy_aliases = {
            "LOGIN-01": ("integrated_login_failed", "login_failed"),
            "NEG-01": ("proof_submitted_or_successful_login_after_cancel",),
            "NEG-03": ("unapproved_browser_origin_accepted_or_challenge_disclosed",),
            "NEG-05": ("replay_caused_second_auth_callback_code_session",),
            "NEG-06": ("wrong_pkce_verifier_accepted_or_tokens_rp_login_session_profile_disclosed",),
            "NEG-07": ("enabled_exactly_mapped_principal_signup_accepted_or_auth_code_callback_new_account_or_profile_disclosed",),
        }

        for case_id, outcomes in failure_outcomes.items():
            index = REQUIRED_CASES.index(case_id)
            for outcome in outcomes:
                with self.subTest(case_id=case_id, outcome=outcome):
                    failed = checkpoint()
                    failed["cases"][index]["status"] = "fail"
                    failed["cases"][index]["observed_result"] = outcome
                    projected = self.validate(failed)
                    self.assertEqual("fail", projected["cases"][index]["status"])
                    self.assertEqual(outcome, projected["cases"][index]["observed_result"])
                    self.assertFalse(projected["complete"])

                    passed = checkpoint()
                    passed["cases"][index]["observed_result"] = outcome
                    self.assert_invalid(passed)

        for case_id, aliases in legacy_aliases.items():
            index = REQUIRED_CASES.index(case_id)
            for alias in aliases:
                with self.subTest(case_id=case_id, legacy_alias=alias):
                    failed = checkpoint()
                    failed["cases"][index]["status"] = "fail"
                    failed["cases"][index]["observed_result"] = alias
                    self.assert_invalid(failed)

    def test_neg05_neg06_pass_codes_keep_every_required_observation_distinct(self):
        required_pass_codes = {
            "NEG-05": (
                "replay_rejected_or_recognized_no_second_authentication_"
                "no_new_callback_no_new_authorization_code_no_new_authenticated_session_"
                "harmless_idempotent_acknowledgement_permitted"
            ),
            "NEG-06": (
                "wrong_pkce_verifier_exchange_rejected_no_tokens_no_rp_login_"
                "no_rp_session_no_profile_disclosure"
            ),
        }
        forbidden_compressed_aliases = {
            "NEG-05": "replayed_completed_login_01_no_second_auth_callback_code_session",
            "NEG-06": "wrong_pkce_verifier_rejected_no_tokens_rp_login_session_or_profile_disclosure",
        }
        distinct_fail_only_observations = {
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
        }
        data = checkpoint()
        projected = self.validate(data)
        by_case = {case["case_id"]: case for case in projected["cases"]}
        for case_id, pass_code in required_pass_codes.items():
            with self.subTest(case_id=case_id, check="exact pass code"):
                self.assertEqual(pass_code, EXPECTED_RESULTS[case_id])
                self.assertEqual(pass_code, by_case[case_id]["expected_result"])
                self.assertEqual(pass_code, by_case[case_id]["observed_result"])

            bad = checkpoint()
            index = REQUIRED_CASES.index(case_id)
            bad["cases"][index]["observed_result"] = forbidden_compressed_aliases[case_id]
            with self.subTest(case_id=case_id, check="compressed alias rejected"):
                self.assert_invalid(bad)

            for observation in distinct_fail_only_observations[case_id]:
                failed = checkpoint()
                failed["cases"][index]["status"] = "fail"
                failed["cases"][index]["observed_result"] = observation
                with self.subTest(case_id=case_id, check="fail-only observation", observation=observation):
                    result = self.validate(failed)["cases"][index]
                    self.assertEqual("fail", result["status"])
                    self.assertEqual(observation, result["observed_result"])
                    self.assertFalse(self.validate(failed)["complete"])

    def test_case_specific_expected_and_observed_results_enforce_status_consistency(self):
        data = checkpoint()
        result = self.validate(data)
        for projected, case_id in zip(result["cases"], REQUIRED_CASES):
            with self.subTest(case_id=case_id):
                self.assertEqual(EXPECTED_RESULTS[case_id], projected["expected_result"])
                self.assertEqual(EXPECTED_RESULTS[case_id], projected["observed_result"])

        for index, case_id in enumerate(REQUIRED_CASES):
            with self.subTest(failed_case=case_id):
                failed = checkpoint()
                failed["cases"][index]["status"] = "fail"
                failed["cases"][index]["observed_result"] = (
                    UNEXPECTED_RESULTS[case_id][0]
                    if isinstance(UNEXPECTED_RESULTS[case_id], tuple)
                    else UNEXPECTED_RESULTS[case_id]
                )
                observed = self.validate(failed)["cases"][index]
                self.assertEqual("fail", observed["status"])
                expected_failure = UNEXPECTED_RESULTS[case_id]
                if isinstance(expected_failure, tuple):
                    self.assertIn(observed["observed_result"], expected_failure)
                else:
                    self.assertEqual(expected_failure, observed["observed_result"])
                self.assertFalse(self.validate(failed)["complete"])

        for status in ("blocked", "not_run", "non_qualifying"):
            with self.subTest(status=status):
                nonrun = checkpoint()
                nonrun["cases"][0]["status"] = status
                nonrun["cases"][0]["observed_result"] = status
                observed = self.validate(nonrun)["cases"][0]
                self.assertEqual(status, observed["observed_result"])

    def test_unexpected_or_status_inconsistent_results_are_rejected(self):
        mutations = (
            ("pass", UNEXPECTED_RESULTS["LOGIN-01"]),
            ("fail", EXPECTED_RESULTS["LOGIN-01"]),
            ("fail", "free-form outcome"),
            ("blocked", "free-form outcome"),
            ("not_run", "blocked"),
            ("pass", "free-form outcome"),
        )
        for status, observed_result in mutations:
            with self.subTest(status=status, observed=observed_result):
                data = checkpoint()
                data["cases"][0]["status"] = status
                data["cases"][0]["observed_result"] = observed_result
                self.assert_invalid(data)

        wrong_expected = checkpoint()
        wrong_expected["cases"][0]["expected_result"] = "free-form outcome"
        self.assert_invalid(wrong_expected)

    def test_android_identity_is_mandatory_for_every_checkpoint(self):
        data = checkpoint()
        del data["android"]
        self.assert_invalid(data)

    def test_evidence_owner_and_link_are_opaque_and_case_local(self):
        for owner in ("person@example.com", "Alice Smith", "alice:owner", "owner@example.org"):
            with self.subTest(owner=owner):
                data = checkpoint()
                data["cases"][0]["evidence_owner"] = owner
                with self.assertRaisesRegex(ValueError, "^invalid evidence checkpoint$") as caught:
                    self.validate(data)
                self.assertNotIn(owner, str(caught.exception))

        for link in (
            "https://example.org/evidence/LOGIN-01.json",
            "evidence/LOGIN-01.json?token=secret",
            "evidence/LOGIN-01.json#fragment",
            "evidence/../TLS-01.json",
            "evidence/TLS-01.json",
            "transactions/LOGIN-01/callback",
            "callback://LOGIN-01",
            f"evidence/{RUN_ID}/LOGIN-01.json",
        ):
            with self.subTest(link=link):
                data = checkpoint()
                data["cases"][0]["evidence_link"] = link
                self.assert_invalid(data)

        result = self.validate(checkpoint())
        self.assertEqual("evidence/LOGIN-01.json", result["cases"][0]["evidence_link"])

    def test_nonpass_statuses_are_sanitized_but_never_complete(self):
        for status in ("fail", "blocked", "not_run", "non_qualifying"):
            with self.subTest(status=status):
                data = checkpoint()
                data["cases"][3]["status"] = status
                data["cases"][3]["observed_result"] = (
                    UNEXPECTED_RESULTS["NEG-01"][0] if status == "fail" else status
                )
                result = self.validate(data)
                self.assertFalse(result["complete"])
                self.assertEqual(status, result["cases"][3]["status"])

        data = checkpoint()
        data["cases"][3]["status"] = "skipped"
        self.assert_invalid(data)

    def test_non_qualifying_is_distinct_from_failure_blocked_and_not_run(self):
        data = checkpoint()
        case = data["cases"][0]
        case["status"] = "non_qualifying"
        case["observed_result"] = "non_qualifying"
        result = self.validate(data)
        projected = result["cases"][0]
        self.assertEqual("non_qualifying", projected["status"])
        self.assertEqual("non_qualifying", projected["observed_result"])
        self.assertEqual(EXPECTED_RESULTS["LOGIN-01"], projected["expected_result"])
        self.assertFalse(result["complete"])

        for confusing_outcome in ("fail", "blocked", "not_run", "login_failed"):
            with self.subTest(outcome=confusing_outcome):
                mismatched = checkpoint()
                mismatched["cases"][0]["status"] = "non_qualifying"
                mismatched["cases"][0]["observed_result"] = confusing_outcome
                self.assert_invalid(mismatched)

    def test_unknown_top_level_and_case_fields_reject_raw_material(self):
        top_level = checkpoint()
        top_level["raw_payload"] = "synthetic-private-payload"
        top_level["access_token"] = "synthetic-token"
        case_level = checkpoint()
        case_level["cases"][0]["callback_url"] = "https://evidence.invalid/callback"
        case_level["cases"][1]["credential"] = "synthetic-credential"
        for malformed in (top_level, case_level):
            self.assert_invalid(malformed)

    def test_projection_contains_only_new_allowlisted_sanitized_metadata(self):
        source = checkpoint()
        original = copy.deepcopy(source)
        result = self.validate(source)

        self.assertEqual(original, source)
        self.assertIsNot(result, source)
        self.assertIsNot(result["cases"], source["cases"])
        self.assertEqual({"profile", "run_id", "complete", "cases", "android"}, set(result))
        expected_case_fields = {
            "case_id", "run_id", "status", "expected_result", "observed_result",
            "evidence_owner", "evidence_link",
        }
        for projected, original_case in zip(result["cases"], source["cases"]):
            self.assertEqual(expected_case_fields, set(projected))
            self.assertIsNot(projected, original_case)
            self.assertEqual(original_case["evidence_owner"], projected["evidence_owner"])
            self.assertEqual(original_case["evidence_link"], projected["evidence_link"])
            self.assertEqual(original_case["expected_result"], projected["expected_result"])
            self.assertEqual(original_case["observed_result"], projected["observed_result"])

        marker = "synthetic-private-payload synthetic-token synthetic-credential"
        self.assertNotIn(marker, repr(result))
        self.assertNotIn("raw_payload", repr(result))
        self.assertNotIn("access_token", repr(result))
        self.assertNotIn("callback_url", repr(result))

    def test_unsafe_links_and_owner_identifiers_are_rejected(self):
        for link in (
            "http://evidence.invalid/runs/example",
            "https://user:pass@evidence.invalid/runs/example",
            "https://evidence.invalid/runs/example?token=synthetic",
            "https://evidence.invalid/runs/example#fragment",
            "https://evidence.invalid:bad/runs/example",
            "https:///runs/example",
            "https://evidence.invalid/a/../secret",
        ):
            with self.subTest(link=link):
                data = checkpoint()
                data["cases"][0]["evidence_link"] = link
                self.assert_invalid(data)

        for owner in ("", "has space", "../owner", "owner/other", "x" * 65):
            with self.subTest(owner=owner):
                data = checkpoint()
                data["cases"][0]["evidence_owner"] = owner
                self.assert_invalid(data)

    def test_invalid_profile_and_run_ids_are_rejected(self):
        for field, value in (("profile", "readiness"), ("profile", "Qualification"),
                             ("run_id", "../" + RUN_ID), ("run_id", "A" * 32),
                             ("run_id", "a" * 31)):
            with self.subTest(field=field, value=value):
                data = checkpoint()
                data[field] = value
                self.assert_invalid(data)

    def test_android_metadata_is_pinned_to_the_approved_identity(self):
        data = checkpoint()
        data["android"] = dict(ANDROID)
        result = self.validate(data)
        self.assertEqual(ANDROID, result["android"])
        self.assertTrue(result["complete"])

        for key, value in (("target", "Pixel_8"), ("package", "org.example.wallet"),
                           ("apk_sha256", "0" * 64), ("signer_sha256", "1" * 64),
                           ("component_receipt_url", "https://example.org/wallet80-component-receipt.json")):
            with self.subTest(key=key):
                wrong = checkpoint()
                wrong["android"] = {**ANDROID, key: value}
                self.assert_invalid(wrong)
        extra = checkpoint()
        extra["android"] = {**ANDROID, "receipt": "https://evidence.invalid/receipt"}
        self.assert_invalid(extra)

        missing_receipt = checkpoint()
        del missing_receipt["android"]["component_receipt_url"]
        self.assert_invalid(missing_receipt)

    def test_canonical_lifecycle_python_suite_names_this_unittest_module(self):
        tree = ast.parse((ROOT / "scripts/lifecycle.py").read_text(encoding="utf-8"))
        python_tests = next(
            ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "PYTHON_TESTS"
                    for target in node.targets)
        )
        self.assertIn("scripts.test_keycloakctl_evidence", python_tests)


if __name__ == "__main__":
    unittest.main()
