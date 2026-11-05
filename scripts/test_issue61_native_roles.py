"""Contract tests for Issue #61 native role-token qualification."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from issue61_native_roles import CASES, STORAGE_ROLES, claims_summary, evaluate_claims, validate_case_ledger


class NativeRoleTokenContractTest(unittest.TestCase):
    def test_required_storage_roles_and_case_ledger_are_closed(self):
        self.assertEqual(
            {
                "storage:read",
                "storage:create",
                "storage:update",
                "storage:delete",
                "storage:enrollment:read",
                "storage:enrollment:withdraw",
            },
            set(STORAGE_ROLES),
        )
        self.assertTrue(validate_case_ledger(CASES))
        self.assertEqual(17, len(CASES))
        self.assertEqual(
            {"role_scope_excluded", "role_scope_intersection", "realm_role_only",
             "different_client_role_only", "wrong_audience_rejected", "widened_audience_rejected"},
            {case["id"] for case in CASES} & {
                "role_scope_excluded", "role_scope_intersection", "realm_role_only",
                "different_client_role_only", "wrong_audience_rejected", "widened_audience_rejected"
            },
        )
        self.assertTrue(all(case["status"] == "not_run" for case in CASES))

    def test_exact_single_audience_and_configured_client_role_array_are_required(self):
        expected = {"aud": "decent-storage", "roles": ["storage:read"]}
        conforming = {
            "aud": "decent-storage",
            "resource_access": {"decent-storage": {"roles": ["storage:read"]}},
        }
        self.assertEqual([], evaluate_claims(conforming, expected, "decent-storage"))
        self.assertTrue(evaluate_claims(
            {**conforming, "aud": ["decent-storage", "other"]}, expected, "decent-storage"
        ))
        self.assertTrue(evaluate_claims(
            {"aud": "decent-storage", "realm_access": {"roles": ["storage:read"]}},
            expected,
            "decent-storage",
        ))
        self.assertTrue(evaluate_claims(
            {"aud": "decent-storage", "resource_access": {"other": {"roles": ["storage:read"]}}},
            expected,
            "decent-storage",
        ))

    def test_sanitized_claim_projection_never_contains_credentials_or_raw_token(self):
        claims = {
            "iss": "http://localhost:18080/realms/issue61",
            "sub": "private-subject",
            "aud": "decent-storage",
            "exp": 1234567890,
            "resource_access": {"decent-storage": {"roles": ["storage:read"]}},
            "access_token": "bearer-secret",
            "refresh_token": "refresh-secret",
            "email": "person@example.test",
        }
        summary = claims_summary(claims, "decent-storage")
        serialized = repr(summary)
        for secret in ("private-subject", "bearer-secret", "refresh-secret", "person@example.test"):
            self.assertNotIn(secret, serialized)
        self.assertEqual("decent-storage", summary["aud"])
        self.assertEqual(["storage:read"], summary["storage_roles"])
        self.assertEqual(1234567890, summary["exp"])

    def test_recorded_runtime_qualification_has_complete_sanitized_case_ledger(self):
        evidence = Path(__file__).parents[1] / "docs/acceptance/evidence/issue61/latest.json"
        result = json.loads(evidence.read_text())
        self.assertEqual("passed", result["result"])
        self.assertEqual(
            {"keycloak_release": "Keycloak 26.8.0", "image_digest":
             "sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad"},
            {key: result["software"][key] for key in ("keycloak_release", "image_digest")},
        )
        self.assertTrue(validate_case_ledger(result["cases"]))
        harness = Path(__file__).with_name("issue61_native_roles.py")
        self.assertEqual(result["harness_sha256"], hashlib.sha256(harness.read_bytes()).hexdigest())
        self.assertTrue(all(case["status"] == "passed" for case in result["cases"]))
        self.assertTrue(all(case["checks"]["signature_verified"] for case in result["cases"]))
        self.assertTrue(result["cleanup"]["container_removed"])
        encoded = json.dumps(result)
        forbidden_values = ("bearer-secret", "refresh-secret", "private-subject", "person@example.test")
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, encoded)
        def contains_raw_token_field(value):
            if isinstance(value, dict):
                return any(key in {"access_token", "refresh_token", "id_token", "password", "credentials"}
                           or contains_raw_token_field(child) for key, child in value.items())
            if isinstance(value, list):
                return any(contains_raw_token_field(child) for child in value)
            return False
        self.assertFalse(contains_raw_token_field(result))

    def test_ledger_rejects_missing_case_or_unrecognized_state(self):
        self.assertFalse(validate_case_ledger(CASES[:-1]))
        altered = [dict(case) for case in CASES]
        altered[0]["status"] = "skipped"
        self.assertFalse(validate_case_ledger(altered))


if __name__ == "__main__":
    unittest.main()
