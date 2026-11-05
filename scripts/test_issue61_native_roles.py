"""Contract tests for Issue #61 native role-token qualification."""

import hashlib
import json
import sys
import unittest
from unittest.mock import call, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from issue61_native_roles import (
    CASES, STORAGE_ROLES, claims_summary, evaluate_claims, validate_case_ledger,
    readback_configuration_fingerprint, storage_client_roles, verified_owned_container,
    cleanup_owned_container,
)


class NativeRoleTokenContractTest(unittest.TestCase):
    def test_every_case_uses_contract_literal_not_run(self):
        self.assertEqual("not-run", CASES[0]["status"])
        self.assertTrue(validate_case_ledger([dict(case) for case in CASES]))
        old_spelling = [dict(case) for case in CASES]
        old_spelling[0]["status"] = "not_run"
        self.assertFalse(validate_case_ledger(old_spelling))

    def test_storage_role_helper_names_the_native_client_role_path(self):
        claims = {"resource_access": {"decent-storage": {"roles": ["storage:read"]}}}
        self.assertEqual(["storage:read"], storage_client_roles(claims, "decent-storage"))

    def test_configuration_fingerprint_projects_readback_and_changes_with_actual_settings(self):
        readback = {
            "realm": {"realm": "issue61", "enabled": True, "accessTokenLifespan": 300,
                      "smtpServer": {"password": "realm-secret"}},
            "storage_client": {"clientId": "decent-storage", "enabled": True,
                               "publicClient": False, "secret": "client-secret"},
            "app_client": {"clientId": "issue61-app", "enabled": True,
                            "publicClient": True, "fullScopeAllowed": False},
            "role_scope": {"name": "storage-role-scope", "protocol": "openid-connect",
                           "attributes": {"sensitive.custom.attribute": "attribute-secret"}},
            "mappers": [
                {"name": "storage-native-client-roles", "protocolMapper": "oidc-usermodel-client-role-mapper",
                 "config": {"claim.name": "resource_access.decent-storage.roles",
                            "access.token.claim": "true", "id.token.claim": "false",
                            "password": "mapper-secret"}},
                {"name": "storage-resource-audience", "protocolMapper": "oidc-audience-mapper",
                 "config": {"included.client.audience": "decent-storage",
                            "access.token.claim": "true"}},
            ],
            "role_scope_mappings": ["storage:read", "storage:create"],
            "storage_roles": [{"name": "storage:read", "description": "native role", "composite": False,
                               "clientRole": True, "id": "ephemeral", "secret": "never-retain"}],
        }
        projected, digest = readback_configuration_fingerprint(readback)
        self.assertEqual("resource_access.decent-storage.roles",
                         projected["mappers"][0]["config"]["claim.name"])
        self.assertEqual(["storage:create", "storage:read"], projected["role_scope_mappings"])
        self.assertEqual(64, len(digest))
        encoded = json.dumps(projected)
        for secret in ("realm-secret", "client-secret", "mapper-secret", "never-retain", "ephemeral", "attribute-secret"):
            self.assertNotIn(secret, encoded)
        changed = json.loads(json.dumps(readback))
        changed["role_scope_mappings"].remove("storage:create")
        self.assertNotEqual(digest, readback_configuration_fingerprint(changed)[1])

    def test_partial_startup_container_requires_exact_readback_ownership(self):
        inspected = [{
            "Id": "full-container-id", "Name": "/issue61-keycloak-run123", "Image": "image-id",
            "Config": {"Labels": {"org.decent-keycloak.issue61.run-id": "run123"}},
        }]
        self.assertTrue(verified_owned_container(inspected, "issue61-keycloak-run123", "run123", "image-id"))
        for modified in (
            [{**inspected[0], "Image": "other-image"}],
            [{**inspected[0], "Config": {"Labels": {}}}],
            [{**inspected[0], "Name": "/other-name"}],
            [],
        ):
            self.assertFalse(verified_owned_container(modified, "issue61-keycloak-run123", "run123", "image-id"))

    def test_cleanup_removes_only_readback_verified_container_by_immutable_id(self):
        inspect = [{"Id": "full-container-id", "Name": "/issue61-keycloak-run123", "Image": "image-id",
                    "Config": {"Labels": {"org.decent-keycloak.issue61.run-id": "run123"}}}]
        outcomes = [
            type("Result", (), {"returncode": 0, "stdout": json.dumps(inspect)})(),
            type("Result", (), {"returncode": 0, "stdout": ""})(),
            type("Result", (), {"returncode": 0, "stdout": ""})(),
            type("Result", (), {"returncode": 0, "stdout": ""})(),
        ]
        with patch("issue61_native_roles.subprocess.run", side_effect=outcomes) as run:
            self.assertTrue(cleanup_owned_container("podman", "issue61-keycloak-run123", "run123", "image-id"))
        self.assertEqual("full-container-id", run.call_args_list[1].args[0][-1])
        self.assertEqual("full-container-id", run.call_args_list[2].args[0][-1])

    def test_cleanup_never_removes_unverified_name_collision(self):
        foreign = [{"Id": "foreign-id", "Name": "/issue61-keycloak-run123", "Image": "image-id",
                    "Config": {"Labels": {"org.decent-keycloak.issue61.run-id": "another-run"}}}]
        with patch("issue61_native_roles.subprocess.run", return_value=type(
                "Result", (), {"returncode": 0, "stdout": json.dumps(foreign)})()) as run:
            self.assertFalse(cleanup_owned_container(
                "podman", "issue61-keycloak-run123", "run123", "image-id"))
        run.assert_called_once_with(["podman", "container", "inspect", "issue61-keycloak-run123"],
                                    text=True, capture_output=True)

    def test_interruption_during_container_start_still_discovers_owned_container(self):
        image = type("Result", (), {"returncode": 0, "stdout": "image-id"})()
        owned = [{"Id": "created-container-id", "Name": "/issue61-keycloak-abc",
                  "Image": "image-id", "Config": {"Labels": {
                      "org.decent-keycloak.issue61.run-id": "abc"}}}]

        owner = {}

        def engine_call(args, **kwargs):
            if args[1:3] == ["image", "inspect"]:
                return image
            if args[1] == "run":
                owner["run_id"] = args[args.index("--label") + 1].split("=", 1)[1]
                owner["name"] = args[args.index("--name") + 1]
                raise KeyboardInterrupt()
            if args[1:3] == ["container", "inspect"]:
                inspected = [{**owned[0], "Name": "/" + owner["name"], "Config": {"Labels": {
                    "org.decent-keycloak.issue61.run-id": owner["run_id"]}}}]
                return type("Result", (), {"returncode": 0, "stdout": json.dumps(inspected)})()
            return type("Result", (), {"returncode": 0, "stdout": ""})()

        with patch("issue61_native_roles._container_engine", return_value="podman"):
            with patch("issue61_native_roles.subprocess.run", side_effect=engine_call) as run:
                result = __import__("issue61_native_roles").run_qualification(18080)
        self.assertEqual("failed", result["result"])
        self.assertTrue(all(case["status"] == "not-run" for case in result["cases"]))
        removal = next(call.args[0] for call in run.call_args_list if call.args[0][1] == "rm")
        self.assertEqual("created-container-id", removal[-1])
        self.assertTrue(result["cleanup"]["container_removed"])

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
        self.assertTrue(all(case["status"] == "not-run" for case in CASES))

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
