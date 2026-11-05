"""Issue #61: real Keycloak native Storage-role token qualification.

The runner starts only the pinned Keycloak image and creates a disposable realm.
Bearer and refresh tokens exist only in process memory and are never serialized.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad"
IMAGE_DIGEST = "sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad"
REALM = "issue61"
STORAGE_CLIENT = "decent-storage"
APP_CLIENT = "issue61-app"
ROLE_SCOPE = "storage-role-scope"
ROLES = (
    "storage:read", "storage:create", "storage:update", "storage:delete",
    "storage:enrollment:read", "storage:enrollment:withdraw",
)
VALID_STATES = {"passed", "failed", "error", "not-run"}
RUN_LABEL = "org.decent-keycloak.issue61.run-id"

# Criterion ledger: fixed case names prevent omissions from appearing qualified.
CASES = [
    {"id": f"assigned_{role.replace(':', '_')}", "status": "not-run"} for role in ROLES
] + [
    {"id": "all_six_assigned", "status": "not-run"},
    {"id": "no_assigned_roles", "status": "not-run"},
    {"id": "role_scope_excluded", "status": "not-run"},
    {"id": "role_scope_intersection", "status": "not-run"},
    {"id": "realm_role_only", "status": "not-run"},
    {"id": "different_client_role_only", "status": "not-run"},
    {"id": "wrong_audience_rejected", "status": "not-run"},
    {"id": "widened_audience_rejected", "status": "not-run"},
    {"id": "refresh_unchanged_assignments", "status": "not-run"},
    {"id": "refresh_after_role_change", "status": "not-run"},
    {"id": "refresh_after_scope_change", "status": "not-run"},
]
STORAGE_ROLES = ROLES


def validate_case_ledger(cases: list[dict[str, Any]]) -> bool:
    return (
        isinstance(cases, list)
        and [item.get("id") for item in cases] == [item["id"] for item in CASES]
        and all(item.get("status") in VALID_STATES for item in cases)
    )


def storage_client_roles(claims: dict[str, Any], storage_client: str) -> list[str]:
    """Extract roles only from the configured Storage client's resource_access entry."""
    value = claims.get("resource_access", {}).get(storage_client, {}).get("roles", [])
    return sorted(value) if isinstance(value, list) and all(isinstance(v, str) for v in value) else []


def evaluate_claims(claims: dict[str, Any], expected: dict[str, Any], storage_client: str) -> list[str]:
    failures = []
    audience = claims.get("aud")
    if audience != expected.get("aud") or not isinstance(audience, str):
        failures.append("audience_not_exact_single_storage_resource")
    actual_roles = storage_client_roles(claims, storage_client)
    wanted_roles = sorted(expected.get("roles", []))
    if actual_roles != wanted_roles:
        failures.append("storage_client_roles_mismatch")
    for client_id, access in claims.get("resource_access", {}).items():
        if client_id != storage_client and any(str(r).startswith("storage:") for r in access.get("roles", [])):
            failures.append("storage_role_outside_configured_client")
            break
    if any(str(r).startswith("storage:") for r in claims.get("realm_access", {}).get("roles", [])):
        failures.append("storage_role_in_realm_roles")
    return failures


def claims_summary(claims: dict[str, Any], storage_client: str) -> dict[str, Any]:
    """Allowlisted sanitized projection; no subject, token, PII, or raw claims."""
    return {
        "aud": claims.get("aud") if isinstance(claims.get("aud"), (str, list)) else None,
        "storage_roles": storage_client_roles(claims, storage_client),
        "other_resource_clients": sorted(
            key for key in claims.get("resource_access", {}) if key != storage_client
        ),
        "realm_role_names": sorted(
            role for role in claims.get("realm_access", {}).get("roles", []) if isinstance(role, str)
        ),
        "exp": claims.get("exp") if isinstance(claims.get("exp"), int) else None,
    }


def _allowlisted_fields(value: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    return {name: value[name] for name in names if name in value}


def readback_configuration_fingerprint(readback: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Fingerprint only allowlisted non-secret fields from Keycloak Admin API readbacks."""
    mapper_fields = ("name", "protocol", "protocolMapper", "consentRequired")
    mapper_config_fields = (
        "usermodel.clientRoleMapping.clientId", "usermodel.clientRoleMapping.rolePrefix",
        "multivalued", "claim.name", "jsonType.label", "access.token.claim",
        "id.token.claim", "userinfo.token.claim", "included.client.audience",
        "included.custom.audience",
    )
    projected = {
        "realm": _allowlisted_fields(readback["realm"],
                                     ("realm", "enabled", "accessTokenLifespan", "refreshTokenMaxReuse")),
        "storage_client": _allowlisted_fields(readback["storage_client"],
                                              ("clientId", "enabled", "protocol", "publicClient",
                                               "standardFlowEnabled", "directAccessGrantsEnabled",
                                               "fullScopeAllowed")),
        "app_client": _allowlisted_fields(readback["app_client"],
                                           ("clientId", "enabled", "protocol", "publicClient",
                                            "standardFlowEnabled", "directAccessGrantsEnabled",
                                            "fullScopeAllowed", "optionalClientScopes")),
        "role_scope": _allowlisted_fields(readback["role_scope"], ("name", "protocol")),
        "mappers": sorted(({
            **_allowlisted_fields(mapper, mapper_fields),
            "config": _allowlisted_fields(mapper.get("config", {}), mapper_config_fields),
        } for mapper in readback["mappers"]), key=lambda mapper: mapper["name"]),
        "role_scope_mappings": sorted(readback["role_scope_mappings"]),
        "storage_roles": sorted(({
            **_allowlisted_fields(role, ("name", "description", "composite", "clientRole")),
        } for role in readback["storage_roles"]), key=lambda role: role["name"]),
    }
    encoded = json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()
    return projected, hashlib.sha256(encoded).hexdigest()


def verified_owned_container(inspected: Any, name: str, run_id: str, image_id: str) -> bool:
    """Accept ownership only when engine readback proves all unique identity fields."""
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        return False
    container = inspected[0]
    config = container.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    container_name = container.get("Name")
    return (
        isinstance(container.get("Id"), str) and bool(container["Id"])
        and isinstance(container_name, str) and container_name.lstrip("/") == name
        and container.get("Image") == image_id
        and isinstance(labels, dict) and labels.get(RUN_LABEL) == run_id
    )


def cleanup_owned_container(engine: str, name: str, run_id: str, image_id: str) -> bool:
    """Remove only a run-owned container confirmed by inspect; verify name absence afterward."""
    inspect = subprocess.run([engine, "container", "inspect", name], text=True, capture_output=True)
    if inspect.returncode == 0:
        try:
            containers = json.loads(inspect.stdout)
        except (TypeError, ValueError):
            return False
        if not verified_owned_container(containers, name, run_id, image_id):
            return False
        container_id = containers[0]["Id"]
        subprocess.run([engine, "stop", "--time", "10", container_id],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([engine, "rm", "--force", container_id],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    inventory = subprocess.run([engine, "ps", "--all", "--filter", f"name=^{name}$",
                                "--format", "{{.Names}}"], text=True, capture_output=True)
    return inventory.returncode == 0 and name not in inventory.stdout.splitlines()


class Http:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def request(self, method: str, path: str, *, data: Any = None, token: str | None = None,
                form: bool = False) -> tuple[int, Any]:
        body = None
        headers = {"Accept": "application/json"}
        if data is not None:
            if form:
                body = urllib.parse.urlencode(data).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(data).encode()
                headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = None
            return error.code, payload

    def require(self, method: str, path: str, *, data: Any = None, token: str | None = None,
                form: bool = False, expected: tuple[int, ...] = (200, 201, 204)) -> Any:
        status, value = self.request(method, path, data=data, token=token, form=form)
        if status not in expected:
            raise RuntimeError(f"admin/http request failed with status {status}: {method} {path}")
        return value


def _path(segment: str) -> str:
    return urllib.parse.quote(segment, safe="")


def _admin_token(http: Http, username: str, password: str) -> str:
    _, data = http.request("POST", "/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": username,
        "password": password,
    }, form=True)
    if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
        raise RuntimeError("admin authentication failed")
    return data["access_token"]


def _create_realm(http: Http, admin: str, password: str) -> dict[str, str]:
    http.require("POST", "/admin/realms", token=admin, data={
        "realm": REALM, "enabled": True, "accessTokenLifespan": 300,
        "refreshTokenMaxReuse": 0,
    })
    base = f"/admin/realms/{REALM}"
    http.require("POST", base + "/clients", token=admin, data={
        "clientId": STORAGE_CLIENT, "enabled": True, "protocol": "openid-connect",
        "publicClient": False, "standardFlowEnabled": False,
    })
    storage = http.require("GET", base + "/clients?clientId=" + STORAGE_CLIENT, token=admin)[0]
    http.require("POST", base + "/clients", token=admin, data={
        "clientId": APP_CLIENT, "enabled": True, "protocol": "openid-connect",
        "publicClient": True, "directAccessGrantsEnabled": True,
        "standardFlowEnabled": False, "fullScopeAllowed": False,
    })
    app = http.require("GET", base + "/clients?clientId=" + APP_CLIENT, token=admin)[0]
    # The native Keycloak client-role mapper and audience mapper are the only
    # claim producers. No custom mapper/SPI or post-issuance token edit is used.
    http.require("POST", base + "/client-scopes", token=admin, data={
        "name": ROLE_SCOPE, "protocol": "openid-connect", "attributes": {},
    })
    scope = http.require("GET", base + "/client-scopes", token=admin)
    scope_id = next(item["id"] for item in scope if item["name"] == ROLE_SCOPE)
    http.require("POST", f"{base}/client-scopes/{scope_id}/protocol-mappers/models", token=admin,
                 data={"name": "storage-native-client-roles", "protocol": "openid-connect",
                       "protocolMapper": "oidc-usermodel-client-role-mapper",
                       "consentRequired": False, "config": {
                           "usermodel.clientRoleMapping.clientId": STORAGE_CLIENT,
                           "usermodel.clientRoleMapping.rolePrefix": "",
                           "multivalued": "true", "claim.name": f"resource_access.{STORAGE_CLIENT}.roles",
                           "jsonType.label": "String", "access.token.claim": "true",
                           "id.token.claim": "false", "userinfo.token.claim": "false",
                       }})
    http.require("POST", f"{base}/client-scopes/{scope_id}/protocol-mappers/models", token=admin,
                 data={"name": "storage-resource-audience", "protocol": "openid-connect",
                       "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                       "config": {"included.client.audience": STORAGE_CLIENT,
                                  "id.token.claim": "false", "access.token.claim": "true"}})
    http.require("PUT", f"{base}/clients/{app['id']}/optional-client-scopes/{scope_id}", token=admin)
    # A separate ordinary audience mapper creates a real signed widened-audience negative case.
    http.require("POST", base + "/client-scopes", token=admin, data={
        "name": "other-resource-audience", "protocol": "openid-connect", "attributes": {},
    })
    scopes = http.require("GET", base + "/client-scopes", token=admin)
    other_scope_id = next(item["id"] for item in scopes if item["name"] == "other-resource-audience")
    http.require("POST", f"{base}/client-scopes/{other_scope_id}/protocol-mappers/models", token=admin,
                 data={"name": "other-resource-audience", "protocol": "openid-connect",
                       "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                       "config": {"included.custom.audience": "other-resource",
                                  "id.token.claim": "false", "access.token.claim": "true"}})
    http.require("PUT", f"{base}/clients/{app['id']}/optional-client-scopes/{other_scope_id}", token=admin)

    for name in ROLES:
        http.require("POST", f"{base}/clients/{storage['id']}/roles", token=admin,
                     data={"name": name, "description": "Issue #61 qualification role"})
    http.require("POST", base + "/roles", token=admin, data={"name": "storage:read"})
    http.require("POST", base + "/clients", token=admin, data={
        "clientId": "other-resource", "enabled": True, "protocol": "openid-connect",
        "publicClient": False,
    })
    other = http.require("GET", base + "/clients?clientId=other-resource", token=admin)[0]
    http.require("POST", f"{base}/clients/{other['id']}/roles", token=admin,
                 data={"name": "storage:read"})
    http.require("POST", base + "/users", token=admin, data={
        "username": "issue61-qualification-user", "enabled": True,
        "firstName": "Qualification", "lastName": "User",
        "email": "issue61-qualification@example.test", "emailVerified": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    user = http.require("GET", base + "/users?username=issue61-qualification-user", token=admin)[0]
    http.require("PUT", base + f"/users/{user['id']}", token=admin,
                 data={"id": user["id"], "requiredActions": [], "enabled": True})
    http.require("PUT", base + f"/users/{user['id']}/reset-password", token=admin,
                 data={"type": "password", "value": password, "temporary": False})
    user_state = http.require("GET", base + f"/users/{user['id']}", token=admin)
    credential_types = {item.get("type") for item in http.require(
        "GET", base + f"/users/{user['id']}/credentials", token=admin)}
    if user_state.get("requiredActions") or "password" not in credential_types:
        raise RuntimeError("qualification user setup incomplete")
    return {"storage_id": storage["id"], "app_id": app["id"], "other_id": other["id"],
            "scope_id": scope_id, "other_scope_id": other_scope_id, "user_id": user["id"]}


def _readback_configuration(http: Http, admin: str, ids: dict[str, str]) -> dict[str, Any]:
    base = f"/admin/realms/{REALM}"
    return {
        "realm": http.require("GET", base, token=admin),
        "storage_client": http.require("GET", f"{base}/clients/{ids['storage_id']}", token=admin),
        "app_client": http.require("GET", f"{base}/clients/{ids['app_id']}", token=admin),
        "role_scope": http.require("GET", f"{base}/client-scopes/{ids['scope_id']}", token=admin),
        "mappers": http.require("GET", f"{base}/client-scopes/{ids['scope_id']}/protocol-mappers/models",
                                 token=admin),
        "role_scope_mappings": [role["name"] for role in http.require(
            "GET", f"{base}/clients/{ids['app_id']}/scope-mappings/clients/{ids['storage_id']}",
            token=admin)],
        "storage_roles": http.require("GET", f"{base}/clients/{ids['storage_id']}/roles", token=admin),
    }


def _client_role(http: Http, admin: str, ids: dict[str, str], name: str) -> dict[str, Any]:
    return http.require("GET", f"/admin/realms/{REALM}/clients/{ids['storage_id']}/roles/{_path(name)}",
                        token=admin)


def _assign(http: Http, admin: str, ids: dict[str, str], client: str, role: dict[str, Any], add: bool) -> None:
    url = f"/admin/realms/{REALM}/users/{ids['user_id']}/role-mappings/clients/{ids[client]}"
    http.require("POST" if add else "DELETE", url, token=admin, data=[role])


def _role_scope(http: Http, admin: str, ids: dict[str, str], role: dict[str, Any], add: bool) -> None:
    url = f"/admin/realms/{REALM}/clients/{ids['app_id']}/scope-mappings/clients/{ids['storage_id']}"
    http.require("POST" if add else "DELETE", url, token=admin, data=[role])


def _issue(http: Http, username: str, password: str, scopes: str) -> tuple[str, str | None]:
    status, data = http.request("POST", f"/realms/{REALM}/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": APP_CLIENT, "username": username,
        "password": password, "scope": scopes,
    }, form=True)
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
        error = data.get("error") if isinstance(data, dict) else None
        description = data.get("error_description") if isinstance(data, dict) else None
        description = description if isinstance(description, str) else ""
        safe_detail = "invalid_grant"
        if "invalid user credentials" in description.lower():
            safe_detail = "invalid_user_credentials"
        elif "not fully set up" in description.lower():
            safe_detail = "required_action_pending"
        elif error in {"invalid_request", "invalid_client", "unauthorized_client", "invalid_scope"}:
            safe_detail = error
        raise RuntimeError("ordinary OIDC token issuance failed: " + safe_detail)
    return data["access_token"], data.get("refresh_token")


def _refresh(http: Http, refresh_token: str) -> tuple[str, str]:
    _, data = http.request("POST", f"/realms/{REALM}/protocol/openid-connect/token", data={
        "grant_type": "refresh_token", "client_id": APP_CLIENT, "refresh_token": refresh_token,
    }, form=True)
    if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
        raise RuntimeError("ordinary OIDC refresh failed")
    return data["access_token"], data.get("refresh_token", refresh_token)


def _verified_claims(token: str, jwks: dict[str, Any], issuer: str) -> dict[str, Any]:
    try:
        from authlib.jose import jwt
    except ImportError as exc:
        raise RuntimeError("Authlib 1.9.2 required; install requirements/issue8-oidc.lock") from exc
    claims = jwt.decode(token, jwks)
    claims.validate(leeway=10)
    if claims.get("iss") != issuer or not isinstance(claims.get("sub"), str):
        raise RuntimeError("signed token issuer/subject validation failed")
    return dict(claims)


def _record(case: dict[str, Any], token: str, jwks: dict[str, Any], issuer: str,
            expected_roles: list[str], audience: str = STORAGE_CLIENT,
            expected_failures: list[str] | None = None) -> dict[str, Any]:
    claims = _verified_claims(token, jwks, issuer)
    summary = claims_summary(claims, STORAGE_CLIENT)
    failures = evaluate_claims(claims, {"aud": audience, "roles": expected_roles}, STORAGE_CLIENT)
    expected = sorted(expected_failures or [])
    case["status"] = "passed" if sorted(failures) == expected else "failed"
    case["claims"] = summary
    case["checks"] = {"signature_verified": True, "claim_contract_conforms": not failures,
                      "expected_failure_categories": expected, "failure_categories": failures}
    return summary


def _container_engine() -> str:
    for engine in ("podman", "docker"):
        if subprocess.run(["sh", "-lc", f"command -v {engine}"], capture_output=True).returncode == 0:
            return engine
    raise RuntimeError("Podman or Docker is required")


def run_qualification(port: int = 18080) -> dict[str, Any]:
    engine = _container_engine()
    # Verify the exact image digest is already available, then pin the run to its immutable ID.
    image_inspect = subprocess.run([engine, "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                                   text=True, capture_output=True)
    if image_inspect.returncode:
        raise RuntimeError("pinned Keycloak image is not present locally; pull it explicitly first")
    image_id = image_inspect.stdout.strip()
    run_id = secrets.token_hex(16)
    name = f"issue61-keycloak-{run_id}"
    admin = "issue61-admin"
    admin_password = secrets.token_urlsafe(24)
    user_password = secrets.token_urlsafe(24)
    cases = [{**item, "status": "not-run"} for item in CASES]
    http = Http(f"http://127.0.0.1:{port}")
    release = None
    cleanup_ok = True
    qualification_result: dict[str, Any] | None = None
    try:
        subprocess.run([engine, "run", "--detach", "--rm", "--name", name,
                        "--label", f"{RUN_LABEL}={run_id}",
                        "--publish", f"127.0.0.1:{port}:8080",
                        "--env", "KC_BOOTSTRAP_ADMIN_USERNAME=" + admin,
                        "--env", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + admin_password,
                        image_id, "start-dev", "--http-enabled=true"], check=True,
                        stdout=subprocess.DEVNULL)
        for _ in range(90):
            probe = subprocess.run([engine, "exec", name, "/opt/keycloak/bin/kc.sh", "--version"],
                                   text=True, capture_output=True)
            if probe.returncode == 0 and "26.8.0" in probe.stdout:
                release = probe.stdout.strip().splitlines()[0]
                break
            time.sleep(2)
        if release is None:
            raise RuntimeError("pinned Keycloak did not become ready with expected release")
        for _ in range(30):
            try:
                admin_token = _admin_token(http, admin, admin_password)
                break
            except Exception:
                time.sleep(2)
        else:
            raise RuntimeError("Keycloak admin endpoint did not become ready")
        ids = _create_realm(http, admin_token, user_password)
        base = f"/admin/realms/{REALM}"
        issuer = f"http://127.0.0.1:{port}/realms/{REALM}"
        jwks = http.require("GET", f"/realms/{REALM}/protocol/openid-connect/certs")
        role_by_name = {name: _client_role(http, admin_token, ids, name) for name in ROLES}
        # Explicitly make only the intended client-role subset effective for app tokens.
        for role in role_by_name.values():
            _role_scope(http, admin_token, ids, role, True)
        config, configuration_sha256 = readback_configuration_fingerprint(
            _readback_configuration(http, admin_token, ids))
        cases_by_id = {item["id"]: item for item in cases}
        for role_name in ROLES:
            role = role_by_name[role_name]
            _assign(http, admin_token, ids, "storage_id", role, True)
            token, _ = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
            _record(cases_by_id[f"assigned_{role_name.replace(':', '_')}"] , token, jwks, issuer, [role_name])
            _assign(http, admin_token, ids, "storage_id", role, False)
        for role in role_by_name.values():
            _assign(http, admin_token, ids, "storage_id", role, True)
        token, refresh = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        _record(cases_by_id["all_six_assigned"], token, jwks, issuer, list(ROLES))
        for role in role_by_name.values():
            _assign(http, admin_token, ids, "storage_id", role, False)
        token, _ = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        _record(cases_by_id["no_assigned_roles"], token, jwks, issuer, [])
        role = role_by_name[ROLES[0]]
        _assign(http, admin_token, ids, "storage_id", role, True)
        _role_scope(http, admin_token, ids, role, False)
        token, _ = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        _record(cases_by_id["role_scope_excluded"], token, jwks, issuer, [])
        _role_scope(http, admin_token, ids, role, True)
        _assign(http, admin_token, ids, "storage_id", role_by_name[ROLES[1]], True)
        _role_scope(http, admin_token, ids, role_by_name[ROLES[1]], False)
        token, _ = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        _record(cases_by_id["role_scope_intersection"], token, jwks, issuer, [ROLES[0]])
        _role_scope(http, admin_token, ids, role_by_name[ROLES[1]], True)
        _assign(http, admin_token, ids, "storage_id", role_by_name[ROLES[1]], False)
        _assign(http, admin_token, ids, "storage_id", role, False)
        realm_role = http.require("GET", base + "/roles/storage%3Aread", token=admin_token)
        http.require("POST", base + f"/users/{ids['user_id']}/role-mappings/realm", token=admin_token,
                     data=[realm_role])
        token, _ = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        _record(cases_by_id["realm_role_only"], token, jwks, issuer, [])
        http.require("DELETE", base + f"/users/{ids['user_id']}/role-mappings/realm", token=admin_token,
                     data=[realm_role])
        other_role = http.require("GET", f"{base}/clients/{ids['other_id']}/roles/storage%3Aread", token=admin_token)
        _assign(http, admin_token, ids, "other_id", other_role, True)
        token, _ = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        _record(cases_by_id["different_client_role_only"], token, jwks, issuer, [])
        _assign(http, admin_token, ids, "other_id", other_role, False)
        token, _ = _issue(http, "issue61-qualification-user", user_password, "openid other-resource-audience")
        _record(cases_by_id["wrong_audience_rejected"], token, jwks, issuer, [],
                expected_failures=["audience_not_exact_single_storage_resource"])
        _assign(http, admin_token, ids, "storage_id", role, True)
        token, _ = _issue(http, "issue61-qualification-user", user_password,
                          "openid " + ROLE_SCOPE + " other-resource-audience")
        _record(cases_by_id["widened_audience_rejected"], token, jwks, issuer, [ROLES[0]],
                expected_failures=["audience_not_exact_single_storage_resource"])
        # Return to baseline: no assigned role, then verify unchanged refresh claims.
        _assign(http, admin_token, ids, "storage_id", role, False)
        token, refresh = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        first = _verified_claims(token, jwks, issuer)
        refreshed, refresh = _refresh(http, refresh or "")
        second = _verified_claims(refreshed, jwks, issuer)
        _record(cases_by_id["refresh_unchanged_assignments"], refreshed, jwks, issuer, [])
        if first.get("aud") != second.get("aud") or storage_client_roles(first, STORAGE_CLIENT) != storage_client_roles(second, STORAGE_CLIENT):
            cases_by_id["refresh_unchanged_assignments"]["status"] = "failed"
        # Role added during an existing session: old signed token unchanged; refreshed token reflects update.
        token, refresh = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        old_claims = _verified_claims(token, jwks, issuer)
        _assign(http, admin_token, ids, "storage_id", role, True)
        refreshed, _ = _refresh(http, refresh or "")
        refreshed_claims = _verified_claims(refreshed, jwks, issuer)
        case = cases_by_id["refresh_after_role_change"]
        _record(case, refreshed, jwks, issuer, [ROLES[0]])
        case["already_issued_token_roles_unchanged_until_exp"] = storage_client_roles(old_claims, STORAGE_CLIENT) == []
        if not case["already_issued_token_roles_unchanged_until_exp"]:
            case["status"] = "failed"
        # Remove role from an existing refresh session. New refresh reflects current role/scope mapping.
        token, refresh = _issue(http, "issue61-qualification-user", user_password, "openid " + ROLE_SCOPE)
        _role_scope(http, admin_token, ids, role, False)
        refreshed, _ = _refresh(http, refresh or "")
        _record(cases_by_id["refresh_after_scope_change"], refreshed, jwks, issuer, [])
        _role_scope(http, admin_token, ids, role, True)
        if not validate_case_ledger(cases) or any(item["status"] != "passed" for item in cases):
            raise RuntimeError("one or more required qualification cases did not pass")
        qualification_result = {"format": "issue61-native-role-qualification-v1", "result": "passed",
                "software": {"keycloak_release": release, "image": IMAGE, "image_id": image_id,
                             "image_digest": IMAGE_DIGEST, "runtime": "single local disposable node"},
                "configuration": config, "configuration_sha256": configuration_sha256,
                "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "cases": cases, "refresh_semantics": {
                    "unchanged_assignments": "same audience and roles on refresh",
                    "role_change": "new refresh-issued access token reflects changed assignment",
                    "scope_change": "new refresh-issued access token reflects changed scope mapping",
                    "prior_access_token": "claims remain signed as issued until exp; no prompt revocation claim",
                }, "cleanup": {"container_removed": False}}
    except BaseException as exc:
        for item in cases:
            if item["status"] == "not-run":
                item["status"] = "error" if not isinstance(exc, KeyboardInterrupt) else "not-run"
        qualification_result = {"format": "issue61-native-role-qualification-v1", "result": "failed",
                "software": {"keycloak_release": release, "image": IMAGE, "image_id": image_id,
                             "image_digest": IMAGE_DIGEST}, "cases": cases,
                "failure_category": type(exc).__name__,
                "failure_detail": str(exc).split(": ", 1)[-1] if str(exc).startswith("ordinary OIDC token issuance failed:") else type(exc).__name__,
                "cleanup": {"container_removed": False}}
    finally:
        try:
            cleanup_ok = cleanup_owned_container(engine, name, run_id, image_id)
        except BaseException:
            cleanup_ok = False
        if qualification_result is None:
            qualification_result = {"format": "issue61-native-role-qualification-v1", "result": "failed",
                                    "cases": cases, "failure_category": "unknown",
                                    "cleanup": {"container_removed": cleanup_ok}}
        qualification_result.setdefault("cleanup", {})["container_removed"] = cleanup_ok
        qualification_result["cleanup"]["container_name_absent"] = cleanup_ok
        if not cleanup_ok:
            qualification_result["result"] = "failed"
    assert qualification_result is not None
    return qualification_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--evidence", type=Path, help="write sanitized result JSON (never tokens)")
    parser.add_argument("--run", action="store_true", help="run disposable local Keycloak qualification")
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("--run is required; this command creates a disposable local container")
    result = run_qualification(args.port)
    output = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(output)
        os.chmod(args.evidence, 0o600)
    print(output, end="")
    return 0 if result.get("result") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
