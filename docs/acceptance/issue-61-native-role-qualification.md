# Issue #61 native Keycloak role-token qualification

This is a disposable, local qualification of one native Keycloak configuration. It does not qualify the Storage service, deployment, or any Keycloak release other than the immutable image identified below.

## Reproduction

Install the hash-locked validator and run the dedicated harness from the repository root:

```bash
python3.11 -m pip install --require-hashes -r requirements/issue8-oidc.lock
python3.11 scripts/issue61_native_roles.py --run --port 18080 \
  --evidence docs/acceptance/evidence/issue61/latest.json
```

The harness uses the locally available pinned image only (it does not pull or rebuild images), starts one loopback-only disposable Keycloak container, creates a short-lived realm/client/user configuration through Keycloak's ordinary Admin REST API, requests ordinary OIDC password-grant access tokens and refreshes, validates JWT signatures against that realm's JWKS, and stops/removes its exact run-owned container. Random bootstrap/admin and test-user passwords and every access/refresh token stay in process memory. Evidence is an allowlisted sanitized claim projection; it contains no raw JWT, subject, credential, or PII. The password grant is only a fixture mechanism in this isolated test realm, not a proposed production login flow.

The realm uses the ordinary `oidc-usermodel-client-role-mapper` for the configured `decent-storage` client's roles and an ordinary `oidc-audience-mapper` for the resource audience. It uses no custom mapper/SPI and does not rewrite issued tokens. The test app and Storage resource client are separate clients. Operators assign roles to the disposable user, and client role-scope mappings determine token inclusion.

## Qualification result

Recorded receipt: [`evidence/issue61/latest.json`](evidence/issue61/latest.json).

- Result: **17/17 passed**, 0 failed, 0 errors, 0 not-run. Every case records signature verification and a sanitized claim summary.
- Keycloak release: **26.8.0**.
- Image reference/digest: `quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad`.
- Local immutable image ID: `43ebe9d4e97c2e5483b7637edf474e6adc1bbf4832a7396686cf90259c396d42`.
- Realm/client config fingerprint: `302c8aee912008b79ca26e1e31d3d8b6b7980b8b57773cbda19a42d52ec651ff`.
- Harness SHA-256: `e3ca85af835f115cff382c8dced6602a1bc3232eea9325c7fae4f77707be1dea`.
- Test interpreter: CPython 3.11.13; `Authlib 1.9.2` from `requirements/issue8-oidc.lock` validates signed JWTs and expiration/issuer claims.

Cases cover each of the six accepted Storage client roles individually and together, no assigned role, role-scope exclusion and intersection, realm-role-only and different-client-role-only assignments, wrong and widened audiences, unchanged refresh, refresh after role assignment change, and refresh after scope-mapping change. The exact-audience positive cases contain only `aud: "decent-storage"`; assigned roles appear under `resource_access.decent-storage.roles`. Wrong-audience and widened-audience tokens are signed Keycloak outputs but correctly fail the exact-single-audience contract.

Refresh generated new access tokens with the then-current role/scope claims. An access token already issued before a role assignment change retained its original claims. This is normal token issuance/refresh behavior; it is not prompt revocation, and no claim is made that an issued token is invalid before its signed `exp`.

## Cleanup and limits

The disposable container was confirmed absent after the run. No image was created, built, pulled, or removed; the pinned image was already present. No volume or network was created or removed, and no listener remained on port 18080. Pre-existing Podman containers/networks/volumes were unchanged.

This evidence qualifies only the pinned Keycloak release/image and the recorded realm/client configuration. It does not qualify Storage-side validation, owner mapping, route authorization, production readiness, another Keycloak release, or a maximum token lifetime/revocation delay. The broader Keycloak issue #56 and Storage issue #18 remain separate gates. No custom mapper, grant, callback, wallet-login, or revocation behavior was added or qualified.
