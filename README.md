# decent-keycloak wallet-login provider (experimental)

This repository owns the Keycloak-specific adapter for the approved, provider-neutral `decent-wallet-login-v1` contract. The ecosystem protocol and vectors live in [`decent-ecosystem`](https://github.com/jetpen/decent-ecosystem/issues/46). This work is separate from Storage's RFC 7523 wallet-grant adapter.

**Status: implemented transport/proof plumbing; not acceptance-qualified as an end-to-end login.** The provider must not be presented as production-ready. A clean local build and route smoke do not prove Registry integration, distributed replay, wallet interoperability, or OIDC completion.

## Current evidence and limits

- Keycloak 26.8.0 provider package: the current worktree's Maven clean package passed 87 tests across 12 suites (0 failures, errors or skips); `git diff --check` passed. The base PR commit has 86 tests; this branch adds a route/CORS response forwarding regression.
- A fresh Keycloak 26.8.0 image returned 200 for OIDC discovery and the deterministic wallet-route probe through an HTTPS hostname/proxy simulation with `/auth` relative path. Invalid handles returned fail-closed 404; an 8,193-byte POST returned 413 through the streaming resource body limit. This is HTTP dispatch/body-bound evidence only, not a valid pending transaction or login.
- No disposable realm/client/required flow, compatible wallet app, or configured Identity/Registry is currently running in the container. The sibling `decent-identity` development venv has a CLI entry point, but the Keycloak container does not have that runtime configured or mounted.
- A separate host-side local acceptance probe used an ephemeral Registry node and synthetic test identity: publish, resolve via a separate CLI client, then resolve through the Java `ProcessIdentityResolver` with the exact UTF-8 identifier and current Ed25519 key. The temporary key and LMDB state were deleted at test exit. This verifies the adapter against host venv dependencies only; it does not qualify the Keycloak container's CLI runtime or an end-to-end login.
- No valid proof exchange through the live Keycloak endpoint, two-node shared-store race, session callback, or OIDC Authorization Code + PKCE wallet login has been demonstrated. Keep those gates unqualified and keep the authenticator fail-closed on any missing prerequisite.

## Implemented flow shape

1. A required Keycloak authenticator requires Standard Flow and exactly one registered exact HTTPS redirect URI, then binds the current authentication session, realm, and trusted public HTTPS origin before issuing a transaction.
2. The Keycloak shared `SingleUseObjectProvider` stores five-minute pending state under a hash of the independent 256-bit opaque URL handle. The signed challenge is base64url-no-padding SHA-256 of a separate 32-byte random nonce; a separate transaction CSRF token is generated.
3. The QR contains an HTTPS transaction locator only. Wallet `GET` reads the no-store `{profile, challenge, csrf_token}` envelope. Wallet `POST` to the same URI submits the exact four-string proof (`profile`, `challenge`, `identity_id`, `signature`). The proof-core uses RFC 8785 JCS UTF-8 signing bytes and Ed25519.
4. A fixed, bounded `decent-identity get` subprocess adapter resolves the exact raw identity ID/current owner public key. One 20-second shared resolver-admission window per initiating browser/client serializes lookup across sibling transactions and prevents immediate fan-out; it expires rather than being owner-released. A unique enabled local Keycloak user must map that exact ID before transaction consumption.
5. Atomic removal of pending state is the proof one-winner point. The accepted proof/status digest is retained until expiry; an identical proof retry reports accepted only, while changed bytes fail. A separate callback gate is published before accepted status and permits one Keycloak resume. Callback rechecks the exact enabled-user mapping before consuming the gate, so a missing/temporarily unavailable account does not strand the receipt. Status stops advertising the callback once its gate is consumed; a final Keycloak resume failure then requires a fresh login rather than replaying the one-use gate. If a resolver process cannot be killed within its grace period, it promotes the shared admission key to a five-minute block for new and existing transactions of the same realm/client/root browser session; sibling pending records remain stored. This is best-effort, not a fencing guarantee if the Keycloak node stalls past the 20-second admission window before promotion, and shared-backend cross-node behavior is unqualified. Storage failure never returns success/code.
6. Five per-transaction invalid-proof slots and a best-effort five-minute browser/client new-transaction lock are stored separately. They throttle abuse only; they do not revoke already-issued sibling transactions or replace atomic per-transaction replay prevention.

This outline describes the current implementation shape, not a claim that every step has passed live acceptance. In particular, atomic behavior of the supported shared Keycloak backend has not yet been qualified across nodes.

## HTTP surface

Mounted below `/realms/{realm}/decent-wallet-login`:

- `GET /v1/transactions/{handle}` — native wallet requests require all Origin/Fetch Metadata headers absent. Browser fetch requires exact wallet Origin plus `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`, and accepted Fetch-Site. Read-only; returns only the challenge envelope. The QR uses Keycloak's trusted public base URI, including a relative path prefix when configured.
- `POST /v1/transactions/{handle}` — streams and buffers at most 8 KiB + 1 byte before rejecting oversize proof bodies. Browser wallet requires exact Origin, `cors`/`empty` Fetch Metadata, JSON content type and transaction CSRF. Native wallet requires all Origin/Fetch Metadata and CSRF absent; valid signature and current-key checks remain mandatory.
- Identical proof-byte retry after acceptance returns accepted status only; a different proof is rejected. Neither path issues a second OIDC result.
- `GET /v1/transactions/{handle}/status` — requires same-origin Fetch Site, `cors`/`empty` metadata and CSRF; bound to Keycloak client, tab, authentication session, redirect and handle.
- `OPTIONS /v1/transactions/{handle}` — requires browser `cors`/`empty` Fetch Metadata, exact Origin, and restricted method/header sets; no credentials or wildcard origin.

The login template renders the QR/locator and polls browser status; it does **not** fetch challenge JSON or submit proof. This repository contains no wallet SDK, native client, or browser-to-native bridge. A compatible wallet client is a prerequisite for end-to-end acceptance.

## Experimental configuration

Configure the authenticator execution as `REQUIRED` and set its comma-separated `trusted-origins` to exact HTTPS origins; one must exactly match the trusted Keycloak public base origin. Do not derive this value from an arbitrary request `Origin` or untrusted forwarding headers.

Realm attributes consumed by the provider:

- `decent.wallet.browser-origin` — exact HTTPS web-wallet Origin; required for browser-wallet requests.
- `decent.wallet.registry.bootstrap` and `decent.wallet.registry.client-port` — required together to configure the current Identity CLI resolver.
- `decent.wallet.identity.executable` — optional fixed command (`decent-identity`) or explicit absolute executable path. Process time and output are bounded; its runtime must be available to the Keycloak process/container.
- `decent.wallet.idp-origin` — optional exact HTTPS assertion; if set, it must match the normalized origin from trusted Keycloak hostname/proxy configuration. It cannot override that origin.

A missing setting does not enable fallback authentication; the flow fails closed. The current smoke container is not configured with these settings or a test realm.

## Account policy

Fresh wallet authentication resolves current Registry identity/key and maps exactly one enabled, pre-provisioned local user by the exact `decent_identity_id` user attribute. Keycloak retains its own opaque user ID as OIDC `sub`; account creation/linking and the signed `decent_identity_id` token mapper are not implemented here. At relying parties, Registry lookup is for explicit signup/account creation only; returning login validates Keycloak OIDC and maps `(iss, sub)` locally.

## Local checks

With Java 21 available:

```bash
mvn -q -o clean package
git diff --check
```

To build the provider image after packaging:

```bash
podman build --pull=never -f container/Dockerfile \
  -t localhost/decent-keycloak-wallet-authenticator-spike:live-slice .
```

A successful Maven build/image build is not live wallet-login qualification. Run a fresh full package after the final source/test edit and record the actual Surefire XML totals.

## Remaining acceptance gates before claiming a working login

1. Configure a disposable Keycloak realm, client and required flow; create and exercise a valid transaction through wallet GET, proof POST, accepted status and callback.
2. Run a compatible native/browser wallet against the real HTTP routes; verify exact Origin/CORS, Fetch Metadata, CSRF, headers, redirects, expiry and no proof/challenge leakage.
3. Provision the `decent-identity` runtime and Registry fixture; verify exact ID/current key plus missing, unavailable, stale/history-incomplete, ambiguous, malformed and rotated-key failures.
4. Verify invalid proof, wrong realm/client/session/tab/origin, expiry, replay, storage and receipt-write failures all yield no authenticated session/code. Test best-effort invalid-attempt controls separately from replay guarantees.
5. Race two Keycloak nodes using the supported shared store and show at most one winner; unit fakes are not distributed replay evidence.
6. Complete actual OIDC Authorization Code + PKCE with the compatible wallet; demonstrate negative cases never yield login/code.
7. Re-run focused and clean full tests, build the pinned provider image, inspect the complete final diff, and report passed/blocked/unrun gates precisely.
8. Open a human-review PR against `main` with `Refs #1` only after review-boundary checks. Do not merge or close issue #1 without explicit instruction.

See Keycloak issue [#1](https://github.com/jetpen/decent-keycloak/issues/1) for the live implementation plan and acceptance criteria. The issue remains open; the merged proof-core PR is not end-to-end acceptance.
