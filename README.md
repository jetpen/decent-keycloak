# decent-keycloak wallet-login provider (experimental)

This repository owns the Keycloak-specific adapter for the approved, provider-neutral `decent-wallet-login-v1` contract. The ecosystem protocol and vectors live in [`decent-ecosystem`](https://github.com/jetpen/decent-ecosystem/issues/46). This work is separate from Storage's RFC 7523 wallet-grant adapter.

**Status: implemented transport/proof plumbing; not acceptance-qualified as an end-to-end login.** The provider must not be presented as production-ready. A clean local build and route smoke do not prove Registry integration, distributed replay, wallet interoperability, or OIDC completion.

## Current evidence and limits

- **Passed in the disposable single-node simulation:** browser preflight accepts challenge GET without custom request headers and proof POST with `Content-Type` plus `X-Decent-CSRF`; extra `Authorization` and unconfigured Origin are denied. Browser challenge, native challenge, valid proof, oversized proof (8,193 bytes → 413), bad-proof failures, and browser status were checked for cache/security headers; errors and status vary by Origin. The 204 CORS preflight responses have Referrer Policy, nosniff, and `Vary: Origin`; Keycloak omits `Cache-Control` on those successes. Rejected preflights are `no-store`. This remains loopback proxy simulation, not browser-engine or real TLS qualification.
- **Latest code verification after callback-order regression:** offline Maven clean package passed 119 tests across 12 suites (no failures/errors/skips); Python source/harness group passed 60 tests + 10 subtests; Python compilation and `git diff --check` passed. Fresh immutable provider image `sha256:955acc1d910fd87ad6328bdaaadc4fb00d8dfb1afca76d839a5eb89846194f0d` passed the full disposable probe: signup action 200, proof 202, exact account creation/readback, signup PKCE/JWKS/claim, rotation current-key 202/stale-key 401 with stale session pending, callback replay denial and existing-login/account-denial controls. Missing-Identity returned 503 because resolver output contained peer-handshake diagnostics; this is unavailable, not evidence of absence. Loopback proxy/synthetic-signer simulation only, not real TLS/browser/wallet or cluster qualification.
- A disposable single-node Keycloak integration probe passed: current Registry key resolution inside the container, native challenge GET, Ed25519 proof POST (202), initiating-browser accepted status (200), callback authorization code, and Code + PKCE token exchange (200). The ID token signature was verified against realm JWKS, with issuer/audience/nonce/expiry checks. Identical proof retry was accepted, changed bytes denied, and a separate wallet client could not poll the initiating browser's status. A second current Registry identity with no matching Keycloak user was rejected with 403; a duplicate exact local account mapping was also rejected with 403. Both transactions stayed pending and no callback was exposed. A valid proof for a mapped disabled account was also rejected with 403 and no callback. A live browser-style challenge fetch returns 200 with `no-store`, allowed Origin, nosniff, Referrer Policy, and Vary headers. The native wallet challenge and valid proof response have the same protections. Proof POST without CSRF returns 403; a CSRF-bearing wrong-challenge proof returns 401. Both error responses and the initiating browser's pending status also include those protections. In separate fresh browser flows, a wrong-origin challenge read was denied and an invalid Ed25519 signature returned 401 without acceptance. The negative flow uses a wrong-challenge proof (401), four malformed proofs (400), and one more rejected proof, then confirms throttling with 429 after five recorded invalid attempts. The initiating browser remains pending without a callback. This exercises the per-transaction limiter in the disposable single-node setup only and does not qualify production-wide abuse controls. The disposable live probe's generated missing-ID lookups emit Registry `Value not found for key /decent-registry/identity/<64-hex-key>` diagnostics followed by exact `not found`; the Keycloak provider independently returns 503 in a fresh transaction. The adapter maps `not found` to absence only when exit code is 1, the terminal output line is exactly `not found`, and preceding output consists solely of that validated Registry-miss form plus the already-known bounded dial-warning form. Any handshake, malformed/mixed output, or other error remains unavailable. The live Registry sometimes emits a handshake failure among those diagnostics, so that path remains 503 and missing/unavailable parity is still not established for that case. Both outcomes remain fail-closed with no accepted receipt or callback. The probe uses loopback HTTPS proxy simulation and a synthetic signer—not real TLS, a wallet app, browser JavaScript execution, or cluster qualification.
- The resolver runtime is supplied by read-only host development mounts plus a UBI9-compatible GMP library. Its sanitized in-container CLI lookup passed. This does not establish a self-contained production image.
- A fresh Keycloak 26.8.0 image returned 200 for OIDC discovery and the deterministic wallet-route probe through an HTTPS hostname/proxy simulation with `/auth` relative path. Invalid handles returned fail-closed 404; 8,193-byte browser and native proof POSTs returned 413, with response security headers present. This confirms transport/body-limit dispatch but does not prove the oversized body caused no transaction-state change or resolver invocation in a real deployment. It is not a valid pending transaction or login.
- **Latest owner-key rotation run passed its bounded disposable gates:** Registry sequence 2 and exact successor owner key were independently read back; the provider-container resolver returned the exact rotated Identity despite bounded peer diagnostics. The stale-owner proof returned 401 and its initiating browser remained pending without a callback. A fresh successor-key transaction returned 202, was accepted in its initiating browser, and exposed the Keycloak callback. Synthetic signer and loopback HTTPS simulation; not production qualification.
- **Latest integration run:** fresh browser cookie jars isolated ordinary login and explicit signup. The signup action POST returned 200, proof POST 202, and Keycloak read back exactly one enabled account with the exact Identity attribute. The callback reached the Keycloak execution, profile/required action completed, OIDC state was preserved, callback replay returned an error with no second code, Code + PKCE token exchange returned 200, and the ID token subject matched the created local account. Disposable missing-Identity resolver response remained HTTP 503 because bounded output contained a peer-handshake failure; this is fail-closed unavailable evidence, not proof of absence.

- The probe removes its disposable Keycloak container, Registry process, synthetic private key and LMDB state at exit; no compatible wallet app is deployed.
- Two-node shared-store replay, real wallet/browser interoperability, real TLS, and the complete negative/no-code matrix remain unqualified.

## Implemented flow shape

1. A required Keycloak authenticator requires Standard Flow and exactly one registered exact HTTPS redirect URI, then binds the current authentication session, realm, and trusted public HTTPS origin before issuing a transaction.
2. The Keycloak shared `SingleUseObjectProvider` stores five-minute pending state under a hash of the independent 256-bit opaque URL handle. The signed challenge is base64url-no-padding SHA-256 of a separate 32-byte random nonce; a separate transaction CSRF token is generated.
3. The QR contains an HTTPS transaction locator only. Wallet `GET` reads the no-store `{profile, challenge, csrf_token}` envelope. Wallet `POST` to the same URI submits the exact four-string proof (`profile`, `challenge`, `identity_id`, `signature`). The proof-core uses RFC 8785 JCS UTF-8 signing bytes and Ed25519.
4. A fixed, bounded `decent-identity get` subprocess adapter resolves the exact raw identity ID/current owner public key. One 20-second shared resolver-admission window per initiating browser/client serializes lookup across sibling transactions and prevents immediate fan-out; it expires rather than being owner-released. A unique enabled local Keycloak user must map that exact ID before transaction consumption.
5. Atomic removal of pending state is the proof one-winner point. The accepted proof/status digest is retained until expiry; an identical proof retry reports accepted only, while changed bytes fail. A separate callback gate is published before accepted status and permits one Keycloak resume. The live single-node probe confirmed that a subsequent callback request does not repeat the original authorization code and that status stops advertising its callback after the gate is consumed. **Callback-order guard:** callback re-reads the exact mapped enabled account and fails closed if missing; it no longer creates or deletes an account after pending proof consumption. Regression tests cover missing-map failure without provisioning/gate consumption, but this latest code has not yet been exercised in a fresh full signup live flow. A final Keycloak resume failure then requires a fresh login rather than replaying the one-use gate. If a resolver process cannot be killed within its grace period, it promotes the shared admission key to a five-minute block for new and existing transactions of the same realm/client/root browser session; sibling pending records remain stored. This is best-effort, not a fencing guarantee if the Keycloak node stalls past the 20-second admission window before promotion, and shared-backend cross-node behavior is unqualified. Storage failure never returns success/code.
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

Configure the authenticator execution as `REQUIRED` and set its comma-separated `trusted-origins` to exact HTTPS origins; one must match the trusted Keycloak public base origin. Default HTTPS port `:443` is canonicalized equivalently to an omitted port. Do not derive this value from an arbitrary request `Origin` or untrusted forwarding headers. The relying-party label is configured once at realm level, not separately per flow, so the browser challenge and native wallet envelope display the same name.

Realm attributes consumed by the provider:

- `decent.wallet.browser-origin` — exact HTTPS web-wallet Origin; required for browser-wallet requests and is itself the exact allowed browser Origin. The optional `decent.wallet.trusted-origins` adds a consistency check; if present it must include this origin.
- `decent.wallet.site-name` — required realm-wide relying-party label, shown consistently in the login page and native wallet challenge.
- `decent.wallet.registry.bootstrap` and `decent.wallet.registry.client-port` — required together to configure the current Identity CLI resolver.
- `decent.wallet.identity.executable` — optional fixed command (`decent-identity`) or explicit absolute executable path. Process time and output are bounded; its runtime must be available to the Keycloak process/container.
- `decent.wallet.idp-origin` — optional exact HTTPS assertion; if set, it must match the normalized origin from trusted Keycloak hostname/proxy configuration. It cannot override that origin.

A missing setting does not enable fallback authentication; the flow fails closed. The separate route-smoke container is not configured with these settings; the disposable integration probe provisions its own realm and teardown.

## Account policy

Keycloak creates or loads exactly one local account with the exact raw `decent_identity_id` only after a fresh, valid wallet proof and before consuming the pending login transaction. Explicit `login` requires exactly one existing enabled match; explicit server-bound `signup` may provision a local account after proof. Concurrent provisioning is accepted only after a fresh exact-ID lookup finds one unique enabled winner; ambiguous mappings fail closed. Keycloak retains its opaque user ID as stable OIDC `sub` and releases `decent_identity_id` only as a signed ID-token claim for configured relying parties. The disposable single-node harness verifies the claim value after JWKS signature validation; relying-party Registry verification and returning-login `(iss, sub)` mapping are external consumer responsibilities and remain unqualified here.

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

### Disposable local integration probe

`scripts/wallet_login_live_e2e.py` requires Podman, OpenSSL, sibling Identity/Registry development runtimes and the uv Python runtime. It defaults to `~/projects`; override `WALLET_IT_PROJECTS` if needed. Supply `WALLET_IT_NATIVE_LIBS` pointing to a directory containing **UBI9-compatible** `libgmp.so.10` (the host's library may require a newer glibc). The exercised library came from Red Hat's `gmp-6.2.0-13.el9.x86_64.rpm`, SHA-256 `d4529445e30b7eb9a8225b0539f70d26d585d7fe306296f948ea73114d1c171f`.

```bash
WALLET_IT_NATIVE_LIBS=/path/to/ubi9/usr/lib64 \
  python scripts/wallet_login_live_e2e.py
```

When invoking with the default host Python, ensure the probe dependencies are installed; in the verified workspace, use `/home/ben/projects/decent-registry/.venv/bin/python` because that environment provides the sibling Registry/Identity runtime dependencies.

`WALLET_IT_IMAGE` can pin an immutable built image ID. The probe uses port 18886, checks it is free, generates disposable credentials/signing material, keeps private material outside the mounted resolver directory, and tears down its own container/Registry. It simulates trusted HTTPS proxy termination over loopback; it does not test certificates or a real wallet application. Its output is bounded stage/evidence metadata, never tokens or proof material.

## Remaining acceptance gates before claiming a working login

1. **Passed in the disposable single-node simulation:** realm/client/required flow, current Registry key, native challenge GET, valid proof POST, accepted browser-bound status, callback, and Code + PKCE. The latest run additionally completed the explicit signup ceremony, exact local-account readback, Keycloak required profile action, no-code callback replay, and signup PKCE/JWKS/claims verification. The live probe returns 404 for unrelated realm/client/tab status requests; an owning-handler unit test shows proof after pending expiry returns 404 before Registry lookup. Loopback HTTPS forwarding and synthetic signers are used; this is not real TLS/browser/wallet-client qualification.
2. Run a compatible native/browser wallet against real deployment HTTP/TLS; verify Origin/CORS, Fetch Metadata, CSRF, headers, redirects, expiry, streamed oversized-body rejection and no proof/challenge leakage. Oversize evidence is currently disposable simulated ingress only. Still unrun.
3. **Latest bounded rotation simulation passed:** independently read back sequence 2 and the exact successor owner key, confirmed the provider-container resolver returned the rotated Identity, rejected the stale-key proof with 401 while its browser stayed pending/no-callback, then accepted a fresh successor-key proof with 202 and exposed its browser-bound callback. Synthetic signer and loopback HTTPS simulation only; not real TLS/browser/wallet or production qualification.
4. **Partial:** retry/replay, identity-denial, expiry, session binding, CORS/security headers, and throttling cases have individual evidence in earlier disposable runs or Java tests. The latest disposable run denied the distinct unmapped, disabled, duplicate-account, and ambiguous-account fixtures with HTTP 403 after Registry resolution. The missing-Identity resolver produced 503 due to handshake noise and did not establish Registry absence. Two-node replay, actual browser/wallet, and a production-realistic missing/unavailable determination remain unqualified.
5. Race two Keycloak nodes using the supported shared store and show at most one winner; unit fakes are not distributed replay evidence. Still unrun.
6. **Fresh signup provisioning and callback guard passed bounded single-node simulation:** on image `sha256:955acc1d910fd87ad6328bdaaadc4fb00d8dfb1afca76d839a5eb89846194f0d`, the harness verified the exact Identity user was absent before proof; signup action returned 200, valid proof returned 202, and one exact enabled account was then read back, followed by signup PKCE/JWKS validation of the exact signed `decent_identity_id` claim. Callback code re-reads only; Java regression verifies an absent mapping fails closed without provisioning or consuming the callback gate. Existing login and account-denial controls passed. Rotation stale-key proof returned 401/pending; successor key returned 202/accepted/callback. Missing-Identity returned 503 with peer-handshake noise (unavailable). Loopback proxy/synthetic signer only; mapping disappearance race/shared cluster not qualified.
7. **Latest offline verification:** Maven clean package passed 119 tests across 12 suites (no failures/errors/skips); Python source/harness group passed 60 tests + 10 subtests; Python compilation and `git diff --check` passed. Two-node shared-store replay, actual browser/wallet, real TLS and production resolver image/runtime remain unqualified.

8. Issue #1 remains open; do not merge or close without explicit instruction.

See Keycloak issue [#1](https://github.com/jetpen/decent-keycloak/issues/1) for the live implementation plan and acceptance criteria. The issue remains open; the merged proof-core PR is not end-to-end acceptance.
