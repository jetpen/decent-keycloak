# decent-keycloak wallet-login provider (experimental)

This repository owns the Keycloak-specific adapter for the approved, provider-neutral `decent-wallet-login-v1` contract. The ecosystem protocol and vectors live in [`decent-ecosystem`](https://github.com/jetpen/decent-ecosystem/issues/46). This work is separate from Storage's RFC 7523 wallet-grant adapter.

**Status: implemented transport/proof plumbing; not acceptance-qualified as an end-to-end login.** The provider must not be presented as production-ready. A clean local build and route smoke do not prove Registry integration, distributed replay, wallet interoperability, or OIDC completion.

## Current evidence and limits

- **Latest repeated disposable runs:** immutable Keycloak image `sha256:ef6c0a0a0a59d89a2549493e3b99b54441fbc9c723870da4da6879c958e9be02`, rebuilt with `podman build --pull=never --no-cache` from this worktree. Both runs completed login/PKCE, signup/account readback, preflight/security checks, throttling, and unmapped/disabled policy denial with fresh `account-policy-rejected` events; attribution is bounded log-tail evidence without an explicit request ID. The first run stopped at stale-owner proof HTTP 503. The retry passed stale-owner rejection (401/pending) and current-key proof 202/accepted, then stopped at ambiguous-account attribution: the provider returned 403 with a fresh policy event, but the independent exact Registry lookup was unavailable, so the harness correctly left the case unclassified. Neither run reached missing-Identity; both exited 1 before the full scenario sequence completed. An earlier full run on image `sha256:53de80ab84036364b864807ffaca3c564174ff4516535fa7d2a84923e54be648` predates the exact challenge-response correction and is historical, not evidence for this image. These nondeterministic single-node loopback proxy simulations with synthetic signers and host-mounted runtime do not establish production, real TLS/browser-wallet, deterministic Registry, or shared-store qualification.
- **Offline verification:** `mvn -o clean package` passed 122 tests across 12 suites (0 failures/errors/skips); `scripts/test_*.py` passed 81 tests and 10 subtests; Python compilation and `git diff --check` passed.
- **Run provenance:** both runs executed 2026-10-15 with host harness SHA-256 `b628838ffb9aa89a73011218e94abdf7d8ac20b873894c4a1bb7f74e9d066398` and image `sha256:ef6c0a0a0a59d89a2549493e3b99b54441fbc9c723870da4da6879c958e9be02`. Both exited 1; the first stopped at stale-owner proof HTTP 503, the retry at ambiguous-account attribution (403 unclassified). Both used this exact invocation:
  ```bash
  WALLET_IT_IMAGE=sha256:ef6c0a0a0a59d89a2549493e3b99b54441fbc9c723870da4da6879c958e9be02 \
  WALLET_IT_NATIVE_LIBS=/home/ben/.hermes/cache/scratch/keycloak-ubi9-lib/usr/lib64 \
  WALLET_IT_PROJECTS=/home/ben/projects \
  PYTHONPATH=/home/ben/projects/decent-registry/src:/home/ben/projects/decent-identity/src \
  /home/ben/projects/decent-registry/.venv/bin/python scripts/wallet_login_live_e2e.py
  ```
- **Still open from Issue #1:** real TLS and actual browser/native-wallet interoperability, including native challenge GET with browser metadata absent (the route behavior is implemented but no real wallet client has qualified it); full no-code negative matrix against stable Registry states, repeatable stale/current-key rotation, and request-correlated reproducible attribution of account-policy denials; two-node shared-store replay; signup consume/receipt-failure recovery (a created account may remain); a self-contained reproducible pinned runtime (the harness currently host-mounts Registry/Identity runtimes and GMP); relying-party/WordPress acceptance; security review; supported Keycloak version/upgrade scope; and docs/CI. Issue #1 remains open.

## Implemented flow shape

1. A required Keycloak authenticator requires Standard Flow and exactly one registered exact HTTPS redirect URI, then binds the current authentication session, realm, and trusted public HTTPS origin before issuing a transaction.
2. The Keycloak shared `SingleUseObjectProvider` stores five-minute pending state under a hash of the independent 256-bit opaque URL handle. The signed challenge is base64url-no-padding SHA-256 of a separate 32-byte random nonce; a separate transaction CSRF token is generated.
3. The QR contains an HTTPS transaction locator only. Wallet `GET` reads the no-store `{profile, challenge, csrf_token}` envelope. Wallet `POST` to the same URI submits the exact four-string proof (`profile`, `challenge`, `identity_id`, `signature`). The proof-core uses RFC 8785 JCS UTF-8 signing bytes and Ed25519.
4. A fixed, bounded `decent-identity get` subprocess adapter resolves the exact raw identity ID/current owner public key. A shared two-second cooldown per initiating browser/client rejects near-simultaneous sibling lookups but does **not** serialize the resolver's full process lifetime or prevent another lookup after cooldown expiry. It expires rather than being owner-released. For signup, exactly one enabled local Keycloak user is provisioned after proof and before pending-transaction consumption; see the failure window below.
5. Atomic removal of pending state is the proof one-winner point. The accepted proof/status digest is retained until expiry; an identical proof retry reports accepted only, while changed bytes fail. A separate callback gate is published before accepted status and permits one Keycloak resume. The live single-node probe confirmed that a subsequent callback request does not repeat the original authorization code and that status stops advertising its callback after the gate is consumed. **Signup callback gate:** callback re-reads the exact enabled account and fails closed if missing; it does not provision or delete after pending proof consumption. Focused regressions cover the missing-map/gate behavior; successful callback behavior has bounded live evidence, but post-consume mapping disappearance is not exercised live. A final Keycloak resume failure then requires a fresh login rather than replaying the one-use gate. The resolver gets a ten-second execution timeout and, after forcible termination is requested, a two-second forced-termination grace period. The shared admission key expires after two seconds, even if the resolver is still running; it is not an owner-released process-lifetime lock. If termination cannot be confirmed, promotion extends that key to five minutes and applies the browser/client lock. Because promotion follows timeout and termination grace, it may occur after the original admission key expired; promotion cannot cancel an already-admitted sibling lookup. This remains best-effort rather than a fencing guarantee. Storage failure never returns success/code.
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

Configure the authenticator execution as `REQUIRED` and set its comma-separated `trusted-origins` to exact HTTPS origins; one must match the trusted Keycloak public base origin. Default HTTPS port `:443` is canonicalized equivalently to an omitted port. Do not derive this value from an arbitrary request `Origin` or untrusted forwarding headers. The relying-party label is configured once at realm level and displayed on the Keycloak wallet-login page. The wallet challenge response stays exactly `{profile,challenge,csrf_token}`; a wallet client displays the HTTPS origin it actually fetched rather than receiving an extra site-name field.

Realm attributes consumed by the provider:

- `decent.wallet.browser-origin` — exact HTTPS web-wallet Origin; required for browser-wallet requests and is itself the exact allowed browser Origin. The optional `decent.wallet.trusted-origins` adds a consistency check; if present it must include this origin.
- `decent.wallet.site-name` — required realm-wide relying-party label, displayed on the Keycloak wallet-login page. It is not an additional wallet challenge-response field.
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

- **Signup failure window:** Signup creates the exact enabled account after proof verification but before pending-transaction consumption. If consumption loses, the losing request publishes no accepted receipt or callback; a concurrent winner may still succeed. If accepted-receipt publication fails after consumption, the transaction has no callback. In either failure case, the account may remain provisioned; automatic removal is intentionally not attempted because it could delete a concurrent winner's account. Provisioning/consume compensation and idempotent recovery remain an acceptance gap; single-node success does not qualify the race.
