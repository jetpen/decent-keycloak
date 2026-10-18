# decent-keycloak wallet-login provider (experimental)

This repository owns the Keycloak-specific adapter for the approved, provider-neutral `decent-wallet-login-v1` contract. The ecosystem protocol and vectors live in [`decent-ecosystem`](https://github.com/jetpen/decent-ecosystem/issues/46). This work is separate from Storage's RFC 7523 wallet-grant adapter.

**Status: implementation is experimental and not fully acceptance-qualified.** The provider must not be presented as production-ready. A pinned runtime and immutable-image loopback probe exist, but local package and loopback evidence do not establish real TLS, browser-engine/native-wallet interoperability, distributed replay, or production Registry behavior.

**Local Registry network exposure:** the disposable harness uses Podman host networking and binds the Registry node to `127.0.0.1`, not all host interfaces. A regression checks the generated config. This confines the listener to local use; it does not qualify Registry availability or reliability.

## Issue #9: support policy, security review and CI

The exact experimental build boundary and upgrade gates are in [`docs/support-policy.md`](docs/support-policy.md); the scoped security review, test evidence and open qualifications are in [`docs/security-review.md`](docs/security-review.md). CI is defined in [`.github/workflows/acceptance.yml`](.github/workflows/acceptance.yml); it runs on pushes, pull requests and manual dispatch without path filters, pins all actions to immutable commit SHAs, grants only `contents: read`, and does not use credentials or publish artifacts. It gates Maven/Surefire, the complete Python harness and compilation, resolver/vector provenance, diff whitespace, provider registration and a no-cache amd64 provider-image build/runtime-version check. GitHub branch protection is separate: an administrator must mark the job's verified status context required.

The declared target is Keycloak **26.8.0**, Temurin build JDK **21.0.12.1+1**, Red Hat OpenJDK runtime **21.0.12.1+1-LTS** from the pinned Keycloak image, the exact digest-pinned Keycloak and UBI 9/Python 3.11.13 bases listed in the policy, and Linux/amd64. The candidate GitHub workflow has not yet run on this branch, and an independent aggregate review after #5/#6 changes is still required. These docs, local tests or a passing image build do not qualify Registry rotation, two-node replay, real TLS/browser/wallet behavior, upgrades or production deployment.

## Previous bounded loopback (before configured/ephemeral comparison)

Image ID `96c7012db2c2353097816f0b121969a9da7338bc9118325c5da60179629a3a17`; digest `sha256:f515944fb09df1e575baaffb7d0a7ae3cc9cc2b05866160facd1db19243a71f0`; harness SHA `75cf8018805abcbef297763613397106dbb8b357172f6f283b79565c979a2daf`. Login/PKCE, browser security/throttle, invalid-proof throttling, account denial and signup paths passed. It reached rotation sequence-2 publication/readback, then stopped after three fresh resolver reads were unavailable. The newer six-read configured/ephemeral comparison is documented below.

**Historical stale-source rotation run.** Image `sha256:e75dc697fd6d4c4b306b49f13ad2761fb404fce3df6b76e72761073fc1bf9504`; harness SHA `96976b506a6a97200a25d209e170c875be348a47254e86b70008a3266bbda626`. This older image reached stale-key 401/pending, current-key 202/accepted and exact local mapping, but predates the current source/harness changes. Its three later fresh reads were unavailable and its missing-ID CLI `not_found` disagreed with provider 503; do not use it to infer current-source behavior, provider absence, or Registry cause.


# Verification layers and remaining gates

This offline acceptance ledger records implementation/build evidence separately from external qualification. **Issue #1 remains open** until the full issue's acceptance criteria pass.

| Slice | Status | Verified so far | Still open |
|---|---|---|---|
| Keycloak #4 self-contained resolver runtime | Merged in integration baseline `48121bec3ac2708b97c4c39240cd85aadf0117e2` | Baseline source verification: Maven 161/12; Python **133 non-ledger tests plus 10 acceptance-ledger tests (143 total across eight imported modules; one module discovers zero tests)**. Leading-dash CLI argument and bundled executable default regressions pass; process-start, timeout, interruption, and output-overflow sanitized diagnostics; positive lookups reject unexpected diagnostics; pinned runtime inputs verified. Latest loopback passed login/PKCE/replay, preflight/security, throttle, account-policy denial, and signup/PKCE. Rotation publication/readback reached sequence 2; six fresh successor reads failed exact Identity/key matching, so stale/current-key proofs did not run. | Registry/provider matrix and stale/current-key rotation proof gate remain open. |
| Keycloak #5 repeatable current-Registry matrix | In progress in a separate worktree; #4 is integrated | No implementation/acceptance run | Exact current/miss/unavailable/history, repeated proofs and rotation |
| Keycloak #6 two-node shared-store replay | In progress in a separate worktree | Not run | Production-mode cluster membership; cross-node consume/status/callback one-winner |
| Keycloak #7 signup consume-race recovery | Blocked on #6 | Not qualified cross-node | Provisioning, consume loss, receipt/callback failure and fresh-signup recovery |
| Keycloak #8 TLS/browser/native wallet + Code/PKCE | Pending #4, Wallet #64 and #9 | Loopback simulation only | Trusted TLS, real browser/wallet and OIDC client |
| Keycloak #9 security/support policy/docs/CI | Implemented on this feature branch; merge and GitHub CI run pending | Support policy, source-review matrix, immutable-action CI and TDD logging fix; Java 21 Maven 162/12, Python 143, actionlint and no-cache provider image verified locally | Independent aggregate review after #5/#6, remote workflow run, and all live/cluster/real TLS/production gates |
| Wallet #64 proof signer | Separate issue/worktree | Prior Android JVM/vector tests; not merged | Delivery/review and real wallet client integration |
| WordPress #6 relying party | Blocked on human decisions #2–#5 | Not implemented | Returning `(iss,sub)` mapping and signup-only Registry policy |

Issue #1 stays open. Component work, unit tests, and loopback simulation do not close its broader acceptance criteria. WordPress HITL decisions must be resolved by the user before implementation. Dependency #4 is merged in the integration baseline; #5 and #6 are progressing separately and their eventual diffs still require an independent aggregate security review before any final #9 security qualification.

**Most recent #4 loopback evidence (before the #9 logging hardening; exact image/harness pair).** Image ID `f259700b220c2eb2f3c6d1b75055a0309901e16823affff1463a282edf59adc9`; digest `sha256:480807ab7ab77d5a169dbcea064ba4a096fcddebb324e0f44caa2e5e603547ae`; harness SHA `23cc8f48d850fee2be0451341d0ed076cd9b4532a5e0e62eef172601613861cd`. Login/PKCE, browser security/preflight, invalid-proof throttling, unmapped/disabled-account denials and signup/PKCE passed. Rotation publication/readback reached sequence 2. All six fresh lookups (three configured-port, three ephemeral-port) failed to confirm the exact successor key; the harness stopped before stale/current-key proofs. Configured-port samples had Registry-miss, dial-warning, peer-handshake and `other` categories; ephemeral samples had Registry-miss, dial-warning and `other`, with JSON-shaped lines in some samples. The harness classified every sample unavailable; exact retained output does not identify why. Root cause remains unknown. A new local regression test identified that the harness previously treated the first standalone `}` as the JSON end; it now uses a balanced-object scan, and sanitized samples separately report JSON validity and exact successor match. These fixes do not establish the live samples had nested JSON or that this was their cause. This is loopback-only evidence, not Registry reliability, real TLS/browser-wallet, or shared-store qualification.
| Type | Status |
|---|---|
```bash
python3 -m unittest \
  scripts.test_wallet_login_result \
  scripts.test_wallet_login_transport_e2e \
  scripts.test_owner_rotation_probe \
  scripts.test_signup_intent_probe \
  scripts.test_self_contained_resolver_runtime \
  scripts.test_owner_rotation_envelope \
  scripts.test_live_gate_order \
  scripts.test_acceptance_ledger -q
python3 -m py_compile scripts/*.py container/*.py
python3 container/build_resolver_runtime.py
```

**Local checks (fresh issue #9 worktree run):** the last Maven run used Eclipse Temurin **21.0.12.1+1**; Python acceptance used CPython **3.11.13**.

```bash
MAVEN_OPTS='-Xmx2g' mvn -q -o clean package
python3.11 -m unittest \
  scripts.test_wallet_login_result \
  scripts.test_wallet_login_transport_e2e \
  scripts.test_owner_rotation_probe \
  scripts.test_signup_intent_probe \
  scripts.test_self_contained_resolver_runtime \
  scripts.test_owner_rotation_envelope \
  scripts.test_live_gate_order \
  scripts.test_acceptance_ledger -q
python3.11 -m py_compile scripts/*.py container/*.py
python3.11 container/build_resolver_runtime.py
python3.11 container/verify_resolver_runtime_inputs.py \
  --archives container/source-archives --manifest container/resolver-runtime.lock.json
git diff --check HEAD
```

Fresh issue #9 results: Maven **162 tests / 12 suites**, zero failures/errors/skips; Python **133 functional tests plus 10 acceptance-ledger tests (143 total across eight imported modules; one module discovers zero tests)**; Python compilation, pinned resolver lock/source-archive verification and actionlint **1.7.12** passed. A no-cache Podman runtime-image build passed with image ID `3fda3cb2a3c2accca0f4893a8c655c25b5f148f9bff4190b3ca843d572198d1a` and digest `sha256:6ea9e4770afba58f92d58f5621b6bbb7baca26ab1439eb5fa8a2278bb3b5fb5a`; it reported `Keycloak 26.8.0` and `Red Hat OpenJDK 21.0.12.1+1-LTS`, and the provider SPI registration was present. This is a local package/image build, not a live login or GitHub Actions result; it does not qualify the open Registry rotation, browser/TLS/wallet or two-node gates.

# Loopback evidence

| Revision | Observed result | Qualification limit |
|---|---|---|
| Prior run: image `sha256:480807ab7ab77d5a169dbcea064ba4a096fcddebb324e0f44caa2e5e603547ae`; harness SHA `b8917a5e13d59d55562406b5733a0a4dc7a6b467c69f59dbfd60dbc17d0c3d2a` | Login/security/throttle/account-denial/signup passed; rotation publication/readback reached sequence 2; six fresh reads unavailable. | Proof stage stopped; root cause unknown. |
| Latest: image `sha256:29fe182466744bf7d9286fde27331cce784041170898eed430bfb8490ae8f602`; harness SHA `d20dcce5730112cbdadd757c867348812decd4d0316c063dbd9ff43e035` | This harness runs signup before rotation. Signup/PKCE and rotation publication/readback to sequence 2 passed. All six fresh successor reads failed exact Identity/key matching. | No stale/current-key proofs. Receipt contains sanitized per-read JSON-balance/exact-match booleans and diagnostic categories; these do not identify the cause. |




| Unqualified | Registry matrix/reliability; stale/current rotation proofs; real TLS/browser/native-wallet; multi-node shared-store replay; signup races/recovery; relying-party acceptance. |

## Remaining Issue #1 gates

| Slice | Status | Verified so far | Still open |
|---|---|---|---|
| Keycloak #4 self-contained resolver runtime | Merged in integration baseline `48121bec3ac2708b97c4c39240cd85aadf0117e2` | Baseline source verification: Maven 161/12; Python **133 non-ledger tests plus 10 acceptance-ledger tests (143 total across eight imported modules; one module discovers zero tests)**. Leading-dash CLI argument and bundled executable default regressions pass; process-start, timeout, interruption, and output-overflow sanitized diagnostics; positive lookups reject unexpected diagnostics; pinned runtime inputs verified. Latest loopback passed login/PKCE/replay, preflight/security, throttle, account-policy denial, and signup/PKCE. Rotation publication/readback reached sequence 2; six fresh successor reads failed exact Identity/key matching, so stale/current-key proofs did not run. | Registry/provider matrix and stale/current-key rotation proof gate remain open. |
| Keycloak #5 repeatable current-Registry matrix | In progress in a separate worktree; #4 is integrated | No implementation/acceptance run | Exact current/miss/unavailable/history, repeated proofs and rotation |
| Keycloak #6 two-node shared-store replay | In progress in a separate worktree | Not run | Production-mode cluster membership; cross-node consume/status/callback one-winner |
| Keycloak #7 signup consume-race recovery | Blocked on #6 | Not qualified cross-node | Provisioning, consume loss, receipt/callback failure and fresh-signup recovery |
| Keycloak #8 TLS/browser/native wallet + Code/PKCE | Pending #4, Wallet #64 and #9 | Loopback simulation only | Trusted TLS, real browser/wallet and OIDC client |
| Keycloak #9 security/support policy/docs/CI | Implemented on this feature branch; merge and GitHub CI run pending | Support policy, source-review matrix, immutable-action CI and TDD logging fix; Java 21 Maven 162/12, Python 143, actionlint and no-cache provider image verified locally | Independent aggregate review after #5/#6, remote workflow run, and all live/cluster/real TLS/production gates |
| Wallet #64 proof signer | Separate issue/worktree | Prior Android JVM/vector tests; not merged | Delivery/review and real wallet client integration |
| WordPress #6 relying party | Blocked on human decisions #2–#5 | Not implemented | Returning `(iss,sub)` mapping and signup-only Registry policy |

Issue #1 remains open. Component work, unit tests, and loopback simulation do not close its broader acceptance criteria. WordPress HITL decisions must be resolved by the user before implementation. Dependency #4 is merged in the integration baseline; #5 and #6 are progressing separately and their eventual diffs still require an independent aggregate security review before any final #9 security qualification.

## Implemented flow shape

1. A required Keycloak authenticator requires Standard Flow and exactly one registered exact HTTPS redirect URI, then binds the current authentication session, realm, and trusted public HTTPS origin before issuing a transaction.
2. The Keycloak shared `SingleUseObjectProvider` stores five-minute pending state under a hash of the independent 256-bit opaque URL handle. The signed challenge is base64url-no-padding SHA-256 of a separate 32-byte random nonce; a separate transaction CSRF token is generated.
3. The QR contains an HTTPS transaction locator only. Wallet `GET` reads the no-store `{profile, challenge, csrf_token}` envelope. Wallet `POST` to the same URI submits the exact four-string proof (`profile`, `challenge`, `identity_id`, `signature`). The proof core uses RFC 8785 JCS UTF-8 signing bytes and Ed25519.
4. A fixed, bounded `decent-identity get` subprocess adapter resolves the exact raw identity ID/current owner public key. A shared two-second cooldown per initiating browser/client rejects near-simultaneous sibling lookups but does **not** serialize the resolver's full process lifetime or prevent another lookup after cooldown expiry. It expires rather than being owner-released. For signup, exactly one enabled local Keycloak user is provisioned after proof and before pending-transaction consumption; see the failure window below.
5. Atomic removal of pending state is the proof one-winner point. The accepted proof/status digest is retained until expiry; an identical proof retry reports accepted only, while changed bytes fail. A separate callback gate is published before accepted status and permits one Keycloak resume. The live single-node probe confirmed that a subsequent callback request does not repeat the original authorization code and that status stops advertising its callback after the gate is consumed. **Signup callback gate:** callback re-reads the exact enabled account and fails closed if missing; it does not provision or delete after pending proof consumption. Focused regressions cover the missing-map/gate behavior; post-consume mapping disappearance is not exercised live. A final Keycloak resume failure then requires a fresh login rather than replaying the one-use gate. The resolver gets a ten-second execution timeout and, after forcible termination is requested, a two-second forced-termination grace period. The shared admission key expires after two seconds, even if the resolver is still running; it is not an owner-released process-lifetime lock. If termination cannot be confirmed, promotion extends that key to five minutes and applies the browser/client lock. Because promotion follows timeout and termination grace, it may occur after the original admission key expired; promotion cannot cancel an already-admitted sibling lookup. This remains best-effort rather than a fencing guarantee. Storage failure never returns success/code.
6. Five per-transaction invalid-proof slots and a best-effort five-minute browser/client new-transaction lock are stored separately. They throttle abuse only; they do not revoke already-issued sibling transactions or replace atomic per-transaction replay prevention.

This outline describes implementation shape, not a claim that every step has passed acceptance. Atomic behavior of the supported shared Keycloak backend has not yet been qualified across nodes.

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
- `decent.wallet.registry.bootstrap` and `decent.wallet.registry.client-port` — required together to configure the bundled Identity resolver runtime built from repository-pinned Identity/Registry sources and dependencies.
- `decent.wallet.identity.executable` — defaults to `/opt/decent-resolver/bin/decent-identity` in the bundled runtime. A development override must be an absolute executable path.
- `decent.wallet.idp-origin` — optional exact HTTPS assertion; if set, it must match the normalized origin from trusted Keycloak hostname/proxy configuration. It cannot override that origin.

A missing setting does not enable fallback authentication; the flow fails closed. The disposable integration probe provisions its own realm and teardown.

## Account policy

Keycloak creates or loads exactly one local account with the exact raw `decent_identity_id` only after a fresh, valid wallet proof and before consuming the pending login transaction. Explicit `login` requires exactly one existing enabled match; explicit server-bound `signup` may provision a local account after proof. Concurrent provisioning is accepted only after a fresh exact-ID lookup finds one unique enabled winner; ambiguous mappings fail closed. Keycloak retains its opaque user ID as stable OIDC `sub` and releases `decent_identity_id` only as a signed ID-token claim for configured relying parties. The disposable single-node harness verifies the claim value after JWKS signature validation; relying-party Registry verification and returning-login `(iss, sub)` mapping are external consumer responsibilities and remain unqualified here.

Latest #4 artifact provenance: the build-input verifier parses `container/resolver-runtime.lock.json`; `container/build_resolver_runtime.py` verifies/materializes inputs, and `container/Dockerfile` builds the runtime. The tracked source archives and repo-extracted copies match the lockfile SHA-256 values. Older untracked source-tree dumps are not build inputs; only the archives and explicit lock/requirements files are consumed by the Docker build.

## Local checks

With Java 21 available:

```bash
mvn -q -o clean package
git diff --check
```

For the standalone local Registry rotation/readback probe, use the invocation documented above; it is a local integration check, not proof of production or network-wide Registry reliability.

After `mvn -q -o clean package`, build both the resolver inputs and the full provider/runtime image from this worktree without using cached layers:

```bash
podman build --no-cache --pull=never --target resolver-builder -f container/Dockerfile \
  -t localhost/decent-keycloak-wallet-authenticator-spike:issue4-resolver-check .
podman build --no-cache --pull=never --target runtime -f container/Dockerfile \
  -t localhost/decent-keycloak-wallet-authenticator-spike:issue4-current-check .
```

A successful Maven or image build is not live wallet-login qualification. Read Surefire XML totals from the current build and use the immutable image ID/digest in the live probe.

### Disposable local integration probe

`scripts/wallet_login_live_e2e.py` requires Podman, OpenSSL, and the pinned runtime image built from this repository. It does not mount sibling Identity or Registry source checkouts or developer Python environments.

After `mvn -q -o clean package`, build both the resolver target and full provider/runtime target from the edited worktree with cache disabled. Use the local image tag for Podman in this environment, verify its immutable ID/digest, and confirm the harness provenance reports that digest. It can also accept an immutable ID if Podman resolves that ID locally. Run the harness with the immutable image ID—not a moving source tag:

```bash
IMAGE_ID="$(podman image inspect --format '{{.Id}}' localhost/decent-keycloak-wallet-authenticator-spike:issue4-current-check)"
WALLET_IT_IMAGE="$IMAGE_ID" python3 scripts/wallet_login_live_e2e.py
```

The harness verifies the ID/digest through Podman before starting the disposable environment. This command is a loopback probe only; a passing result does not establish production Registry behavior, real TLS/browser-wallet interoperability, or shared-store replay.


```python
python scripts/rotation_registry_roundtrip.py --identifier ID --old-key OLD --new-key NEW \
  --host 127.0.0.1 --port PORT --bootstrap PEER --datastore DIR \
  --envelope ENVELOPE --readback READBACK
```

It constructs a finalized authorized rotation, publishes it, then performs repeated reads from fresh CLI clients and succeeds only when the new sequence and exact successor key are independently observed. The wallet-login harness runs this helper from the pinned resolver-tools image and keeps Registry results separate from Keycloak provider proof outcomes.

- **Signup failure window:** Signup creates the exact enabled account after proof verification but before pending-transaction consumption. If consumption loses, the losing request publishes no accepted receipt or callback; a concurrent winner may still succeed. If accepted-receipt publication fails after consumption, the transaction has no callback. The exact Identity user may remain provisioned after a consume/receipt failure; failed provisioning attempts do not delete accounts, even when the failure appears unambiguous; avoiding deletion prevents a race from removing a user another request may already observe. Search and occupancy lookup failures, including candidate-cap overflow, are unavailable and stop before account creation. A successful create with an empty/failed exact-ID read-back returns `503`, leaves the transaction pending, and does not delete the possibly visible user. Verified duplicate/disabled/mismatched mappings remain non-success; these safeguards have local UserProvider/handler unit coverage only, not live multi-node race evidence.
