# decent-keycloak wallet-login provider (experimental)

This repository owns the Keycloak-specific adapter for the approved, provider-neutral `decent-wallet-login-v1` contract. The ecosystem protocol and vectors live in [`decent-ecosystem`](https://github.com/jetpen/decent-ecosystem/issues/46). This work is separate from Storage's RFC 7523 wallet-grant adapter.

**Status: implementation is experimental and not fully acceptance-qualified.** The provider must not be presented as production-ready. A pinned runtime and immutable-image loopback probe exist, but local package and loopback evidence do not establish real TLS, browser-engine/native-wallet interoperability, distributed replay, or production Registry behavior.

**Local Registry network exposure:** the disposable harness uses Podman host networking and binds the Registry node to `127.0.0.1`, not all host interfaces. A regression checks the generated config. This confines the listener to local use; it does not qualify Registry availability or reliability.

## PR #12 check failure and remediation

The checks failed against the synthetic merge revision `0f355a8e0e6d108a117ecce45f077d26d08071f3` (PR head `cbdaf4c94b8c2292396c4d619db77376efabd2bb`). Maven passed, but the Python step ran 146 tests and reported three assertion failures plus one error: ledger assertions were stale against the merge README. The failure-specific probe also assumed the Hermes scratch directory exists on the runner. The README's second documented test command repeated `scripts.test_acceptance_workflow`; the new regression check catches duplicate module entries and requires the documented commands and CI list to match.

The first remediation run on commit `04637ce45962e1903aad17ce153c1159ec13faba` fixed these Python/doc discrepancies and passed Maven 163/12, Python 146, compilation, pinned resolver-source verification, diff validation, and provider registration. The image step then failed because Buildx looked for `./Dockerfile`, while this repository's Dockerfile is `container/Dockerfile`. The workflow now selects that path explicitly and has a regression test. The next GitHub Actions run is needed to confirm this fix. The implementation remains experimental: provider qualification, independent aggregate security review, and support-policy approval are separate open gates.

The exact experimental build boundary and upgrade gates are in [`docs/support-policy.md`](docs/support-policy.md); the scoped security review, test evidence and open qualifications are in [`docs/security-review.md`](docs/security-review.md). CI is defined in [`.github/workflows/acceptance.yml`](.github/workflows/acceptance.yml); it runs on pushes, pull requests and manual dispatch without path filters, pins all actions to immutable commit SHAs, grants only `contents: read`, and does not use credentials or publish artifacts. It gates Maven/Surefire, the complete Python harness and compilation, resolver/vector provenance, diff whitespace, provider registration and a no-cache amd64 provider-image build/runtime-version check. GitHub branch protection is separate: an administrator must mark the job's verified status context required.

The declared target is Keycloak **26.8.0**, Temurin build JDK **21.0.12.1+1**, Red Hat OpenJDK runtime **21.0.12.1+1-LTS** from the pinned Keycloak image, the exact digest-pinned Keycloak and UBI 9/Python 3.11.13 bases listed in the policy, and Linux/amd64. The candidate GitHub workflow has not yet run on this branch, and an independent aggregate review after #5/#6 changes is still required. These docs, local tests or a passing image build do not qualify Registry rotation, two-node replay, real TLS/browser/wallet behavior, upgrades or production deployment.

## Previous bounded loopback (before configured/ephemeral comparison)

Image ID `96c7012db2c2353097816f0b121969a9da7338bc9118325c5da60179629a3a17`; digest `sha256:f515944fb09df1e575baaffb7d0a7ae3cc9cc2b05866160facd1db19243a71f0`; harness SHA `75cf8018805abcbef297763613397106dbb8b357172f6f283b79565c979a2daf`. Login/PKCE, browser security/throttle, invalid-proof throttling, account denial and signup paths passed. It reached rotation sequence-2 publication/readback, then stopped after three fresh resolver reads were unavailable. The newer six-read configured/ephemeral comparison is documented below.

**Historical stale-source rotation run.** Image `sha256:e75dc697fd6d4c4b306b49f13ad2761fb404fce3df6b76e72761073fc1bf9504`; harness SHA `96976b506a6a97200a25d209e170c875be348a47254e86b70008a3266bbda626`. This older image reached stale-key 401/pending, current-key 202/accepted and exact local mapping, but predates the current source/harness changes. Its three later fresh reads were unavailable and its missing-ID CLI `not_found` disagreed with provider 503; do not use it to infer current-source behavior, provider absence, or Registry cause.


# Verification layers and remaining gates

Reviewed integration merge `48121bec3ac2708b97c4c39240cd85aadf0117e2`

This offline acceptance ledger records implementation/build evidence separately from external qualification. **Issue #1 remains open** until the full issue's acceptance criteria pass.

| Slice | Status | Verified so far | Still open |
|---|---|---|---|
| Keycloak #4 self-contained resolver runtime | Base implementation was already merged before #9; Issue #4 remains open | Maven 163/12 and Python 146 on the exact clean PR-merge reproduction; local lookup-path regressions pass. Supplemental owner-key rotation loopback evidence remains unqualified and is not an #4 acceptance gate. | Provider-level terminal `not_found` and network-isolated image build |
| Keycloak #5 repeatable current-Registry matrix | In progress in a separate worktree; #4 is integrated | No implementation/acceptance run | Exact current/miss/unavailable/history, repeated proofs and rotation |
| Keycloak #6 single-node transaction replay and callback | Current feature branch `feature/issue-6-single-node-live`; last local integrated evidence is incomplete | Single-node profile against Keycloak 26.8.0/dev-file: proof 202; initial status accepted; identical retry 202; changed retry 409; one-use callback; replay no code; status 404; Code+PKCE 200 | Expiry and post-consume store-failure/recovery gates remain unqualified |
| Keycloak #7 signup provisioning and recovery (single-node only) | Open; no longer blocked on #6 topology | Local UserProvider/handler tests; fresh signup recovery remains offline-only evidence | Run the bounded single-node signup recovery profile; do not claim distributed races |
| Keycloak #8 TLS/browser/native wallet + Code/PKCE | Pending #4 and Wallet #64; #9 is downstream closeout | Loopback simulation only | Trusted TLS, real browser/wallet and OIDC client |
| Keycloak #9 security/support policy/docs/CI | Implemented; remote rerun pending | Commit `04637ce45962e1903aad17ce153c1159ec13faba` passed Maven 163/12, Python 146, compilation, resolver verification, diff validation and provider registration. Its image build failed because Buildx looked for a root `Dockerfile`; workflow now selects `container/Dockerfile`. | Independent aggregate security review and support-policy approval |
| Wallet #64 proof signer | Separate issue/worktree | Prior Android JVM/vector tests; not merged | Delivery/review and real wallet client integration |
| WordPress #6 relying party | Blocked on human decisions #2–#5 | Not implemented | Returning `(iss,sub)` mapping and signup-only Registry policy |

Issue #1 stays open. Component work, unit tests, and loopback simulation do not close its broader acceptance criteria. WordPress HITL decisions must be resolved by the user before implementation. Dependency #4 is merged in the integration baseline; #5 and #6 are progressing separately and their eventual diffs still require an independent aggregate security review before any final #9 security qualification.

**Most recent #4 loopback evidence (before the #9 logging hardening; exact image/harness pair).** Image ID `f259700b220c2eb2f3c6d1b75055a0309901e16823affff1463a282edf59adc9`; digest `sha256:480807ab7ab77d5a169dbcea064ba4a096fcddebb324e0f44caa2e5e603547ae`; harness SHA `23cc8f48d850fee2be0451341d0ed076cd9b4532a5e0e62eef172601613861cd`. Login/PKCE, browser security/preflight, invalid-proof throttling, unmapped/disabled-account denials and signup/PKCE passed. Rotation publication/readback reached sequence 2. All six fresh lookups (three configured-port, three ephemeral-port) failed to confirm the exact successor key; the harness stopped before stale/current-key proofs. Configured-port samples had Registry-miss, dial-warning, peer-handshake and `other` categories; ephemeral samples had Registry-miss, dial-warning and `other`, with JSON-shaped lines in some samples. The harness classified every sample unavailable; exact retained output does not identify why. Root cause remains unknown. A new local regression test identified that the harness previously treated the first standalone `}` as the JSON end; it now uses a balanced-object scan, and sanitized samples separately report JSON validity and exact successor match. These fixes do not establish the live samples had nested JSON or that this was their cause. This is loopback-only evidence, not Registry reliability, real TLS/browser-wallet, or shared-store qualification.
| Type | Status |
|---|---|
```bash
python3 -m unittest \
  scripts.test_acceptance_workflow \
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

**Local checks on the exact clean PR-merge reproduction:** Java 21 Maven 163 tests / 12 suites; Python acceptance 146 tests (141 non-ledger, 11 ledger, 2 workflow guard tests; one imported module discovers zero). Resolver-input verification, Python compilation, actionlint, and diff checks passed locally.

```bash
MAVEN_OPTS='-Xmx2g' mvn -q -o clean package
python3.11 -m unittest \
  scripts.test_acceptance_workflow \
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

`python3.11 -m unittest scripts.test_acceptance_workflow scripts.test_wallet_login_result scripts.test_wallet_login_transport_e2e scripts.test_owner_rotation_probe scripts.test_signup_intent_probe scripts.test_self_contained_resolver_runtime scripts.test_owner_rotation_envelope scripts.test_live_gate_order scripts.test_acceptance_ledger -q` ran 146 tests: 141 non-ledger, 11 ledger, 2 workflow guards; one imported module discovers zero. The exact clean merge checkout Maven build passed 163/12 with zero failures/errors/skips. Python compilation, resolver-source verification, actionlint, and diff checks passed locally.

# Loopback evidence

| Revision | Observed result | Qualification limit |
|---|---|---|
| Earlier #4 run: image ID `f259700b220c2eb2f3c6d1b75055a0309901e16823affff1463a282edf59adc9`; digest `sha256:480807ab7ab77d5a169dbcea064ba4a096fcddebb324e0f44caa2e5e603547ae`; harness SHA `23cc8f48d850fee2be0451341d0ed076cd9b4532a5e0e62eef172601613861cd` | Login/PKCE, security/throttle, account denial and signup passed; rotation publication/readback reached sequence 2; six fresh reads unavailable. | Proof stage stopped; root cause unknown. |
| Latest #4 run from the current worktree based on `d700281409a876b74ee025f6d27ff50b40b0fca5`: image ID `92cc5d4c06fd4a65dd1e2fbbb5472f70fd901201536b88019706bff48c14ce13`; digest `sha256:b4120b6aa22de7bf036250a9f66b701245e6f4fd8082cbeaf71f96d832cfd58b`; harness SHA `e220a7920c211b5d995a0b389b4665107565bf8c40da0b43d8cc4c9d2afd8d61` | Login/PKCE/replay, preflight/security, throttle, account denial, and signup/PKCE passed; this exercises the positive `resolved` path. Rotation publication/readback reached sequence 2. All six fresh successor reads (three configured-port, three ephemeral) were unavailable with balanced JSON, exact identity/key match false and unexpected diagnostics; two configured-port samples had peer-handshake diagnostics. | Harness exited 1 at the successor-read gate; no stale/current-key proofs or provider `not_found` case ran. This resolver-tool readback does not qualify the provider missing-Identity path; the diagnostic categories do not establish root cause. |
| Prior #4 run (image predates d700): image ID `ad9834f964d24aa9a0c8320ed095af4514760d9d2ce10eeaca52a20c6ff31fb9`; digest `sha256:29fe182466744bf7d9286fde27331cce784041170898eed430bfb8490ae8f602`; harness SHA `d20dcce5730112cbdadd757c867348812decd4d0316c063dbd9ff43e035` | Signup/PKCE and rotation publication/readback to sequence 2 passed; all six fresh successor reads failed exact Identity/key matching. | No stale/current-key proofs ran. The bounded receipt separates JSON balance from exact identity/key match but does not establish cause. |

**Separate #5 matrix attempt (not the #4 loopback run).** It used the same image ID/digest but harness SHA `3743c2b44e2f40f9f4ad3179d1d9a9767b0797661ce6dd9d6fc8729d1a13a7a6`. Two current-Identity attempts had exact independent readback and accepted proof. The first missing-Identity attempt had exact CLI `not_found` but Keycloak returned 503; status remained pending with no receipt or callback (`provider_registry_inconsistent`). The second missing-Identity attempt stopped at owner-key generation; the cause is unknown. A per-attempt key-filename fix was added afterward and was not live-verified. This partial #5 evidence does not qualify provider `not_found` or the complete Registry matrix.

**Resolver build-input provenance.** `container/resolver-runtime.lock.json` SHA-256 is `a9380af7777df65be522f0dda83ebef4a9aadd57a991694d58ec7adb4db3e699`. It pins Identity commit `2caec24de52c2dbe241e72fe317281c051d03f89` (archive SHA-256 `0d86022748ee9c8d197718a833d819037e5a32bbe2aff7e3a545083c44dd78e2`) and Registry commit `0fa9a6b631bd77725418e990ae9ea4d974dc546c` (archive SHA-256 `bf3e912ad18a9bf33f2d7aaebbc0ce43d34708e9d449e8daf81793a70917e098`), with dependency lock SHA-256 `6ff0d4c41ae5aa8834bbc9a88bfa30cb8386aae6ebb9b13467b55a6d996098ff` and Registry constraints SHA-256 `70387e4aedbe5e9561243a8195d14d90dd6e68d74672c26678f2de938dec5539`. The lock targets Python 3.11.13 and the pinned UBI 9 builder. The latest no-cache image was built from the current #4 worktree based on `d700281409a876b74ee025f6d27ff50b40b0fca5`; immutable image ID/digest and harness SHA are in the latest loopback row. The provider JAR inside that image has SHA-256 `4a2d1364180350fffc671a7f61812ecbea5e68f04c90df95f95c0b669d4fbbcd`; the current Maven target JAR SHA-256 is `c0f84827366911b7714f8590c2055c956fdd47d87cbcb01462f88ee8f5ac05c5`. Whole-archive hashes differ, but all 46 ZIP entry names and uncompressed contents match. The no-cache Docker build downloaded hash-locked dependency artifacts, so it was not network-isolated (`--network=none` was not used). Offline archive/lock verification and source/build tests passed; a network-isolated image build remains unshown.




| Unqualified | Registry matrix/reliability; stale/current rotation proofs; real TLS/browser/native-wallet; multi-node shared-store replay; signup races/recovery; relying-party acceptance. |

## Remaining Issue #1 gates

| Slice | Status | Verified so far | Still open |
|---|---|---|---|
| Keycloak #4 self-contained resolver runtime | Base implementation was already merged before #9; Issue #4 remains open | Maven 163/12 and Python 146 on the exact clean PR-merge reproduction; local lookup-path regressions pass. Supplemental owner-key rotation loopback evidence remains unqualified and is not an #4 acceptance gate. | Provider-level terminal `not_found` and network-isolated image build |
| Keycloak #5 repeatable current-Registry matrix | In progress in a separate worktree; #4 is integrated | No implementation/acceptance run | Exact current/miss/unavailable/history, repeated proofs and rotation |
| Keycloak #6 single-node transaction replay and callback | Current feature branch `feature/issue-6-single-node-live`; last local integrated evidence is incomplete | Single-node profile against Keycloak 26.8.0/dev-file: proof 202; initial status accepted; identical retry 202; changed retry 409; one-use callback; replay no code; status 404; Code+PKCE 200 | Expiry and post-consume store-failure/recovery gates remain unqualified |
| Keycloak #7 signup provisioning and recovery (single-node only) | Open; no longer blocked on #6 topology | Local UserProvider/handler tests; fresh signup recovery remains offline-only evidence | Run the bounded single-node signup recovery profile; do not claim distributed races |
| Keycloak #8 TLS/browser/native wallet + Code/PKCE | Pending #4 and Wallet #64; #9 is downstream closeout | Loopback simulation only | Trusted TLS, real browser/wallet and OIDC client |
| Keycloak #9 security/support policy/docs/CI | Implemented; remote rerun pending | Commit `04637ce45962e1903aad17ce153c1159ec13faba` passed Maven 163/12, Python 146, compilation, resolver verification, diff validation and provider registration. Its image build failed because Buildx looked for a root `Dockerfile`; workflow now selects `container/Dockerfile`. | Independent aggregate security review and support-policy approval |
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

A missing setting does not enable fallback authentication: missing Registry configuration returns unavailable (503), not absence (401). If only one Registry attribute is set, provider creation fails closed. A terminal exact Registry miss is accepted only for exit code 1, terminal `not found`, and a Registry object-key miss matching SHA-256 of the requested raw UTF-8 identity; a Registry miss accompanied by a dial warning is unavailable. Handshake, unknown, mixed-key, or otherwise inconclusive output is unavailable. The disposable integration probe provisions its own realm and teardown.

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
