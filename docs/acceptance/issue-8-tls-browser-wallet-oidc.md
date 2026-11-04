# Issue #8 TLS/browser/native-wallet/OIDC qualification

**Record version:** 1
**Issue status:** open
**Live E2E qualification:** `not_run`
**Scope:** disposable interactive wallet login; this record does not qualify Issue #1, production readiness, or multi-node behavior.

## Dependency reconciliation

The original Issue #8 blocker text is stale. Keycloak #4 is closed. Wallet #64 is closed, and [Wallet PR #65](https://github.com/jetpen/decent-wallet/pull/65) merged at `a385ac60aa89f251b7f997f514e75e21d8eab68f`; this satisfies the one-use proof-signer prerequisite. The signer change does not deliver UI, QR handoff, approval presentation, or a native HTTP client. Those remain part of Issue #8. Keycloak #9 is downstream final closeout, not a prerequisite to begin or qualify Issue #8.

## Criterion-to-evidence map

`offline_tested` and `harness_only` are implementation evidence, not live qualification. No row is `qualified` until it is exercised with the named real client boundary and recorded in sanitized evidence.

| Gate | Issue #8 criterion | Current evidence/status | Remaining proof |
|---|---|---|---|
| issue8-material-and-tls | Fresh disposable identity/account; trusted TLS with matching hostname/SAN and normal Chromium/Android trust; correct proxy/public origin | `not_run`. The existing live harness uses loopback HTTP with forwarded-header simulation; it has no TLS certificate/trust profile. | Run disposable setup behind trusted matching-SAN TLS; verify Chromium and Android reject untrusted/mismatched certificates and accept the configured test origin. |
| issue8-browser-and-consent | Start in Chromium, preserve its Keycloak session, hand off an opaque transaction URL, show origin and identity/intent context, require explicit user approval | `not_run`. Existing Python `urllib`/cookie-jar actors do not exercise a browser engine, handoff UI, or a human approval surface. | Use Chromium for initiation and the actual wallet UI for contextual, explicit approval; prove the initiating browser cookie/session is retained. |
| issue8-signer-and-native-transport | Use the narrow one-use signer and exact bytes; wallet separately GETs the challenge and POSTs the exact proof using a native HTTP client | `not_run`. The merged wallet signer is a prerequisite API, not a UI/network client; the current Keycloak harness signs with its OpenSSL test key and uses a separate Python actor. | Integrate a real Android wallet client using the merged API; capture sanitized GET/POST outcomes and prove no secret export or generic message-signing fallback. |
| issue8-browser-callback-and-pkce | Resume callback in the initiating browser; complete Authorization Code + PKCE with the original verifier | `harness_only`. The loopback Python harness covers scripted callback/PKCE behavior, not Chromium cookie/session behavior or wallet-to-browser handoff. | Run the full callback in the original Chromium context after actual native-wallet approval and proof submission. |
| issue8-oidc-validation | Validate ID-token issuer, audience, expiry, nonce, and JWKS signature with a maintained OIDC library | `offline_tested`. `scripts/wallet_login_live_e2e.py` now uses Authlib `CodeIDToken` claim validation and `joserfc` RS256/JWKS verification. `scripts/test_issue8_oidc.py` uses synthetic RSA tokens and a fake JWKS endpoint to cover valid claims and rejection cases. | Repeat as part of the real Code+PKCE browser/wallet ceremony against the disposable Keycloak issuer. Synthetic keys and a fake JWKS response are not issuer qualification. |
| issue8-negative-matrix | Cancel, timeout, expiry, wrong origin, invalid/stale/replayed proof, and TLS-trust failure must fail closed without session, code, or callback disclosure | `harness_only` / `not_run` for native cases. Existing loopback regressions cover some provider/proof failures; no real wallet cancel/timeout, TLS trust, browser callback, or native-client matrix was run. | Execute every required negative case through Chromium plus the native wallet; verify no authenticated browser session, OIDC code, or callback leak. |
| issue8-sanitized-versioned-evidence | Record browser/device/image/harness versions and sanitized outcomes | `partial`. This versioned ledger records scope and gaps; it is not a live qualification receipt. No Issue #8 real-client receipt exists. | Produce and read back a sanitized receipt bound to the exact source, image, harness, Chromium, Android image/device, and case outcomes; ensure no proof, private key, transaction URL, code, or raw callback is persisted. |

## Implementation and verification record

The offline OIDC-validation slice is intentionally narrower than the full issue. Its pinned runtime is in [`requirements/issue8-oidc.lock`](../../requirements/issue8-oidc.lock). The live harness now:

- pins `RS256` and requires exactly one matching RSA signing key from the realm JWKS;
- verifies the JWT signature through `joserfc` using the JWKS key set; and
- validates expected `iss`, `aud`, `nonce`, and registered ID-token claims using Authlib `CodeIDToken`.

PR worktree SHA-256 provenance: `scripts/wallet_login_live_e2e.py` = `c0a3026649e76d815b68b080b5e4f13e8f47943092963067d3284ada2c651600`; `scripts/test_issue8_oidc.py` = `259ab493230052798787c9633e98be32c0118a56684cd5f1b83b81b467dab46b`; `requirements/issue8-oidc.lock` = `b5c166b7f9667713ff750c7868d11fa4f2063382222dc9ef6eba510766fdbb9b`. These hashes match the corresponding PR files at `9f727e3ebfe5bd05f089180f801e614eefdff3e3`. They identify the offline verifier/test/dependency inputs; the separate lifecycle receipt below was generated at `0ff9c05e0e9fee13d8df078b52c325b1d9bb63b2` and does not qualify these PR files.

The focused synthetic-token tests do not exercise TLS, Chromium, Android, the wallet signer, the actual Keycloak JWKS, or a real OIDC ceremony. Canonical offline lifecycle receipts under `target/lifecycle/evidence/` are separate build/test evidence and do not qualify Issue #8's real-client gates; a timed-out/incomplete lifecycle attempt is not a pass.

## Final offline lifecycle evidence

One prior offline run is recorded in the locally generated, uncommitted `target/lifecycle/evidence/948a4a2e2bf3472f8d0ef8fea2820fd8.json` receipt (schema version 1, exit code 0). Its receipt marks the lifecycle steps passed, including Maven/Surefire, Python acceptance tests, Python compilation, pinned resolver-source and binary-dependency verification, provider registration, Keycloak 26.8.0 image build/smoke, `git diff --check`, receipt persistence, and teardown. It records source revision `0ff9c05e0e9fee13d8df078b52c325b1d9bb63b2`, image-source SHA-256 `139f64fb308f9b62f4cd5ba5ae5c8a1ec5919ab153f5eca4abd204275f3af96a`, artifact SHA-256 `81a22230404c0ca4920a41ed33f7cff51333c737c4bd447645974678d6ab7ba2`, and immutable image ID `sha256:08f99295bf6a2fdc12dca6b25f19b25dd4a0edb420aceb9de109f96587312d98`. Cleanup reports 3,502 baseline images, 60 candidates, 2 run-owned images removed, 12 unowned new images, and zero inconclusive candidates; it does not establish that the image inventory returned exactly to baseline. The receipt is local-only and is not included in this PR. This historical offline evidence does not qualify the current PR or upgrade any real TLS/browser/native-wallet gate to qualified.

## Environment and next gate

The checked environment has Chromium `155.0.8059.84`, Android SDK/emulator tooling, configured AVDs, and Android system images; `adb devices -l` returned no attached devices. No browser or emulator was launched for Issue #8. The immediate integration gap is a real wallet UI/native HTTP path; the Keycloak repository does not contain that wallet application. Keep Issue #8 open until the complete positive and negative real-client matrix and its sanitized receipt are verified.
