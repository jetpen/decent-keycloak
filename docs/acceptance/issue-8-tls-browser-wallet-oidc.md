# Keycloak #8: Implement and offline-verify Keycloak wallet login

**Issue status:** open
**Scope:** provider implementation and deterministic offline/loopback verification only.
**Live TLS/browser/native-wallet/OIDC qualification:** out of scope here; tracked by [Keycloak #66](https://github.com/jetpen/decent-keycloak/issues/66).

Keycloak #8 is the narrow offline slice aligned with the closed, narrowed [Wallet #66 foundation](https://github.com/jetpen/decent-wallet/issues/66). It does not close broader Keycloak #1, claim production readiness, or qualify a real issuer, client, device, browser, or relying party. The remaining live-client work is deferred across [Keycloak #66](https://github.com/jetpen/decent-keycloak/issues/66) and [Wallet #80](https://github.com/jetpen/decent-wallet/issues/80). Keycloak #66 owns residual live TLS/browser/native-wallet/OIDC qualification; Wallet #80 retains wallet-owned readiness and evidence.

## Acceptance criteria

| Status | Criterion | Evidence boundary |
|---|---|---|
| [x] | The Keycloak adapter implements the unchanged `decent-wallet-login-v1` challenge/proof contract and standard OIDC Authorization Code + PKCE flow. | Provider and offline/loopback tests cover the in-scope transaction, proof, and callback behavior; these do not establish real wallet, Chromium, public TLS, or RP behavior. |
| [x] | Offline ID-token validation uses Authlib `CodeIDToken` claim validation and `joserfc` RS256/JWKS signature verification for issuer, audience, expiry, and nonce; synthetic signed-token tests cover valid input and rejection cases. | `scripts/test_issue8_oidc.py`; synthetic keys/tokens and a fake JWKS endpoint only, not a live issuer. |
| [x] | The canonical offline lifecycle installs `requirements/issue8-oidc.lock` with `--require-hashes` into an isolated suite environment and puts that target first on suite `PYTHONPATH`. | `scripts/lifecycle.py` and `scripts/test_lifecycle.py`; the canonical offline lifecycle must pass on the final candidate. |
| [x] | This acceptance record limits #8 to offline/loopback evidence, cross-links Keycloak #66 and Wallet #80 for residual real-client qualification, and does not promote live gates from APK configuration or synthetic tests. | This record and `scripts/test_acceptance_ledger.py`; the final candidate's regression and canonical lifecycle checks must pass. |

## Ownership and deferred scope

- **Keycloak #8:** the existing provider, its offline/loopback wallet-login and OIDC callback tests, synthetic OIDC verification, and a deterministic dependency-locked offline lifecycle.
- **Keycloak #66:** Keycloak-owned live provider/OIDC, trusted public-origin/proxy, browser/session, TLS, and sanitized cross-component evidence. It is the child issue under #8 for residual live qualification and remains open after #8 closes.
- **Wallet #80:** wallet-owned qualification app, import/unlock, App Links, native transport and TLS behavior, consent, diagnostics/privacy audit, and wallet evidence. Wallet #80 blocks on Keycloak #66 for Keycloak-owned evidence; it does not block this offline slice.
- **Ecosystem #51 and relying parties:** adopted protocol consumer conformance, runtime evidence, and independent security/privacy review remain separately owned and are not claimed here.

No emulator, service exposure, Funnel, or live provider/RP run is authorized by Keycloak #8 or by merging its offline-scope PR. Such work requires its own prerequisites and explicit authorization.

## Offline implementation and verification notes

The offline verifier's pinned dependency closure is [`requirements/issue8-oidc.lock`](../../requirements/issue8-oidc.lock). The harness pins RS256, requires exactly one matching RSA signing key from the supplied JWKS, verifies the signature through `joserfc`, and validates the expected issuer, audience, nonce, and registered ID-token claims with Authlib `CodeIDToken`.

The APK's configuration/metadata is not Android runtime evidence. Synthetic-token tests and the loopback harness do not exercise TLS, Chromium, Android runtime, the native wallet, a real Keycloak JWKS, a real issuer, or a relying party. No live gate is promoted from APK configuration, synthetic tests, or offline receipts.

Canonical offline lifecycle receipts are retained locally under ignored `target/lifecycle/evidence/`; they are not included in the PR. Earlier receipts are not commit-bound to this candidate and do not transfer to a later candidate. The final candidate's receipt must be read back with its source revision, per-step outcomes, and teardown status, and its offline result must not be presented as live qualification.

## PR and closure boundary

The provider and offline OIDC implementation/tests were added in merged [PR #58](https://github.com/jetpen/decent-keycloak/pull/58). This issue remains open until the two remaining criteria above are included in a reviewed PR, local and canonical checks pass on the exact candidate, and that PR merges. After merge, close #8 against its narrowed offline scope; keep Keycloak #66, Wallet #80, Ecosystem #51, and Keycloak #1 open for their independent gates.
