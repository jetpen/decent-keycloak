# decent-keycloak wallet-challenge provider spike

This repository is the planned home of Keycloak-specific adapter code. The reusable wallet-auth protocol remains provider-neutral and ecosystem-owned; the existing Storage RFC 7523 grant adapter remains in `decent-simple-storage`.

## Wallet-login v1 proof-core progress

This branch adds strict parsing of the approved four-member wallet proof, RFC 8785 JCS UTF-8 signing input, JDK Ed25519 signature verification against a caller-supplied current key, and tests consuming the shared positive and negative ecosystem vectors. The authenticator remains fail-closed; challenge transport, current Registry/Identity resolution, transaction/replay persistence, account mapping, and OIDC login are not implemented here.

## Wallet-login v1 contract — approved; implementation tracked in ecosystem #46

The user has approved the provider-neutral wallet-login contract in `decent-ecosystem` issue [#46](https://github.com/jetpen/decent-ecosystem/issues/46). The approved relying-party rule is Registry lookup for explicit signup/account creation only; returning-account login validates Keycloak OIDC and maps `(iss, sub)` without Registry lookup. Keycloak itself resolves current Registry identity when it performs fresh wallet authentication.

**The protocol is approved; implementation is not complete.** Remaining end-to-end work and cross-component acceptance are tracked in ecosystem #46 and Keycloak #1. This repository remains a fail-closed Keycloak 26.8.0 SPI shell until those are implemented and verified.

## Current slice: proof-core verifier plus fail-closed SPI shell

This branch adds strict parsing of the approved four-member wallet proof, RFC 8785 JCS UTF-8 signing input, and JDK Ed25519 signature verification against a current public key supplied by the caller. Tests consume the ecosystem positive and negative fixtures vendored under `src/test/resources/wallet-login-v1/` and verify their hashes against the upstream manifest. It does not yet implement browser/wallet transport, challenge transaction state, current Registry/Identity resolution, replay persistence, user mapping/provisioning, or end-to-end OIDC login. The Authenticator remains fail-closed; do not enable it as an active production flow.

## Verify

```bash
JAVA_HOME=/path/to/java-21 PATH="$JAVA_HOME/bin:$PATH" mvn test package
podman build --pull=never -f container/Dockerfile -t localhost/decent-keycloak-wallet-authenticator-spike .
```

The vector fixtures are vendored byte-for-byte from ecosystem #46 under `src/test/resources/wallet-login-v1/`; tests verify their SHA-256 values against the upstream manifest. Update these fixtures only from a reviewed ecosystem vector revision. Image packaging is not proof of wallet login or end-to-end qualification. The deterministic signing seed in the shared vector is deliberately public test material; never use it as a wallet credential or include it in runtime configuration.


1. Implement the approved challenge contract from ecosystem #46 (JCS profile, HTTP transaction/status flow, origin/session binding, CSRF/web/native handling, expiry/idempotency/error behavior). Do not create a competing transcript in this adapter repo.
2. Wire proof verification to current exact-identifier Registry/Identity resolution, then implement the approved Keycloak transaction-state, challenge/QR transport, atomic replay consumption and local user mapping/provisioning behavior.
3. Build and package the pinned Keycloak 26.8.0 provider, then verify it is discovered and correctly configured in a disposable custom login flow.
4. Verify Keycloak’s per-transaction atomic single-use consumption on the production-supported shared backend with two-node race tests; do not claim cluster replay guarantees from an in-memory fake.
5. Exercise the full browser cross-device flow: signup and login intents, valid proof → normal OIDC Code + PKCE; invalid, malformed, expired, replayed, wrong-client/origin/session, Identity unavailable/ambiguous, and store failure → no session/code. Verify relying-party Registry behavior at signup and no Registry dependency on returning login.
6. Pin runtime/image/provider/source/dependency revisions. Report only the tested Keycloak version/cluster scope; no successor-release compatibility, production-readiness, or aggregate conformance claim until corresponding gates pass.
