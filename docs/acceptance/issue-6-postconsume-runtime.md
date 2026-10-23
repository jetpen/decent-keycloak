# Issue #6 — post-consume runtime fault-injection profile

## Status and scope

This is an opt-in, one-node runtime profile for the post-consume accepted-receipt failure boundary. It is deliberately test-image-only. The test-scope `SingleUseObjectProviderFactory` delegates to Keycloak's `infinispan` provider, commits the accepted-receipt `replace`, then throws once. It does not alter the production provider JAR or the production Docker target.

The profile checks that the proof request fails closed with an empty HTTP 503 and no redirect, the identical proof retry and initiating-browser status poll return empty 404 responses, and neither callback nor authorization code is exposed. It requires exactly one request-correlated production-handler failure marker and one fixed test-decorator commit-then-throw marker. It then uses the same browser session to start a distinct transaction and complete callback, callback-replay denial, and Code+PKCE recovery.

This is not evidence about an unmodified Keycloak/Infinispan provider committing and throwing. It is also not multi-node or distributed evidence, and it does not close Issue #6. The isolated test image was built and its `kc.sh show-config` output inspected; the selected SPI provider value is masked in that output. No Keycloak server or live browser/profile was started for this change. Running the live profile remains a separate action requiring fresh explicit authorization; adding the command below is not authorization.

## Offline checks

Run with Java 21:

```bash
mvn -q -o -Dtest=Issue6PostConsumeReceiptFailureProviderFactoryTest test
python3.11 -m unittest scripts.test_wallet_login_transport_e2e -v
mvn -q -o -DskipTests test-compile
python3.11 scripts/build_issue6_postconsume_provider.py
```

The provider-builder packages only the test-compiled decorator class and its test-scope service registration. The production runtime image continues to select `infinispan`; the separate `issue6-postconsume-test-runtime` target selects the decorator at Keycloak build time.

## Optional image/profile commands (runtime profile not run)

The test-image target has been built and its build configuration inspected. To rebuild it and, after a separately authorized runtime attempt, select it explicitly:

```bash
mvn -q -o -DskipTests test-compile
python3.11 scripts/build_issue6_postconsume_provider.py
podman build --target issue6-postconsume-test-runtime \
  -f container/Dockerfile -t localhost/decent-keycloak-issue6-postconsume:test .
WALLET_IT_PROFILE=issue6-postconsume-receipt-failure \
WALLET_IT_TEST_IMAGE=localhost/decent-keycloak-issue6-postconsume:test \
python3.11 scripts/wallet_login_live_e2e.py
```

The profile refuses to run without `WALLET_IT_TEST_IMAGE`; it does not fall back to the regular runtime image. Successful output is projected through the existing bounded evidence sanitizer. It does not retain the transaction locator, proof, callback URL, authorization code, request handle, or raw logs.

## Qualification gaps

Current behavior evidence is offline unit/mocked-harness evidence. The isolated image target was built and build configuration was inspected, but no Keycloak server/profile was started. Production-provider post-consume failure behavior, live expiry, live changed-signature replay, and the remaining Issue #6 acceptance gates remain open. Do not treat this test decorator or its unit tests as production-provider qualification.
