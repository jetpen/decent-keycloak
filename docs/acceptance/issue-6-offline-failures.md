# Issue #6 — Offline publication-failure boundaries

These tests characterize the single-node transaction-store publication boundary using a deterministic `SingleUseObjectProvider` test double. They are offline unit/handler tests, not evidence from the real Keycloak 26.8 provider.

Run the focused Java tests with:

```bash
MAVEN_SKIP_RC=1 TMPDIR=/home/ben/.hermes/cache/scratch mise exec java@21.0.2 -- \
  mvn -o -Dtest=WalletLoginTransactionStoreTest,WalletLoginTransportHandlerTest test
```

Coverage includes callback-gate and accepted-receipt failures after pending-transaction consumption; publication exceptions before and after provider mutation; duplicate acceptance and receipt-key collisions; and failure to remove an owned callback gate after a receipt collision. The handler regressions assert unavailable responses and that accepted state/callback redemption is not exposed. Store regressions check that consumed pending state is not restored and pre-existing receipt/gate state is preserved on definite collisions.

The implementation distinguishes a definite `putIfAbsent(false)` collision from an ambiguous exception. On a definite collision, it preserves the existing record and cleans up only a callback gate confirmed as owned by this attempt. If that compensation fails, the process-local acceptance guard remains failed until expiry so the receipt cannot be redeemed with an uncertain callback gate. On an exception from `putIfAbsent`, ownership was not confirmed: the handle is quarantined rather than deleting a key that could belong to another writer. After confirmed inserts, later publication failures best-effort remove only records owned by this attempt; uncertain provider cleanup is not proof of durable removal.

The deterministic test double does not qualify real Keycloak provider semantics, process-crash/restart behavior, multi-node races, live expiry, selected-provider provenance, or live post-consume recovery. Multi-node and HA claims remain excluded. Issue #6 remains open pending separately authorized, sanitized single-node runtime evidence for the outstanding acceptance gates.
