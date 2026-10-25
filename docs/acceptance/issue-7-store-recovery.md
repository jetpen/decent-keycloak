# Issue #7 store recovery: scoped current-main candidate

Refs #7: https://github.com/jetpen/decent-keycloak/issues/7

**Disposition: scoped offline implementation candidate for human review; Issue #7 remains OPEN. This does not close the issue or qualify runtime behavior.**
No live/container/Registry invocation or image build was performed for this slice.
Real Keycloak HTTP, selected runtime SPI, wallet/browser and production-provider recovery
remain unqualified. Neither passing scripted HTTP tests nor an SPI JAR proves runtime qualification.
Multi-node integration and distributed provisioning/replay guarantees are out of scope.

## Preserved ordering and residual states

Current `main` already implements server-bound explicit signup intent, fresh signed proof and current Registry verification, exact enabled local-account create/readback, then pending consume. This slice adds scripted offline test coverage and evidence documentation only; it does not change production Java, provider code, the live harness flow, or #4/#5/#6 behavior. The existing profiles/coordinator and owned-resource lifecycle remain responsible for runtime setup, cooldown, checkpoints, and cleanup.

| Opt-in `WALLET_IT_PROFILE` | One-shot test wrapper operation | Recovery |
|---|---|---|
| `issue7-consume-loss-recovery` | Remove pending transaction through the delegate, then throw | Fresh explicit SIGNUP resolves the retained exact enabled account; two signup transactions |
| `issue7-accepted-receipt-write-recovery` | Replace accepted receipt through the delegate, then throw | Fresh LOGIN for the same retained subject; one signup plus one login |
| `issue7-accepted-receipt-write-false-recovery` | Reject accepted receipt replacement before delegation/commit | Fresh LOGIN for the same retained subject; one signup plus one login |

All three require the faulted proof to return empty 503, then browser status and old identical
proof retry to return empty 404. Each response must have no case-insensitive Location header
and no newly followed redirect. The account must remain one exact enabled local subject.
A per-request UTC log cursor bounds the log read. The helper requires exactly one fixture
fault marker plus the matching handle-hash production `consume-unavailable` or `not_accepted`
signal. Evidence contains allowlisted counts/booleans/statuses only, never raw logs, subjects,
locators, proofs, signatures or callback/code values.

The old gate is never restored and old proof is never replayed to recover. The ordinary fresh
login helper verifies a distinct transaction, proof/retry/status, callback state/code/replay,
PKCE exchange and signed retained subject. Consume-loss uses the existing explicit signup
callback/PKCE path and verifies the same subject. Recovery waits beyond main's two-second
identity-admission cooldown. Invalid failure evidence prevents recovery; invalid recovery
never emits a complete checkpoint. Failed-signup facts are checkpointed before recovery.

Account creation and gate/receipt publication are not a compound atomic transaction. A
retained account after failure is expected; do not delete it or a possibly concurrent winner.
Users start the indicated fresh ceremony; operators inspect exact enabled mappings without
resetting consumed gates. Empty/unavailable/over-cap readback profiles already on main remain
separate and unchanged. The offline Java suite now includes a local handler characterization of
two distinct signup transactions racing to create the same account, followed by a store-level
consume-loser interleaving after the other transaction publishes its accepted receipt and a
fresh-signup reuse (see `issue-7-safe-retry-boundary.md`). It does not qualify restart persistence,
actual Keycloak/JPA/provider winner or consume-loss behavior, real provider atomicity, or
distributed guarantees. Unsupported live loser/concurrent modes fail closed before external
setup; they are not aliases.

## Test-only artifact and invocation (not executed here)

First run Java 21 offline `mvn -o clean package`, then:

```bash
python3.11 scripts/build_issue7_fault_provider.py
podman build --no-cache --pull=never --network=none \
  --file container/Dockerfile --target issue7-store-recovery-test-runtime \
  --tag decent-keycloak:issue7-store-recovery .
IMAGE_ID=$(podman image inspect --format '{{.Id}}' decent-keycloak:issue7-store-recovery)
WALLET_IT_PROFILE=issue7-consume-loss-recovery \
  WALLET_IT_STORE_RECOVERY_IMAGE="$IMAGE_ID" \
  python3.11 scripts/wallet_login_live_e2e.py
```

Each profile requires an explicit `WALLET_IT_STORE_RECOVERY_IMAGE` before image/container
resolution. Use a new isolated container per profile. The fault marker lives in that
container's `/tmp` and prevents repeated injection even if the factory is recreated.
The dedicated image persists `--spi-single-use-object--provider-default=issue7-fault-injection`
at `kc.sh build`; the launcher passes only an allowlisted fault-mode environment variable,
not an overriding runtime SPI selector. Production `runtime` does not include the fixture.
The JAR builder includes the outer factory and `$*.class` delegates and generates its own
service registration; tests and unrelated test SPI classes stay out. No shared test service
descriptor was added, so existing test providers' registrations are not replaced.
Provider enumeration is only availability evidence; actual fixture/production markers are
still required. An immutable image build and selected-SPI smoke start require separate
runtime authorization before these commands may be executed.

## Source and verification limits

This candidate is based on current `main` after PR #36 at `dd350bbf59c749a6c8fe5b81e0cc6daabc9e9924`. Its implementation delta is the scripted production-entrypoint regression, ledger assertions, and offline evidence updates. It does not modify the production account/provider Java, test SPI/image packaging, or production request-flow code; the recovery profiles/coordinator are the existing code now exercised by the new orchestration test.


The Python store-recovery module now includes an all-mode production-entrypoint regression: the production `main()` with external setup mocked selects each configured store profile, executes the real `issue7_store_recovery.run`, and calls the real `signup_wallet_flow` plus either a fresh real signup (consume-loss) or real `auth_flow` (both receipt-write modes) using scripted browser/wallet HTTP and Admin readbacks. It checks scripted browser/wallet request ordering (explicit signup intent, challenge, proof, status and retry); empty 503 and old pending/retry 404 without redirect/callback/code; exact retained enabled-user readback from fixed Admin responses; and serialized evidence from a hand-authored request-correlated log fixture; cooldown; distinct recovery transaction; correct ceremony and accurate transaction counts; same local subject; callback/replay/state/code/PKCE; and final checkpoint/stdout sanitization. The test does not observe current Registry verification, actual local-account creation/readback, pending-store consumption, or provider-emitted fault logs. Those Issue #7 gates remain runtime/provider qualifications. The core flow and coordinator are not mocked. All secrets, private subject/identity, locators, challenges, proof material, codes, tokens and raw logs are excluded from serialized evidence. This is scripted offline application-path evidence only; external setup is mocked and no container, Registry, Keycloak server/provider or live profile was run. Java tests continue to exercise one-shot decorator mutation ordering and delegation. None of this qualifies actual Keycloak acceptance, JPA/provider persistence/atomicity, real Registry/wallet behavior, or runtime/browser/provider selection. The added scenario passed against the unchanged production flow and is characterization of the previously untested orchestration; no product defect or runtime pass is claimed.
