# Issue #7 store recovery: scoped current-main candidate

Refs #7: https://github.com/jetpen/decent-keycloak/issues/7

**Disposition: offline implementation candidate; DO NOT MERGE YET. Issue #7 remains OPEN.**
No live/container/Registry invocation or image build was performed for this slice.
Real Keycloak HTTP, selected runtime SPI, wallet/browser and production-provider recovery
remain unqualified. Neither passing scripted HTTP tests nor an SPI JAR proves runtime qualification.
Multi-node integration and distributed provisioning/replay guarantees are out of scope.

## Preserved ordering and residual states

Current main already implements server-bound explicit signup intent, fresh signed proof and
current Registry verification, exact enabled local-account create/readback, then pending consume.
This slice does not replace or change production Java or the #4/#5/#6 flows.
It extends the existing signup probe and reuses the existing owned-resource lifecycle,
immutable-image resolution, runtime-baseline checks, cleanup, cooldown and final checkpoint.
The new helper is `scripts/issue7_store_recovery.py`; the production entry point remains
`scripts/wallet_login_live_e2e.py`.

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
separate and unchanged. This candidate does not qualify restart persistence, JPA, actual
concurrent winners, consume-loser interleaving, or application/provider atomicity across nodes.
Unsupported loser/concurrent modes fail closed before external setup; they are not aliases.

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

## Source disposition and verification limits

Protected source worktree `/home/ben/projects/decent-keycloak-issue7-single-node-acceptance`
was read only. Its frozen parent-verified fingerprint was
`805456c5502747a43a045936f1460d3b10ef42e8df05f2ec693a9848b0cb9c2b`.
The clean candidate is based on current-main commit
`077526d1dccce9d2347a8f3df04468deb779597d`, branch
`feature/issue-7-store-recovery-main`. Only the store-fault/recovery slice was adapted;
the old full harness, README, production Java, ready-gate poisoning, concurrent-consume
barrier/admission bypass, restart profiles and source-only test totals were not imported.

The new Python module tests real signup failure response chains and real fresh LOGIN with
scripted HTTP, plus production `main()` with external setup mocked while the real store
coordinator runs through the final sanitized checkpoint for each profile. Negative cases
cover disclosures in each response/body/Location/redirect chain, missing/wrong causal logs,
account readback, same-subject mismatch and invalid recovery outcomes/cleanup. Java tests
exercise one-shot decorator mutation ordering and delegation. These are offline evidence,
not a claim that actual Keycloak accepted the image/SPI or that a real browser obtained code.
Behavioral RED was observed for absent profile selection and packaging, intermediate failure
checkpoint preservation and contradictory receipt transaction-count projection. Additional
scripted success/failure and Java decorator cases were added as characterization coverage;
no claim is made that they were all written before implementation.
