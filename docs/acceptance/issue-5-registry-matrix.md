# Issue #5 — Repeatable current-Registry acceptance matrix

## Status

Issue #4's resolver-runtime implementation and direct exact-image resolver gate are integrated. Issue #4 remains open pending review and explicit closure; its resolver-only qualification does not establish provider-level missing-Identity behavior. Any README wording that #4 blocks #5 is stale.

Issue #5 remains open and unqualified overall. This is disposable single-node loopback evidence only. It does not qualify Registry reliability, production TLS, browser/native-wallet interoperability, shared-store behavior, or production use. In particular, HTTP 503 is not evidence of absence, stale-key rejection, or account-policy denial.

This consolidation ports the matrix harness and offline tests but does not rerun a live profile. The historical attempt below is partial evidence from an earlier source snapshot; the integrated harness has not been live-verified.

## Historical attempted run and provenance

The source worktree's harness was run with the immutable image ID below, not a moving tag. The run stopped during the second missing-Identity attempt; no full E2E rerun followed that failure.

| Provenance | Value |
|---|---|
| Source revision at run | `48121bec3ac2708b97c4c39240cd85aadf0117e2` |
| Harness SHA-256 at run | `3743c2b44e2f40f9f4ad3179d1d9a9767b0797661ce6dd9d6fc8729d1a13a7a6` |
| Immutable image ID | `ad9834f964d24aa9a0c8320ed095af4514760d9d2ce10eeaca52a20c6ff31fb9` |
| Image digest | `sha256:29fe182466744bf7d9286fde27331cce784041170898eed430bfb8490ae8f602` |
| Pinned Identity source commit | `2caec24de52c2dbe241e72fe317281c051d03f89` |
| Pinned Registry source commit | `0fa9a6b631bd77725418e990ae9ea4d974dc546c` |
| Runtime manifest SHA-256 | `a9380af7777df65be522f0dda83ebef4a9aadd57a991694d58ec7adb4db3e699` |
| Runtime requirements lock SHA-256 | `6ff0d4c41ae5aa8834bbc9a88bfa30cb8386aae6ebb9b13467b55a6d996098ff` |

After the run, the source harness was changed to give each repeated unpublished-key fixture a distinct generated-key filename. That fix was not live-verified. The selected source worktree's current harness SHA-256 was `ac2b8e10f1bebce6d80c379ef26cabd2675acc307f7f4bc2dd618cffab2fed8e`; this is not the version that ran. The harness integrated here is newer still and has not been live-run.

## Observed outcomes from the historical attempt

| Case | Result | Qualification limit |
|---|---|---|
| Current Identity: 2/2 attempts | Both attempts separately read back the exact Identity and owner key; both valid Keycloak proofs returned 202 and browser status returned 200 accepted. The existing login/PKCE path completed. | Exact current-Identity loopback case only for that image/run; not Registry reliability or production qualification. |
| Missing Identity: 1/2 attempts | Attempt 1's separate resolver CLI classified the requested hashed Registry key as terminal `not_found`. The valid proof through Keycloak returned 503; the initiating browser still saw exactly `pending` (HTTP 200), with no accepted receipt or callback. The bounded outcome is `provider_registry_inconsistent`, not provider absence. | Direct CLI miss was observed; the production resolver path did not confirm a miss. Missing-Identity acceptance remains open. |
| Missing Identity repeat: attempt 2 | Stopped at the owner-key generation gate (`successor owner-key generation`). Raw subprocess output was not retained, so the exact cause is unknown. | Attempt incomplete; the later distinct-fixture fix is not live-verified. |
| Unavailable Registry | Not run; execution stopped before changing/read-checking the bootstrap and making provider proof attempts. | Open; no unavailable-state qualification. |
| History-incomplete, malformed, and ambiguous Registry results | Not run live. Existing parser/unit cases are local classification checks only. The separate ambiguous-local-account case is not an ambiguous Registry result. | Open; no Registry/Keycloak-path qualification. |
| Owner-key rotation | Not reached in the #5 attempt. | Open; no stale/current-key proof from that run. |

A separate earlier #4 loopback run reached rotation sequence-2 publication/readback, then six fresh successor reads failed exact Identity/key matching; stale/current-key proofs did not run. Its sanitized categories do not establish a cause. Do not treat its 503s as Registry absence or policy evidence.

## Matrix gates and evidence handling

The harness records bounded attempts in `registry_matrix` and checkpoints after each attempt. Each repeated missing-Identity attempt uses a distinct generated key and unpublished Identity fixture. The matrix keeps direct resolver and Keycloak provider outcomes separate, preserves proof/status HTTP observations after failure, and sanitizes checkpoints to omit raw Identity values, keys, endpoints, resolver output, tokens, and credentials.

1. **Current Identity:** before each independent proof, perform a separate resolver read and require the exact Identity and owner key; then use a fresh Keycloak login/proof and retain proof/status outcomes.
2. **Missing Identity:** use a fresh unpublished Identity/key and a separate resolver lookup; classify direct results as `not_found` only after checking the exact requested Registry key. Use a fresh Keycloak transaction and valid signature, poll browser status separately, and distinguish provider `503` from a terminal miss.
3. **Unavailable Registry:** point the disposable realm bootstrap at the same peer ID on a different, unreachable local TCP port; read configuration back; run direct lookup and a valid Keycloak proof; record provider/status results; restore and read back the original bootstrap in `finally`.
4. **History-incomplete, malformed, and ambiguous Registry results:** keep explicit empty attempt lists until safe real fixtures reach the pinned Keycloak resolver path. Synthetic parser tests do not fill live gates.
5. **Rotation:** publish an authorized successor and independently confirm sequence/key before proofs; require stale-key `401` with the transaction pending, then current-key `202`/accepted. The harness records two rounds on the same Identity (sequence 2, then sequence 3). Neither round ran in the historical #5 attempt.

Account-mapping denial evidence is separate; its `403`/policy observations are not used to classify Registry miss or unavailable outcomes.

## Offline verification

Run the focused behavior suite without starting Keycloak, containers, or live profiles:

```bash
python3.11 -m unittest scripts.test_registry_acceptance_matrix -v
```

The suite covers eight offline behaviors: attempt ordering and checkpoint timing, distinct fixtures, retention of proof/status outcomes after a failed attempt, miss-versus-unavailable-versus-policy classification, unavailable-bootstrap construction, malformed-evidence rejection and checkpoint sanitization, plus the guide/status guard. Offline tests do not qualify live Registry states.

## Historical reproduction command

This is the invocation used for the earlier partial attempt, not authorization to repeat it:

```bash
WALLET_IT_IMAGE='ad9834f964d24aa9a0c8320ed095af4514760d9d2ce10eeaca52a20c6ff31fb9' \
  python3 scripts/wallet_login_live_e2e.py
```

Use an immutable image ID and preserve image/harness/source provenance for any future authorized run. Do not rerun the long full E2E merely to chase the prior six non-exact reads. Until every gate is actually observed, leave provider-level miss/unavailable, history, malformed/ambiguous, stale-key, and repeated-rotation acceptance open. Do not close Issue #5 based on the partial run or offline tests.
