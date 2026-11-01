# Issue #5 — Repeatable current-Registry acceptance matrix

## Status

Issue #4 is closed; its resolver-runtime implementation and direct exact-image resolver gate are integrated. That resolver-only qualification does not establish provider-level missing-Identity behavior. Any README wording that #4 blocks #5 is stale.

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
4. **Hostile Registry peers:** a test-only fixture supplies malformed bytes, a history-incomplete Identity, conflicting equal-sequence heads, and mixed legacy/rotated heads. The `issue5-adversarial` profile sends each fixture through a separate direct resolver lookup and Keycloak proof transaction; it requires exact-key requests at the CLI and provider peers, pending status, and no receipt/callback/code, then restores the original bootstrap and stops the fixture. These loopback fixtures do not change normal Registry publication or qualify network-wide behavior. The profile is implemented but has not been live-run on this integrated candidate.
5. **Rotation:** publish an authorized successor and independently confirm sequence/key before proofs; require stale-key `401` with the transaction pending, then current-key `202`/accepted. The harness records two rounds on the same Identity (sequence 2, then sequence 3). Neither round ran in the historical #5 attempt.

### Lifecycle receipt gate mapping

The `issue5-live` receipt maps each criterion to an explicit gate. Offline receipts leave every live gate `not_run`; the matrix step cannot pass unless the harness evidence is complete and each ordinary gate is mapped. An incomplete or interrupted attempt remains `inconclusive` (or `fail` when observed evidence contradicts the criterion), never an implicit pass.

| Criterion | Receipt gate | Evidence source |
|---|---|---|
| Current Identity and valid current-key proof | `current_identity`, `valid_current_key_proof` | Two distinct exact resolver readbacks and two Keycloak proof/status outcomes. |
| Exact missing Identity | `exact_missing_identity` | Two independent unpublished-key reads and provider/status outcomes; only exact-key `not_found` qualifies. |
| Registry unavailable | `registry_unavailable` | Read-back of temporary unreachable bootstrap, direct lookup, provider proof/status, and restored configuration readback. |
| Malformed result | `malformed_result` | Bounded test-only hostile peer, exact-key request witness, provider pending status, no receipt/callback/code. |
| History-incomplete result | `history_incomplete` | Same bounded hostile-peer evidence requirements. |
| Ambiguous equal-sequence result | `ambiguous_registry_result` | Same bounded hostile-peer evidence requirements. |
| Mixed legacy/rotated heads | `mixed_legacy_rotated_head` | Same bounded hostile-peer evidence requirements. |
| Stale-key denial | `stale_key_denial` | Rotation proof returns 401 while the transaction remains pending. |
| Owner-key rotation | `owner_key_rotation` | Two successor publication/readback rounds and successful current-key proofs. |
| Independent rotation readback | `independent_rotation_readback` | Resolver readback witnesses for both sequence 2 and sequence 3 before proof. |

### Image retention and publication

The lifecycle removes the run-owned image by default after saving its receipt. `--retain-image` is explicit local retention only; its receipt records the immutable image ID and verified run-owned tag. Retention does not publish or complete any acceptance gate. Registry publication is a separate `promote` action that requires a fully successful `issue5-live` receipt, every criterion gate in its required state, the still-present retained image with the exact recorded ID, an explicit release-candidate destination, and `--allow-publish`. It uses the existing image without rebuilding and reads back the remote manifest/config digest before reporting success. No registry destination or image promotion is authorized by this documentation or by the live-run approval.

Account-mapping denial evidence is separate; its `403`/policy observations are not used to classify Registry miss or unavailable outcomes.

## Offline verification

Run the focused behavior suite without starting Keycloak, containers, or live profiles:

```bash
python3.11 -m unittest scripts.test_registry_acceptance_matrix -v
```

The focused suite exercises matrix ordering/checkpointing, outcome classification, bootstrap setup, hostile-peer evidence projection, and cleanup witnesses. The pinned adversarial-peer and rotation tests must run inside the resolver-builder against the materialized, hash-verified Identity/Registry sources after the overlay is applied; the ordinary host suite intentionally does not import those source trees. Those offline resolver tests do not exercise the Keycloak provider proof path. Live Registry and provider gates remain `not_run` until the explicitly authorized live profile completes on this exact candidate.

## Historical reproduction command

This is the invocation used for the earlier partial attempt, not authorization to repeat it:

```bash
WALLET_IT_IMAGE='ad9834f964d24aa9a0c8320ed095af4514760d9d2ce10eeaca52a20c6ff31fb9' \
  python3 scripts/wallet_login_live_e2e.py
```

Use an immutable image ID and preserve image/harness/source provenance for any future authorized run. Do not rerun the long full E2E merely to chase the prior six non-exact reads. Until every gate is actually observed, leave provider-level miss/unavailable, history, malformed/ambiguous, stale-key, and repeated-rotation acceptance open. Do not close Issue #5 based on the partial run or offline tests.
