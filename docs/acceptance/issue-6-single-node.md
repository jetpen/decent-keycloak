# Issue #6 — Single-node transaction replay and callback qualification

## Scope and status

Issue #6 is scoped to one Keycloak node. Multi-node clustering, cross-node replay, and high-availability guarantees are out of scope. The new `issue6-single-node` profile uses the existing run-scoped container ownership and cleanup helpers; it does not replace them.

The consolidation branch adds an isolated profile entry point, bounded/sanitized auth-flow checkpoints, a changed-signature replay request, and exact relying-party redirect checks for callback replay. Offline regression tests cover the parsers, evidence projection, and profile dispatch. **This branch has not been run against live containers.** These tests do not qualify the runtime behavior.

## Historical evidence (not evidence for this branch)

A previous one-node run used source revision `f93f1cba9075ae204df1e19ac700912af6d91d5`, harness SHA-256 `68c5a8ee71e61423e07b3da2a01d4788a32b6cb269cdf64eb20ba413423a15ec`, immutable image ID `5b86ae7e85af1160377aa9bb7542b4244842815fc2b491ebaa11094a966a8cea`, and image digest `sha256:ad64442c93eebf5e2ff0361e34e93b63ad4eaa65fff69f818d9f28f75341d0f0`. It reported Keycloak 26.8.0 with `dev-file`/`local` configuration and covered proof acceptance, callback, replay, and Code+PKCE. Its changed-proof request only appended JSON whitespace; it did **not** change the signature. The reported outcomes therefore do not qualify the changed-signature case added on this branch.

No historical result transfers to the consolidation branch. A fresh result would need to identify the exact source revision, harness hash, immutable image ID/digest, observed HTTP/callback outcomes, and verified cleanup.

## Offline verification

```bash
python3.11 -m unittest scripts.test_issue6_single_node_profile -v
python3.11 -m py_compile scripts/wallet_login_live_e2e.py scripts/test_issue6_single_node_profile.py
```

These commands verify offline wiring and evidence projection only. No live profile invocation is authorized by this document.

## Open acceptance gates

- Live single-node profile on this exact source/image/harness snapshot, including a distinct alternate-key signature over the identical signed fields, expected replay denial, callback replay to the registered redirect URI with state/error and no code, Code+PKCE, and run-owned cleanup.
- Expired transaction rejected without an accepted receipt or callback. The prior authorized attempt failed before transaction creation; rerun requires renewed explicit authorization.
- Post-consume receipt/store-failure and callback-gate publication/read failure remain unqualified on the production Keycloak provider/runtime.
- Independent review of the final consolidated patch and successful CI on the pushed PR head.

Do not claim Issue #6 complete, merge-ready, or closed until every in-scope gate has fresh evidence and the authorized review/merge lifecycle is complete.
