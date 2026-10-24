# Issue #6 — Single-node transaction replay and callback qualification

## Current disposition — replay/PKCE passed, full qualification open

The [final combined qualification and fault-profile runs](issue-6-qualification.md) pass expiry, actual production-provider provenance (`infinispan`), and both same-browser decorator recoveries through strict replay/PKCE. Runtime acceptance is now passed; final independent review is pending. Earlier open-expiry/provider/recovery statements below are historical and superseded by that matrix.

The 2026-10-24 auth-only rerun on image `435600c226968435e34eb707d74f2a06b8b64ef78782a712ec6cd86390529948`, source fingerprint `f38f2423cad49633d088b657dceb31e47c10f6bc9e50d1dc1c76e8223d601573`, and harness SHA-256 `a53867225194211f80793583ec6b59d801673a016d0f700adb1222d345007511` passed the strict replay gate and Code+PKCE. Replay returned 302 to the exact RP URI with original state, error and no code; status-after-callback was 404 and PKCE was 200. This supersedes the replay-blocked statements in the historical evidence below.

Root cause: the harness incorrectly counted OAuth `error_description` as a static redirect-URI query field. Its mismatch also forced the derived state result false. The fix distinguishes response metadata from registered static query fields, with negative tests retaining exact destination/static query, state multiplicity and no-code requirements. No production behavior was changed for this fix. Keycloak's framework handled denial without custom authenticator re-entry. Historical parser results cannot prove the actual state was absent or the origin was wrong.

The protected sanitized receipt is `/home/ben/.hermes/cache/scratch/issue6-error-metadata-fix-f38f2423cad4.json`; resource inventories matched before/after. Expiry was not run. Selected production-provider provenance, decorator recovery reruns and independent review remain open; Issue #6 is not complete or merge-ready. The remaining sections preserve earlier snapshots and do not override this disposition.

## Scope and status

Issue #6 is scoped to one Keycloak node. Multi-node clustering, cross-node replay, and high-availability guarantees are out of scope. `issue6-auth-flow` is the bounded replay/proof/Code+PKCE phase only; it never invokes the 301-second expiry runner. `issue6-single-node` is the combined auth-flow-plus-expiry selector. Keep these selectors distinct so a replay qualification run cannot silently consume an expiry authorization. Both use existing run-scoped container ownership and cleanup helpers.

The candidate separates `issue6-auth-flow` (auth/replay/Code+PKCE only; no expiry wait) from combined `issue6-single-node` (auth plus 301-second expiry). The latest authorized auth-only production run used source fingerprint `7ee5cf91725b99d43bb1324a1d19dcda39c2d8f69d1617b2d9642429f79047f4`, image `1245920e5757b36f0c4a38f307442cace45070716a9ce3abe128c6b90402af04`, and harness SHA `87aab8cba94410e01fe15a5286579264eae3ff162c3263e26c7cbdc423c5edb6`. It observed Keycloak 26.8.0/one node, effective DB `dev-file`, and local cache from the pinned configuration log; selected production provider remained unavailable. Proof/retry/callback passed at 202/202/409/302, but the replay response returned 302 with an error and no state/code, and its destination again failed `redirect_origin_mismatch`. The flow-callback re-arm candidate was included, so the offline seam regression did not predict the live outcome. Code+PKCE was not reached. Receipt and callback-gate profile outcomes are recorded in the README; expiry was not attempted. Keep replay, PKCE, expiry, provider selection, and recovery gates open.

## Historical evidence (not evidence for this branch)

A previous one-node run used source revision `f93f1cba9075ae204df1e19ac700912af6d91d5`, harness SHA-256 `68c5a8ee71e61423e07b3da2a01d4788a32b6cb269cdf64eb20ba413423a15ec`, immutable image ID `5b86ae7e85af1160377aa9bb7542b4244842815fc2b491ebaa11094a966a8cea`, and image digest `sha256:ad64442c93eebf5e2ff0361e34e93b63ad4eaa65fff69f818d9f28f75341d0f0`. It reported Keycloak 26.8.0 with `dev-file`/`local` configuration and covered proof acceptance, callback, replay, and Code+PKCE. Its changed-proof request only appended JSON whitespace; it did **not** change the signature. The reported outcomes therefore do not qualify the changed-signature case added on this branch.

No historical result transfers to the consolidation branch. For any future rerun, record the exact source revision, harness hash, immutable image ID/digest, observed HTTP/callback outcomes, and verified cleanup.

## Offline verification

```bash
python3.11 -m unittest scripts.test_issue6_single_node_profile -v
python3.11 -m py_compile scripts/wallet_login_live_e2e.py scripts/test_issue6_single_node_profile.py
```

These commands verify offline wiring and evidence projection only. This document does not itself authorize runtime use; any live invocation requires explicit authorization outside this document.

## Open acceptance gates

- Live single-node replay/Code+PKCE: the latest production auth-only profile, built from the current flow-callback re-arm candidate, again failed the strict replay destination/state gate (`state` absent, error present, no code, destination failed `redirect_origin_mismatch`). The offline Keycloak 26.8 `DefaultAuthenticationFlow` regression reaches the authenticator's protocol-denial call after `AuthenticationProcessor.resetFlow()`, but the live stale-action path still did not satisfy the contract; do not claim the workaround succeeds. Require a real response to the registered RP with original state/error/no code, or the separately documented safe same-issuer error page. The strict gate remains open.
- Expired transaction rejection remains unqualified. The current rerun used `issue6-auth-flow` and deliberately did not invoke the 301-second wait. An earlier combined `issue6-single-node` run stopped at replay before expiry; renewed explicit authorization is required before another expiry attempt.
- Post-consume receipt/callback-gate commit-then-throw failure has offline provider-double coverage in `issue-6-postconsume.md`; production-provider behavior and live callback recovery remain unqualified.
- Independent review of the final consolidated patch and successful CI on the pushed PR head.

Do not claim Issue #6 complete, merge-ready, or closed until every in-scope gate has fresh evidence and the authorized review/merge lifecycle is complete.

## Latest non-expiry live evidence (2026-10-24)

The latest production `issue6-auth-flow` and the receipt/callback-gate test profiles are recorded in the README's **Latest bounded Issue #6 non-expiry reruns** table. All used Keycloak 26.8.0 on one node. Production proof/retry/initial callback passed, but replay failed the strict RP-origin/state gate (`redirect_origin_mismatch`) with no code and no PKCE. The two test-decorator profiles confirmed their correlated commit-then-throw and 503/404 fail-closed behavior, then fresh recovery failed at `fresh_replay`; their first replay responses went to Keycloak's login-actions authenticate path without state/error/code. All replay GETs disabled redirect following, so these are first-response Locations, not later chain destinations. No replay-guard log marker was observed in any run. This is consistent with stale action handling before the custom authenticator, not proof of the precise internal branch. The offline OIDC protocol test proves controlled redirect construction only; it does not qualify the live response.

The earlier callback-gate `preflight` result is superseded: a later run exposed an invalid synthetic email (`.invalid`) during `provision_identity`; the harness now uses reserved `wallet-owner@example.com` separately from the decentralized Identity ID, and the profile reached the fault injection/recovery path. Production provider selection remains unavailable. Effective DB/cache were `dev-file`/`local`; no selected-provider inference is made. Expiry was not attempted and requires renewed explicit authorization. Issue #6 remains blocked and open.
