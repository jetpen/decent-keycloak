# Issue #6 single-node expiry live acceptance

Status: **OPEN — one authorized expiry attempt failed before transaction creation.** Issue #6 remains partial; effective runtime database/cache facts, expired-proof denial, selected-provider evidence, and post-consume store-failure behavior/recovery remain open. The current scope is one Keycloak node only. Multi-node and HA claims are explicitly excluded. The one authorized expiry-profile attempt has been consumed; do not retry it.

## One authorized invocation (not a rerun instruction)

The single bounded attempt used the following profile command shape with immutable runtime image ID `9c61160977394f029fb53c6343a1bee2ab5e7a99f94b41b7cf70e1dffc471a9a`:

```bash
WALLET_IT_PROFILE=expiry WALLET_IT_IMAGE="$IMAGE_ID" python3 scripts/wallet_login_live_e2e.py
```

`IMAGE_ID` must be the immutable image ID built from this worktree. The opt-in profile launches one Keycloak node using `--db=dev-file` and `--cache=local`; before expiry assertions it queries authenticated `/auth/admin/serverinfo` and the exact, full-ID-verified Keycloak container's effective allowlisted config. The evidence projection records actual version, node count, configured/effective database and cache modes, the optional `cache_stack_effective` value from the separate `kc.cache-stack` setting (null when absent; not storage proof or a qualification gate), and the IDs of providers advertised under the `single-use-object` SPI. The effective database/cache values are read independently from `show-config`. Advertised provider IDs establish availability only. Keycloak 26.8.0 `show-config` masks SPI option values, so the selected provider path is established from the allowlisted implementation ID in the post-cursor, request-correlated neutral production denial marker emitted by the actual transaction-store instance; it must also match the server-info available-provider map. Missing or inconsistent facts remain explicitly open; configured arguments or documentation are not runtime evidence. It waits the production transaction TTL plus its fixed margin and requires exact denial HTTP codes, no accepted result/receipt, callback, or OIDC code in proof/status bodies, `Location`, or redirects, and that request-correlated marker. The default profile remains selected when `WALLET_IT_PROFILE` is unset. The single approved attempt is recorded below and is not a qualification pass; the profile stopped at the pre-request runtime baseline gate.

## Sanitized result (single attempt; incomplete)

```json
{
  "profile_attempt_status": "failed_before_transaction_creation",
  "profile_attempt_count": 1,
  "profile_attempt_retried": false,
  "failure_type": "RuntimeError",
  "source_commit": "5c5c0cb4f0a742e2bab24f26660659ebd4a0e84c",
  "harness_sha256": "ebca6e7bc304742a8b1115950884d80bd93d69d89b4e6d2f068c429fea32b130",
  "runtime_manifest_sha256": "a9380af7777df65be522f0dda83ebef4a9aadd57a991694d58ec7adb4db3e699",
  "runtime_lock_sha256": "6ff0d4c41ae5aa8834bbc9a88bfa30cb8386aae6ebb9b13467b55a6d996098ff",
  "image_id": "9c61160977394f029fb53c6343a1bee2ab5e7a99f94b41b7cf70e1dffc471a9a",
  "image_digest": "sha256:4b24387d658572b2ccb5023e282d68606679c42290f7458124a511b3c9776122",
  "keycloak_version": "26.8.0",
  "keycloak_nodes": null,
  "database_mode_configured": "dev-file",
  "database_mode_effective": "unavailable",
  "cache_mode_configured": "local",
  "cache_mode_effective": "unavailable",
  "cache_stack_effective": null,
  "single_use_object_provider_ids": ["infinispan"],
  "single_use_object_provider_path": null,
  "runtime_qualification_status": "open_runtime_facts_unavailable",
  "expiry_case": {"stage": "started", "ttl_seconds": 300, "wait_seconds_planned": 305},
  "login_page_http": null,
  "challenge_get_http": null,
  "proof_post_http": null,
  "status_http": null,
  "request_correlated_denial": null,
  "no_accepted_receipt": null,
  "no_callback": null,
  "no_authorization_code": null,
  "admin_environment_file": "removed",
  "owned_resources_cleanup": "verified"
}
```

The run stopped at the pre-request runtime-baseline gate: configured database/cache arguments were present, but their independent effective `show-config` observations were unavailable. It did not request the login page, create a transaction, or wait 305 seconds. `infinispan` was advertised as available; selected-provider evidence was not observed. No expired-proof HTTP result, request-correlated denial, or negative acceptance assertion was produced. The one authorized expiry attempt was not retried; a future live attempt requires renewed authorization. The saved record contains only allowlisted statuses/booleans, HTTP fields, and provenance. Do not store request IDs, raw Keycloak logs, credentials, handles, proof bodies, callbacks, or authorization codes.

## Remaining Issue #6 gates

- Verify actual Keycloak 26.8.0 runtime, one-node topology, effective database/cache modes, and selected `SingleUseObjectProvider` path from the run. `cache_stack_effective` is an optional separate cache-stack observation and is not a qualification gate.
- Renewed authorization and a successful one-node expiry denial/provider evidence run; do not rerun under the consumed one-attempt approval. Any future live attempt requires renewed explicit authorization.
- Separately cover post-consume store failure and recovery; this candidate does not cover it.
- Keep multi-node/HA excluded under the current parent #1 scope.
