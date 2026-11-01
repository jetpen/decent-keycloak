# Issue #26: container image lifecycle evidence

Issue #26 is an artifact-lifecycle change, not provider/Registry qualification. Keep Issue #26 open until every acceptance criterion is verified. It does not close Issue #1.

## Image inventory and local workflow

| Dockerfile target / role | Purpose and consumer | Lifecycle |
|---|---|---|
| `runtime` / `wallet-provider` | Installable Keycloak 26.8.0 provider image; canonical offline lifecycle smoke and opt-in local/live profiles consume its immutable ID. | Run-scoped tag; removed by default; explicit `--retain-image` for local consumers or later promotion. |
| `issue7-user-readback-test-runtime` / `wallet-provider-issue7-user-readback-test` | Isolated Issue #7 readback-fault provider for that profile and its tests. | Temporary test image; not a promotion target. |
| `issue7-store-recovery-test-runtime` / `wallet-provider-issue7-store-recovery-test` | Isolated Issue #7 store-fault provider. | Temporary test image; not a promotion target. |
| `issue6-postconsume-test-runtime` / `wallet-provider-issue6-postconsume-test` | Isolated Issue #6 receipt-failure provider. | Temporary test image; not a promotion target. |
| `issue6-callback-gate-test-runtime` / `wallet-provider-issue6-callback-gate-test` | Isolated Issue #6 callback-gate provider. | Temporary test image; not a promotion target. |
| `resolver-builder`, `keycloak-with-resolver` / intermediate roles | Build intermediates. | Run-owned labels and lifecycle teardown; not promotion targets. |

Every documented Dockerfile build passes a source revision and target-specific source/artifact SHA-256 fingerprints from `scripts/lifecycle.py image-fingerprints`; the test targets include their additional injected-provider JARs in the artifact digest. The canonical runtime lifecycle also records the immutable image ID in its sanitized receipt. Same-machine Podman consumers in different checkouts share the local per-user image store; neither a local registry nor a remote push is needed. Upstream UBI/Keycloak base images remain outside repository-owned cleanup. The local image-retention command does not prune builder caches.

Local repository-built images use a configurable three-day default age. `scripts/image_lifecycle.py cleanup` only considers exact repository/component labels and an allowlisted role; it protects active-container, pinned, extended, and recent images, rechecks ownership before removing an immutable ID, and verifies removal. Consumers pin with `pin`, extend with `extend`, and release pins with `unpin`. Automated tests cover the age boundary, active images, ownership mismatch, upstream exclusion, pins/extensions, and immutable IDs.

**Local engine verification (2026-11-01):** the canonical `ci` profile built and smoke-tested the runtime image with Podman; its receipt passed all offline steps and teardown readback restored the exact 3,502-image baseline. A separately built, disposable repository-labeled image was inspected by immutable ID from `/home/ben/projects/decent-ecosystem`, confirming cross-checkout visibility in the same Podman store. Its age was advanced through the cleanup function's injected clock (no multi-day wait); the three-day cleanup selected and removed that exact image, verified its absence, and restored the full engine inventory to baseline. This verifies local store visibility and the real deletion/read-back path, not an elapsed three-day retention period or a downstream provider integration consumer.

## Local and CI publication boundary

`.github/workflows/acceptance.yml` is triggered by `pull_request` and `workflow_dispatch`, grants only `contents: read`, and runs `scripts/lifecycle.py run ci`. That lifecycle builds and smoke-tests a local CI image but has no registry login, push, or package-write permission. Local `offline` and `ci` profiles do not publish. The explicit `promote` command is the only repository publication path; it requires an explicit `--allow-publish`, passing gated receipt, retained immutable source image, explicit destination, matching image provenance labels, and an image-source fingerprint exactly matching the Git tree at the recorded source revision. Before checking that revision's ancestry, promotion explicitly fetches `origin/main`; fetch failure blocks promotion. Publication is not provider/Registry qualification.

## Remote registry and expiry status

No GHCR package or publisher is configured in this repository. The available GitHub CLI credential does not have `read:packages`; a direct anonymous GHCR token request for `jetpen/decent-keycloak` returned HTTP 403. Therefore package existence, package read access, write permission, and GHCR retention behavior remain unverified. No image was published, and no remote deletion was attempted. Do not claim GHCR is suitable or configure it until a maintainer can verify package access and repository policy. The smallest safe alternative is to keep PR CI read-only and require a maintainer to use the explicit, credentialed OCI `promote` command only after confirming access to the selected registry.

There is no verified downstream consumer of this provider image: `decent-integration-test` documents Identity CLI integration tests and does not consume it. Pending confirmation of an actual consumer and registry policy, use this conservative manual review schedule for any explicitly published release candidate:

- Check named consumers and pinned digests every 30 days; record the owner, reason, and next review date for each extension.
- Retire an unconsumed candidate no later than 90 days after publication, after confirming no consumer references its digest.
- Never delete a manifest while a confirmed downstream consumer still uses its digest. If that condition persists at day 90, escalate for a reviewed replacement/migration and record a time-bounded owner-approved exception rather than silently deleting a live dependency.
- Remove only the exact candidate tag (for an OCI registry supporting deletion, for example `skopeo delete docker://registry/repository:rc-tag`) and read back that it is absent. Consumers pin `registry/repository@sha256:…` digests.

These 30/90-day intervals are an interim review safeguard, not registry-enforced expiry or a verified registry maximum. Because no package capability or downstream lifecycle is established, the final retention interval remains provisional and must be reassessed before enabling publication.

## Acceptance status

| Issue #26 criterion | Evidence / status |
|---|---|
| Inventory images, roles, consumers, local/CI workflows; separate bases and caches. | Inventory above, README consumer check, workflow inspection; verified. |
| Component/role names, source provenance, local refs, immutable promotion digests. | All Dockerfile targets require source revision and source/artifact SHA-256 labels; target-specific injected JARs are fingerprinted by the helper; lifecycle receipt ID and promotion digest output are tested. |
| Shared same-machine Podman store without push/local registry. | Canonical runtime build/smoke passed; a disposable repository-labeled image was read by the same immutable ID from another checkout. No push or local registry was used. |
| Local-only/PR builds cannot publish; trusted explicit promotion only. | Pull-request workflow is read-only and non-publishing; promotion checks committed-source fingerprint equality, refreshes `origin/main`, then checks source ancestry and image labels. |
| Configurable 3-day local retention, pin/extend, exclusions, active protection. | `scripts/image_lifecycle.py`, policy tests, and a real disposable-image cleanup/readback with simulated age; full Podman inventory restored. |
| Verify GHCR suitability and required permissions; document blocker/alternative. | **Blocked:** package/read/write policy not verifiable with available permissions; blocker and safe alternative above. |
| Remote expiry/release and maximum safeguard based on consumers/registry capabilities. | Interim manual procedure above; actual consumer and registry policy are unknown, so the final interval is **not verified**. |
| Automated tests for naming, provenance, publication boundary, cleanup, retention, digest references. | `scripts.test_image_lifecycle` and `scripts.test_lifecycle`; covered by canonical Python suite. |
| Contributor/CI docs and verification limitations. | README/CONTRIBUTING updated; PR CI remains read-only and publication is not acceptance qualification. |

The source includes no GHCR package publication or remote deletion result. Keep the issue open until the GHCR/access and final consumer/registry retention checks are resolved; do not infer completion from local test/build success.
