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

GitHub Container Registry is technically suitable: GitHub documents Docker v2 schema 2 and OCI image support, granular package permissions, and anonymous pulls for public packages. The user refreshed the active `gh` credential to include `read:packages`; `gh auth status` and authenticated package-list API calls succeeded. Listing container packages for both the authenticated user's namespace and `users/jetpen` returned zero visible container packages. No GHCR package or publisher is configured in this repository, so there is no package against which to verify package-specific read/write access, visibility, or retention settings. The credential has `read:packages` but not `write:packages` or `delete:packages`; the PR workflow grants only `contents: read` and no `packages: write`. No image was published, and no remote deletion was attempted. The blocker and safe alternative are explicit: keep CI and local profiles non-publishing and continue using immutable local image IDs; do not configure a GHCR publisher or claim a GHCR image is available until a package is deliberately configured and write access is authorized and verified. See [the cited registry/retention research](issue-26-remote-retention-research.md).

The public-repository scan found no image consumer in the seven inspected public repositories, and the repository owner confirmed on 2026-11-01 that there are no additional private or external consumers. This is the current known consumer set; register any future consumer and its digest before publication. The owner-approved manual review policy for any future explicitly published release candidate is:

- Check named consumers and pinned manifest digests every 3 days; record the owner, reason, and next review date for each retention exception.
- Retire an unconsumed candidate by day 7 only after confirming no consumer references its digest.
- Never delete a manifest while a confirmed downstream consumer still uses its digest. If it remains active at day 7, arrange migration or retain it under a named, time-bounded exception with an owner, reason, and next review date. Delete only after no consumer uses the digest.
- GHCR expiry is manual, not a verified automatic TTL. If GHCR is later configured, delete only the exact package version/digest through an authorized package operation and read back its absence; consumers pin `registry/repository@sha256:…` digests. GitHub documents a 30-day restoration window and restrictions on deleting public package versions after high download counts; verify current package policy before any deletion.

The 3/7-day schedule is the owner-approved project policy for unconsumed candidates, not registry-enforced expiry or a hard maximum for active consumers. GitHub's documented manual deletion/restore behavior and public-version download restrictions are the registry constraints considered. No package currently exists, and no remote cleanup or publication was executed; the policy does not authorize publishing until package write access is configured and verified.

## Acceptance status

| Issue #26 criterion | Evidence / status |
|---|---|
| Inventory images, roles, consumers, local/CI workflows; separate bases and caches. | Inventory above, README consumer check, workflow inspection; verified. |
| Component/role names, source provenance, local refs, immutable promotion digests. | All Dockerfile targets require source revision and source/artifact SHA-256 labels; target-specific injected JARs are fingerprinted by the helper; lifecycle receipt ID and promotion digest output are tested. |
| Shared same-machine Podman store without push/local registry. | Canonical runtime build/smoke passed; a disposable repository-labeled image was read by the same immutable ID from another checkout. No push or local registry was used. |
| Local-only/PR builds cannot publish; trusted explicit promotion only. | Pull-request workflow is read-only and non-publishing; promotion checks committed-source fingerprint equality, refreshes `origin/main`, then checks source ancestry and image labels. |
| Configurable 3-day local retention, pin/extend, exclusions, active protection. | `scripts/image_lifecycle.py`, policy tests, and a real disposable-image cleanup/readback with simulated age; full Podman inventory restored. |
| Verify GHCR suitability and required permissions; document blocker/alternative. | GHCR's OCI/Docker support and permission model are verified from GitHub docs; authenticated `read:packages` listing works and returns zero visible container packages in `jetpen`. Package-specific access and write/delete permission remain unavailable; the local-only safe alternative and no-publisher boundary are documented above. No push was attempted. |
| Remote expiry/release and maximum safeguard based on consumers/registry capabilities. | Owner confirmed no private/external consumers beyond the public scan. The owner-approved manual 3-day review / day-7 retirement policy for unconsumed candidates, active-consumer protection, immutable-digest contract, and GitHub deletion constraints are documented above. No automatic TTL or actual remote deletion is claimed. |
| Automated tests for naming, provenance, publication boundary, cleanup, retention, digest references. | `scripts.test_image_lifecycle` and `scripts.test_lifecycle`; covered by canonical Python suite. |
| Contributor/CI docs and verification limitations. | README/CONTRIBUTING updated; PR CI remains read-only and publication is not acceptance qualification. |

No GHCR package was found or published, and no remote deletion was attempted. This evidence closes the lifecycle acceptance through the documented GHCR blocker/safe alternative and owner-approved consumer/retention policy; it does not claim GHCR write access or a published image. Keep remote publication disabled until package-specific write access is configured and verified, and do not infer provider/Registry qualification from image lifecycle evidence.
