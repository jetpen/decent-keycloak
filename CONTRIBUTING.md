# Contributing

Thanks for helping improve the experimental decent-keycloak provider. Keep changes focused, explain user-visible and security-relevant behavior, and do not present a local/offline result as live or production qualification.

## Prerequisites

Install the tools below before running `scripts/lifecycle.py`. Versions are the lifecycle's current declared/checked values; where the project does not pin a patch version, that is stated explicitly rather than implying a tested version range.

| Tool | Required version | Notes |
|---|---|---|
| CPython | **3.11.13** | Exact version checked by lifecycle preflight and used by CI. |
| Authlib OIDC validator | **1.9.2** with hash-locked transitive dependencies | Installed from `requirements/issue8-oidc.lock`; used by the OIDC acceptance tests and live token validation. |
| Java build JDK | Any Java 21-compatible JDK | The lifecycle checks the Java major version only; no vendor, patch, or build is pinned. CI installs Java 21. |
| Apache Maven | Installed and on `PATH`; **version not pinned by the lifecycle** | Used for `mvn clean package` and Surefire. |
| Git | Installed and on `PATH`; **version not pinned by the lifecycle** | Required for source fingerprints, diff checks, and version control. |
| Podman | Installed, daemon/service available; **version not pinned by the lifecycle** | Default local container engine. Pinned base images must already be present; local build uses `--pull=never`. |
| Docker Engine + Buildx | Installed and available; **versions not pinned by the lifecycle** | Alternative local container path for compatibility image builds; the current PR CI slice does not use Buildx. |
| OpenSSL | Installed; **version not pinned** | Required only for opt-in live profiles. |

The keycloakctl acceptance profile requires Python 3.11.13, Java 21, Maven, Git, the hash-locked OIDC dependency, and a local Podman engine (Docker/Buildx in CI). The canonical Python suite materializes pinned Identity/Registry sources, locked resolver artifacts, and locked PyPI wheels in temporary directories, so dependency acquisition may use the network; it does not contact the Registry. Image builds use network-isolated build steps and the engine's existing base images; a missing base may require acquisition. HTTP 503/unavailable is not a clean Identity miss; treat it as an indeterminate result, not as evidence that the Identity does not exist. The RP fixture image smoke runs its configured entrypoint with network access disabled, starts a loopback listener on an ephemeral port, checks its fixed generic rejection response, and shuts down without issuer access. This is startup evidence only, not browser/Keycloak or live qualification. The binary dependency inventory in [`container/resolver-binary-dependencies.lock.json`](container/resolver-binary-dependencies.lock.json) records each package version, upstream distribution URL, and SHA-256.

## Local development workflow

Work from a clean branch based on the current default branch, and keep each change limited to its requested scope. Before coding, read the relevant source, tests, and acceptance/support docs. For implementation changes, add or update the owning tests; run focused tests while iterating.

Inspect the remaining compatibility lifecycle capabilities and the offline profile plan; these are still legacy-owned:

```bash
python3.11 scripts/lifecycle.py --help
python3.11 scripts/lifecycle.py profiles
python3.11 scripts/lifecycle.py run offline --plan
```

Run the shared local/CI keycloakctl acceptance profile from the worktree before publishing the PR or treating this slice as verified:

```bash
./keycloakctl acceptance --profile offline
```

Read the sanitized, source-bound receipt in `target/keycloakctl/acceptance/` and confirm the executed acceptance stages passed; cleanup is recorded as `not_run`. The offline profile retains its built images and does not perform cleanup or verify cleanup readback. It runs local preflight, Maven/Surefire, provider registration, canonical Python tests/compile, builds and smokes both local images, and checks whitespace. CI invokes the same `--profile offline` command using Docker/Buildx; local development defaults to Podman. The RP fixture smoke runs its image entrypoint, binds an ephemeral loopback listener, checks a fixed rejection response, and shuts down; it is startup evidence only, not RP browser/Keycloak qualification. Remote transfer, readiness, live qualification, teardown of deployed resources, and Registry promotion remain gated and outside this profile. Preserve `scripts/lifecycle.py` for its remaining callers and gates; do not interpret this receipt as full Issue #74 acceptance.

The canonical runtime image is named `localhost/decent-keycloak/wallet-provider`; its labels include the source revision and canonical lifecycle image-input fingerprints. The documented isolated fault-test builds pass a source revision too. Use the runtime receipt's immutable image ID for consumers. To run a periodic local age sweep, use `./keycloakctl images cleanup`. The default age is three days and can be configured with `DECENT_IMAGE_RETENTION_DAYS` or `--max-age-days`. The command only considers images carrying all exact repository/component/role labels, never prunes bases or builder caches, checks active containers, and verifies ownership and absence around removal. Protect a consumer image indefinitely with `./keycloakctl images pin <image-or-id> <name>`; use `./keycloakctl images extend <image-or-id> <days>` for a bounded expiry, and `./keycloakctl images unpin <image-or-id> <name>` to release it. See the README's image-lifecycle section for remote policy and GHCR verification limits.

Legacy `scripts/lifecycle.py` live commands require `--allow-live`, but that flag is not owner approval and must never be treated as authorization. This candidate does not implement approval custody or remote operations; Issue #74 remains incomplete and remote lifecycle, qualification, teardown, and publication are deferred. Do not use legacy remote procedures on the basis of this documentation.

## Documentation and evidence

- Keep the README oriented to new users and the contributor entry path. Put implementation coordination and changing progress in GitHub issues/comments, not in the README.
- Keep detailed test/qualification evidence with its relevant document under `docs/acceptance/`. Bind claims to the source, harness, and image that produced them; distinguish offline fixtures, wrappers, loopback results, and unqualified behavior.
- Never commit credentials, private keys, wallet proofs, raw Identity data, tokens, or unredacted logs/receipts. Use the existing allowlisted/sanitized evidence format.
- Update docs when a command, supported build target, configuration key, lifecycle gate, or qualification status changes. Do not change historical evidence in a way that makes it appear to belong to a newer source/image.
- Respect the pinned Keycloak version and Java 21 major-version compatibility boundary in [`docs/support-policy.md`](docs/support-policy.md). A build pass alone does not extend compatibility.

## Pull requests

Use a focused branch and commit, state the behavior/documentation changed, and list the exact local commands run with their outcomes. Explain limitations and any gates not run. Link the owning issue without closing it unless the complete issue acceptance criteria are verified and closure is explicitly requested. Do not merge or enable auto-merge as part of opening a PR for review.

Before publishing, check the final diff and `git diff --check`; stage only files belonging to the change. Never claim the broader Issue #5 is complete from this documentation or lifecycle slice: its Registry acceptance and remaining remediation criteria are tracked in [Issue #5](https://github.com/jetpen/decent-keycloak/issues/5).
