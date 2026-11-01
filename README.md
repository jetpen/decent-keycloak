# decent-keycloak

An experimental Keycloak provider for wallet-based sign-in using the provider-neutral [`decent-wallet-login-v1`](https://github.com/jetpen/decent-ecosystem) protocol. This repository implements the Keycloak adapter; it does not include a wallet application or relying-party website. Protocol design and vectors are maintained by [decent-ecosystem](https://github.com/jetpen/decent-ecosystem). The wallet proof-signer is a separate component.

> **Status: experimental — not production-ready.** The supported build target is Keycloak 26.8.0 on Linux/amd64. A passing build, unit suite, image smoke test, or local loopback test does not establish production readiness. Production Registry reliability, real TLS/browser/native-wallet interoperability, and production readiness remain unqualified. See [support policy](docs/support-policy.md), [security review and limitations](docs/security-review.md), and [acceptance records](docs/acceptance/).

## What this provider does

The Keycloak authenticator presents a wallet-login challenge, checks the wallet's proof against the current Identity owner key resolved through the configured Registry, and resumes the bound Keycloak authentication flow on success. The login page displays a QR/transaction locator and polls provider status. A compatible wallet client is required to fetch the challenge and submit the proof; it is not shipped here.

The provider supports explicit `login` and, when enabled by the realm, `signup` intent. It maps the exact Identity ID to a local Keycloak account; Keycloak's opaque user ID remains the OIDC subject. Relying parties remain responsible for validating the signed token and applying their own account policy.

## Build and verify locally

The repository's lifecycle command is the canonical build and offline-acceptance entry point. Start with a narrow test while developing, then complete the offline lifecycle before treating an artifact as an install candidate:

```bash
python3.11 scripts/lifecycle.py run offline
```

The lifecycle checks prerequisites, runs Maven/Surefire and the canonical Python acceptance suite, compiles Python sources, verifies pinned resolver sources and every recorded binary dependency provenance entry, checks provider registration, builds and smoke-tests the Keycloak image, checks whitespace, writes a sanitized receipt under `target/lifecycle/evidence/`, and removes its run-owned image tag. Use `--retain-image` only when a workflow explicitly requires the local immutable image; the default remains cleanup. Inspect the receipt; a successful offline run is not live Registry or wallet qualification. See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites and the contributor workflow.

To inspect the steps without running them:

```bash
python3.11 scripts/lifecycle.py run offline --plan
```

CI invokes the same lifecycle with `ci` on pull requests. `issue5-live` is a separate, opt-in loopback profile and requires explicit authorization plus `--allow-live`; it is not part of normal development or CI:

```bash
python3.11 scripts/lifecycle.py run issue5-live --allow-live
```

Live loopback evidence does not prove production Registry behavior, real TLS, or wallet/browser interoperability. Never treat 503/unavailable as an Identity miss or policy denial. The offline lifecycle downloads the resolver's hash-locked Python/RPM artifacts and commit-pinned source repositories into run-scoped temporary build contexts; it does not contact the Registry. Retaining a local image is a separate opt-in (`--retain-image`) and does not publish it. Registry promotion is a separate command that requires a successful, fully gated `issue5-live` receipt, the retained image's exact immutable ID, an explicit release-candidate destination, and `--allow-publish`; it pushes and reads back the registry manifest before reporting success. No destination or publication is configured by default.

Repository-built image inventory:

| Dockerfile target / role | Purpose and consumers | Lifecycle |
|---|---|---|
| `runtime` / `wallet-provider` | Installable Keycloak 26.8.0 provider image; offline lifecycle smoke and opt-in local/live acceptance profiles consume the exact immutable ID. | Run-scoped tagged build, removed by default; explicit `--retain-image` for local consumers or trusted promotion. |
| `issue7-user-readback-test-runtime` / `wallet-provider-issue7-user-readback-test` | Isolated Issue #7 fault-injection provider for its recovery profile and tests. | Temporary test artifact; never a release role. |
| `issue7-store-recovery-test-runtime` / `wallet-provider-issue7-store-recovery-test` | Isolated Issue #7 datastore-fault provider. | Temporary test artifact; never a release role. |
| `issue6-postconsume-test-runtime` / `wallet-provider-issue6-postconsume-test` | Isolated Issue #6 post-consume receipt-failure provider. | Temporary test artifact; never a release role. |
| `issue6-callback-gate-test-runtime` / `wallet-provider-issue6-callback-gate-test` | Isolated Issue #6 callback-gate fault provider. | Temporary test artifact; never a release role. |
| `resolver-builder`, `keycloak-with-resolver` / intermediate roles | Build intermediates only. | Run-owned intermediates are removed by bounded lifecycle teardown; never promotion targets. |

`container/Dockerfile` pins upstream UBI and Keycloak bases by digest. They are not this repository's artifacts and are excluded from the local age cleaner; builder caches are also out of scope. The only tracked CI workflow is `.github/workflows/acceptance.yml`: it runs the canonical offline lifecycle for pull requests, and neither publishes images nor grants package-write permissions. The `decent-integration-test` repository currently documents Identity CLI integration tests rather than consuming this Keycloak image; no remote image consumer is verified.

## Build and retain a local image

The canonical lifecycle builds the component-and-role image `localhost/decent-keycloak/wallet-provider`, labels it with the source revision and source/artifact fingerprints, and writes the exact immutable image ID to its sanitized receipt. The lifecycle's run tag is unique; use the receipt's `image.immutable_id` for same-machine consumers rather than resolving a mutable tag later. Podman consumers in this and other checkouts share the same per-user local image store; no local registry or remote push is needed.

```bash
python3.11 scripts/lifecycle.py run offline --retain-image
# Read image.immutable_id and image.run_owned_tag from target/lifecycle/evidence/<run-id>.json
podman run --rm --entrypoint /opt/keycloak/bin/kc.sh \
  "sha256:<immutable-image-id>" --version
```

The default lifecycle removes its run-owned image after smoke testing. `--retain-image` is explicit and is not a publication action. The `offline` and `ci` profiles never publish. The PR workflow is pull-request-only, has `contents: read`, and contains no login, push, or package-publication step. Trusted release promotion is a separate manual `scripts/lifecycle.py promote` action and requires a successful gated receipt, a retained immutable source image, an explicit destination, `--allow-publish`, and a source commit already merged into `origin/main`; the command rejects unmerged PR revisions. Publishing does not itself qualify provider/Registry behavior. Consumers of a published image must pin the returned registry manifest digest (`registry/repository@sha256:…`), not its mutable tag.

Repository-built images carry repository/component/role and source-revision labels. The canonical runtime lifecycle additionally labels its image-source and compiled-artifact fingerprints; its temporary tag includes the `lifecycle-<run-id>`. See [Issue #26 lifecycle evidence](docs/acceptance/issue-26-image-lifecycle.md) for the target inventory and verified provenance details.

## Local image retention and cleanup

Run the safe cleanup command periodically (for example, from a user-owned scheduled job). It removes only images with all exact `io.decent.image.*` repository/component/role labels that are older than three days, and only after read-back confirms the same image ID/labels and no container uses it. It never runs `image prune`, and never selects upstream bases, builder caches, unlabeled images, recent images, pinned images, or active-container images.

```bash
python3.11 scripts/image_lifecycle.py cleanup
DECENT_IMAGE_RETENTION_DAYS=7 python3.11 scripts/image_lifecycle.py cleanup
python3.11 scripts/image_lifecycle.py pin sha256:<immutable-image-id> integration-test
python3.11 scripts/image_lifecycle.py extend sha256:<immutable-image-id> 14
python3.11 scripts/image_lifecycle.py unpin sha256:<immutable-image-id> integration-test
```

The `pin-*` tag protects an image indefinitely until removed with `unpin`; `retain-until-<UTC timestamp>` tags created by `extend` protect it until that expiry. Extension days are bounded to 1–3650. Cleanup checks active containers both before selection and immediately before removal, and fails closed if inventory, ownership readback, or removal verification is inconclusive.

## Remote promotion and retention policy

Local builds and PR CI do not publish. Remote promotion is a separate, explicit maintainer action that requires a passing gated receipt, a retained immutable source image, a trusted source commit, an explicit destination, and `--allow-publish`. Published consumers must use the returned manifest digest, not a mutable release-candidate tag. The current verification limits and interim expiry/release procedure are recorded in [Issue #26 lifecycle evidence](docs/acceptance/issue-26-image-lifecycle.md).

Before publishing to any registry, verify its package permissions and retention behavior. Do not configure GHCR or claim a package is available until that check succeeds. Keep a release-candidate manifest while a named downstream consumer still uses its digest; review unconsumed candidates every 30 days and retire unconsumed candidates within 90 days after confirming no consumer references them. Any extension requires a named owner, reason, and next review date. Delete only the exact candidate tag after the no-consumer check, then verify the tag is absent. These are interim review intervals, not verified registry-enforced expiry limits; see the linked evidence for the unresolved registry/consumer constraints.

The image is an experimental Keycloak 26.8.0 runtime and is not production-ready. Building or publishing it is not wallet-login or Registry acceptance qualification. For local prerequisites and lifecycle details, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Configure a disposable realm

Before enabling the authenticator, configure the realm with the following attributes. Set the bootstrap peer and client port together; the resolver returns unavailable when they are missing or incomplete. Values are realm-specific; use the exact HTTPS origins that match the trusted Keycloak public hostname/proxy and wallet origin.

| Realm attribute | Requirement | Purpose |
|---|---|---|
| `decent.wallet.site-name` | Required | Human-readable relying-party label shown on the Keycloak wallet page. |
| `decent.wallet.browser-origin` | Required for browser-wallet requests | Exact HTTPS Origin of the wallet web client. |
| `decent.wallet.trusted-origins` | Optional | Comma-separated exact wallet-origin allowlist; when set it must include the browser origin. |
| `decent.wallet.registry.bootstrap` | Required with `registry.client-port` | Comma-separated Registry bootstrap peer addresses. |
| `decent.wallet.registry.client-port` | Required with `registry.bootstrap` | Registry client listen port, 1–65535. |
| `decent.wallet.identity.executable` | Optional | Fixed command `decent-identity` or an absolute executable path; defaults to `/opt/decent-resolver/bin/decent-identity`. |
| `decent.wallet.idp-origin` | Optional assertion | If set, must exactly match Keycloak's trusted HTTPS public origin; it cannot override it. |

In the realm's authentication flow, add **Decent wallet challenge (development spike)** as a `REQUIRED` execution and set `trusted-origins` to the exact HTTPS Keycloak public origin (include a non-default port). Configure the Keycloak public hostname/proxy before enabling this flow; do not derive trusted origins from arbitrary request headers. For `signup`, enable realm user registration deliberately; otherwise use login-only behavior. Register exact HTTPS redirect URIs on the OIDC client as usual.

The extension endpoint is mounted at `/realms/{realm}/decent-wallet-login`; the login page renders the QR/locator, but the compatible wallet must perform challenge retrieval and proof submission. The repository does not currently provide a complete end-user wallet flow, deployment chart, or production configuration recipe.

## Scope and evidence

- [Issue #5 Registry matrix](docs/acceptance/issue-5-registry-matrix.md) records live acceptance gaps and limits.
- [Issue #6 qualification](docs/acceptance/issue-6-qualification.md) records single-node transaction/replay evidence and remaining gates.
- [Issue #7 qualification](docs/acceptance/issue-7-renewed-qualification.md) records the scoped signup/recovery results.
- [Support policy](docs/support-policy.md) defines the narrow build-time target and upgrade process.

Build/test evidence is not an endorsement for production use. Do not infer Registry absence, identity denial, stale-key rejection, or production support from an unavailable response or offline fixture. Keep implementation status and coordination in the owning [GitHub issues](https://github.com/jetpen/decent-keycloak/issues), not in this README.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, local checks, evidence handling, and pull-request expectations. Report security issues privately rather than posting credentials, proof material, or unredacted logs in public issues.
