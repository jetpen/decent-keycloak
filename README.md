# decent-keycloak

An experimental Keycloak provider for wallet-based sign-in using the provider-neutral [`decent-wallet-login-v1`](https://github.com/jetpen/decent-ecosystem) protocol. This repository implements the Keycloak adapter; it does not include a wallet application or relying-party website. Protocol design and vectors are maintained by [decent-ecosystem](https://github.com/jetpen/decent-ecosystem). The wallet proof-signer is a separate component.

> **Status: experimental — not production-ready.** The supported build target is Keycloak 26.8.0 on Linux/amd64. A passing build, unit suite, image smoke test, or local loopback test does not establish production readiness. Production Registry reliability, real TLS/browser/native-wallet interoperability, and production readiness remain unqualified. See [support policy](docs/support-policy.md), [security review and limitations](docs/security-review.md), and [acceptance records](docs/acceptance/).

## What this provider does

The Keycloak authenticator presents a wallet-login challenge, checks the wallet's proof against the current Identity owner key resolved through the configured Registry, and resumes the bound Keycloak authentication flow on success. The login page displays a QR/transaction locator and polls provider status. A compatible wallet client is required to fetch the challenge and submit the proof; it is not shipped here.

The provider supports explicit `login` and, when enabled by the realm, `signup` intent. It maps the exact Identity ID to a local Keycloak account; Keycloak's opaque user ID remains the OIDC subject. Relying parties remain responsible for validating the signed token and applying their own account policy.

## Build and verify locally

The `keycloakctl` acceptance entry point is used locally and by pull-request CI. Start with a narrow test while developing, then run the shared offline profile before treating an artifact as an install candidate:

```bash
./keycloakctl acceptance --profile offline
```

The command runs local preflight, Maven/Surefire and canonical Python suites, compiles Python sources, builds both provider and test-only RP fixture images, runs their offline smokes, checks whitespace, and writes a sanitized source-bound receipt. Offline acceptance retains its built images and records cleanup as `not_run`; remove eligible repository images only through the separate explicit `./keycloakctl images cleanup` action. The RP fixture smoke executes the image entrypoint, starts a loopback listener on an ephemeral port, checks a fixed safe response, and shuts down without issuer access. This is local startup evidence only, not browser/Keycloak or live qualification. See [CONTRIBUTING.md](CONTRIBUTING.md) and the migration map.

Issue #74 is incomplete. This candidate covers local preparation/build/test, a **local-only run-intent receipt** (not the proposed #73 owner-approved qualification intent), and offline acceptance; remote lifecycle, qualification, manual evidence, and publication are deferred. Legacy `scripts/lifecycle.py` options such as `--allow-live` are not owner approval and do not authorize remote operations. Do not infer authorization from the flag or from this offline acceptance receipt. See [CONTRIBUTING.md](CONTRIBUTING.md) for the local contributor path.

This inventory describes repository-built images used by existing local and legacy lifecycle helpers. This Issue #74 candidate changes only local preparation/build/test and a local-only run-intent receipt, plus offline acceptance; it does not add or qualify the live lifecycle described below.

| Dockerfile target / role | Purpose and consumers | Lifecycle |
|---|---|---|
| `runtime` / `wallet-provider` | Installable Keycloak 26.8.0 provider image; consumed by existing local lifecycle helpers. | Legacy run-scoped tagged build; Issue #74 local-only candidate does not add or qualify live profiles or trusted promotion. |
| `issue7-user-readback-test-runtime` / `wallet-provider-issue7-user-readback-test` | Isolated Issue #7 fault-injection provider for its recovery profile and tests. | Temporary test artifact; never a release role. |
| `issue7-store-recovery-test-runtime` / `wallet-provider-issue7-store-recovery-test` | Isolated Issue #7 datastore-fault provider. | Temporary test artifact; never a release role. |
| `issue6-postconsume-test-runtime` / `wallet-provider-issue6-postconsume-test` | Isolated Issue #6 post-consume receipt-failure provider. | Temporary test artifact; never a release role. |
| `issue6-callback-gate-test-runtime` / `wallet-provider-issue6-callback-gate-test` | Isolated Issue #6 callback-gate fault provider. | Temporary test artifact; never a release role. |
| `resolver-builder`, `keycloak-with-resolver` / intermediate roles | Build intermediates only. | Run-owned intermediates are removed by bounded lifecycle teardown; never promotion targets. |

`container/Dockerfile` pins upstream UBI and Keycloak bases by digest. They are not this repository's artifacts and are excluded from the local age cleaner; builder caches are also out of scope. For pull requests, `.github/workflows/acceptance.yml` runs keycloakctl's Maven/Surefire, provider service-registration, canonical Python, compilation, whitespace, provider-image build/smoke, and test-only RP fixture image build/smoke stages using the offline profile. It does not publish images, contact a remote target, or grant package-write permissions. The `decent-integration-test` repository currently documents Identity CLI integration tests rather than consuming this Keycloak image; no remote image consumer is verified. The PR workflow's image build/smoke does not exercise `keycloakctl full`; that path remains separately covered by focused tests.

## Legacy local image lifecycle (outside this Issue #74 candidate)

The existing canonical lifecycle builds the component-and-role image `localhost/decent-keycloak/wallet-provider`, labels it with the source revision and source/artifact fingerprints, and writes the exact immutable image ID to its sanitized receipt. The lifecycle's run tag is unique; use the receipt's `image.immutable_id` for same-machine consumers rather than resolving a mutable tag later. Podman consumers in this and other checkouts share the same per-user local image store; no local registry or remote push is needed. This existing helper is not exercised by the Issue #74 local-only `full` command.

Build and retain a local image with the existing canonical lifecycle by using its legacy offline run with `--retain-image`; this is separate from keycloakctl acceptance and Issue #74's local-only candidate.

```bash
python3.11 scripts/lifecycle.py run offline --retain-image  # legacy helper; not keycloakctl acceptance or full
# Read image.immutable_id and image.run_owned_tag from target/lifecycle/evidence/<run-id>.json
podman run --rm --entrypoint /opt/keycloak/bin/kc.sh \
  "sha256:<immutable-image-id>" --version
```

The offline acceptance profile is pull-request-only and does not publish or contact a remote target. PR CI retains local build images; local image cleanup is a separate explicit action. This bounded acceptance is not a qualification or release decision.

Repository-built images carry repository/component/role and source-revision labels. The canonical runtime lifecycle additionally labels its image-source and compiled-artifact fingerprints; its temporary tag includes the `lifecycle-<run-id>`. See [Issue #26 lifecycle evidence](docs/acceptance/issue-26-image-lifecycle.md) for the target inventory and verified provenance details.

## Local image retention and cleanup

Run the safe cleanup command periodically (for example, every 3 days from a user-owned scheduled job). It removes only images with all exact `io.decent.image.*` repository/component/role labels that are older than three days, and only after read-back confirms the same image ID/labels and no container uses it. It never runs `image prune`, and never selects upstream bases, builder caches, unlabeled images, recent images, pinned images, or active-container images.

```bash
./keycloakctl images cleanup
DECENT_IMAGE_RETENTION_DAYS=7 ./keycloakctl images cleanup
./keycloakctl images pin sha256:<immutable-image-id> integration-test
./keycloakctl images extend sha256:<immutable-image-id> 14
./keycloakctl images unpin sha256:<immutable-image-id> integration-test
```

The `pin-*` tag protects an image indefinitely until removed with `unpin`; `retain-until-<UTC timestamp>` tags created by `extend` protect it until that expiry. Extension days are bounded to 1–3650. Cleanup checks active containers both before selection and immediately before removal, and fails closed if inventory, ownership readback, or removal verification is inconclusive.

For any future explicitly published release candidate, the owner-approved manual policy is to check named consumers and pinned digests every 3 days, then retire an unconsumed candidate by day 7 only after confirming no consumer references it. Active consumers require a named, time-bounded exception; this remote policy is not a registry-enforced TTL and is outside the Issue #74 local-only candidate.

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
- [Issue #8 TLS/browser/native-wallet/OIDC qualification](docs/acceptance/issue-8-tls-browser-wallet-oidc.md) records the unqualified live-client gates and offline OIDC-validation slice.
- [Support policy](docs/support-policy.md) defines the narrow build-time target and upgrade process.

Build/test evidence is not an endorsement for production use. Do not infer Registry absence, identity denial, stale-key rejection, or production support from an unavailable response or offline fixture. Keep implementation status and coordination in the owning [GitHub issues](https://github.com/jetpen/decent-keycloak/issues), not in this README.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, local checks, evidence handling, and pull-request expectations. Report security issues privately rather than posting credentials, proof material, or unredacted logs in public issues.
