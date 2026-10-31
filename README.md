# decent-keycloak

An experimental Keycloak provider for wallet-based sign-in using the provider-neutral [`decent-wallet-login-v1`](https://github.com/jetpen/decent-ecosystem) protocol. This repository implements the Keycloak adapter; it does not include a wallet application or relying-party website. Protocol design and vectors are maintained by [decent-ecosystem](https://github.com/jetpen/decent-ecosystem). The wallet proof-signer is a separate component.

> **Status: experimental — not production-ready.** The supported build target is Keycloak 26.8.0 on Linux/amd64. A passing build, unit suite, image smoke test, or local loopback test does not establish production readiness. Real TLS/browser/native-wallet interoperability and full current-Registry acceptance remain incomplete. See [support policy](docs/support-policy.md), [security review and limitations](docs/security-review.md), and [acceptance records](docs/acceptance/).

## What this provider does

The Keycloak authenticator presents a wallet-login challenge, checks the wallet's proof against the current Identity owner key resolved through the configured Registry, and resumes the bound Keycloak authentication flow on success. The login page displays a QR/transaction locator and polls provider status. A compatible wallet client is required to fetch the challenge and submit the proof; it is not shipped here.

The provider supports explicit `login` and, when enabled by the realm, `signup` intent. It maps the exact Identity ID to a local Keycloak account; Keycloak's opaque user ID remains the OIDC subject. Relying parties remain responsible for validating the signed token and applying their own account policy.

## Build and verify locally

The repository's lifecycle command is the canonical build and offline-acceptance entry point. Start with a narrow test while developing, then complete the offline lifecycle before treating an artifact as an install candidate:

```bash
python3.11 scripts/lifecycle.py run offline
```

The lifecycle checks prerequisites, runs Maven/Surefire and the canonical Python acceptance suite, compiles Python sources, verifies pinned resolver sources and every recorded binary dependency provenance entry, checks provider registration, builds and smoke-tests the Keycloak image, checks whitespace, writes a sanitized receipt under `target/lifecycle/evidence/`, and tears down its run-owned image tag. Inspect the receipt; a successful offline run is not live Registry or wallet qualification. See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites and the contributor workflow.

To inspect the steps without running them:

```bash
python3.11 scripts/lifecycle.py run offline --plan
```

CI invokes the same lifecycle with `ci` on pull requests. `issue5-live` is a separate, opt-in loopback profile and requires explicit authorization plus `--allow-live`; it is not part of normal development or CI:

```bash
python3.11 scripts/lifecycle.py run issue5-live --allow-live
```

Live loopback evidence does not prove production Registry behavior, real TLS, or wallet/browser interoperability. Never treat 503/unavailable as an Identity miss or policy denial.

## Build an installable local image

No release image is published by this repository. The offline lifecycle deliberately removes its temporary image after smoke testing. To keep a local image for evaluation, first run the offline lifecycle above, then build a separately tagged image from the same pinned sources. The following Podman example assumes the lifecycle prerequisites are installed and pinned base images are already present locally; it leaves the resulting image in Podman and removes only its temporary source checkout:

```bash
set -eu
mvn --batch-mode --no-transfer-progress clean package
source_parent="$(mktemp -d)"
trap 'rm -rf -- "$source_parent"' EXIT
sources="$source_parent/sources"
python3.11 container/build_resolver_runtime.py \
  --materialize-sources --sources-directory "$sources"
python3.11 container/verify_resolver_runtime_inputs.py --sources "$sources"
podman build --no-cache --pull=never --network=none \
  --build-context "identity-src=$sources/identity" \
  --build-context "registry-src=$sources/registry" \
  --file container/Dockerfile --target runtime \
  --tag localhost/decent-keycloak-wallet-provider:local .
podman run --rm --entrypoint /opt/keycloak/bin/kc.sh \
  localhost/decent-keycloak-wallet-provider:local --version
```

The image is an optimized Keycloak 26.8.0 runtime containing this provider and the pinned resolver runtime. Use it as the Keycloak image in a disposable evaluation environment. Do not deploy this development target to production. To pull pinned base images during the build, use an explicit authorized image-pull workflow; the lifecycle's Podman default is `--pull=never`.

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
