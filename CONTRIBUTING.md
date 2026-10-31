# Contributing

Thanks for helping improve the experimental decent-keycloak provider. Keep changes focused, explain user-visible and security-relevant behavior, and do not present a local/offline result as live or production qualification.

## Prerequisites

Install the tools below before running `scripts/lifecycle.py`. Versions are the lifecycle's current declared/checked values; where the project does not pin a patch version, that is stated explicitly rather than implying a tested version range.

| Tool | Required version | Notes |
|---|---|---|
| CPython | **3.11.13** | Exact version checked by lifecycle preflight and used by CI. |
| Java build JDK | **Eclipse Temurin 21.0.12.1+1** | Lifecycle checks Java 21; this exact distribution/build is the CI target. |
| Apache Maven | Installed and on `PATH`; **version not pinned by the lifecycle** | Used for `mvn clean package` and Surefire. |
| Git | Installed and on `PATH`; **version not pinned by the lifecycle** | Required for source fingerprints, diff checks, and version control. |
| Podman | Installed, daemon/service available; **version not pinned by the lifecycle** | Default local container engine. Pinned base images must already be present; local build uses `--pull=never`. |
| Docker Engine + Buildx | Installed and available; **versions not pinned by the lifecycle** | Alternative container path; Buildx must be enabled. CI uses Buildx on `ubuntu-24.04`. |
| OpenSSL | Installed; **version not pinned** | Required only for the opt-in `issue5-live` profile. |

You need one supported container path: Podman, or Docker with Buildx. The normal offline lifecycle needs network access to materialize pinned Identity/Registry source checkouts and Maven dependencies. Python package and UBI RPM inputs are inventoried in [`container/resolver-binary-dependencies.lock.json`](container/resolver-binary-dependencies.lock.json): it records each package version, upstream distribution URL, and SHA-256, while the runtime verifier checks the wheelhouse contents against that inventory and the hash-locked requirements before use. Update this inventory and its digest in `container/resolver-runtime.lock.json` whenever a bundled dependency changes. Podman's image build does not pull base images by default; arrange the pinned base images before running it or explicitly use the documented `--pull-base-images` option. Docker Buildx pulls the digest-pinned bases. The provider image build's Dockerfile `RUN` steps are network-isolated.

## Local development workflow

Work from a clean branch based on the current default branch, and keep each change limited to its requested scope. Before coding, read the relevant source, tests, and acceptance/support docs. For implementation changes, add or update the owning tests; run focused tests while iterating.

Check available lifecycle commands and the offline plan:

```bash
python3.11 scripts/lifecycle.py --help
python3.11 scripts/lifecycle.py profiles
python3.11 scripts/lifecycle.py run offline --plan
```

Before committing or pushing, run the complete offline acceptance lifecycle from the working tree:

```bash
python3.11 scripts/lifecycle.py run offline
```

Read the sanitized receipt in `target/lifecycle/evidence/` and confirm each required stage passed. The lifecycle runs Maven/Surefire, the canonical Python suite, Python compilation, pinned resolver-source materialization and verification, provider SPI registration, the runtime image build and version smoke, whitespace checks, evidence retention, and bounded teardown. PR CI runs the same named lifecycle as independent verification; it is not a substitute for completing local acceptance before publishing the PR.

The `issue5-live` profile is a separate networked loopback qualification. It is not a default test, and it is not authorized by a code change, successful offline run, or PR request. Run it only after the owning human explicitly approves the exact live run; the CLI additionally requires `--allow-live`:

```bash
python3.11 scripts/lifecycle.py run issue5-live --allow-live
```

A passing loopback test is limited to its recorded environment and case. It does not establish production Registry behavior, real TLS, browser/native-wallet compatibility, or production readiness. Keep `not_run`, failure, and unavailable states distinct; in particular, HTTP 503/unavailable is not a clean Identity miss.

## Documentation and evidence

- Keep the README oriented to new users and the contributor entry path. Put implementation coordination and changing progress in GitHub issues/comments, not in the README.
- Keep detailed test/qualification evidence with its relevant document under `docs/acceptance/`. Bind claims to the source, harness, and image that produced them; distinguish offline fixtures, wrappers, loopback results, and unqualified behavior.
- Never commit credentials, private keys, wallet proofs, raw Identity data, tokens, or unredacted logs/receipts. Use the existing allowlisted/sanitized evidence format.
- Update docs when a command, supported build target, configuration key, lifecycle gate, or qualification status changes. Do not change historical evidence in a way that makes it appear to belong to a newer source/image.
- Respect the exact Keycloak/JDK/runtime tuple and upgrade policy in [`docs/support-policy.md`](docs/support-policy.md). A build pass alone does not extend compatibility.

## Pull requests

Use a focused branch and commit, state the behavior/documentation changed, and list the exact local commands run with their outcomes. Explain limitations and any gates not run. Link the owning issue without closing it unless the complete issue acceptance criteria are verified and closure is explicitly requested. Do not merge or enable auto-merge as part of opening a PR for review.

Before publishing, check the final diff and `git diff --check`; stage only files belonging to the change. Never claim the broader Issue #5 is complete from this documentation or lifecycle slice: its Registry acceptance and remaining remediation criteria are tracked in [Issue #5](https://github.com/jetpen/decent-keycloak/issues/5).
