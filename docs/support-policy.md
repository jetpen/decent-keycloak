# Supported build boundary and upgrade policy

**Status: experimental, build-time support boundary only. This is not a production support statement.** The provider is compiled against Keycloak internals and is qualified only for the exact tuple below after its required gates pass. A passing package or image build does not imply compatibility with other releases or a production deployment.

## Candidate supported tuple

| Component | Exact target | Evidence source / limitation |
|---|---|---|
| Keycloak API and runtime | **26.8.0** | `pom.xml` sets `keycloak.version` to `26.8.0`. `container/Dockerfile` uses `quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad`; CI builds the provider into that image and checks the runtime-reported version. No other Keycloak release is claimed. |
| JDK used for build and tests | **Eclipse Temurin JDK 21.0.12.1+1** | CI pins this exact Temurin release and checks `java -version`. The project compiler release is 21. No other compiler JDK major, distribution or patch build is declared supported by this policy. |
| JDK bundled in the Keycloak runtime | **Red Hat OpenJDK 21.0.12.1+1-LTS**, as reported by the pinned Keycloak image | CI checks the exact runtime JVM line from `kc.sh --version`; this is distinct from the Temurin build JDK. No externally supplied JVM or other runtime build is claimed. |
| Provider runtime container | **Linux/amd64**, based on the Keycloak digest above | The resulting provider image is built from the exact immutable Keycloak base in `container/Dockerfile`. This repository does not publish that image. No ARM or other platform claim is made. |
| Resolver builder/runtime | **UBI 9**, `registry.access.redhat.com/ubi9/python-311@sha256:a0bdb55576fc5b8d6704279307817828ef027e1065533ceba133fe9516003a6c`, Python **3.11.13**, UBI 9 / glibc 2.34 | Version and source/dependency identities are recorded in `container/resolver-runtime.lock.json`; the Dockerfile verifies vendored RPM/source/lock hashes. This is a build/runtime component, not a supported host-Python matrix. |
| CI host | **GitHub-hosted `ubuntu-24.04`** | This is the currently configured acceptance runner, not a claim that all Ubuntu 24.04 installations are equivalent. The runner image itself is maintained by GitHub and is not pinned by digest. |
| Python acceptance interpreter | **CPython 3.11.13** | CI selects this interpreter for the repository's Python harness and compilation checks. Other Python versions are not acceptance-tested by this workflow. |

The Keycloak digest is authoritative for the runtime base identity; its version label is checked in CI rather than inferred from a mutable tag. The workflow's Java/Python tool versions are explicit, and all `uses:` actions are pinned to immutable full commit SHAs. These controls improve repeatability but do not make the Maven build hermetic: Maven dependencies still resolve from repositories by coordinates, and the hosted runner/tool-download services remain external inputs.

## Administrative CI setting

A green workflow does not configure GitHub branch protection or make its status required. A repository administrator must require the `Provider acceptance (Java 21 / Python 3.11 / amd64)` check for the protected integration/release branches after confirming its exact GitHub status context. This workflow creates no branch rules, status checks, or auto-close behavior.

## Upgrade policy

Do not widen or advance the supported tuple by changing only a version number or relying on semver. For a candidate Keycloak/JDK/container update:

1. Review the Keycloak release and migration notes, SPI/API changes, JDK compatibility, container base digest, and all changed transitive/runtime inputs. Record the candidate exact versions and digests.
2. Update the Maven Keycloak API version and matching runtime base digest together. Keep the resolver builder image, source archives, RPMs and Python locks checksum-verified. Refresh the Dockerfile frontend digest when intentionally upgrading it.
3. Run the complete required CI suite on the candidate: clean Java package and Surefire totals, all Python harness tests, Python compilation, resolver/vector provenance checks, diff validation, and a no-cache provider-image build. Verify the built image reports the exact candidate Keycloak version and discovers/builds the provider.
4. Execute the relevant disposable integration gates on the exact candidate image and record immutable image identity, source revision, harness identity, reached stages, and limits in the README evidence ledger. A fresh-start smoke is not migration, rolling-upgrade, rollback, cluster, or production evidence.
5. Obtain an independent security/code review of the resulting diff and update this policy only for the tuple whose required evidence actually passed. Preserve the previous tuple's evidence; do not retroactively label it as evidence for the candidate.

Until those steps finish, describe the new version as a candidate and keep affected rows `not-run` or `not-qualified`. No forward-release compatibility, persisted-state migration, mixed-version rolling upgrade, rollback restoration, optimized-startup behavior, or database/backend matrix is claimed here. There is no automatic fallback to another Keycloak version. Treat a security update as an urgent candidate that still needs a tested artifact and explicit review; this policy does not justify deploying an unverified upgrade.
