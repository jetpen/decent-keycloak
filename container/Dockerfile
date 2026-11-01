# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM registry.access.redhat.com/ubi9/python-311@sha256:a0bdb55576fc5b8d6704279307817828ef027e1065533ceba133fe9516003a6c AS resolver-builder
ARG LIFECYCLE_RUN_ID=manual
ARG IMAGE_ROLE=resolver-builder
ARG SOURCE_REVISION
ARG IMAGE_SOURCE_SHA256
ARG IMAGE_ARTIFACTS_SHA256
RUN --network=none \
    case "$SOURCE_REVISION" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#SOURCE_REVISION}" -ge 40 && test "${#SOURCE_REVISION}" -le 64 && \
    case "$IMAGE_SOURCE_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_SOURCE_SHA256}" -eq 64 && \
    case "$IMAGE_ARTIFACTS_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_ARTIFACTS_SHA256}" -eq 64
LABEL io.decent.lifecycle.run-id="$LIFECYCLE_RUN_ID" \
      io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="$IMAGE_ROLE" \
      io.decent.image.source-revision="$SOURCE_REVISION" \
      io.decent.image.source-sha256="$IMAGE_SOURCE_SHA256" \
      io.decent.image.artifacts-sha256="$IMAGE_ARTIFACTS_SHA256"
USER 0
WORKDIR /resolver-build
COPY container/rotation_registry_roundtrip.py ./rotation_registry_roundtrip.py
COPY --from=identity-src /.pinned-commit ./sources/identity/.pinned-commit
COPY --from=identity-src /src ./sources/identity/src
COPY --from=registry-src /.pinned-commit ./sources/registry/.pinned-commit
COPY --from=registry-src /src ./sources/registry/src
COPY container/verify_resolver_runtime_inputs.py ./verify_resolver_runtime_inputs.py
COPY container/patch_resolver_runtime.py container/pinned_lookup_outcomes.py ./
COPY scripts/test_pinned_dht_peer_outcomes.py scripts/test_pinned_registry_lookup_outcomes.py scripts/test_pinned_adversarial_identity_peer.py scripts/test_rotation_registry_roundtrip.py scripts/rotation_registry_roundtrip.py scripts/issue5_adversarial_cases.py ./scripts/
COPY container/resolver-runtime.lock.json container/registry-lock-constraints.txt container/resolver-requirements.in container/resolver-requirements.lock.txt container/resolver-build-requirements.lock.txt ./
COPY container/resolver-binary-dependencies.lock.json ./
COPY --from=binary-dependencies /resolver-wheelhouse.tar.gz ./resolver-wheelhouse.tar.gz
COPY --from=binary-dependencies /gmp-devel-6.2.0-13.el9.x86_64.rpm ./gmp-devel-6.2.0-13.el9.x86_64.rpm
COPY --from=binary-dependencies /cpio-2.13-16.el9.x86_64.rpm ./cpio-2.13-16.el9.x86_64.rpm
RUN --network=none python3.11 verify_resolver_runtime_inputs.py --sources /resolver-build/sources --manifest resolver-runtime.lock.json --dependencies /resolver-build
RUN --network=none printf '%s  %s\n' "6ff0d4c41ae5aa8834bbc9a88bfa30cb8386aae6ebb9b13467b55a6d996098ff" resolver-requirements.lock.txt | sha256sum --check \
 && printf '%s  %s\n' "70387e4aedbe5e9561243a8195d14d90dd6e68d74672c26678f2de938dec5539" registry-lock-constraints.txt | sha256sum --check \
 && printf '%s  %s\n' "6f209b51694b56c0d4bd9760004303349c6b23217e828b85c07a7e778844fe9c" resolver-build-requirements.lock.txt | sha256sum --check \
 && printf '%s  %s\n' "d9b53fda4b8757fd63b53a415f533ab876c18c28a94fd21d10658de85978f254" cpio-2.13-16.el9.x86_64.rpm | sha256sum --check \
 && rpm -i --nodeps cpio-2.13-16.el9.x86_64.rpm \
 && test "$(sha256sum resolver-requirements.lock.txt | cut -d ' ' -f 1)" = "$(python3.11 -c 'import json; print(json.load(open("resolver-runtime.lock.json"))["runtime_requirements"]["lock_sha256"])')" \
 && test "$(sha256sum registry-lock-constraints.txt | cut -d ' ' -f 1)" = "$(python3.11 -c 'import json; print(json.load(open("resolver-runtime.lock.json"))["registry_dependency_lock"]["registry_lock_constraints_sha256"])')"
RUN --network=none mkdir -p /tmp/gmp-root /opt/decent-resolver/lib /usr/lib64 \
 && printf '%s  %s\n' "8dae9819eeba660528c52e7c5a3ac1e354084ea5782088160d9b46e9d43dde97" gmp-devel-6.2.0-13.el9.x86_64.rpm | sha256sum --check \
 && rpm2cpio gmp-devel-6.2.0-13.el9.x86_64.rpm | /usr/bin/cpio -idm --quiet -D /tmp/gmp-root \
 && cp /tmp/gmp-root/usr/include/gmp.h /usr/include/gmp.h \
 && cp /tmp/gmp-root/usr/include/gmp-x86_64.h /usr/include/gmp-x86_64.h \
 && cp /lib64/libgmp.so.10.4.0 /opt/decent-resolver/lib/libgmp.so.10.4.0 \
 && printf '%s  %s\n' "b9d1265de01c92a6565272aa3ffa30034fe3656c73c348fc988a2e65389d6782" /opt/decent-resolver/lib/libgmp.so.10.4.0 | sha256sum --check \
 && ln -s libgmp.so.10.4.0 /opt/decent-resolver/lib/libgmp.so.10 \
 && ln -s /opt/decent-resolver/lib/libgmp.so.10.4.0 /usr/lib64/libgmp.so

RUN --network=none python3.11 verify_resolver_runtime_inputs.py --sources /resolver-build/sources --manifest resolver-runtime.lock.json --dependencies /resolver-build \
 && mkdir -p /resolver-build/wheelhouse /opt/decent-resolver/identity-src /opt/decent-resolver/registry-src \
 && tar -xzf resolver-wheelhouse.tar.gz -C /resolver-build/wheelhouse \
 && cp -a /resolver-build/sources/identity/src /opt/decent-resolver/identity-src/ \
 && cp -a /resolver-build/sources/registry/src /opt/decent-resolver/registry-src/
RUN --network=none python3.11 -m venv --copies /opt/decent-resolver/venv \
 && /opt/decent-resolver/venv/bin/python -m pip install --disable-pip-version-check --no-compile --no-index --find-links=/resolver-build/wheelhouse --require-hashes -r resolver-build-requirements.lock.txt \
 && /opt/decent-resolver/venv/bin/python -m pip install --disable-pip-version-check --no-compile --no-index --find-links=/resolver-build/wheelhouse --no-build-isolation --require-hashes -r resolver-requirements.lock.txt
RUN --network=none /opt/decent-resolver/venv/bin/python patch_resolver_runtime.py \
 --site-packages "/opt/decent-resolver/venv/lib64/python3.11/site-packages" \
 --registry-file /opt/decent-resolver/registry-src/src/decent_registry/dht/libp2p_dht.py \
 && /opt/decent-resolver/venv/bin/python -m compileall -q /opt/decent-resolver/venv/lib64/python3.11/site-packages/libp2p/kad_dht /opt/decent-resolver/registry-src/src
RUN --network=none mkdir -p /opt/decent-resolver/bin \
 && cat > /opt/decent-resolver/bin/decent-identity <<'EOF'
#!/bin/sh
set -eu
export PYTHONPATH=/opt/decent-resolver/identity-src/src:/opt/decent-resolver/registry-src/src:/opt/decent-resolver/venv/lib64/python3.11/site-packages
unset PYTHONHOME
unset PYTHONPATH_OVERRIDE
export LD_LIBRARY_PATH=/opt/decent-resolver/lib
exec /opt/decent-resolver/venv/bin/python -c 'from decent_identity.cli import main; main()' "$@"
EOF
RUN --network=none cat > /opt/decent-resolver/bin/decent-registry <<'EOF'
#!/bin/sh
set -eu
export PYTHONPATH=/opt/decent-resolver/registry-src/src:/opt/decent-resolver/venv/lib64/python3.11/site-packages:/opt/decent-resolver/venv/lib/python3.11/site-packages
unset PYTHONHOME
export LD_LIBRARY_PATH=/opt/decent-resolver/lib
exec /opt/decent-resolver/venv/bin/python -c 'from decent_registry.cli import main; main()' "$@"
EOF
RUN --network=none chmod 0755 /opt/decent-resolver/bin/decent-identity /opt/decent-resolver/bin/decent-registry \
 && cp rotation_registry_roundtrip.py /opt/decent-resolver/rotation_registry_roundtrip.py \
 && python3.11 -m compileall -q /opt/decent-resolver/identity-src/src /opt/decent-resolver/registry-src/src
RUN --network=none if [ ! -e /etc/resolv.conf ]; then \
      printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf; \
      created_resolv_conf=1; \
    else \
      created_resolv_conf=0; \
    fi \
 && LD_LIBRARY_PATH=/opt/decent-resolver/lib /opt/decent-resolver/venv/bin/python /resolver-build/scripts/test_pinned_dht_peer_outcomes.py \
 && RESOLVER_TEST_REGISTRY_SOURCE=/opt/decent-resolver/registry-src/src LD_LIBRARY_PATH=/opt/decent-resolver/lib /opt/decent-resolver/venv/bin/python /resolver-build/scripts/test_pinned_registry_lookup_outcomes.py \
 && RESOLVER_TEST_LIBP2P_SOURCE=/opt/decent-resolver/venv/lib64/python3.11/site-packages/libp2p RESOLVER_TEST_REGISTRY_SOURCE=/opt/decent-resolver/registry-src/src RESOLVER_TEST_IDENTITY_SOURCE=/opt/decent-resolver/identity-src/src PYTHONPATH=/resolver-build:/resolver-build/scripts:/opt/decent-resolver/identity-src/src:/opt/decent-resolver/registry-src/src:/opt/decent-resolver/venv/lib64/python3.11/site-packages LD_LIBRARY_PATH=/opt/decent-resolver/lib /opt/decent-resolver/venv/bin/python /resolver-build/scripts/test_pinned_adversarial_identity_peer.py \
 && PYTHONPATH=/resolver-build:/resolver-build/scripts:/opt/decent-resolver/identity-src/src:/opt/decent-resolver/registry-src/src:/opt/decent-resolver/venv/lib64/python3.11/site-packages LD_LIBRARY_PATH=/opt/decent-resolver/lib /opt/decent-resolver/venv/bin/python /resolver-build/scripts/test_rotation_registry_roundtrip.py \
 && /opt/decent-resolver/bin/decent-identity --help >/dev/null \
 && /opt/decent-resolver/bin/decent-registry --help >/dev/null \
 && if [ "$created_resolv_conf" = 1 ]; then rm -f /etc/resolv.conf; fi

FROM quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad AS keycloak-with-resolver
ARG LIFECYCLE_RUN_ID=manual
ARG IMAGE_ROLE=keycloak-with-resolver
ARG SOURCE_REVISION
ARG IMAGE_SOURCE_SHA256
ARG IMAGE_ARTIFACTS_SHA256
RUN --network=none \
    case "$SOURCE_REVISION" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#SOURCE_REVISION}" -ge 40 && test "${#SOURCE_REVISION}" -le 64 && \
    case "$IMAGE_SOURCE_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_SOURCE_SHA256}" -eq 64 && \
    case "$IMAGE_ARTIFACTS_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_ARTIFACTS_SHA256}" -eq 64
LABEL io.decent.lifecycle.run-id="$LIFECYCLE_RUN_ID" \
      io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="$IMAGE_ROLE" \
      io.decent.image.source-revision="$SOURCE_REVISION" \
      io.decent.image.source-sha256="$IMAGE_SOURCE_SHA256" \
      io.decent.image.artifacts-sha256="$IMAGE_ARTIFACTS_SHA256"
USER 0
COPY --from=resolver-builder /opt/decent-resolver/ /opt/decent-resolver/
COPY --from=resolver-builder /usr/lib64/python3.11/ /usr/lib64/python3.11/
COPY --from=resolver-builder /usr/lib64/libpython3.11.so.1.0 /usr/lib64/libpython3.11.so.1.0
COPY --from=resolver-builder /usr/lib64/libssl.so.3 /usr/lib64/libssl.so.3
COPY --from=resolver-builder /usr/lib64/libcrypto.so.3 /usr/lib64/libcrypto.so.3
COPY --from=resolver-builder /usr/bin/python3.11 /usr/bin/python3.11
COPY --from=resolver-builder /opt/decent-resolver/lib/libgmp.so.10.4.0 /usr/lib64/libgmp.so.10.4.0
COPY --from=resolver-builder /usr/include/gmp.h /usr/include/gmp.h
USER 1000

FROM keycloak-with-resolver AS runtime
ARG LIFECYCLE_RUN_ID=manual
ARG IMAGE_ROLE=wallet-provider
ARG SOURCE_REVISION
ARG IMAGE_SOURCE_SHA256
ARG IMAGE_ARTIFACTS_SHA256
RUN --network=none \
    case "$SOURCE_REVISION" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#SOURCE_REVISION}" -ge 40 && test "${#SOURCE_REVISION}" -le 64 && \
    case "$IMAGE_SOURCE_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_SOURCE_SHA256}" -eq 64 && \
    case "$IMAGE_ARTIFACTS_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_ARTIFACTS_SHA256}" -eq 64
LABEL io.decent.lifecycle.run-id="$LIFECYCLE_RUN_ID" \
      io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="$IMAGE_ROLE" \
      io.decent.image.source-revision="$SOURCE_REVISION" \
      io.decent.image.source-sha256="$IMAGE_SOURCE_SHA256" \
      io.decent.image.artifacts-sha256="$IMAGE_ARTIFACTS_SHA256"
COPY target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY target/providers/java-json-canonicalization-1.1.jar /opt/keycloak/providers/
COPY target/providers/core-3.4.0.jar /opt/keycloak/providers/
RUN --network=none /opt/keycloak/bin/kc.sh build --db=dev-file --cache=local --spi-single-use-object--provider-default=infinispan

# The fault injector exists only in this separately built test target.
FROM runtime AS issue7-user-readback-test-runtime
ARG LIFECYCLE_RUN_ID=manual
ARG IMAGE_ROLE=wallet-provider-issue7-user-readback-test
ARG SOURCE_REVISION
ARG IMAGE_SOURCE_SHA256
ARG IMAGE_ARTIFACTS_SHA256
RUN --network=none \
    case "$SOURCE_REVISION" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#SOURCE_REVISION}" -ge 40 && test "${#SOURCE_REVISION}" -le 64 && \
    case "$IMAGE_SOURCE_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_SOURCE_SHA256}" -eq 64 && \
    case "$IMAGE_ARTIFACTS_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_ARTIFACTS_SHA256}" -eq 64
LABEL io.decent.lifecycle.run-id="$LIFECYCLE_RUN_ID" \
      io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="$IMAGE_ROLE" \
      io.decent.image.source-revision="$SOURCE_REVISION" \
      io.decent.image.source-sha256="$IMAGE_SOURCE_SHA256" \
      io.decent.image.artifacts-sha256="$IMAGE_ARTIFACTS_SHA256"
USER 0
COPY target/issue7-user-readback-provider.jar /opt/keycloak/providers/
USER 1000
RUN --network=none /opt/keycloak/bin/kc.sh build --db=dev-file --cache=local --http-relative-path=/auth --spi-single-use-object--provider-default=infinispan --spi-datastore--provider-default=issue7-user-readback-fault

# Opt-in store fault wrapper; never included in the production runtime target.
FROM runtime AS issue7-store-recovery-test-runtime
ARG LIFECYCLE_RUN_ID=manual
ARG IMAGE_ROLE=wallet-provider-issue7-store-recovery-test
ARG SOURCE_REVISION
ARG IMAGE_SOURCE_SHA256
ARG IMAGE_ARTIFACTS_SHA256
RUN --network=none \
    case "$SOURCE_REVISION" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#SOURCE_REVISION}" -ge 40 && test "${#SOURCE_REVISION}" -le 64 && \
    case "$IMAGE_SOURCE_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_SOURCE_SHA256}" -eq 64 && \
    case "$IMAGE_ARTIFACTS_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_ARTIFACTS_SHA256}" -eq 64
LABEL io.decent.lifecycle.run-id="$LIFECYCLE_RUN_ID" \
      io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="$IMAGE_ROLE" \
      io.decent.image.source-revision="$SOURCE_REVISION" \
      io.decent.image.source-sha256="$IMAGE_SOURCE_SHA256" \
      io.decent.image.artifacts-sha256="$IMAGE_ARTIFACTS_SHA256"
COPY target/issue7-fault-provider.jar /opt/keycloak/providers/
RUN --network=none /opt/keycloak/bin/kc.sh build --db=dev-file --cache=local --http-relative-path=/auth --spi-single-use-object--provider-default=issue7-fault-injection

# The Issue #6 receipt fault decorator is available only in this isolated test image.
FROM keycloak-with-resolver AS issue6-postconsume-test-runtime
ARG LIFECYCLE_RUN_ID=manual
ARG IMAGE_ROLE=wallet-provider-issue6-postconsume-test
ARG SOURCE_REVISION
ARG IMAGE_SOURCE_SHA256
ARG IMAGE_ARTIFACTS_SHA256
RUN --network=none \
    case "$SOURCE_REVISION" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#SOURCE_REVISION}" -ge 40 && test "${#SOURCE_REVISION}" -le 64 && \
    case "$IMAGE_SOURCE_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_SOURCE_SHA256}" -eq 64 && \
    case "$IMAGE_ARTIFACTS_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_ARTIFACTS_SHA256}" -eq 64
LABEL io.decent.lifecycle.run-id="$LIFECYCLE_RUN_ID" \
      io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="$IMAGE_ROLE" \
      io.decent.image.source-revision="$SOURCE_REVISION" \
      io.decent.image.source-sha256="$IMAGE_SOURCE_SHA256" \
      io.decent.image.artifacts-sha256="$IMAGE_ARTIFACTS_SHA256"
COPY target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY target/providers/java-json-canonicalization-1.1.jar /opt/keycloak/providers/
COPY target/providers/core-3.4.0.jar /opt/keycloak/providers/
COPY target/issue6-postconsume-receipt-failure-provider.jar /opt/keycloak/providers/
RUN --network=none /opt/keycloak/bin/kc.sh build --db=dev-file --cache=local --spi-single-use-object--provider-default=issue6-postconsume-receipt-failure

# The sibling callback-gate injector is isolated from both production and receipt-failure targets.
FROM keycloak-with-resolver AS issue6-callback-gate-test-runtime
ARG LIFECYCLE_RUN_ID=manual
ARG IMAGE_ROLE=wallet-provider-issue6-callback-gate-test
ARG SOURCE_REVISION
ARG IMAGE_SOURCE_SHA256
ARG IMAGE_ARTIFACTS_SHA256
RUN --network=none \
    case "$SOURCE_REVISION" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#SOURCE_REVISION}" -ge 40 && test "${#SOURCE_REVISION}" -le 64 && \
    case "$IMAGE_SOURCE_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_SOURCE_SHA256}" -eq 64 && \
    case "$IMAGE_ARTIFACTS_SHA256" in ""|*[!0-9a-f]*) exit 1;; esac && \
    test "${#IMAGE_ARTIFACTS_SHA256}" -eq 64
LABEL io.decent.lifecycle.run-id="$LIFECYCLE_RUN_ID" \
      io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="$IMAGE_ROLE" \
      io.decent.image.source-revision="$SOURCE_REVISION" \
      io.decent.image.source-sha256="$IMAGE_SOURCE_SHA256" \
      io.decent.image.artifacts-sha256="$IMAGE_ARTIFACTS_SHA256"
COPY target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY target/providers/java-json-canonicalization-1.1.jar /opt/keycloak/providers/
COPY target/providers/core-3.4.0.jar /opt/keycloak/providers/
COPY target/issue6-postconsume-callback-gate-failure-provider.jar /opt/keycloak/providers/
RUN --network=none /opt/keycloak/bin/kc.sh build --db=dev-file --cache=local --spi-single-use-object--provider-default=issue6-postconsume-callback-gate-failure
