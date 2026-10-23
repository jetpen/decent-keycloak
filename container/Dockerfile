# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM registry.access.redhat.com/ubi9/python-311@sha256:a0bdb55576fc5b8d6704279307817828ef027e1065533ceba133fe9516003a6c AS resolver-builder
USER 0
WORKDIR /resolver-build
COPY container/rotation_registry_roundtrip.py ./rotation_registry_roundtrip.py
COPY container/source-archives/identity.tar.gz container/source-archives/registry.tar.gz ./
COPY container/verify_resolver_runtime_inputs.py ./verify_resolver_runtime_inputs.py
COPY container/resolver-runtime.lock.json container/registry-lock-constraints.txt container/resolver-requirements.in container/resolver-requirements.lock.txt container/resolver-build-requirements.lock.txt ./
COPY container/resolver-wheelhouse.tar.gz ./resolver-wheelhouse.tar.gz
COPY container/gmp-devel-6.2.0-13.el9.x86_64.rpm ./gmp-devel.rpm
COPY container/cpio-2.13-16.el9.x86_64.rpm ./cpio.rpm
RUN printf '%s  %s\n' "6ff0d4c41ae5aa8834bbc9a88bfa30cb8386aae6ebb9b13467b55a6d996098ff" resolver-requirements.lock.txt | sha256sum --check \
 && printf '%s  %s\n' "70387e4aedbe5e9561243a8195d14d90dd6e68d74672c26678f2de938dec5539" registry-lock-constraints.txt | sha256sum --check \
 && printf '%s  %s\n' "6f209b51694b56c0d4bd9760004303349c6b23217e828b85c07a7e778844fe9c" resolver-build-requirements.lock.txt | sha256sum --check \
 && printf '%s  %s\n' "d9b53fda4b8757fd63b53a415f533ab876c18c28a94fd21d10658de85978f254" cpio.rpm | sha256sum --check \
 && rpm -i --nodeps cpio.rpm \
 && test "$(sha256sum resolver-requirements.lock.txt | cut -d ' ' -f 1)" = "$(python3.11 -c 'import json; print(json.load(open("resolver-runtime.lock.json"))["runtime_requirements"]["lock_sha256"])')" \
 && test "$(sha256sum registry-lock-constraints.txt | cut -d ' ' -f 1)" = "$(python3.11 -c 'import json; print(json.load(open("resolver-runtime.lock.json"))["registry_dependency_lock"]["registry_lock_constraints_sha256"])')"
RUN mkdir -p /tmp/gmp-root /opt/decent-resolver/lib /usr/lib64 \
 && printf '%s  %s\n' "8dae9819eeba660528c52e7c5a3ac1e354084ea5782088160d9b46e9d43dde97" gmp-devel.rpm | sha256sum --check \
 && rpm2cpio gmp-devel.rpm | /usr/bin/cpio -idm --quiet -D /tmp/gmp-root \
 && cp /tmp/gmp-root/usr/include/gmp.h /usr/include/gmp.h \
 && cp /tmp/gmp-root/usr/include/gmp-x86_64.h /usr/include/gmp-x86_64.h \
 && cp /lib64/libgmp.so.10.4.0 /opt/decent-resolver/lib/libgmp.so.10.4.0 \
 && printf '%s  %s\n' "b9d1265de01c92a6565272aa3ffa30034fe3656c73c348fc988a2e65389d6782" /opt/decent-resolver/lib/libgmp.so.10.4.0 | sha256sum --check \
 && ln -s libgmp.so.10.4.0 /opt/decent-resolver/lib/libgmp.so.10 \
 && ln -s /opt/decent-resolver/lib/libgmp.so.10.4.0 /usr/lib64/libgmp.so

RUN python3.11 verify_resolver_runtime_inputs.py --archives . --manifest resolver-runtime.lock.json \
 && mkdir -p /resolver-build/wheelhouse /opt/decent-resolver/identity-src /opt/decent-resolver/registry-src \
 && tar -xzf resolver-wheelhouse.tar.gz -C /resolver-build/wheelhouse \
 && tar -xzf identity.tar.gz --strip-components=1 -C /opt/decent-resolver/identity-src \
 && tar -xzf registry.tar.gz --strip-components=1 -C /opt/decent-resolver/registry-src
RUN python3.11 -m venv --copies /opt/decent-resolver/venv \
 && /opt/decent-resolver/venv/bin/python -m pip install --disable-pip-version-check --no-compile --no-index --find-links=/resolver-build/wheelhouse --require-hashes -r resolver-build-requirements.lock.txt \
 && /opt/decent-resolver/venv/bin/python -m pip install --disable-pip-version-check --no-compile --no-index --find-links=/resolver-build/wheelhouse --no-build-isolation --require-hashes -r resolver-requirements.lock.txt
RUN mkdir -p /opt/decent-resolver/bin \
 && cat > /opt/decent-resolver/bin/decent-identity <<'EOF'
#!/bin/sh
set -eu
export PYTHONPATH=/opt/decent-resolver/identity-src/src:/opt/decent-resolver/registry-src/src:/opt/decent-resolver/venv/lib64/python3.11/site-packages
unset PYTHONHOME
unset PYTHONPATH_OVERRIDE
export LD_LIBRARY_PATH=/opt/decent-resolver/lib
exec /opt/decent-resolver/venv/bin/python -c 'from decent_identity.cli import main; main()' "$@"
EOF
RUN cat > /opt/decent-resolver/bin/decent-registry <<'EOF'
#!/bin/sh
set -eu
export PYTHONPATH=/opt/decent-resolver/registry-src/src:/opt/decent-resolver/venv/lib64/python3.11/site-packages:/opt/decent-resolver/venv/lib/python3.11/site-packages
unset PYTHONHOME
export LD_LIBRARY_PATH=/opt/decent-resolver/lib
exec /opt/decent-resolver/venv/bin/python -c 'from decent_registry.cli import main; main()' "$@"
EOF
RUN chmod 0755 /opt/decent-resolver/bin/decent-identity /opt/decent-resolver/bin/decent-registry \
 && cp rotation_registry_roundtrip.py /opt/decent-resolver/rotation_registry_roundtrip.py \
 && python3.11 -m compileall -q /opt/decent-resolver/identity-src/src /opt/decent-resolver/registry-src/src \
 && /opt/decent-resolver/bin/decent-registry --help >/dev/null

FROM quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad AS keycloak-with-resolver
USER 0
COPY --from=resolver-builder /opt/decent-resolver/ /opt/decent-resolver/
COPY --from=resolver-builder /usr/lib64/python3.11/ /usr/lib64/python3.11/
COPY --from=resolver-builder /usr/lib64/libpython3.11.so.1.0 /usr/lib64/libpython3.11.so.1.0
COPY --from=resolver-builder /usr/lib64/libssl.so.3 /usr/lib64/libssl.so.3
COPY --from=resolver-builder /usr/lib64/libcrypto.so.3 /usr/lib64/libcrypto.so.3
COPY --from=resolver-builder /usr/bin/python3.11 /usr/bin/python3.11
COPY --from=resolver-builder /opt/decent-resolver/lib/libgmp.so.10.4.0 /usr/lib64/libgmp.so.10.4.0
COPY --from=resolver-builder /usr/include/gmp.h /usr/include/gmp.h
RUN if [ ! -e /etc/resolv.conf ]; then \
      printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf; \
      created_resolv_conf=1; \
    else \
      created_resolv_conf=0; \
    fi \
 && ln -sf libpython3.11.so.1.0 /usr/lib64/libpython3.11.so \
 && ln -sf libgmp.so.10.4.0 /usr/lib64/libgmp.so.10 \
 && chmod 0755 /usr/lib64/libgmp.so.10.4.0 \
 && python3.11 -c 'import ssl, sqlite3, sys; assert sys.version_info[:3] == (3, 11, 13)' \
 && /opt/decent-resolver/bin/decent-identity --help >/dev/null \
 && PYTHONPATH=/opt/decent-resolver/registry-src/src:/opt/decent-resolver/venv/lib64/python3.11/site-packages:/opt/decent-resolver/venv/lib/python3.11/site-packages LD_LIBRARY_PATH=/opt/decent-resolver/lib python3.11 -c 'from decent_registry.cli import main; main()' --help >/dev/null \
 && if [ "$created_resolv_conf" = 1 ]; then rm -f /etc/resolv.conf; fi
USER 1000

FROM keycloak-with-resolver AS runtime
COPY target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY target/providers/java-json-canonicalization-1.1.jar /opt/keycloak/providers/
COPY target/providers/core-3.4.0.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build --spi-single-use-object--provider=infinispan

# The fault injector exists only in this separately built test target.
FROM runtime AS issue7-user-readback-test-runtime
USER 0
COPY target/issue7-user-readback-provider.jar /opt/keycloak/providers/
USER 1000
RUN /opt/keycloak/bin/kc.sh build --spi-user--provider-default=issue7-user-readback-fault
