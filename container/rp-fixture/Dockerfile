FROM registry.access.redhat.com/ubi9/python-311@sha256:a0bdb55576fc5b8d6704279307817828ef027e1065533ceba133fe9516003a6c
USER 0
WORKDIR /opt/rp-fixture
COPY --from=binary-dependencies /resolver-wheelhouse.tar.gz /tmp/resolver-wheelhouse.tar.gz
COPY requirements/rp-fixture.lock /tmp/rp-fixture.lock
RUN --network=none mkdir -p /tmp/rp-fixture-wheelhouse \
    && tar -xzf /tmp/resolver-wheelhouse.tar.gz -C /tmp/rp-fixture-wheelhouse \
    && python3.11 -m pip install --disable-pip-version-check --no-compile --no-index \
       --find-links=/tmp/rp-fixture-wheelhouse --require-hashes -r /tmp/rp-fixture.lock \
    && rm -rf /tmp/resolver-wheelhouse.tar.gz /tmp/rp-fixture-wheelhouse /tmp/rp-fixture.lock
COPY scripts/oidc_rp_fixture.py /opt/rp-fixture/oidc_rp_fixture.py
LABEL io.decent.image.repository="https://github.com/jetpen/decent-keycloak" \
      io.decent.image.component="decent-keycloak" \
      io.decent.image.role="rp-fixture" \
      io.decent-keycloak.test-only="true"
