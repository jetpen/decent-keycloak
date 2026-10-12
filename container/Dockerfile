ARG KEYCLOAK_BASE=quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad
FROM ${KEYCLOAK_BASE}
COPY target/decent-keycloak-wallet-authenticator-spike-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY target/providers/java-json-canonicalization-1.1.jar /opt/keycloak/providers/
COPY target/providers/core-3.4.0.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
