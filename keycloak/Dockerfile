FROM quay.io/keycloak/keycloak:25.0.2 AS builder

# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_TRANSACTION_XA_ENABLED=false
ENV KC_OTEL=true
# Configure a database vendor
ENV KC_DB=mssql
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin

WORKDIR /opt/keycloak

RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore
RUN /opt/keycloak/bin/kc.sh build --features="admin-fine-grained-authz"

FROM quay.io/keycloak/keycloak:latest
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# COPY import/ /opt/keycloak/data/import
# RUN /opt/keycloak/bin/kc.sh import --dir=/opt/keycloak/data/import/ --override true; exit 0

ENV KC_DB=mssql
ENV KC_DB_URL=jdbc:sqlserver://localhost:1433;databaseName=keycloak;integratedSecurity=true;encrypt=false;
ENV KC_DB_USERNAME=sa
ENV KC_DB_PASSWORD=Abcd1234
ENV KC_HOSTNAME=localhost
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]