# Build arguments are supplied exclusively from images.lock.json by scripts/build.sh.
ARG KEYCLOAK_IMAGE
ARG BUILD_IMAGE
ARG RUNTIME_IMAGE
ARG KEYCLOAK_JAVA_MAJOR
FROM ${KEYCLOAK_IMAGE} AS distribution

FROM ${BUILD_IMAGE} AS source
ARG KEYCLOAK_JAVA_MAJOR
COPY --from=distribution /opt/keycloak /opt/keycloak
COPY .cache/keycloak/ /tmp/keycloak-dependencies/
COPY tests/GuavaCompatibility.java /tmp/GuavaCompatibility.java
# Preserve the filename referenced by Quarkus' existing app model; the payload's
# Maven metadata is 33.7.2-jre. Verify both payloads before reaugmentation.
RUN cd /opt/keycloak && sha256sum -c /tmp/keycloak-dependencies/upstream.sha256 \
    && target=$(cut -d ' ' -f 3 /tmp/keycloak-dependencies/upstream.sha256) \
    && cp /tmp/keycloak-dependencies/guava.jar "$target" \
    && sha256sum -c /tmp/keycloak-dependencies/patched.sha256 \
    && javac -cp '/opt/keycloak/lib/lib/main/*' -d /tmp /tmp/GuavaCompatibility.java \
    && java -Xmx64m -cp '/tmp:/opt/keycloak/lib/lib/main/*' GuavaCompatibility "$(cat /tmp/keycloak-dependencies/version.txt)" \
    && rm -rf /tmp/keycloak-dependencies /tmp/GuavaCompatibility.java /tmp/GuavaCompatibility.class
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_METRICS_ENABLED=true
RUN java -version 2>&1 | grep -F "version \"${KEYCLOAK_JAVA_MAJOR}."

FROM source AS core-builder
RUN /opt/keycloak/bin/kc.sh build
USER 0
RUN rm -rf /opt/keycloak/bin && mkdir -p /opt/keycloak/data && chmod -R a+rX /opt/keycloak

FROM source AS aws-builder
COPY .cache/aws/providers/ /opt/keycloak/providers/
COPY tests/AwsHttpTransport.java /tmp/AwsHttpTransport.java
RUN javac -cp '/opt/keycloak/providers/*:/opt/keycloak/lib/lib/main/*' -d /tmp /tmp/AwsHttpTransport.java \
    && java -cp '/tmp:/opt/keycloak/providers/*:/opt/keycloak/lib/lib/main/*' AwsHttpTransport
ENV KC_DB_DRIVER=software.amazon.jdbc.Driver KC_TRANSACTION_XA_ENABLED=false
RUN /opt/keycloak/bin/kc.sh build
RUN rm -rf /opt/keycloak/bin && mkdir -p /opt/keycloak/data && chmod -R a+rX /opt/keycloak

FROM ${RUNTIME_IMAGE} AS runtime
COPY --chown=0:0 config/java.options /opt/keycloak/java.options
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_METRICS_ENABLED=true \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:MinRAMPercentage=70 -XX:InitialRAMPercentage=50"
WORKDIR /opt/keycloak
USER 65532:65532
VOLUME ["/tmp", "/opt/keycloak/data"]
EXPOSE 8080 8443 9000
ENTRYPOINT ["/usr/bin/java", "@/opt/keycloak/java.options", "-cp", "/opt/keycloak/lib/quarkus-run.jar", "io.quarkus.bootstrap.runner.QuarkusEntryPoint"]
CMD ["start", "--optimized"]

FROM runtime AS aws
COPY --from=aws-builder --chown=0:0 /opt/keycloak /opt/keycloak
COPY --from=aws-builder --chown=65532:65532 /opt/keycloak/data /opt/keycloak/data
COPY --chown=0:0 .cache/aws/certs/rds-ca-bundle.pem /opt/keycloak/certs/rds-ca-bundle.pem
ENV KC_DB_DRIVER=software.amazon.jdbc.Driver KC_TRANSACTION_XA_ENABLED=false \
    KC_DB_TLS_MODE=verify-server KC_DB_TLS_TRUST_STORE_FILE=/opt/keycloak/certs/rds-ca-bundle.pem

# Keep the generic image as the default final target for direct Containerfile users.
FROM runtime AS core
COPY --from=core-builder --chown=0:0 /opt/keycloak /opt/keycloak
COPY --from=core-builder --chown=65532:65532 /opt/keycloak/data /opt/keycloak/data
