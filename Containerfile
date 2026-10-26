# Build arguments are supplied exclusively from images.lock.json by scripts/build.sh.
ARG KEYCLOAK_IMAGE
ARG BUILD_IMAGE
ARG RUNTIME_IMAGE
ARG UBI_BUILD_IMAGE
ARG KEYCLOAK_JAVA_MAJOR
FROM ${KEYCLOAK_IMAGE} AS distribution

FROM ${UBI_BUILD_IMAGE} AS ubi-runtime-builder
USER 0
COPY scripts/prepare-ubi-runtime.sh /tmp/prepare-ubi-runtime.sh
RUN bash /tmp/prepare-ubi-runtime.sh

FROM ${BUILD_IMAGE} AS source
ARG KEYCLOAK_JAVA_MAJOR
COPY --from=distribution /opt/keycloak /opt/keycloak
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
COPY --from=ubi-runtime-builder /opt/ubi-root/ /
COPY licenses/UBI-EULA.pdf /licenses/UBI-EULA.pdf
COPY --chown=0:0 config/java.options /opt/keycloak/java.options
ENV LANG=en_US.UTF-8
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_METRICS_ENABLED=true \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:MinRAMPercentage=70 -XX:InitialRAMPercentage=50"
WORKDIR /opt/keycloak
LABEL org.opencontainers.image.description="Experimental UBI Micro Keycloak runtime; branch evaluation only" \
    com.redhat.license_terms="https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf"
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
