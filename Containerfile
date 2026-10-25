# Build arguments are supplied exclusively from images.lock.json by scripts/build.sh.
ARG KEYCLOAK_IMAGE
ARG RUNTIME_IMAGE
FROM ${KEYCLOAK_IMAGE} AS builder
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_METRICS_ENABLED=true
RUN /opt/keycloak/bin/kc.sh build
USER 0
RUN rm -rf /opt/keycloak/bin && mkdir -p /opt/keycloak/data && chmod -R a+rX /opt/keycloak

FROM ${RUNTIME_IMAGE}
COPY --from=builder --chown=0:0 /opt/keycloak /opt/keycloak
COPY --from=builder --chown=65532:65532 /opt/keycloak/data /opt/keycloak/data
COPY --chown=0:0 config/java.options /opt/keycloak/java.options
ENV KC_DB=postgres KC_HEALTH_ENABLED=true KC_METRICS_ENABLED=true \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:MinRAMPercentage=70 -XX:InitialRAMPercentage=50"
WORKDIR /opt/keycloak
USER 65532:65532
EXPOSE 8080 8443 9000
ENTRYPOINT ["/usr/bin/java", "@/opt/keycloak/java.options", "-cp", "/opt/keycloak/lib/quarkus-run.jar", "io.quarkus.bootstrap.runner.QuarkusEntryPoint"]
CMD ["start", "--optimized"]
