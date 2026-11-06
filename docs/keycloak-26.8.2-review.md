# Keycloak 26.8.2 upgrade review

The [official 26.8.2 release](https://github.com/keycloak/keycloak/releases/tag/26.8.2), published on November 5, 2026, includes server security fixes. This upgrade is tracked in [Issue #123](https://github.com/rambow-cloud/keycloak/issues/123). The release fragment explicitly identifies account-linking, device authorization ACR, OIDC client-registration and login-page sanitization fixes; the upstream release lists additional changes. These are upstream-declared fixes, not local exploit reproductions.

## Launcher and Java

The [tagged kc.sh](https://github.com/keycloak/keycloak/blob/26.8.2/quarkus/dist/src/main/content/bin/kc.sh) SHA-256 is `5f68e52cc8f86336b4b674e48a465ca9249e27dd4ba5aafa126437b648020afe`, identical to the reviewed 26.8.1 script. Review confirmed the existing system properties, encoding settings, module access, native access and `io.quarkus.bootstrap.runner.QuarkusEntryPoint` remain applicable. The direct Java process remains PID 1; native image CI verifies graceful shutdown.

The [tagged supported configurations](https://github.com/keycloak/keycloak/blob/26.8.2/docs/guides/server/supported-configurations.adoc) still list OpenJDK 17, 21 and 25 LTS, making 25 the latest explicitly supported LTS. Only the reviewed version reference changes in the compatibility baseline; its launcher hash and Java major are preserved.

## Existing dependency exceptions

The [26.8.2 parent POM](https://github.com/keycloak/keycloak/blob/26.8.2/pom.xml) selects Quarkus 3.40.1.1. Its [official BOM](https://repo.maven.apache.org/maven2/io/quarkus/platform/quarkus-bom/3.40.1.1/quarkus-bom-3.40.1.1.pom) still selects Guava 33.6.0-jre and OpenTelemetry core 1.62.0. The [tagged runtime POM](https://github.com/keycloak/keycloak/blob/26.8.2/quarkus/runtime/pom.xml) continues excluding Guava transitive dependencies.

Retain the existing Guava 33.7.2-jre exception for CVE-2026-102554 and coherent fourteen-module OpenTelemetry 1.67.0 exception for CVE-2026-118259. Only their explicitly reviewed Keycloak version changes. Original and replacement JAR checksums, module inventory, pre-augmentation compatibility probes and final-image integrity checks remain enforced. An unexpected distribution payload or a subsequent Keycloak version fails closed. No arbitrary new provider or transitive dependency replacement is introduced.

The parent POM still pins MariaDB JDBC 3.5.10. Do not claim the four MariaDB advisories tracked in [Issue #120](https://github.com/rambow-cloud/keycloak/issues/120) are fixed merely because the Keycloak patch version changes. Fresh native Trivy inventories determine their actual state.

## Validation and publication

Both profiles require native Linux amd64 and arm64 builds with Buildah, Podman runtime/TLS/authentication/shutdown validation, existing dependency probes and checksum-pinned Trivy gates. The publication reuses the exact successful source OCI artifacts and freshly scans every child before an immutable `v26.8.2-r1` Release can complete. Only `26.8.2-r1-core` and `26.8.2-r1-aws` tags are intended; each selects either supported architecture. Release records retain exact source/run/digest evidence. Live cloud database validation and vulnerability-specific exploitation are outside this review.
