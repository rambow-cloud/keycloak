# Keycloak distribution security overrides

`overrides.lock.json` temporarily pins Guava 33.7.2-jre for Keycloak 26.8.1 to remediate [CVE-2026-102554](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94). The official [33.7.2 release](https://github.com/google/guava/releases/tag/v33.7.2) identifies the fix and its failureaccess runtime dependency. No vulnerability finding is suppressed.

The build downloads the official Maven Central JAR on the host, verifies its committed SHA-256, then checks the original distribution JAR's checksum before replacing it in the shared source stage. Both core/aws reaugment only after replacement. The existing `com.google.guava.guava-33.6.0-jre.jar` filename is intentionally retained because Quarkus' existing app model references it; its actual payload and Maven metadata are 33.7.2-jre. No duplicate Guava JAR is added. The build-stage probe exercises actual distribution linkage, collections, splitting, weak-key maps and normal serialization. Full image CI verifies runtime behavior and scans the actual JAR metadata.

Keycloak 26.8.1 explicitly [excludes Guava's transitive dependencies](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/runtime/pom.xml). This override preserves that upstream dependency graph and does not add failureaccess or claim support for Guava futures/loading-cache APIs requiring it.

A different Keycloak version or upstream JAR checksum fails closed. On the next upstream upgrade, inspect the distribution: remove this override when it already includes a fixed Guava, or explicitly review its new source/dependency graph and hashes. Never update the expected checksum merely to pass CI. No JARs or build tools are fetched by the final runtime.
