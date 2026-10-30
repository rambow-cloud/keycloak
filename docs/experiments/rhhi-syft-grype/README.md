# Red Hat Hardened Java 25 comparison

Issue: [#89](https://github.com/rambow-cloud/keycloak/issues/89). Retained branch: `chore/89-rhhi-syft-grype`. **Do not merge this branch.**

Tested code: `5a3eb5c638761df8fa44a18e188ee15072904ea3`. [Native Actions run](https://github.com/rambow-cloud/keycloak/actions/runs/40982781434), result: **failure**. Complete [machine evidence](results.json) retains exact candidate/baseline index and child digests, scanner hashes, database identity, findings, compatibility and certificate outcomes.

Only the effective runtime input changed. Keycloak 26.8.1, Java major 25, builder, PostgreSQL, provider locks, Guava and OpenTelemetry overrides remain identical to the reviewed source. The baseline uses the exact published r4 children; it was not rebuilt.

## Result

- **Compatibility:** all four candidate core/aws native runtime suites passed on amd64/arm64. All eight candidate/baseline certificate regressions passed, including 14 incident chains and both controls.
- **CVE counts:** no overall reduction. Every pair reports **66 → 84 package findings** and **41 → 44 unique CVEs**, while HIGH entries change **17 → 0**.
- **JVM:** candidate Red Hat `25.0.4.1+1`; baseline Temurin `25.0.5+8-LTS`. Of the candidate findings, 80 are JVM package entries representing 40 CVEs; four other package findings remain. The Debian baseline feed reports no JVM matches, which is not comprehensive JVM clearance.
- **Scan acceptance:** the workflow failed its Java identity guard. Syft catalogs the patched OpenTelemetry JARs as old 1.62.0 coordinates despite 1.67.0 manifest metadata. [Diagnostics](catalog-diagnostics.json) retain all 14 exact official payload identities for all eight inventories, verified against the reviewed SHA-256 lock. This does not mean the r4 fix was lost. Raw SBOMs and Grype reports are not modified.
- **Recommendation:** keep this branch for evaluation; these results do not justify replacing the production runtime. No merge, registry push or Release occurred.

## Same-database results

| Runtime | Profile | Architecture | Findings | Unique CVEs | Critical / High / Medium | Fixable HIGH/CRITICAL | Scan completeness |
| --- | --- | --- | ---: | ---: | --- | ---: | --- |
| distroless | aws | amd64 | 66 | 41 | 0 / 17 / 25 | 0 | coverage-failed |
| rhhi | aws | amd64 | 84 | 44 | 0 / 0 / 57 | 0 | coverage-failed |
| distroless | aws | arm64 | 66 | 41 | 0 / 17 / 25 | 0 | coverage-failed |
| rhhi | aws | arm64 | 84 | 44 | 0 / 0 / 57 | 0 | coverage-failed |
| distroless | core | amd64 | 66 | 41 | 0 / 17 / 25 | 0 | coverage-failed |
| rhhi | core | amd64 | 84 | 44 | 0 / 0 / 57 | 0 | coverage-failed |
| distroless | core | arm64 | 66 | 41 | 0 / 17 / 25 | 0 | coverage-failed |
| rhhi | core | arm64 | 84 | 44 | 0 / 0 / 57 | 0 | coverage-failed |

## Inputs and scanner coverage

Syft **1.55.0**, Grype **0.121.0**. Database SHA-256: `4c2b606e9f83984fe5f683a8b1088ab50e05d3c7aa2d5d0529143dc312a15f11`. Built: `2026-10-29T06:23:34Z`. All four native jobs consume the identical database archive with automatic updates disabled.

Candidate: `registry.access.redhat.com/hi/openjdk:25-runtime@sha256:48196e83cf2c3355e52a29995b97023fbc50e1fc592d1a0a7fd0208c998c1189`. The public Red Hat base is consumed unchanged; its licenses and package metadata remain in its layers. Runtime platform children and scanner archives are pinned in [inputs.lock.json](inputs.lock.json).

At report time, the official `latest-runtime` alias resolved to the same tested digest; see [registry alias evidence](registry-alias.json). The observed Java 25.0.4.1 runtime is therefore not an arbitrarily selected older runtime digest. This statement is limited to the checked OpenJDK runtime alias, not every Red Hat Java product or variant.

Raw inventories and Grype reports are in `rhhi-result-<profile>-<architecture>-1` Actions artifacts for seven days. This Git report retains normalized matches, package/JVM identity, namespaces, source digests, raw-report hashes and controls beyond artifact expiry.

## Four Debian util-linux HIGH alerts

- **distroless / aws / amd64**: `CVE-2026-76642` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78408` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78409` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78410` (`libuuid1 2.41.5-0+deb13u1`).
- **rhhi / aws / amd64**: none reported.
- **distroless / aws / arm64**: `CVE-2026-76642` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78408` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78409` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78410` (`libuuid1 2.41.5-0+deb13u1`).
- **rhhi / aws / arm64**: none reported.
- **distroless / core / amd64**: `CVE-2026-76642` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78408` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78409` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78410` (`libuuid1 2.41.5-0+deb13u1`).
- **rhhi / core / amd64**: none reported.
- **distroless / core / arm64**: `CVE-2026-76642` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78408` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78409` (`libuuid1 2.41.5-0+deb13u1`), `CVE-2026-78410` (`libuuid1 2.41.5-0+deb13u1`).
- **rhhi / core / arm64**: none reported.

## Runtime and certificate checks

| Runtime | Profile | Architecture | Actual Java / vendor | Runtime suite | Certificate chains |
| --- | --- | --- | --- | --- | --- |
| distroless | aws | amd64 | 25.0.5+8-LTS / Eclipse Adoptium | previously-validated-r4 | passed |
| rhhi | aws | amd64 | 25.0.4.1+1 / Red Hat, Inc. | success | passed |
| distroless | aws | arm64 | 25.0.5+8-LTS / Eclipse Adoptium | previously-validated-r4 | passed |
| rhhi | aws | arm64 | 25.0.4.1+1 / Red Hat, Inc. | success | passed |
| distroless | core | amd64 | 25.0.5+8-LTS / Eclipse Adoptium | previously-validated-r4 | passed |
| rhhi | core | amd64 | 25.0.4.1+1 / Red Hat, Inc. | success | passed |
| distroless | core | arm64 | 25.0.5+8-LTS / Eclipse Adoptium | previously-validated-r4 | passed |
| rhhi | core | arm64 | 25.0.4.1+1 / Red Hat, Inc. | success | passed |

## Package and trust-store visibility

- **distroless / aws / amd64**: OS packages / app JARs 25 / 527, JVM inventory temurin-25-jre 25.0.5.0.0+8-1 (deb); trust anchors 148, incident-root flags false / false.
- **rhhi / aws / amd64**: OS packages / app JARs 47 / 527, JVM inventory java-25-openjdk-crypto-adapter 1:25.0.4.1.1-1.1.hum1 (rpm), java-25-openjdk-headless 1:25.0.4.1.1-1.1.hum1 (rpm); trust anchors 118, incident-root flags false / false.
- **distroless / aws / arm64**: OS packages / app JARs 25 / 527, JVM inventory temurin-25-jre 25.0.5.0.0+8-0 (deb); trust anchors 148, incident-root flags false / false.
- **rhhi / aws / arm64**: OS packages / app JARs 47 / 527, JVM inventory java-25-openjdk-crypto-adapter 1:25.0.4.1.1-1.1.hum1 (rpm), java-25-openjdk-headless 1:25.0.4.1.1-1.1.hum1 (rpm); trust anchors 118, incident-root flags false / false.
- **distroless / core / amd64**: OS packages / app JARs 25 / 495, JVM inventory temurin-25-jre 25.0.5.0.0+8-1 (deb); trust anchors 148, incident-root flags false / false.
- **rhhi / core / amd64**: OS packages / app JARs 47 / 495, JVM inventory java-25-openjdk-crypto-adapter 1:25.0.4.1.1-1.1.hum1 (rpm), java-25-openjdk-headless 1:25.0.4.1.1-1.1.hum1 (rpm); trust anchors 118, incident-root flags false / false.
- **distroless / core / arm64**: OS packages / app JARs 25 / 495, JVM inventory temurin-25-jre 25.0.5.0.0+8-0 (deb); trust anchors 148, incident-root flags false / false.
- **rhhi / core / arm64**: OS packages / app JARs 47 / 495, JVM inventory java-25-openjdk-crypto-adapter 1:25.0.4.1.1-1.1.hum1 (rpm), java-25-openjdk-headless 1:25.0.4.1.1-1.1.hum1 (rpm); trust anchors 118, incident-root flags false / false.

The certificate probe comes from retained `chore/37-emudhra-regression` commit `4c997af311311f1c756f10076ca8c580934cee62`, using the checksummed public fixtures in the main security evidence. It checks 14 incident chains at their historical validation time, a normal trusted chain and identical incident chains after restoring only the two incident roots.

## Limits and retained failures

- Branch-only experiment; no merge to main, image registry push or formal release.
- One frozen Grype database and the same pinned native Syft/Grype versions were used for all eight scans. Positive/negative Guava controls are retained.
- Raw finding/advisory counts reflect vendor feed, package splitting and JVM identification differences. A lower count does not prove proportionally lower exploitable risk.
- JVM inventory/matches are recorded separately. Neither source proves exhaustive JVM vulnerability coverage.
- Certificate regression is offline historical-time PKIX validation with normal and restored-root controls, not live HTTPS/RDS/PolarDB certification.
- The experiment does not change or satisfy the production Trivy gate. Workflow execution success alone does not indicate production readiness.
- Initial preparation attempts stopped before image construction: whole-file hashing exceeded 2 GiB, then Skopeo rejected a combined tag/digest reference. The retained script uses bounded reads and digest-only Skopeo references.
- aws / amd64: Incomplete scan or coverage.
- aws / arm64: Incomplete scan or coverage.
- core / amd64: Incomplete scan or coverage.
- core / arm64: Incomplete scan or coverage.

## Why the baseline now lists 17 HIGH entries

This comparison uses Grype for both images. The earlier r4 publication report used Trivy and listed four HIGH entries. The image bytes are unchanged; severity/source selection differs between the scanners. The Grype HIGH entries also include expat, zlib, GCC runtime and glibc advisories. Neither count is a newly rebuilt baseline.

## Reproduce

Run the existing `ci.yml` workflow on `chore/89-rhhi-syft-grype` with `rhhi_experiment=true`. It has read-only permissions, builds locally with Buildah, verifies with Podman and transfers no images to a registry. A new run fetches a fresh Grype database and freezes it for its own matrix; reproducing the historical counts requires the exact recorded database snapshot. The retained run's prepared artifact and full scanner artifacts expire after seven days; the normalized findings and identity diagnostics remain in this branch.
