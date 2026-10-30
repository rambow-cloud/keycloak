# Red Hat Hardened Images evaluation

Issue: [#89](https://github.com/rambow-cloud/keycloak/issues/89).
Retained branch: `chore/89-rhhi-syft-grype`. Do not merge this experiment into main.

The experiment replaces only the effective runtime input on native runners, leaving the Git production lock and the Keycloak, builder, PostgreSQL, provider and dependency-override pins unchanged. Candidate core/aws builds use the existing Buildah/Podman runtime regression. No image is pushed and no release is created.

`inputs.lock.json` pins the public Red Hat OpenJDK 25 runtime index/children, exact published r4 baseline children, native Syft/Grype archives and their upstream SHA-256 values. The preparation job freezes one validated Grype database for all four native jobs and checks known vulnerable/fixed Guava controls. Both runtimes are scanned from OCI archives through the same explicit Syft SBOM format and Grype database; scan coverage must identify the expected OS and application artifacts.

The certificate-chain probe is copied from retained branch `chore/37-emudhra-regression`, commit `4c997af311311f1c756f10076ca8c580934cee62`. It reuses the public, checksum-verified fixtures retained in main, including historical validation times and identical-chain controls with restored incident roots. Java metadata records actual JVM/vendor/providers/trust-store identity. This is offline PKIX evidence, not live HTTPS/cloud certification.

Run the existing `ci.yml` workflow manually on this branch with `rhhi_experiment=true`. The experiment is explicitly scoped to this branch and uses read-only permissions. Production CI, Trivy gates, registry credentials and publication automation are not changed on main. Raw results are uploaded even on a diagnosed runtime/coverage failure. Findings, fixes, unique advisory/CVE counts, OS/JVM inventory, namespaces and coverage limits will be retained in the final report. Lower counts alone do not establish lower exploitable risk.
