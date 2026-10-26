# UBI Micro branch evaluation

This experiment belongs to Issue #32. It must remain on its experimental branch/draft PR until separately approved for adoption. Main, published tags/digests, release records and Quay credentials are unchanged. No experimental image is published.

## Inputs and construction

Keep Keycloak 26.8.1, Java 25, Temurin build optimization and Linux amd64. `images.lock.json` pins UBI 9.7 Micro and the matching UBI standard build stage. Only `ubi-9-baseos-rpms` and `ubi-9-appstream-rpms` may supply runtime RPMs; subscription-manager is disabled. Install the headless Java runtime, locale, certificates and time zones into an isolated root, then erase installation-only shell/package-manager packages from both the filesystem and RPM database. Retain RPM records and licenses for actual runtime libraries. Copy the root into UBI Micro and keep direct Java startup and UID/GID 65532.

The base image digests are immutable. The public RPM repositories are rolling: the exact installed NEVRA/vendor/license inventory is preserved at `/usr/share/rambow/ubi-runtime-packages.tsv`. Before any production adoption, review a reproducible RPM snapshot/lock and the license inventory; do not claim that pinning the two OCI bases also pins future RPM transactions.

## Validation and comparison

Use the existing read-only CI for core/aws Buildah builds, OCI export, Podman rootfs/version checks, verified PostgreSQL TLS (including wrong CA/hostname rejection), schema/authentication checks, AWS offline IAM signing/delegation and graceful shutdown. The experiment requires nonempty RHEL RPM and Java package scan coverage; scanner errors, missing coverage, EOL and fixable HIGH/CRITICAL findings still fail. No ignore rules or severity thresholds change. Compare complete JSON reports, package counts and database metadata, rather than comparing dashboard totals alone.

The published AWS baseline is `quay.io/rambow-cloud/keycloak@sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7`. Its release scan (run 40260151709, Trivy 0.76.1, 2026-10-26) reported 64 package findings: 0 critical, 4 high, 39 medium, 20 low, 1 unknown; none had an available fix. These were 39 unique CVEs, all in Debian OS packages; the Java result contained 526 packages and no vulnerability findings. This historical baseline uses a different vendor advisory source and is not a matched-time proof of security improvement.

Results are pending the experimental branch CI. Live AWS RDS/PolarDB tests are out of scope; no production certification or zero-CVE claim is made.

## Licensing and support

UBI permits commercial deployment and redistribution without a paid subscription, subject to the [UBI EULA](https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf) and component licenses. Preserve its EULA and notices, use only publicly redistributable UBI content, and make no Red Hat support/endorsement claim. See the [UBI FAQ](https://developers.redhat.com/articles/ubi-faq) and [content availability policy](https://access.redhat.com/support/policy/updates/ubi).
