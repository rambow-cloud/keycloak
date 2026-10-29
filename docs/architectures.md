# Linux architectures

Both `core` and `aws` build and run natively on Linux amd64 and arm64. Use the matching Linux host or WSL environment; no emulation, privileged containers or Docker tooling is required.

```sh
# On an ARM64 Linux host; defaults to the native architecture.
BUILD_ARCH=arm64 bash scripts/build.sh
BUILD_ARCH=arm64 bash scripts/verify-image.sh

BUILD_PROFILE=aws BUILD_ARCH=arm64 bash scripts/build.sh
BUILD_PROFILE=aws BUILD_ARCH=arm64 bash scripts/verify-image.sh
```

`BUILD_ARCH` must match the host. `images.lock.json` explicitly locks `linux/amd64` and `linux/arm64`; each pinned Keycloak, builder, distroless and PostgreSQL index must contain exactly one supported Linux child per architecture. The updater checks architecture coverage before proposing new base digests.

CI uses native `ubuntu-26.04` and `ubuntu-26.04-arm` runners for every affected profile. Each job verifies actual image architecture, Java/Keycloak versions, Guava integrity, a shell-free nonroot rootfs, verified PostgreSQL TLS and rejection cases, protocol authentication and graceful shutdown. AWS jobs also validate provider isolation and offline signing/transport. Neither architecture can substitute for the other.

Each native Trivy binary is pinned by archive SHA-256. Scan summaries and artifacts bind profile, architecture, head SHA, run and attempt. Fixable HIGH/CRITICAL findings, missing coverage and scanner errors fail the gate on each architecture. The trusted default-branch PR reporter lists the architecture results separately. Old amd64-only CI reports remain readable.

## Release artifacts and tags

After all native jobs pass, CI packages one OCI index per changed profile, retaining the exact child manifest digests. Its artifact is named `keycloak-oci-<profile>-multiarch-<commit>`; native archives use `keycloak-oci-<profile>-<architecture>-<commit>`. Packaging validates both native archives, source locks and passed scan summaries. No registry credentials are available to these jobs.

New formal revisions retain `26.8.1-r<N>-core` and `26.8.1-r<N>-aws` tags. Each points to an immutable OCI index, so Podman selects the host architecture. An index digest pins both children; the publication JSON and generated catalog also preserve their individual digests. Aliases, when explicitly configured, point to the same index.

Publication freshly scans every child from the exact selected CI artifact before freezing the index/child digests and before the protected publisher requests Quay OIDC. Index identity, child config labels/architectures and layer checksums are verified again before authentication. Skopeo uploads all children with digest preservation. A conflicting index fails; same-digest and partial retries reuse the frozen index without rebuilding.

Previously published r1/r2 tags remain **amd64 only**, with unchanged bytes, JSON records and digests. The first multi-architecture release is `v26.8.1-r3`. A main or branch push does not publish an image. The latest actually published tags are listed on the [homepage](../README.md#current-images), and [publication records](../releases/README.md) distinguish new indexes from historical single-architecture images.
