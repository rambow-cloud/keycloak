# Rambow Cloud Keycloak

Minimal Keycloak OCI images for PostgreSQL deployments, with a **distroless Java 25 LTS** runtime, **non-root execution** and build-time optimization. Images are built with Buildah, verified with Podman and published to Quay. See the [Amazon Linux runtime and scan contract](docs/amazon-linux-runtime.md).

## Current images

Published profiles are OCI indexes selecting native Linux amd64 or arm64. See [recorded digests and validation](releases/README.md).

| Profile | Latest published tag | Image reference |
| --- | --- | --- |
| aws | `26.8.2-r4-aws` | `quay.io/rambow-cloud/keycloak:26.8.2-r4-aws` |
| core | `26.8.2-r4-core` | `quay.io/rambow-cloud/keycloak:26.8.2-r4-core` |

Pull a profile with Podman:

```sh
podman pull quay.io/rambow-cloud/keycloak:26.8.2-r4-aws
podman pull quay.io/rambow-cloud/keycloak:26.8.2-r4-core
```

Current release: [26.8.2-r4 — shell-free Operator support](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.2-r4). Runtime-update revisions retain their [paired CVE comparison contract](docs/distroless-updates.md). No `latest` tag is published.

## Features

- Optimized PostgreSQL configuration with health and metrics enabled.
- Shell-free runtime without a package manager or build tools; runs as UID/GID 65532.
- Verified database TLS and read-only root filesystem checks in CI.
- Per-profile vulnerability scanning with Trivy; fixable HIGH/CRITICAL findings block publication.
- Issue-driven upstream updates and versioned image releases with recorded change history.

The default command is `start --optimized`. Build-time option or provider changes require a rebuild. Live RDS/PolarDB compatibility requires staging verification; see the configuration guides below.

## Keycloak Operator compatibility

Images built from this source include a **static Go launcher** at `/opt/keycloak/bin/kc.sh`, compiled with pinned Go and `CGO_ENABLED=0`. The filename is an executable, not a shell script. It supports the matching Keycloak **26.8.2 Operator** commands for optimized startup, Realm Import and `update-compatibility metadata/check`, while keeping the runtime shell-free. Check the [per-tag change history](releases/README.md) before deploying an older published image; images predating this feature do not contain the launcher.

| Profile | Native architectures | Verified Operator behavior |
| --- | --- | --- |
| core | Linux amd64 / arm64 | Startup, Realm Import, Pod recovery and Auto patch rolling upgrade. |
| aws | Linux amd64 / arm64 | The same checks using the JDBC wrapper against TLS PostgreSQL. |

The **26.8.1 -> 26.8.2** test preserved realm/user/client data and a continuing login session. Both replicas rolled gracefully, and the final native matrix completed **4,341 authenticated HTTPS requests with no failures or retries**. The historical 26.8.1 test images retained their original layers and only gained the same launcher; this does not establish Operator support for the unmodified old images. See the [report and retained failure history](docs/reports/159-operator-patch-upgrade/README.md) and [final native evidence](https://github.com/rambow-cloud/keycloak/issues/159#issuecomment-6833669772).

For the tested direct TLS passthrough setup, configure **two replicas**, `startOptimized: true`, `update.strategy: Auto`, `shutdown-delay=30s`, `shutdown-timeout=10s` and `terminationGracePeriodSeconds: 120`. Provide UID/GID/fsGroup **65532** and writable `/opt/keycloak/data` and `/tmp` volumes when using a read-only root filesystem. These are deployment settings, not image defaults: the default draining window produced a recorded connection reset in one earlier run. The [Operator guide](docs/operator-support.md) includes the configuration fragment and command boundaries.

Validation covers this patch-version pair on one-node kind clusters with ordinary PostgreSQL. Production HA, other upgrade pairs, minor/major upgrades, RDS IAM/failover and PolarDB need their own validation. Runtime augmentation, `start-dev`, full shell-script behavior, `kcadm.sh` and `kcreg.sh` are unsupported.

## Documentation

| Guide | Contents |
| --- | --- |
| [Build and run](docs/build-and-run.md) | Local setup, image builds, runtime example, input updates and compatibility limits. |
| [Architectures](docs/architectures.md) | Native amd64/arm64 builds, separate scans and multi-architecture release indexes. |
| [Keycloak Operator](docs/operator-support.md) | Shell-free launcher, deployment settings, Realm Import and verified Auto patch upgrades. |
| [RDS PostgreSQL](docs/rds-postgresql.md) | AWS profile configuration, database TLS, IAM authentication and staging checks. |
| [PolarDB PostgreSQL](docs/polardb-postgresql.md) | Experimental core-profile configuration and required cloud verification. |
| [Published images](releases/README.md) | All versions, exact digests, validation links and pull commands. |
| [Security release notes](docs/security/README.md) | Newly shipped security fixes, newest version first. |
| [Security history](docs/security/history.md) | Detailed CVE records, corrections and retained verification evidence. |
| [Vulnerability scanning](docs/vulnerability-scanning.md) | Scan coverage, merge gates and PR reports. |
| [Signatures and SBOMs](docs/supply-chain.md) | Cosign trust policy, per-architecture CycloneDX inventories and verification commands for new release contracts. |
| [Upstream updates](docs/upstream-updates.md) | Automated dependency updates and review policy. |
| [Release workflow](docs/quay-releases.md) | Quay publication, immutable tags and recovery. |
| [Amazon ECR Public](docs/ecr-public.md) | Supplemental digest-preserving distribution, AWS OIDC and anonymous native pull verification. |

## Contributing

Start with a [Feature, Bug or Maintenance issue](https://github.com/rambow-cloud/keycloak/issues/new/choose), then submit a linked PR. See [CONTRIBUTING.md](CONTRIBUTING.md), [working agreements](AGENTS.md) and [image change policy](docs/image-change-policy.md). Use English for repository contributions. Report sensitive vulnerabilities through [SECURITY.md](SECURITY.md).
