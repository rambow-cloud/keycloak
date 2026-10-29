# Rambow Cloud Keycloak

Minimal Keycloak OCI images for PostgreSQL deployments, with a **distroless Java 25 LTS** runtime, **non-root execution** and build-time optimization. Images are built with Buildah, verified with Podman and published to Quay.

## Current images

Current published release: [v26.8.1-r3](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r3). Keycloak **26.8.1**, Java **25 LTS**, Linux **amd64 and arm64**.

Each tag is an immutable OCI index that automatically selects **amd64** or **arm64**. Earlier r1/r2 tags remain amd64-only. See [architecture support](docs/architectures.md).

| Profile | Latest published tag | Image reference | Purpose |
| --- | --- | --- | --- |
| core | `26.8.1-r3-core` | `quay.io/rambow-cloud/keycloak:26.8.1-r3-core` | PostgreSQL with the native JDBC driver. |
| aws | `26.8.1-r3-aws` | `quay.io/rambow-cloud/keycloak:26.8.1-r3-aws` | RDS PostgreSQL with the AWS JDBC Wrapper, IAM authentication support and a pinned RDS CA bundle. |

Pull either profile with Podman:

```sh
podman pull quay.io/rambow-cloud/keycloak:26.8.1-r3-core
podman pull quay.io/rambow-cloud/keycloak:26.8.1-r3-aws
```

Use [digest-pinned references](releases/README.md) for deployments. Formal tags are immutable; no `latest` tag is published. See [security release notes](docs/security/README.md) for fixes in each version.

## Features

- Optimized PostgreSQL configuration with health and metrics enabled.
- Shell-free runtime without a package manager or build tools; runs as UID/GID 65532.
- Verified database TLS and read-only root filesystem checks in CI.
- Per-profile vulnerability scanning with Trivy; fixable HIGH/CRITICAL findings block publication.
- Issue-driven upstream updates and versioned image releases with recorded change history.

The default command is `start --optimized`. Build-time option or provider changes require a rebuild. Live RDS/PolarDB compatibility requires staging verification; see the configuration guides below.

## Documentation

| Guide | Contents |
| --- | --- |
| [Build and run](docs/build-and-run.md) | Local setup, image builds, runtime example, input updates and compatibility limits. |
| [Architectures](docs/architectures.md) | Native amd64/arm64 builds, separate scans and multi-architecture release indexes. |
| [RDS PostgreSQL](docs/rds-postgresql.md) | AWS profile configuration, database TLS, IAM authentication and staging checks. |
| [PolarDB PostgreSQL](docs/polardb-postgresql.md) | Experimental core-profile configuration and required cloud verification. |
| [Published images](releases/README.md) | All versions, exact digests, validation links and pull commands. |
| [Security release notes](docs/security/README.md) | Newly shipped security fixes, newest version first. |
| [Security history](docs/security/history.md) | Detailed CVE records, corrections and retained verification evidence. |
| [Vulnerability scanning](docs/vulnerability-scanning.md) | Scan coverage, merge gates and PR reports. |
| [Upstream updates](docs/upstream-updates.md) | Automated dependency updates and review policy. |
| [Release workflow](docs/quay-releases.md) | Quay publication, immutable tags and recovery. |

## Contributing

Start with a [Feature, Bug or Maintenance issue](https://github.com/rambow-cloud/keycloak/issues/new/choose), then submit a linked PR. See [CONTRIBUTING.md](CONTRIBUTING.md), [working agreements](AGENTS.md) and [image change policy](docs/image-change-policy.md). Use English for repository contributions. Report sensitive vulnerabilities through [SECURITY.md](SECURITY.md).
