# Rambow Cloud Keycloak

Minimal Keycloak OCI images for PostgreSQL deployments, with a **distroless Java 25 LTS** runtime, **non-root execution** and build-time optimization. Images are built with Buildah, verified with Podman and published to Quay. See the [Amazon Linux runtime and scan contract](docs/amazon-linux-runtime.md).

## Current images

Current release: [v26.8.2-r2](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.2-r2). Keycloak **26.8.2**, Corretto **25 LTS** on Amazon Linux 2023, Linux **amd64 and arm64**. Each profile has one OCI index tag that selects the host architecture.

| Profile | Latest published tag | Image reference | Purpose |
| --- | --- | --- | --- |
| core | `26.8.2-r2-core` | `quay.io/rambow-cloud/keycloak:26.8.2-r2-core` | PostgreSQL with the native JDBC driver. |
| aws | `26.8.2-r2-aws` | `quay.io/rambow-cloud/keycloak:26.8.2-r2-aws` | RDS PostgreSQL integration with the AWS JDBC Wrapper and pinned CA bundle. |

Pull a profile with Podman:

```sh
podman pull quay.io/rambow-cloud/keycloak:26.8.2-r2-core
podman pull quay.io/rambow-cloud/keycloak:26.8.2-r2-aws
```

Use [digest-pinned references and validation records](releases/README.md) for deployments. See the [security release notes](docs/security/README.md) for newly included fixes and [runtime migration evidence](releases/evidence/v26.8.2-r2-runtime.json) for remaining findings and limits. No `latest` tag is published.

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
| [Signatures and SBOMs](docs/supply-chain.md) | Cosign trust policy, per-architecture CycloneDX inventories and verification commands for new release contracts. |
| [Upstream updates](docs/upstream-updates.md) | Automated dependency updates and review policy. |
| [Release workflow](docs/quay-releases.md) | Quay publication, immutable tags and recovery. |

## Contributing

Start with a [Feature, Bug or Maintenance issue](https://github.com/rambow-cloud/keycloak/issues/new/choose), then submit a linked PR. See [CONTRIBUTING.md](CONTRIBUTING.md), [working agreements](AGENTS.md) and [image change policy](docs/image-change-policy.md). Use English for repository contributions. Report sensitive vulnerabilities through [SECURITY.md](SECURITY.md).
