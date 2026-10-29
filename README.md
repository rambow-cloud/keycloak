# Rambow Cloud Keycloak

Keycloak OCI images built with **Buildah**, with **distroless Java 25 LTS** and **non-root UID 65532** by default. This project uses issue-driven development and English throughout.

Image work is gated per profile: no fix/feature input change means no image publication, and docs/catalog-only CI skips container builds. Every published tag has nonempty Issue-linked updates in the [catalog](releases/README.md). See [image work and change history](docs/image-change-policy.md).

See the [security release notes](docs/security/README.md) for new fixes by version, newest first. The [detailed history and CVE/event index](docs/security/history.md) retain exact image digests and verification evidence.

## Initial supported configuration

- Keycloak 26.8.1, optimized at build time for PostgreSQL, with health and metrics enabled.
- Two build profiles: `core` (default, native PostgreSQL driver) and `aws` (AWS JDBC Wrapper 4.5.0, AWS SDK 2.46.10, XA disabled, checksum-pinned public RDS CA bundle, and verified database TLS by default). See [RDS configuration](docs/rds-postgresql.md) and the [ECS/Fargate task example](examples/ecs-rds.task-definition.json). Live cloud certification is pending dedicated staging tests.
- [PolarDB PostgreSQL configuration](docs/polardb-postgresql.md) uses the core profile, private primary endpoint, mounted CA, and native verified TLS. Compatibility is experimental until actual PolarDB schema, migration, and authentication checks pass; no Alibaba-specific SDK or JDBC driver is added.
- Java 25 LTS for both build optimization (Temurin JDK) and the final distroless runtime. Select the latest LTS explicitly supported by the pinned Keycloak release, rather than copying the upstream container's default JDK. [Keycloak recommends Java 25](https://www.keycloak.org/server/supported-configurations); its upstream container remains on Java 21. Build tools and the JDK are excluded from the final image.
- Linux amd64. Keycloak, distroless, and the verification database are pinned by digest in [images.lock.json](images.lock.json).
- Buildah for builds; Podman for verification/runtime; Skopeo for OCI inspection. No Docker daemon, Docker CLI, Docker-in-Docker, or Docker-based build actions are required. The `docker.io` registry and Skopeo's `docker://` registry transport are names, not Docker tooling.
- A multi-stage [Containerfile](Containerfile) takes the official Keycloak distribution, optimizes it using a pinned Temurin 25 JDK, and copies it into a shell-free distroless Java 25 runtime. Java runs directly as PID 1. Application files are root-owned; only the data directory is owned by UID 65532.

## Issue-driven workflow

Start with a [Feature, Bug, or Maintenance form](https://github.com/rambow-cloud/keycloak/issues/new/choose). Blank issues are disabled. Every change, including dependency, security, documentation, and CI work, needs an issue with acceptance criteria and validation.

Use a branch such as `fix/12-startup`, reference the issue in commits, and open a PR with a standalone `Closes #12` line. The required `Issue policy` check rejects missing, closed, malformed, or cross-repository issue references. API/CLI-created issues must follow the same headings as the forms. The required `Build and verify` check validates the resulting image. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

Issue #1 covers the one-time bootstrap commit. All subsequent changes go through PRs and required checks.

## Build and verify

Use Linux with Node.js 22+, Buildah, Podman, Skopeo, and OpenSSL. Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends -y buildah podman skopeo openssl
bash scripts/build.sh
bash scripts/verify-image.sh

# The AWS profile uses the wrapper JDBC URL format described in docs/rds-postgresql.md.
BUILD_PROFILE=aws bash scripts/build.sh
BUILD_PROFILE=aws bash scripts/verify-image.sh
```

On Windows, use a separate Linux host or Linux WSL distribution; Docker Desktop is not needed. Rootless Buildah/Podman require working user namespaces and subordinate UID/GID mappings.

CI builds both profiles with Buildah, checks Java/Keycloak versions and the shell-free/non-root filesystem, and starts each image against temporary PostgreSQL with verified TLS and a read-only root filesystem. Wrong CA and hostname configurations must fail. Protocol tests create an isolated realm, perform database writes, validate signed client-credentials tokens, and remove the realm before checking graceful shutdown. The required `Build and verify` status aggregates static checks and both image jobs. Each profile uploads its OCI archive, checksum, and locks. CI does not publish registry images. Download a profile artifact from [Actions](https://github.com/rambow-cloud/keycloak/actions/workflows/ci.yml) and load it with:

```sh
sha256sum -c keycloak.oci.tar.sha256
podman load -i keycloak.oci.tar
```

CI also scans both built images with checksum-pinned native Trivy, reports findings in one maintained PR comment, and uploads full JSON reports. Fixable HIGH/CRITICAL vulnerabilities block the required check and upstream auto-merge; unfixed findings remain visible. See [vulnerability scanning and PR reports](docs/vulnerability-scanning.md) for policy, coverage and recovery.

Formal releases publish both profiles to `quay.io/rambow-cloud/keycloak` after fresh vulnerability gates. Use `v26.8.1-r1`-style GitHub Releases and `26.8.1-r1-core` / `26.8.1-r1-aws` registry tags. See the [published image catalog](releases/README.md) and [Quay release setup/recovery](docs/quay-releases.md). Main updates alone do not publish, and no `latest` or implicit custom alias is created.

Archive checksums detect transfer corruption; they are not a signature or provenance attestation. Artifacts expire after seven days. SBOM generation, signing, and multi-architecture support remain follow-up work requiring their own issues.

The [automatic upstream updater](docs/upstream-updates.md) checks Keycloak, distroless and the current Temurin image family hourly. It creates an Issue-linked PR, runs both image profiles, and auto-merges patch/digest updates after required checks. Larger or compatibility-changing upgrades require review.

To refresh immutable inputs manually:

```sh
node scripts/lock-images.mjs 26.8.1
```

Review changes in a maintenance issue/PR and rerun the image checks. There is no floating base image fallback.

To refresh AWS dependencies and the public RDS CA bundle, use Maven 3.9+ and Java 17+ on the maintenance host:

```sh
node scripts/aws-dependencies.mjs lock
```

Review and commit the POM, JAR lock, and updated image lock together. Normal AWS builds only download the locked JARs and CA bundle and verify their SHA-256 hashes; they do not require Maven. The asynchronous Netty client and duplicate PostgreSQL/SLF4J JARs are excluded. The AWS fixture also exercises IAM token signing with deliberately fake credentials; PostgreSQL must reject that token. This is not live RDS IAM certification. See [external staging verification](docs/rds-postgresql.md#external-staging-verification) for opt-in cloud tests.

## Run locally against existing PostgreSQL

Provide the variables below in your shell or secret manager. Replace `KC_DB_URL` with a database address reachable from the container. The example binds HTTP only to loopback for local inspection:

```sh
export KC_DB_URL=jdbc:postgresql://database.example.internal:5432/keycloak
export KC_DB_USERNAME=keycloak
read -r -s -p 'Database password: ' KC_DB_PASSWORD; export KC_DB_PASSWORD
podman run --rm --name keycloak --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --memory=2g \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 \
  --tmpfs /opt/keycloak/data:rw,nosuid,size=256m,mode=1777 \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 \
  -e KC_DB_URL -e KC_DB_USERNAME -e KC_DB_PASSWORD \
  -e KC_HOSTNAME=http://localhost:8080 -e KC_HTTP_ENABLED=true \
  localhost/rambow-keycloak:test
```

Open [the master realm discovery document](http://localhost:8080/realms/master/.well-known/openid-configuration) and verify the issuer and endpoint URLs. Open [readiness](http://localhost:9000/health/ready) and verify `UP`. Use your deployment's hostname for equivalent checks after deployment.

For production, set an HTTPS hostname, configure TLS or a trusted reverse proxy, inject secrets at runtime, restrict port 9000, and supply persistent storage if your enabled features need it. The temporary data mount above is only for local use. Initial administrator bootstrap, proxy trust, and PostgreSQL TLS settings must follow the [Keycloak configuration guides](https://www.keycloak.org/guides#server).

## Compatibility and security limits

The image supports the default `start --optimized` command with build-time options already baked in. Rebuild to change database vendors, enabled build-time features, or providers. Final images have no `kc.sh`, admin CLI, shell, or package manager. Runtime reaugmentation and `start-dev` are unsupported.

The direct launcher tracks the [upstream 26.8.1 startup script](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/dist/src/main/content/bin/kc.sh). Upgrade reviews must compare its JVM flags and launcher requirements. Shell-specific `JAVA_OPTS*` variables are not interpreted; use standard JVM `JAVA_TOOL_OPTIONS` for additional options. Replacing it also replaces the default heap percentages, so include your desired heap settings and always set a container memory limit.

Distroless reduces attack surface; it does not guarantee zero CVEs. This initial setup does not certify FIPS, LDAP/Kerberos integrations, custom providers, or additional architectures. See [SECURITY.md](SECURITY.md), [Keycloak containers](https://www.keycloak.org/server/containers), and [distroless Java](https://github.com/GoogleContainerTools/distroless/blob/main/java/README.md).
