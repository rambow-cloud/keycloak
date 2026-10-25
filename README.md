# Rambow Cloud Keycloak

Keycloak OCI images built with **Buildah**, with **distroless Java 21** and **non-root UID 65532** by default. This project uses issue-driven development and English throughout.

## Initial supported configuration

- Keycloak 26.8.1, optimized at build time for PostgreSQL, with health and metrics enabled.
- Linux amd64. Keycloak, distroless, and the verification database are pinned by digest in [images.lock.json](images.lock.json).
- Buildah for builds; Podman for verification/runtime; Skopeo for OCI inspection. No Docker daemon, Docker CLI, Docker-in-Docker, or Docker-based build actions are required. The `docker.io` registry and Skopeo's `docker://` registry transport are names, not Docker tooling.
- A multi-stage [Containerfile](Containerfile) copies the optimized Keycloak distribution into a shell-free distroless runtime. Java runs directly as PID 1. Application files are root-owned; only the data directory is owned by UID 65532.

## Issue-driven workflow

Start with a [Feature, Bug, or Maintenance form](https://github.com/rambow-cloud/keycloak/issues/new/choose). Blank issues are disabled. Every change, including dependency, security, documentation, and CI work, needs an issue with acceptance criteria and validation.

Use a branch such as `fix/12-startup`, reference the issue in commits, and open a PR with a standalone `Closes #12` line. The required `Issue policy` check rejects missing, closed, malformed, or cross-repository issue references. API/CLI-created issues must follow the same headings as the forms. The required `Build and verify` check validates the resulting image. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

Issue #1 covers the one-time bootstrap commit. All subsequent changes go through PRs and required checks.

## Build and verify

Use Linux with Node.js 22+, Buildah, Podman, and Skopeo. Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends -y buildah podman skopeo
bash scripts/build.sh
bash scripts/verify-image.sh
```

On Windows, use a separate Linux host or Linux WSL distribution; Docker Desktop is not needed. Rootless Buildah/Podman require working user namespaces and subordinate UID/GID mappings.

CI builds with Buildah, checks the shell-free filesystem, verifies the version/non-root configuration, starts Keycloak against temporary PostgreSQL on a read-only root filesystem, and checks graceful SIGTERM shutdown. It then uploads an OCI archive, its SHA-256 checksum, and the input lock file. CI does not publish registry images. Download the artifact from [Actions](https://github.com/rambow-cloud/keycloak/actions/workflows/ci.yml) and load it with:

```sh
sha256sum -c keycloak.oci.tar.sha256
podman load -i keycloak.oci.tar
```

Archive checksums detect transfer corruption; they are not a signature or provenance attestation. Artifacts expire after seven days. Registry publication, SBOM generation, vulnerability scanning, signing, and multi-architecture support are follow-up work requiring their own issues before production releases.

To refresh immutable inputs:

```sh
node scripts/lock-images.mjs 26.8.1
```

Review changes in a maintenance issue/PR and rerun the image checks. There is no floating base image fallback.

## Run locally against existing PostgreSQL

Provide the variables below in your shell or secret manager. Replace `KC_DB_URL` with a database address reachable from the container. The example binds HTTP only to loopback for local inspection:

```sh
export KC_DB_URL=jdbc:postgresql://database.example.internal:5432/keycloak
export KC_DB_USERNAME=keycloak
read -r -s -p 'Database password: ' KC_DB_PASSWORD; export KC_DB_PASSWORD
podman run --rm --name keycloak --read-only --cap-drop=ALL \\
  --security-opt=no-new-privileges --memory=2g \\
  --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=65532,gid=65532 \\
  --tmpfs /opt/keycloak/data:rw,nosuid,size=256m,uid=65532,gid=65532 \\
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 \\
  -e KC_DB_URL -e KC_DB_USERNAME -e KC_DB_PASSWORD \\
  -e KC_HOSTNAME=http://localhost:8080 -e KC_HTTP_ENABLED=true \\
  localhost/rambow-keycloak:test
```

Open [the master realm discovery document](http://localhost:8080/realms/master/.well-known/openid-configuration) and verify the issuer and endpoint URLs. Open [readiness](http://localhost:9000/health/ready) and verify `UP`. Use your deployment's hostname for equivalent checks after deployment.

For production, set an HTTPS hostname, configure TLS or a trusted reverse proxy, inject secrets at runtime, restrict port 9000, and supply persistent storage if your enabled features need it. The temporary data mount above is only for local use. Initial administrator bootstrap, proxy trust, and PostgreSQL TLS settings must follow the [Keycloak configuration guides](https://www.keycloak.org/guides#server).

## Compatibility and security limits

The image supports the default `start --optimized` command with build-time options already baked in. Rebuild to change database vendors, enabled build-time features, or providers. Final images have no `kc.sh`, admin CLI, shell, or package manager. Runtime reaugmentation and `start-dev` are unsupported.

The direct launcher tracks the [upstream 26.8.1 startup script](https://github.com/keycloak/keycloak/blob/26.8.1/quarkus/dist/src/main/content/bin/kc.sh). Upgrade reviews must compare its JVM flags and launcher requirements. Shell-specific `JAVA_OPTS*` variables are not interpreted; use standard JVM `JAVA_TOOL_OPTIONS` for additional options. Replacing it also replaces the default heap percentages, so include your desired heap settings and always set a container memory limit.

Distroless reduces attack surface; it does not guarantee zero CVEs. This initial setup does not certify FIPS, LDAP/Kerberos integrations, custom providers, or additional architectures. See [SECURITY.md](SECURITY.md), [Keycloak containers](https://www.keycloak.org/server/containers), and [distroless Java](https://github.com/GoogleContainerTools/distroless/blob/main/java/README.md).

