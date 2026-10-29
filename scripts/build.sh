#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
profile=${BUILD_PROFILE:-core}
case "$profile" in core|aws) ;; *) echo 'BUILD_PROFILE must be core or aws' >&2; exit 1 ;; esac
for tool in buildah node; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }; done
architecture=$(node scripts/platform.mjs native)
[[ "${BUILD_ARCH:-$architecture}" == "$architecture" ]] || { echo 'Build on a native runner for the requested architecture' >&2; exit 1; }
node scripts/platform.mjs require "$architecture"
read_lock() { node -p "require('./images.lock.json').$1"; }
keycloak=$(read_lock keycloak)
builder=$(read_lock builder)
runtime=$(read_lock runtime)
java_version=$(read_lock javaVersion)
[[ "$java_version" =~ ^[0-9]+$ ]] || { echo 'Java major must be an integer' >&2; exit 1; }
for image in "$keycloak" "$builder" "$runtime"; do
  [[ "$image" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'Base image must be digest-pinned' >&2; exit 1; }
done
node scripts/keycloak-dependencies.mjs
if [[ "$profile" == aws ]]; then node scripts/aws-dependencies.mjs fetch; fi
buildah build --target "$profile" --format oci --platform "linux/$architecture" \
  --build-arg "KEYCLOAK_IMAGE=$keycloak" --build-arg "BUILD_IMAGE=$builder" \
  --build-arg "RUNTIME_IMAGE=$runtime" --build-arg "KEYCLOAK_JAVA_MAJOR=$java_version" \
  --label "org.opencontainers.image.title=Rambow Cloud Keycloak" \
  --label "org.opencontainers.image.source=https://github.com/rambow-cloud/keycloak" \
  --label "org.opencontainers.image.version=$(read_lock keycloakVersion)" \
  --label "cloud.rambow.keycloak.profile=$profile" \
  --label "org.opencontainers.image.revision=${GITHUB_SHA:-$(git rev-parse HEAD)}" \
  --tag "${IMAGE_TAG:-localhost/rambow-keycloak:test}" --file Containerfile .
