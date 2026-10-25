#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
for tool in buildah node; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }; done
read_lock() { node -p "require('./images.lock.json').$1"; }
keycloak=$(read_lock keycloak)
runtime=$(read_lock runtime)
for image in "$keycloak" "$runtime"; do
  [[ "$image" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'Base image must be digest-pinned' >&2; exit 1; }
done
buildah build --format oci --platform "$(read_lock platform)" \
  --build-arg "KEYCLOAK_IMAGE=$keycloak" --build-arg "RUNTIME_IMAGE=$runtime" \
  --label "org.opencontainers.image.title=Rambow Cloud Keycloak" \
  --label "org.opencontainers.image.source=https://github.com/rambow-cloud/keycloak" \
  --label "org.opencontainers.image.version=$(read_lock keycloakVersion)" \
  --label "org.opencontainers.image.revision=${GITHUB_SHA:-$(git rev-parse HEAD)}" \
  --tag "${IMAGE_TAG:-localhost/rambow-keycloak:test}" --file Containerfile .
