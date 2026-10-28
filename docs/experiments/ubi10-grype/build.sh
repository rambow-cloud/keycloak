#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
profile=${1:?Expected profile}
case "$profile" in core|aws) ;; *) exit 1 ;; esac
export BUILD_PROFILE=$profile
directory=".cache/ubi10/$profile"
node docs/experiments/ubi10-grype/prepare.mjs "$profile"
exec > >(tee "$directory/build-and-runtime.log") 2>&1
/lib64/ld-linux-x86-64.so.2 --help > "$directory/loader-capabilities.txt"
grep -Eq 'x86-64-v3 \(supported, searched\)' "$directory/loader-capabilities.txt"
lscpu > "$directory/cpu.txt"
read_lock() { node -p "require('./images.lock.json').$1"; }
read_candidate() { node -p "require('./docs/experiments/ubi10-grype/inputs.lock.json').$1"; }
node scripts/keycloak-dependencies.mjs
if [[ "$profile" == aws ]]; then node scripts/aws-dependencies.mjs fetch; fi
buildah build --layers --skip-unused-stages=true --ignorefile "$directory/containerignore" \
  --target "$profile" --format oci --platform "$(read_lock platform)" \
  --build-arg "KEYCLOAK_IMAGE=$(read_lock keycloak)" --build-arg "BUILD_IMAGE=$(read_lock builder)" \
  --build-arg "RUNTIME_IMAGE=$(read_candidate runtime)" --build-arg "EXPERIMENT_BUILD_IMAGE=$(read_candidate runtimeBuilder)" \
  --build-arg "KEYCLOAK_JAVA_MAJOR=$(read_lock javaVersion)" \
  --label "org.opencontainers.image.version=$(read_lock keycloakVersion)" \
  --label "org.opencontainers.image.revision=$GITHUB_SHA" --label "cloud.rambow.keycloak.profile=$profile" \
  --label 'cloud.rambow.keycloak.experimental-runtime=ubi10' \
  --file "$directory/Containerfile" --tag localhost/rambow-keycloak:test .
buildah push localhost/rambow-keycloak:test "oci-archive:$directory/keycloak.oci.tar"
(cd "$directory" && sha256sum keycloak.oci.tar > keycloak.oci.tar.sha256)
skopeo inspect "oci-archive:$directory/keycloak.oci.tar" > "$directory/image-metadata.json"
container=$(podman create localhost/rambow-keycloak:test)
podman cp "$container:/usr/share/rambow/ubi-runtime-packages.tsv" "$directory/ubi-runtime-packages.tsv"
podman rm -v "$container" >/dev/null
if bash scripts/verify-image.sh; then
  printf '{"status":"passed"}\n' > "$directory/runtime-status.json"
else
  printf '{"status":"failed"}\n' > "$directory/runtime-status.json"
  exit 1
fi
