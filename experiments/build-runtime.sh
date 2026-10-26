#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
candidate=${EXPERIMENT_RUNTIME:?EXPERIMENT_RUNTIME is required}
profile=${BUILD_PROFILE:?BUILD_PROFILE is required}
case "$candidate:$profile" in ubi10:core|ubi10:aws|bellsoft:core|bellsoft:aws|dhi:core|dhi:aws) ;; *) exit 1 ;; esac
directory=".cache/runtime-comparison/$candidate-$profile"
read_input() { node -p "JSON.parse(require('node:fs').readFileSync('$directory/inputs.json','utf8')).$1"; }
if [[ "$candidate" == ubi10 ]]; then
  /lib64/ld-linux-x86-64.so.2 --help | tee "$directory/loader-capabilities.txt"
  grep -Eq 'x86-64-v3 \(supported, searched\)' "$directory/loader-capabilities.txt"
fi
lscpu > "$directory/cpu.txt"
if [[ "$profile" == aws ]]; then node scripts/aws-dependencies.mjs fetch; fi
printf '{"auths":{}}\n' > "$directory/anonymous-auth.json"
buildah build --authfile "$directory/anonymous-auth.json" --ignorefile experiments/containerignore --skip-unused-stages=true \
  --target "$profile" --format oci --platform "$(read_input imageLock.platform)" \
  --build-arg "KEYCLOAK_IMAGE=$(read_input imageLock.keycloak)" \
  --build-arg "BUILD_IMAGE=$(read_input imageLock.builder)" \
  --build-arg "RUNTIME_IMAGE=$(read_input candidateConfig.runtime)" \
  --build-arg "EXPERIMENT_BUILD_IMAGE=$(read_input buildImage)" \
  --build-arg "KEYCLOAK_JAVA_MAJOR=$(read_input imageLock.javaVersion)" \
  --label 'org.opencontainers.image.title=Rambow Cloud experimental Keycloak' \
  --label "org.opencontainers.image.version=$(read_input imageLock.keycloakVersion)" \
  --label "org.opencontainers.image.revision=$GITHUB_SHA" \
  --label "cloud.rambow.keycloak.profile=$profile" \
  --label "cloud.rambow.keycloak.experimental-runtime=$candidate" \
  --file "$(read_input containerfile)" --tag localhost/rambow-keycloak:test .
buildah push localhost/rambow-keycloak:test oci:.cache/trivy-image
skopeo inspect oci:.cache/trivy-image > "$directory/image-metadata.json"
skopeo inspect --config oci:.cache/trivy-image > "$directory/image-config.json"
podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --entrypoint /usr/bin/java localhost/rambow-keycloak:test -version 2>&1 | tee "$directory/java-version.txt"
