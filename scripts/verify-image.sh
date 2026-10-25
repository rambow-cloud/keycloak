#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
image=${IMAGE_TAG:-localhost/rambow-keycloak:test}
version=$(node -p "require('./images.lock.json').keycloakVersion")
postgres=$(node -p "require('./images.lock.json').postgres")
run_id="kc-verify-${RANDOM}-${RANDOM}"
network="$run_id-net"
db="$run_id-db"
server="$run_id-server"
cleanup() {
  podman rm -f "$server" "$db" >/dev/null 2>&1 || true
  podman network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
[[ "$(podman image inspect --format '{{.Config.User}}' "$image")" == '65532:65532' ]]
podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges "$image" --version | tee /tmp/"$run_id-version.log"
grep -F "Keycloak $version" /tmp/"$run_id-version.log"
rm /tmp/"$run_id-version.log"
# Export the final merged rootfs, rather than assuming distroless has no shell.
probe=$(podman create "$image")
rootfs=$(mktemp)
podman export "$probe" > "$rootfs"
podman rm "$probe" >/dev/null
entries=$(tar -tf "$rootfs")
rm "$rootfs"
if grep -Eq '(^|/)(sh|bash|dash|ash|busybox|apt|apt-get|dpkg|rpm|dnf|microdnf|apk|javac|jshell)$' <<< "$entries"; then
  echo 'Unexpected shell, package manager or development tool in final image' >&2; exit 1
fi
podman network create "$network" >/dev/null
# Only ephemeral test credentials; no ports are published to the host.
db_password=$(node -e "console.log(require('node:crypto').randomBytes(24).toString('hex'))")
podman run -d --name "$db" --network "$network" --network-alias database \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e "POSTGRES_PASSWORD=$db_password" "$postgres" >/dev/null
db_ready=false
for ((attempt=0; attempt<60; attempt++)); do
  if podman exec "$db" pg_isready -U keycloak -d keycloak >/dev/null 2>&1; then db_ready=true; break; fi
  sleep 2
done
[[ "$db_ready" == true ]] || { podman logs "$db"; exit 1; }
podman run -d --name "$server" --network "$network" --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --memory=2g \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m,uid=65532,gid=65532 \
  --tmpfs /opt/keycloak/data:rw,nosuid,size=256m,uid=65532,gid=65532 \
  -e KC_DB_URL=jdbc:postgresql://database:5432/keycloak -e KC_DB_USERNAME=keycloak \
  -e "KC_DB_PASSWORD=$db_password" -e KC_HOSTNAME=https://localhost -e KC_HTTP_ENABLED=true \
  "$image" >/dev/null
started=false
for ((attempt=0; attempt<120; attempt++)); do
  if podman logs "$server" 2>&1 | grep -q 'Listening on:'; then started=true; break; fi
  [[ "$(podman inspect --format '{{.State.Running}}' "$server")" == true ]] || break
  sleep 2
done
podman logs "$server"
[[ "$started" == true ]] || { echo 'Keycloak did not start' >&2; exit 1; }
podman stop --time 30 "$server" >/dev/null
exit_code=$(podman inspect --format '{{.State.ExitCode}}' "$server")
[[ "$exit_code" == 0 || "$exit_code" == 143 ]] || { echo "Unexpected shutdown: $exit_code" >&2; exit 1; }
podman logs "$server" 2>&1 | grep -Eq 'stopped in|Shutdown complete'
echo 'Verified: version, UID, shell-free rootfs, read-only PostgreSQL startup and graceful SIGTERM shutdown.'
