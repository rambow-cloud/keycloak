#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
profile=${BUILD_PROFILE:-core}
case "$profile" in core|aws) ;; *) echo 'BUILD_PROFILE must be core or aws' >&2; exit 1 ;; esac
image=${IMAGE_TAG:-localhost/rambow-keycloak:test}
version=$(node -p "require('./images.lock.json').keycloakVersion")
java_version=$(node -p "require('./images.lock.json').javaVersion")
postgres=$(node -p "require('./images.lock.json').postgres")
run_id="kc-verify-${RANDOM}-${RANDOM}"
network="$run_id-net"
db="$run_id-db"
server="$run_id-server"
fixture=$(mktemp -d)
probe=''
rootfs=''
cleanup() {
  podman rm -fv "$server" "$db" >/dev/null 2>&1 || true
  if [[ -n "$probe" ]]; then podman rm -fv "$probe" >/dev/null 2>&1 || true; fi
  podman network rm "$network" >/dev/null 2>&1 || true
  podman secret rm "$run_id-key" >/dev/null 2>&1 || true
  if [[ -n "$rootfs" ]]; then rm -f "$rootfs"; fi
  rm -rf "$fixture"
}
trap cleanup EXIT
[[ "$(podman image inspect --format '{{.Config.User}}' "$image")" == '65532:65532' ]]
[[ "$(podman image inspect --format '{{index .Labels "cloud.rambow.keycloak.profile"}}' "$image")" == "$profile" ]]
java_output=$(podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --entrypoint /usr/bin/java "$image" -version 2>&1)
printf '%s\n' "$java_output"
grep -F "version \"$java_version." <<< "$java_output"
podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges "$image" --version | tee "$fixture/version.log"
grep -F "Keycloak $version" "$fixture/version.log"
probe=$(podman create "$image")
rootfs=$(mktemp)
podman export "$probe" > "$rootfs"
podman rm -v "$probe" >/dev/null
probe=''
entries=$(tar -tf "$rootfs")
rm "$rootfs"
rootfs=''
if grep -Eq '(^|/)(sh|bash|dash|ash|busybox|apt|apt-get|dpkg|rpm|dnf|microdnf|apk|javac|jshell)$' <<< "$entries"; then
  echo 'Unexpected shell, package manager or development tool in final image' >&2; exit 1
fi
if [[ "$profile" == aws ]]; then
  grep -q '/providers/aws-advanced-jdbc-wrapper-' <<< "$entries"
  if grep -Eq '/providers/(netty-|postgresql-|slf4j-api-)' <<< "$entries"; then echo 'Conflicting provider JAR found' >&2; exit 1; fi
elif grep -q '/providers/aws-advanced-jdbc-wrapper-' <<< "$entries"; then
  echo 'AWS wrapper leaked into core image' >&2; exit 1
fi

# An ephemeral CA lets CI verify encryption, trust, and hostname validation independently.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=Keycloak-Test-CA \
  -keyout "$fixture/ca.key" -out "$fixture/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=database -addext subjectAltName=DNS:database \
  -keyout "$fixture/server.key" -out "$fixture/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$fixture/server.csr" -CA "$fixture/ca.pem" -CAkey "$fixture/ca.key" \
  -CAcreateserial -days 2 -copy_extensions copy -out "$fixture/server.pem" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=Wrong-CA \
  -keyout "$fixture/wrong-ca.key" -out "$fixture/wrong-ca.pem" >/dev/null 2>&1
chmod 755 "$fixture"
chmod 644 "$fixture/ca.pem" "$fixture/server.pem" "$fixture/wrong-ca.pem"
podman network create "$network" >/dev/null
podman secret create "$run_id-key" "$fixture/server.key" >/dev/null
db_password=$(node -e "console.log(require('node:crypto').randomBytes(24).toString('hex'))")
admin_password=$(node -e "console.log(require('node:crypto').randomBytes(24).toString('hex'))")
podman run -d --name "$db" --network "$network" --network-alias database --network-alias wrong-host \
  --secret "$run_id-key,target=server.key,uid=999,gid=999,mode=0600" -v "$fixture:/tls:ro,Z" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e "POSTGRES_PASSWORD=$db_password" \
  "$postgres" postgres -c ssl=on -c ssl_cert_file=/tls/server.pem -c ssl_key_file=/run/secrets/server.key >/dev/null
db_ready=false
for ((attempt=0; attempt<60; attempt++)); do
  if podman exec "$db" pg_isready -U keycloak -d keycloak >/dev/null 2>&1; then db_ready=true; break; fi
  sleep 2
done
[[ "$db_ready" == true ]] || { podman logs "$db"; exit 1; }
url_prefix=jdbc:postgresql
url_suffix=''
if [[ "$profile" == aws ]]; then url_prefix=jdbc:aws-wrapper:postgresql; url_suffix='?wrapperPlugins='; fi

start_server() {
  local host=$1 ca=$2 iam=${3:-false} suffix=$url_suffix
  local -a aws_env=()
  if [[ "$iam" == true ]]; then
    suffix='?wrapperPlugins=iam&iamRegion=us-east-1&iamHost=fixture.abc123.us-east-1.rds.amazonaws.com'
    # Offline signing only: these are deliberately fake credentials, never sent to AWS.
    aws_env=(-e AWS_REGION=us-east-1 -e AWS_ACCESS_KEY_ID=fixture-not-real -e AWS_SECRET_ACCESS_KEY=fixture-not-real -e AWS_EC2_METADATA_DISABLED=true)
  fi
  podman run -d --name "$server" --network "$network" --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --memory=2g \
    --volume /tmp --volume /opt/keycloak/data \
    -v "$fixture:/tls:ro,Z" -p 127.0.0.1::8080 -p 127.0.0.1::9000 \
    "${aws_env[@]}" -e "KC_DB_URL=$url_prefix://$host:5432/keycloak$suffix" -e KC_DB_USERNAME=keycloak \
    -e "KC_DB_PASSWORD=$db_password" -e KC_DB_TLS_MODE=verify-server -e "KC_DB_TLS_TRUST_STORE_FILE=/tls/$ca" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=ci-admin -e "KC_BOOTSTRAP_ADMIN_PASSWORD=$admin_password" \
    -e KC_HOSTNAME_STRICT=false -e KC_HTTP_ENABLED=true "$image" >/dev/null
}
expect_tls_failure() {
  local host=$1 ca=$2 stopped=false
  start_server "$host" "$ca"
  for ((attempt=0; attempt<60; attempt++)); do
    if [[ "$(podman inspect --format '{{.State.Running}}' "$server")" == false ]]; then stopped=true; break; fi
    sleep 2
  done
  podman logs "$server" > "$fixture/failure.log" 2>&1
  [[ "$stopped" == true ]] || { cat "$fixture/failure.log"; echo 'Invalid TLS configuration was not rejected' >&2; exit 1; }
  [[ "$(podman inspect --format '{{.State.ExitCode}}' "$server")" != 0 ]]
  grep -Eiq 'certificate|PKIX|SSL error|hostname.*(match|verif)' "$fixture/failure.log" || { cat "$fixture/failure.log"; exit 1; }
  podman rm -v "$server" >/dev/null
  echo "Rejected TLS configuration: $host / $ca"
}
expect_tls_failure database wrong-ca.pem
expect_tls_failure wrong-host ca.pem
if [[ "$profile" == aws ]]; then
  # A normal PostgreSQL fixture must reject the generated IAM token, not accept its password.
  # This exercises plugin loading, SDK credential resolution, signing, TLS, and driver delegation.
  start_server database ca.pem true
  iam_rejected=false
  for ((attempt=0; attempt<60; attempt++)); do
    if podman logs "$server" 2>&1 | grep -F 'password authentication failed' >/dev/null; then iam_rejected=true; break; fi
    [[ "$(podman inspect --format '{{.State.Running}}' "$server")" == true ]] || break
    sleep 2
  done
  [[ "$iam_rejected" == true ]] || { podman logs "$server"; echo 'Offline IAM signing/delegation failed' >&2; exit 1; }
  podman rm -fv "$server" >/dev/null
  echo 'Offline IAM token reached PostgreSQL and was rejected as expected.'
fi
start_server database ca.pem
VERIFY_BASE_URL="http://$(podman port "$server" 8080/tcp)"
VERIFY_MANAGEMENT_URL="http://$(podman port "$server" 9000/tcp)"
export VERIFY_BASE_URL VERIFY_MANAGEMENT_URL
export VERIFY_ADMIN_USERNAME=ci-admin VERIFY_ADMIN_PASSWORD="$admin_password"
if ! node tests/keycloak-protocol.mjs; then podman logs "$server"; exit 1; fi
podman exec "$db" psql -U keycloak -d keycloak -Atc "SELECT count(*) FROM databasechangelog" | grep -Eq '^[1-9][0-9]*$'
podman stop --time 30 "$server" >/dev/null
exit_code=$(podman inspect --format '{{.State.ExitCode}}' "$server")
[[ "$exit_code" == 0 || "$exit_code" == 143 ]] || { echo "Unexpected shutdown: $exit_code" >&2; exit 1; }
podman logs "$server" 2>&1 | grep -E 'stopped in|Shutdown complete' >/dev/null
echo "Verified $profile: Java/Keycloak versions, UID, shell-free rootfs, verified TLS, schema, authentication and graceful shutdown."
