#!/usr/bin/env bash
set -euo pipefail

# Branch-only experiment: use public UBI repositories, never subscribed RHEL repos.
# Base OCI images are pinned; the RPM inventory records this rolling-repository
# transaction. A reviewed RPM snapshot/lock is still needed before adoption.
rootfs=/opt/ubi-root
mkdir -p "$rootfs"
dnf --disableplugin=subscription-manager --disablerepo='*' \
  --enablerepo=ubi-9-baseos-rpms --enablerepo=ubi-9-appstream-rpms \
  --installroot="$rootfs" --releasever=9 --setopt=install_weak_deps=false \
  --setopt=keepcache=false --nodocs install -y \
  java-25-openjdk-headless glibc-langpack-en ca-certificates tzdata

# These packages serve installation/scriptlets rather than direct Java startup.
# Erase their metadata as well as their files; preserve the remaining RPM DB for
# accurate RHEL scanning. Do not hide vulnerable libraries or remove RPM records
# while leaving the corresponding files behind.
for package in bash coreutils coreutils-single rpm microdnf dnf dnf-data \
  python3-dnf yum java-25-openjdk-devel; do
  if rpm --root "$rootfs" -q "$package" >/dev/null 2>&1; then
    rpm --root "$rootfs" --erase --nodeps --noscripts --notriggers "$package"
  fi
done
rm -rf "$rootfs/var/cache/dnf" "$rootfs/var/cache/yum"
mkdir -p "$rootfs/usr/share/rambow" "$rootfs/opt/keycloak/data" "$rootfs/tmp"
rpm --root "$rootfs" -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{VENDOR}\t%{LICENSE}\n' \
  | sort > "$rootfs/usr/share/rambow/ubi-runtime-packages.tsv"
cat "$rootfs/usr/share/rambow/ubi-runtime-packages.tsv"
test -s "$rootfs/usr/share/rambow/ubi-runtime-packages.tsv"
printf 'keycloak:x:65532:65532:Keycloak:/opt/keycloak:/sbin/nologin\n' >> "$rootfs/etc/passwd"
printf 'keycloak:x:65532:\n' >> "$rootfs/etc/group"
chown 65532:65532 "$rootfs/opt/keycloak/data"
chmod 1777 "$rootfs/tmp"
