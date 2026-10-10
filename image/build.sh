#!/usr/bin/env bash
# Reproducible build of the airsign live ISO.
#
#   sudo image/build.sh <out-dir>
#
# The host only runs debootstrap once, to create a builder chroot from the
# Debian snapshot pinned in snapshot.env. Everything that shapes the output
# runs inside that chroot at fixed paths, using the snapshot's own tools:
# rustc and gcc, debootstrap, squashfs-tools, xorriso and GRUB. That covers
# compiling airsign, bootstrapping the image, building the squashfs and making
# the ISO. Two machines building the same commit should therefore produce the
# same SHA256SUMS.
#
# Host needs: debootstrap, debian-archive-keyring, git, network access.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
# shellcheck source=snapshot.env
. "$HERE/snapshot.env"
MIRROR=http://snapshot.debian.org/archive/debian/$SNAPSHOT
WORK=${WORK:-/root/build/airsign-repro}
B=$WORK/builder
export LC_ALL=C TZ=UTC

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

unmount_all() {
  for m in build/work/rootfs/dev/pts build/work/rootfs/dev build/work/rootfs/proc build/work/rootfs/sys \
           build/work/rootfs/run dev/pts dev proc sys run; do
    umount -l "$B/$m" 2>/dev/null || true
  done
}
trap unmount_all EXIT

mount_builder() {
  mount --bind /dev "$B/dev"; mount -t devpts devpts "$B/dev/pts"
  mount -t proc proc "$B/proc"; mount -t sysfs sysfs "$B/sys"; mount -t tmpfs tmpfs "$B/run"
}

BUILDER_PKGS="debootstrap debian-archive-keyring squashfs-tools cryptsetup-bin systemd-ukify systemd-boot-efi
  python3-pefile sbsigntool efitools xorriso mtools dosfstools faketime rustc cargo gcc libc6-dev ca-certificates"
READY=$B/.ready-$SNAPSHOT-$(echo "$BUILDER_PKGS" | sha256sum | cut -c1-12)

if [ ! -f "$READY" ]; then
  rm -rf "$B"; mkdir -p "$B"
  debootstrap --variant=minbase "$SUITE" "$B" "$MIRROR"
  echo "deb [check-valid-until=no] $MIRROR $SUITE main" > "$B/etc/apt/sources.list"
  echo 'Acquire::Check-Valid-Until "false";' > "$B/etc/apt/apt.conf.d/99snapshot"
  cp /etc/resolv.conf "$B/etc/resolv.conf"
  mount_builder
  chroot "$B" apt-get update -qq
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive chroot "$B" apt-get install -y -qq --no-install-recommends $BUILDER_PKGS >/dev/null
  unmount_all
  touch "$READY"
fi

cp /etc/resolv.conf "$B/etc/resolv.conf"
# An interrupted earlier run can leave mounts behind; clear them, and never let
# a delete cross into a mounted filesystem.
unmount_all
mount_builder

# Sources: the tracked files of the working tree, always at /build/src.
rm -rf --one-file-system "$B/build"; mkdir -p "$B/build/src"
GIT="git -c safe.directory=* -C $REPO"
$GIT ls-files -z | (cd "$REPO" && tar --null -T - -cf -) | tar -xf - -C "$B/build/src"
COMMIT=$($GIT rev-parse HEAD)
$GIT diff --quiet HEAD -- || COMMIT="$COMMIT-dirty"

chroot "$B" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C TZ=UTC \
  SNAPSHOT="$SNAPSHOT" SUITE="$SUITE" MIRROR="$MIRROR" COMMIT="$COMMIT" \
  bash /build/src/image/build-in-builder.sh

cp "$B"/build/out/* "$OUT/"
echo
cat "$OUT/SHA256SUMS"
