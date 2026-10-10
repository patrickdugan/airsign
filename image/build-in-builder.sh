#!/usr/bin/env bash
# Runs inside the snapshot-pinned builder chroot (see build.sh). Fixed paths:
#   /build/src   sources        /build/work  scratch        /build/out  results
# Builds airsign, bootstraps the image root from the same snapshot, removes
# every network/radio/DMA driver, scrubs build-time state, and assembles a
# hybrid BIOS+UEFI ISO with all timestamps set to SOURCE_DATE_EPOCH.
set -euo pipefail

SRC=/build/src
WORK=/build/work
OUT=/build/out
ROOT=$WORK/rootfs
ISO=$WORK/iso
HERE=$SRC/image
SOURCE_DATE_EPOCH=$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2} ${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}" +%s)
export SOURCE_DATE_EPOCH DEBIAN_FRONTEND=noninteractive
umask 022
rm -rf "$WORK" "$OUT"
mkdir -p "$WORK" "$OUT"

umount_all() {
  for m in dev/pts dev proc sys run; do umount -l "$ROOT/$m" 2>/dev/null || true; done
}
trap umount_all EXIT

# --- 1. airsign, compiled by the snapshot's rustc and gcc --------------------------
export CARGO_HOME=/build/cargo-home
export RUSTFLAGS="--remap-path-prefix=$SRC=/airsign --remap-path-prefix=$CARGO_HOME=/cargo"
(cd "$SRC" && cargo build --quiet --release --locked --target-dir "$WORK/target")
BIN=$WORK/target/release/airsign

# --- 2. the image root ------------------------------------------------------------
debootstrap --variant=minbase "$SUITE" "$ROOT" "$MIRROR" >/dev/null
mount --bind /dev "$ROOT/dev"; mount -t devpts devpts "$ROOT/dev/pts"
mount -t proc proc "$ROOT/proc"; mount -t sysfs sysfs "$ROOT/sys"; mount -t tmpfs tmpfs "$ROOT/run"

echo airsign > "$ROOT/etc/hostname"
echo "deb [check-valid-until=no] $MIRROR $SUITE main" > "$ROOT/etc/apt/sources.list"
# Keep initramfs/kernel hooks from trying to talk to systemd inside the chroot.
printf '#!/bin/sh\nexit 101\n' > "$ROOT/usr/sbin/policy-rc.d"
chmod +x "$ROOT/usr/sbin/policy-rc.d"

chroot "$ROOT" apt-get -o Acquire::Check-Valid-Until=false update -qq
chroot "$ROOT" apt-get install -y -qq --no-install-recommends \
  linux-image-amd64 live-boot systemd-sysv udev kmod \
  usbguard zbar-tools \
  util-linux nvme-cli hdparm >/dev/null

cp -a "$HERE/rootfs/." "$ROOT/"
install -m 0755 "$BIN" "$ROOT/usr/local/bin/airsign"
chmod 0755 "$ROOT"/usr/local/lib/airsign/*.sh
chmod 0600 "$ROOT/etc/usbguard/rules.conf"
sed -i 's/^PresentDevicePolicy=.*/PresentDevicePolicy=apply-policy/; s/^ImplicitPolicyTarget=.*/ImplicitPolicyTarget=block/' \
  "$ROOT/etc/usbguard/usbguard-daemon.conf"

# The signer runs as an unprivileged user with no password and no shell login.
chroot "$ROOT" useradd --system --no-create-home --shell /usr/sbin/nologin --groups video signer
chroot "$ROOT" passwd -l root >/dev/null

chroot "$ROOT" systemctl enable airsign.service airsign-lockdown.service airsign-selftest.service \
  airsign-wipe.service usbguard.service >/dev/null 2>&1
chroot "$ROOT" systemctl set-default multi-user.target >/dev/null 2>&1
# Nothing to log in to: no gettys on any virtual terminal.
chroot "$ROOT" systemctl mask getty@.service serial-getty@.service getty-static.service \
  systemd-networkd.service systemd-resolved.service systemd-timesyncd.service \
  apt-daily.timer apt-daily-upgrade.timer usbguard-dbus.service \
  nvmf-autoconnect.service nvmf-connect.target nvmf-connect-nbft.service >/dev/null 2>&1 || true

# --- 3. remove every network, radio and DMA-bus driver ----------------------------
KVER=$(ls "$ROOT/lib/modules" | sort -V | tail -1)
MODS=$ROOT/lib/modules/$KVER/kernel
{
  echo "# removed kernel module trees ($KVER)"
  for d in drivers/net net/wireless net/mac80211 net/bluetooth drivers/bluetooth net/nfc drivers/nfc \
           net/ieee802154 drivers/net/ieee802154 net/can drivers/net/can drivers/infiniband \
           drivers/thunderbolt drivers/firewire drivers/isdn drivers/atm net/atm drivers/staging; do
    if [ -d "$MODS/$d" ]; then
      echo "$d $(find "$MODS/$d" -name '*.ko*' | wc -l)"
      rm -rf "${MODS:?}/$d"
    fi
  done
  # Stragglers outside those trees (e.g. platform/x86/toshiba_bluetooth).
  find "$MODS" \( -name '*bluetooth*' -o -name '*wifi*' -o -name '*wlan*' \) -name '*.ko*' -print -delete \
    | sed "s|$MODS/|removed |" | sort
} > "$WORK/removed-modules.txt"
chroot "$ROOT" depmod -a "$KVER"
rm -rf "$ROOT/lib/firmware" "$ROOT/usr/lib/firmware"
chroot "$ROOT" update-initramfs -u -k "$KVER" >/dev/null 2>&1

# --- 4. scrub everything that records when or where the build ran ------------------
rm -f "$ROOT/usr/sbin/policy-rc.d"
chroot "$ROOT" apt-get clean
PACKAGES=$(chroot "$ROOT" dpkg-query -W -f '${Package} ${Version}\n')
umount_all
rm -rf "$ROOT"/var/lib/apt/lists/* "$ROOT"/var/cache/* "$ROOT"/tmp/* "$ROOT"/root/.cache
# Empty the logs but keep their directories (USBGuard refuses to start without
# /var/log/usbguard). They live in the RAM overlay at run time.
find "$ROOT/var/log" -type f -delete
install -d -m 0700 "$ROOT/var/log/usbguard"
rm -f "$ROOT"/etc/{passwd,group,shadow,gshadow,subuid,subgid}- \
      "$ROOT"/var/lib/dpkg/*-old "$ROOT"/var/lib/systemd/catalog/database \
      "$ROOT"/var/lib/dbus/machine-id \
      "$ROOT"/etc/nvme/hostid "$ROOT"/etc/nvme/hostnqn  # random NVMe-oF host IDs from nvme-cli's postinst; unused
# systemd creates a fresh machine-id at boot when this file is empty.
: > "$ROOT/etc/machine-id"
# Password-change dates are "days since 1970" taken from the clock unless the
# tool honours SOURCE_DATE_EPOCH; pin them either way.
DAYS=$((SOURCE_DATE_EPOCH / 86400))
sed -i -E "s/^([^:]*:[^:]*:)[0-9]+:/\1$DAYS:/" "$ROOT/etc/shadow"

# --- 5. squashfs and ISO -------------------------------------------------------------
mkdir -p "$ISO/live" "$ISO/boot/grub"
cp "$ROOT/boot/vmlinuz-$KVER" "$ISO/live/vmlinuz"
cp "$ROOT/boot/initrd.img-$KVER" "$ISO/live/initrd.img"
# squashfs-tools 4.6 takes every inode time and the mkfs time from SOURCE_DATE_EPOCH.
mksquashfs "$ROOT" "$ISO/live/filesystem.squashfs" -noappend -comp xz -quiet -no-progress \
  -wildcards -e 'boot/*' 'proc/*' 'sys/*' 'run/*' 'tmp/*'
cp "$HERE/grub.cfg" "$ISO/boot/grub/grub.cfg"
find "$ISO" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
# grub-mkrescue names /.disk/<time>.uuid and stamps the boot images it embeds
# from the wall clock, ignoring SOURCE_DATE_EPOCH: run it with the clock frozen.
# `-f` with an absolute date (no "@") makes libfaketime return exactly that
# instant on every call; the plain `faketime DATE` form computes an offset from
# the real clock instead, which drifts across a second boundary between runs.
# The temporary files it writes still get real mtimes from the kernel, so have
# xorriso (native commands after "--") record one date for every file.
TZ=UTC faketime -f "$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S')" \
  grub-mkrescue -o "$OUT/airsign-live.iso" "$ISO" -- \
  -volid AIRSIGN -volume_date all_file_dates "=$SOURCE_DATE_EPOCH" >/dev/null 2>&1

# --- 6. what was built, from what ------------------------------------------------------
cp "$BIN" "$OUT/airsign"
cp "$ISO/live/filesystem.squashfs" "$ISO/live/vmlinuz" "$ISO/live/initrd.img" "$OUT/"
(cd "$OUT" && sha256sum airsign-live.iso filesystem.squashfs vmlinuz initrd.img airsign > SHA256SUMS)
{
  echo "airsign live image"
  echo "commit   $COMMIT"
  echo "snapshot $MIRROR"
  echo "epoch    $SOURCE_DATE_EPOCH ($(date -u -d "@$SOURCE_DATE_EPOCH" +%FT%TZ))"
  echo "kernel   $KVER"
  echo "rustc    $(rustc --version)"
  echo
  cat "$OUT/SHA256SUMS"
  echo
  cat "$WORK/removed-modules.txt"
  echo
  echo "# image packages"
  echo "$PACKAGES"
} > "$OUT/manifest.txt"
