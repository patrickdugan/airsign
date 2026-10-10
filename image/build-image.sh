#!/usr/bin/env bash
# Build the airsign live USB image: a Debian trixie text-console system that
# boots from USB, copies itself into RAM, has no network drivers, cannot see
# internal disks, blocks USB storage after boot, and runs airsign on tty1.
#
#   sudo ./build-image.sh <airsign-static-binary> <out-dir>
#
# Output: <out-dir>/airsign-live.iso (hybrid: dd it to a USB stick; BIOS+UEFI)
#         <out-dir>/manifest.txt (package versions, removed modules, hashes)
set -euo pipefail

BIN=$(readlink -f "$1")
OUT=$(readlink -f "$2")
HERE=$(cd "$(dirname "$0")" && pwd)
SUITE=${SUITE:-trixie}
MIRROR=${MIRROR:-http://deb.debian.org/debian}
WORK=${WORK:-/root/build/airsign-image}
ROOT=$WORK/rootfs
ISO=$WORK/iso
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
file "$BIN" | grep -qE "statically linked|static-pie linked" || { echo "$BIN must be a static binary (musl build)"; exit 1; }
mkdir -p "$OUT"

umount_all() {
  for m in dev/pts dev proc sys run; do umount -l "$ROOT/$m" 2>/dev/null || true; done
}
trap umount_all EXIT

if [ ! -f "$WORK/.bootstrapped" ]; then
  rm -rf "$ROOT"; mkdir -p "$ROOT"
  debootstrap --variant=minbase --include=ca-certificates "$SUITE" "$ROOT" "$MIRROR"
  touch "$WORK/.bootstrapped"
fi

mount --bind /dev "$ROOT/dev"; mount -t devpts devpts "$ROOT/dev/pts"
mount -t proc proc "$ROOT/proc"; mount -t sysfs sysfs "$ROOT/sys"; mount -t tmpfs tmpfs "$ROOT/run"

echo airsign > "$ROOT/etc/hostname"
cat > "$ROOT/etc/apt/sources.list" <<EOF
deb $MIRROR $SUITE main
EOF
# Keep initramfs/kernel hooks from trying to talk to systemd inside the chroot.
printf '#!/bin/sh\nexit 101\n' > "$ROOT/usr/sbin/policy-rc.d"; chmod +x "$ROOT/usr/sbin/policy-rc.d"

chroot "$ROOT" apt-get update -qq
chroot "$ROOT" apt-get install -y -qq --no-install-recommends \
  linux-image-amd64 live-boot systemd-sysv udev kmod \
  usbguard zbar-tools \
  util-linux nvme-cli hdparm >/dev/null

# --- overlay: units, policies, scripts --------------------------------------
cp -a "$HERE/rootfs/." "$ROOT/"
install -m 0755 "$BIN" "$ROOT/usr/local/bin/airsign"
chmod 0755 "$ROOT"/usr/local/lib/airsign/*.sh
chmod 0600 "$ROOT/etc/usbguard/rules.conf"
sed -i 's/^PresentDevicePolicy=.*/PresentDevicePolicy=apply-policy/; s/^ImplicitPolicyTarget=.*/ImplicitPolicyTarget=block/' \
  "$ROOT/etc/usbguard/usbguard-daemon.conf"

# The signer runs as an unprivileged user with no password and no shell login.
chroot "$ROOT" useradd --system --no-create-home --shell /usr/sbin/nologin --groups video signer 2>/dev/null || true
chroot "$ROOT" passwd -l root >/dev/null

chroot "$ROOT" systemctl enable airsign.service airsign-lockdown.service airsign-selftest.service \
  airsign-wipe.service usbguard.service >/dev/null
chroot "$ROOT" systemctl set-default multi-user.target >/dev/null
# Nothing to log in to: no gettys on any virtual terminal.
chroot "$ROOT" systemctl mask getty@.service serial-getty@.service getty-static.service \
  systemd-networkd.service systemd-resolved.service systemd-timesyncd.service \
  apt-daily.timer apt-daily-upgrade.timer usbguard-dbus.service \
  nvmf-autoconnect.service nvmf-connect.target nvmf-connect-nbft.service >/dev/null 2>&1 || true

# --- remove every network, radio and DMA-bus driver ---------------------------
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
  find "$MODS" \( -name '*bluetooth*' -o -name '*wifi*' -o -name '*wlan*' \) -name '*.ko*' -print -delete | sed "s|$MODS/|removed |"
} > "$WORK/removed-modules.txt"
chroot "$ROOT" depmod -a "$KVER"
# Firmware for radios is not installed; make sure none slipped in.
rm -rf "$ROOT/lib/firmware" "$ROOT/usr/lib/firmware"

chroot "$ROOT" update-initramfs -u -k "$KVER" >/dev/null

# Leave no package manager state that could be mistaken for a way online.
rm -f "$ROOT/usr/sbin/policy-rc.d"
chroot "$ROOT" apt-get clean
rm -rf "$ROOT"/var/lib/apt/lists/* "$ROOT"/var/cache/*
# Empty the logs but keep their directories (USBGuard refuses to start without
# /var/log/usbguard). They live in the RAM overlay at run time.
find "$ROOT/var/log" -type f -delete
install -d -m 0700 "$ROOT/var/log/usbguard"

# --- assemble the ISO ------------------------------------------------------------
umount_all
rm -rf "$ISO"; mkdir -p "$ISO/live" "$ISO/boot/grub"
cp "$ROOT/boot/vmlinuz-$KVER" "$ISO/live/vmlinuz"
cp "$ROOT/boot/initrd.img-$KVER" "$ISO/live/initrd.img"
mksquashfs "$ROOT" "$ISO/live/filesystem.squashfs" -noappend -comp xz -quiet \
  -wildcards -e 'boot/*' 'proc/*' 'sys/*' 'run/*' 'tmp/*'
cp "$HERE/grub.cfg" "$ISO/boot/grub/grub.cfg"
grub-mkrescue -o "$OUT/airsign-live.iso" "$ISO" -- -volid AIRSIGN >/dev/null 2>&1

{
  echo "airsign live image  suite=$SUITE  kernel=$KVER  built=$(date -u -d @"$SOURCE_DATE_EPOCH" +%FT%TZ)"
  echo "airsign sha256 $(sha256sum "$BIN" | cut -d' ' -f1)"
  echo "iso     sha256 $(sha256sum "$OUT/airsign-live.iso" | cut -d' ' -f1)  size $(stat -c %s "$OUT/airsign-live.iso")"
  echo
  cat "$WORK/removed-modules.txt"
  echo
  echo "# packages"
  chroot "$ROOT" dpkg-query -W -f '${Package} ${Version}\n'
} > "$OUT/manifest.txt"
echo "built $OUT/airsign-live.iso"
