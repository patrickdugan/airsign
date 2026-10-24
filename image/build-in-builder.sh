#!/usr/bin/env bash
# Runs inside the snapshot-pinned builder chroot (see build.sh). Fixed paths:
#   /build/src   sources        /build/work  scratch        /build/out  results
# Builds airsign, bootstraps the image root from the same snapshot, removes
# every network/radio/DMA driver, scrubs build-time state, then makes the
# verified-boot pieces: squashfs + dm-verity hash tree, one multi-profile UKI
# whose command lines carry the root hash, systemd-boot, and an unsigned
# UEFI-only ISO. All timestamps come from SOURCE_DATE_EPOCH.
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

umount_all() {
  for m in dev/pts dev proc sys run; do umount -l "$ROOT/$m" 2>/dev/null || true; done
}
trap umount_all EXIT
umount_all
rm -rf --one-file-system "$WORK" "$OUT"
mkdir -p "$WORK" "$OUT"

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
  util-linux nvme-cli hdparm \
  dmsetup libcryptsetup12 >/dev/null

# The builder source checkout may be owned by the CI runner (UID 1001).
# Never preserve that ownership in a privileged live image. A prior cp -a
# installed rootfs/ overlay files as runner:runner, so root:root mode 0600
# USBGuard policy became unreadable to the enforcing daemon.
cp -a --no-preserve=ownership "$HERE/rootfs/." "$ROOT/"
install -m 0755 "$BIN" "$ROOT/usr/local/bin/airsign"
chmod 0755 "$ROOT"/usr/local/lib/airsign/*.sh \
  "$ROOT/etc/initramfs-tools/hooks/airsign-verity" \
  "$ROOT/etc/initramfs-tools/scripts/live-bottom/airsign-verity"
# USBGuard's policy is intentionally private, owned and writable only by root.
chown 0:0 "$ROOT/etc/usbguard/rules.conf"
chmod 0600 "$ROOT/etc/usbguard/rules.conf"
[ "$(stat -c '%u:%g:%a' "$ROOT/etc/usbguard/rules.conf")" = '0:0:600' ] ||
  { echo "usbguard rule file ownership/mode is unsafe" >&2; exit 1; }
sed -i 's/^PresentDevicePolicy=.*/PresentDevicePolicy=apply-policy/; s/^ImplicitPolicyTarget=.*/ImplicitPolicyTarget=block/' \
  "$ROOT/etc/usbguard/usbguard-daemon.conf"

# The signer runs as an unprivileged user with no password and no shell login.
chroot "$ROOT" useradd --system --no-create-home --shell /usr/sbin/nologin --groups video signer
chroot "$ROOT" passwd -l root >/dev/null

chroot "$ROOT" systemctl enable airsign.service airsign-lockdown.service airsign-verify-boot.service airsign-unload-storage.service \
  airsign-selftest.service airsign-wipe.service usbguard.service >/dev/null 2>&1
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
# Debootstrap copied the builder's /etc/resolv.conf into the guest root.
# GitHub runners use different DNS servers, producing different SquashFS
# contents and hence different dm-verity roots. The signer has no networking:
# replace that host-specific file only after the package installation is done.
rm -f "$ROOT/etc/resolv.conf"
printf '# airsign offline image: no DNS resolver configured\n' > "$ROOT/etc/resolv.conf"
chmod 0644 "$ROOT/etc/resolv.conf"
# systemd creates a fresh machine-id at boot when this file is empty.
: > "$ROOT/etc/machine-id"
# Password-change dates are "days since 1970" taken from the clock unless the
# tool honours SOURCE_DATE_EPOCH; pin them either way.
DAYS=$((SOURCE_DATE_EPOCH / 86400))
sed -i -E "s/^([^:]*:[^:]*:)[0-9]+:/\1$DAYS:/" "$ROOT/etc/shadow"

# --- 5. squashfs and its dm-verity hash tree ----------------------------------------------
mkdir -p "$ISO/live" "$WORK/esp/EFI/BOOT" "$WORK/esp/EFI/Linux" "$WORK/esp/loader"
# squashfs-tools 4.6 takes every inode time and the mkfs time from SOURCE_DATE_EPOCH.
mksquashfs "$ROOT" "$ISO/live/filesystem.squashfs" -noappend -comp xz -quiet -no-progress \
  -wildcards -e 'boot/*' 'proc/*' 'sys/*' 'run/*' 'tmp/*'
# A fixed salt and UUID make the hash tree, and so the root hash, reproducible.
SALT=$(printf 'airsign-verity-v1' | sha256sum | cut -c1-64)
ROOTHASH=$(veritysetup format --salt="$SALT" --uuid=00000000-0000-0000-0000-000000000000 \
  "$ISO/live/filesystem.squashfs" "$ISO/live/filesystem.squashfs.verity" | awk '/^Root hash:/ { print $3 }')
[ "${#ROOTHASH}" -eq 64 ] || { echo "veritysetup gave no root hash"; exit 1; }

# --- 6. one UKI: kernel + initramfs + sealed command lines ---------------------------------
# Under Secure Boot, systemd-stub ignores any command line the loader passes and
# uses only these, so the root hash and every hardening flag are covered by the
# signature. Three profiles of one UKI become three systemd-boot menu entries.
COMMON="boot=live toram nomodeset consoleblank=0 quiet loglevel=3 systemd.show_status=false panic=10"
COMMON="$COMMON init_on_free=1 init_on_alloc=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on"
COMMON="$COMMON vsyscall=none debugfs=off lockdown=confidentiality dm-verity-root-hash=filesystem.squashfs:$ROOTHASH"
# Internal-disk and DMA-bus drivers the kernel refuses to load in signing mode.
BLOCK="module_blacklist=ahci,nvme,nvme_core,mmc_block,sdhci_pci,virtio_blk,ata_piix,pata_acpi,ata_generic,firewire_ohci,thunderbolt"
VERSION=$(awk -F'"' '/^version/ { print $2; exit }' "$SRC/Cargo.toml")
printf 'NAME="airsign"\nPRETTY_NAME="airsign %s"\nID=airsign\nVERSION_ID=%s\n' "$VERSION" "$VERSION" > "$WORK/os-release"

ukify build --profile="ID=selftest
TITLE=self-test: results on screen and serial port" \
  --cmdline="$COMMON $BLOCK airsign.selftest=1 console=tty0 console=ttyS0,115200" \
  --output="$WORK/profile-selftest.efi" >/dev/null
ukify build --profile="ID=wipe
TITLE=ERASE this computer's internal drives, asks before each" \
  --cmdline="$COMMON airsign.wipe=1" \
  --output="$WORK/profile-wipe.efi" >/dev/null
ukify build --linux="$ROOT/boot/vmlinuz-$KVER" --initrd="$ROOT/boot/initrd.img-$KVER" \
  --os-release=@"$WORK/os-release" --cmdline="$COMMON $BLOCK" \
  --profile="ID=signer
TITLE=offline signer" \
  --join-profile="$WORK/profile-selftest.efi" --join-profile="$WORK/profile-wipe.efi" \
  --output="$OUT/airsign.efi" >/dev/null

# --- 7. the unsigned ISO (UEFI only) ---------------------------------------------------------
# It boots with Secure Boot off. image/sign.sh makes the version your firmware
# will verify, from these same published pieces.
cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi "$OUT/systemd-bootx64.efi"
cp "$OUT/systemd-bootx64.efi" "$WORK/esp/EFI/BOOT/BOOTX64.EFI"
cp "$OUT/airsign.efi" "$WORK/esp/EFI/Linux/airsign.efi"
cp "$HERE/esp/loader/loader.conf" "$WORK/esp/loader/loader.conf"
bash "$HERE/make-iso.sh" "$ISO" "$WORK/esp" "$OUT/airsign-live.iso"

# --- 8. what was built, from what ------------------------------------------------------------
cp "$BIN" "$OUT/airsign"
cp "$ISO/live/filesystem.squashfs" "$ISO/live/filesystem.squashfs.verity" "$OUT/"
# veritysetup creates the detached hash tree mode 0600. The built artifact
# has no secrets and must be readable by the unprivileged release verifier
# and the machine that runs image/sign.sh. File-mode change leaves its SHA256
# and the deterministic ISO payload unchanged.
chmod 0644 "$OUT/filesystem.squashfs.verity"
cp "$ROOT/boot/vmlinuz-$KVER" "$OUT/vmlinuz"
cp "$ROOT/boot/initrd.img-$KVER" "$OUT/initrd.img"
echo "$ROOTHASH" > "$OUT/ROOTHASH"
(cd "$OUT" && sha256sum airsign-live.iso airsign.efi systemd-bootx64.efi filesystem.squashfs \
  filesystem.squashfs.verity vmlinuz initrd.img airsign > SHA256SUMS)
{
  echo "airsign live image"
  echo "commit   $COMMIT"
  echo "snapshot $MIRROR"
  echo "epoch    $SOURCE_DATE_EPOCH ($(date -u -d "@$SOURCE_DATE_EPOCH" +%FT%TZ))"
  echo "kernel   $KVER"
  echo "rustc    $(rustc --version)"
  echo "verity   root hash $ROOTHASH"
  echo "cmdline  $COMMON $BLOCK"
  echo
  cat "$OUT/SHA256SUMS"
  echo
  cat "$WORK/removed-modules.txt"
  echo
  echo "# image packages"
  echo "$PACKAGES"
} > "$OUT/manifest.txt"
