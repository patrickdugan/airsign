#!/bin/bash
# Wipe boot entry: erase this computer's internal drives so that it holds
# nothing, then power off. Every drive is erased only after the operator types
# its name. The USB stick airsign booted from is never offered.
#
# Order of methods, strongest first, each verified by reading the drive back:
#   NVMe   nvme format --ses=1 (controller-level user data erase)
#   other  blkdiscard --secure, then plain discard
#   all    if the read-back still finds data: overwrite every byte with zeros
# Limits (said on screen too): an SSD's spare area is only reached by the
# controller-level erase; overwriting cannot prove it. Spinning disks are fully
# covered by the zero pass.
set -u
set -o pipefail

# Mirror everything shown (prompts included) to the serial port when there is
# one, so the wipe can be driven and checked from a test harness.
if [ -w /dev/ttyS0 ] && stty -F /dev/ttyS0 115200 >/dev/null 2>&1; then
  exec > >(tee -a /dev/ttyS0) 2>&1
fi

for m in ahci nvme mmc_block sdhci_pci virtio_blk ata_piix; do modprobe "$m" 2>/dev/null; done
udevadm settle 2>/dev/null || sleep 3

echo
echo "=== airsign: ERASE INTERNAL DRIVES ==="
echo "This permanently destroys everything on the drives you confirm."
echo

# Name, size in bytes, model, serial, read from sysfs (no eval of device-supplied
# strings). Anything attached over USB is skipped: that includes the boot stick.
DISKS=()
for sys in /sys/block/*; do
  name=${sys##*/}
  case "$name" in loop*|sr*|zram*|ram*|dm-*|md*) continue ;; esac
  case "$(readlink -f "$sys/device")" in */usb*) continue ;; esac
  size=$(( $(cat "$sys/size") * 512 ))
  [ "$size" -gt 0 ] || continue
  model=$(tr -cd '[:alnum:] ._-' < "$sys/device/model" 2>/dev/null || true)
  serial=$(tr -cd '[:alnum:] ._-' < "$sys/device/serial" 2>/dev/null || true)
  DISKS+=("$name|$size|${model:-?}|${serial:-?}")
done

if [ ${#DISKS[@]} -eq 0 ]; then
  echo "No internal drives found."
  read -r -p "Press Enter to power off. " _
  systemctl poweroff
  exit 0
fi

# cmp checks every logical byte and fails on a mismatch, premature EOF or
# read error. Samples alone cannot justify declaring a device wiped.
all_zero_full() {
  local dev=$1 size=$2
  [ "$size" -gt 0 ] || return 1
  LC_ALL=C cmp -n "$size" /dev/zero "$dev" >/dev/null 2>&1
}

wipe_one() {
  local name=$1 size=$2 dev=/dev/$1
  echo "--- erasing $dev"
  if [[ $name == nvme* ]]; then
    nvme format "$dev" --ses=1 --force >/dev/null 2>&1 && echo "    NVMe user-data erase: done" \
      || echo "    NVMe user-data erase: not supported"
  else
    if blkdiscard --secure "$dev" 2>/dev/null; then
      echo "    secure discard: done"
    elif blkdiscard --force "$dev" 2>/dev/null; then
      echo "    discard: done"
    else
      echo "    discard: not supported"
    fi
  fi
  if all_zero_full "$dev" "$size"; then
    echo "    read-back: entire logical device is zero"
  else
    echo "    read-back found data or failed; overwriting the logical device"
    if ! dd if=/dev/zero of="$dev" bs=4M count="$size" iflag=count_bytes oflag=direct status=progress 2>&1 | tr '\r' '\n' | tail -n 1; then
      echo "    ERROR: overwrite command failed" >&2
    fi
    sync
  fi
  if all_zero_full "$dev" "$size"; then
    echo "    VERIFIED: all $size logical bytes read back as zero (SSD spare areas excluded)"
  else
    echo "    ERROR: could not verify all logical bytes of $dev" >&2
    return 1
  fi
}

for d in "${DISKS[@]}"; do
  IFS='|' read -r name size model serial <<<"$d"
  echo
  printf 'Drive %s  %s GB  model %s  serial %s\n' "$name" "$((size / 1000000000))" "$model" "$serial"
  read -r -p "Type the drive name ($name) to erase it, or press Enter to skip: " answer
  if [ "$answer" = "$name" ]; then
    wipe_one "$name" "$size" || {
      echo "ERASE FAILED: stopping before the next drive." >&2
      systemctl poweroff || true
      exit 1
    }
  else
    echo "    skipped"
  fi
done

echo
echo "SSD note: wear-levelling spare area is only cleared by the controller erase;"
echo "a zero pass cannot reach or verify it."
read -r -p "Done. Press Enter to power off. " _
systemctl poweroff
