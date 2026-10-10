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

all_zero_sample() {
  # 1 MiB at the start, the end, and 62 evenly spaced points.
  local dev=$1 size=$2 mib=$((1024 * 1024)) i off
  local blocks=$((size / mib))
  [ "$blocks" -lt 1 ] && blocks=1
  for i in $(seq 0 63); do
    off=$(( i * (blocks - 1) / 63 ))
    if [ "$(dd if="$dev" bs=$mib skip=$off count=1 iflag=direct 2>/dev/null | tr -d '\000' | head -c1 | wc -c)" != 0 ]; then
      return 1
    fi
  done
  return 0
}

all_zero_full() {
  local dev=$1
  [ "$(dd if="$dev" bs=4M iflag=direct 2>/dev/null | tr -d '\000' | head -c1 | wc -c)" = 0 ]
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
  if all_zero_sample "$dev" "$size"; then
    echo "    read-back sample: all zero"
  else
    echo "    read-back still finds data: overwriting every byte with zeros"
    dd if=/dev/zero of="$dev" bs=4M oflag=direct status=progress 2>&1 | tr '\r' '\n' | tail -n 1
    sync
  fi
  if all_zero_full "$dev"; then
    echo "    VERIFIED: every byte reads back as zero"
  else
    echo "    WARNING: $dev did not read back as all zeros"
  fi
}

for d in "${DISKS[@]}"; do
  IFS='|' read -r name size model serial <<<"$d"
  echo
  printf 'Drive %s  %s GB  model %s  serial %s\n' "$name" "$((size / 1000000000))" "$model" "$serial"
  read -r -p "Type the drive name ($name) to erase it, or press Enter to skip: " answer
  if [ "$answer" = "$name" ]; then
    wipe_one "$name" "$size"
  else
    echo "    skipped"
  fi
done

echo
echo "SSD note: wear-levelling spare area is only cleared by the controller erase;"
echo "a zero pass cannot reach or verify it."
read -r -p "Done. Press Enter to power off. " _
systemctl poweroff
