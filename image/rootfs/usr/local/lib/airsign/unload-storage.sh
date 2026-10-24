#!/bin/bash
# Runs after USBGuard has refused every storage device present at boot (the
# boot stick included): unload the USB storage drivers so that nothing is left
# that a storage device could bind to. /run/modprobe.d (lockdown.sh) keeps them
# from being loaded again.
set -u

# Do not merely trust a successful module unload. A built-in driver, a
# previously detected SATA/USB device, or an unsupported bus must also block
# entry into the offline signer. The live image uses only loop/dm/ram devices.
no_physical_disks() {
  if [ ! -d /sys/block ]; then
    echo "airsign-unload-storage: /sys/block unavailable; refusing signing session" >&2
    return 1
  fi
  local disk name
  for disk in /sys/block/*; do
    [ -e "$disk" ] || continue
    name=${disk##*/}
    case "$name" in
      loop[0-9]*|dm-[0-9]*|ram[0-9]*|zram[0-9]*) ;;
      *)
        echo "airsign-unload-storage: unexpected block device $name; refusing signing session" >&2
        return 1
        ;;
    esac
  done
  return 0
}

for _ in $(seq 1 60); do
  for intf in /sys/bus/usb/drivers/usb-storage/*:* /sys/bus/usb/drivers/uas/*:*; do
    [ -e "$intf" ] && echo "${intf##*/}" > "${intf%/*}/unbind" 2>/dev/null
  done
  modprobe -r uas usb_storage 2>/dev/null
  if grep -qE '^(usb_storage|uas) ' /proc/modules; then
    : # One or both modules are still resident. Retry after unbind.
  else
    rc=$?
    if [ "$rc" -eq 1 ]; then
      no_physical_disks || exit 1
      if ! systemctl is-active --quiet usbguard.service; then
        echo "airsign-unload-storage: USBGuard is not active; refusing signing session" >&2
        exit 1
      fi
      exit 0
    fi
    echo "airsign-unload-storage: cannot read /proc/modules; refusing signing session" >&2
    exit 1
  fi
  sleep 0.5
done
echo "airsign-unload-storage: USB storage driver still loaded after 30 s; refusing signing session" >&2
exit 1
