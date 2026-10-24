#!/bin/bash
# Runs after USBGuard has refused every storage device present at boot (the
# boot stick included): unload the USB storage drivers so that nothing is left
# that a storage device could bind to. /run/modprobe.d (lockdown.sh) keeps them
# from being loaded again.
set -u
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
      exit 0
    fi
    echo "airsign-unload-storage: cannot read /proc/modules; refusing signing session" >&2
    exit 1
  fi
  sleep 0.5
done
echo "airsign-unload-storage: USB storage driver still loaded after 30 s; refusing signing session" >&2
exit 1
