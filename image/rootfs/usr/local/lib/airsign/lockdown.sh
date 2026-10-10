#!/bin/bash
# Runs before USBGuard. The session is only amnesic if the whole system lives in
# RAM: once USBGuard refuses the boot stick, nothing may still be reading it.
set -u

say() {
  echo "airsign-lockdown: $*"
  printf '%s\n' "$*" > /dev/tty1 2>/dev/null || true
}

# With `toram`, live-boot copies the medium into memory and releases the stick.
# If it could not (too little RAM), /run/live/medium is still the stick itself.
src=$(findmnt -n -o SOURCE /run/live/medium 2>/dev/null || true)
fstype=$(findmnt -n -o FSTYPE /run/live/medium 2>/dev/null || true)
if [ -n "$src" ] && [ "$fstype" != tmpfs ] && [ -b "$src" ]; then
  say "airsign could not copy itself into memory (is there at least 2 GB of RAM?)."
  say "Refusing to start: the boot stick would still be in use. Powering off in 60 s."
  sleep 60
  systemctl poweroff
  exit 1
fi

# USB storage stays unusable for the rest of the session, even if USBGuard were
# stopped: modprobe reads /run/modprobe.d as well as /etc/modprobe.d.
mkdir -p /run/modprobe.d
cat > /run/modprobe.d/airsign-no-usb-storage.conf <<'EOF'
install usb_storage /bin/false
install uas /bin/false
EOF
# udevd caches the modprobe configuration; make it pick up the block above, or
# it would reload the drivers for the next storage device it sees.
udevadm control --reload 2>/dev/null || true
# The drivers themselves are unloaded by unload-storage.sh, after USBGuard has
# refused the boot stick: until then the stick is authorized and udev would
# simply probe it again.
say "airsign: running from RAM; you can remove the USB stick."
exit 0
