#!/bin/bash
# Self-test boot entry: checks the properties the design depends on, prints
# PASS/FAIL lines on the serial port, draws a QR code on tty1 for the host to
# photograph (QEMU screendump), then powers off.
exec > /dev/ttyS0 2>&1
set -u

# Public BIP39 test mnemonic and a regtest request it signs; the expected
# signatures were produced by the host build and match Bitcoin Core's.
SEED="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
REQ=AS1ZGPH83W6PGQQYQQP6N0VEWY6R42NZL4HV7K4MR3NKK6ZM9YYW92GPTAMJMFK2Q4CELGQPQ8PAVTSQQSQQX703FSWQ9SKKEYTLCHVLU0TFTTHY3W93DWAU2FJANCDNTVCYKQUJ2U97YF70QX6CSYEVJM8SU
SIG=AS1Z0PM3RZFMFPQSK59MP4YFFUUVQYEFL0FVQKYN6L4ZDSF5HM9YA68689SFELJ8NHMZPCGJYYSWDMLML7E5U2C82JCC0G5JP7WXYAVK4TV

fails=0
check() {
  if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}

sleep 3 # let USBGuard finish applying policy to devices present at boot
echo "AIRSIGN-SELFTEST-BEGIN $(uname -r)"
echo "cmdline: $(cat /proc/cmdline)"
echo "net interfaces: $(ls /sys/class/net | tr '\n' ' ')"
echo "block devices: $(ls /sys/block | tr '\n' ' ')"
echo "live mounts: $(grep -E ' /run/live| / ' /proc/mounts | awk '{print $1":"$2":"$3}' | tr '\n' ' ')"
echo "mem auto-init: $(dmesg | grep -o 'mem auto-init:.*' | head -1)"
echo "usb devices: $(for d in /sys/bus/usb/devices/*/authorized; do printf '%s=%s ' "$(basename "$(dirname "$d")")" "$(cat "$d")"; done)"

check "kernel zeroes freed memory (init_on_free)" "dmesg | grep -q 'mem auto-init:.*heap free:on'"
check "booted with toram" "grep -qw toram /proc/cmdline"
check "boot medium not mounted from the stick" "! findmnt -n -o SOURCE /run/live/medium | grep -q '^/dev/sd'"
check "only the loopback network interface exists" "[ \"\$(ls /sys/class/net)\" = lo ]"
check "no network driver modules in the image" "[ -z \"\$(find /lib/modules -path '*drivers/net*' -name '*.ko*' -print -quit)\" ]"
check "no wireless or bluetooth stack modules" "[ -z \"\$(find /lib/modules \\( -path '*net/wireless*' -o -path '*bluetooth*' \\) -name '*.ko*' -print -quit)\" ]"
check "no NVMe controller bound" "[ -z \"\$(ls /sys/class/nvme 2>/dev/null)\" ]"
check "AHCI/SATA driver not loaded" "! grep -qw ahci /proc/modules"
check "no SCSI/SATA/USB disks visible (stick refused after boot)" "! ls /sys/block | grep -qE '^(sd|hd|vd|nvme|mmcblk)'"
check "USB storage driver cannot be loaded" "! modprobe usb_storage"
check "USBGuard is enforcing" "systemctl is-active -q usbguard"
check "no swap" "[ \"\$(wc -l < /proc/swaps)\" -le 1 ]"
check "kernel lockdown: confidentiality" "grep -q '\\[confidentiality\\]' /sys/kernel/security/lockdown"
check "no login prompts on any terminal" "! grep -qx agetty /proc/[0-9]*/comm"
check "airsign binary runs" "/usr/local/bin/airsign --version"
printf '%s\n' "$SEED" > /run/selftest-seed
OUT=$(/usr/local/bin/airsign sign --mnemonic-file /run/selftest-seed --request "$REQ" --yes --format as1 2>/dev/null)
rm -f /run/selftest-seed
check "airsign signs the fixture exactly as Bitcoin Core does" "[ \"$OUT\" = \"$SIG\" ]"

if [ "$fails" -gt 0 ]; then
  echo "--- diagnostics"
  systemctl --no-pager --failed
  journalctl -b --no-pager -u usbguard -u airsign-lockdown | tail -n 25
  echo "modules: $(grep -E '^(usb_storage|uas|sd_mod) ' /proc/modules | cut -d' ' -f1-4 | tr '\n' ';')"
  ls -la /run/modprobe.d; modprobe -n -v usb_storage; echo "modprobe -n exit $?"
  find /lib/modules \( -path '*net/wireless*' -o -path '*bluetooth*' \) -name '*.ko*' | head
  echo "--- end diagnostics"
fi

printf '\033[2J\033[H' > /dev/tty1
/usr/local/bin/airsign show "$SIG" --format qr > /dev/tty1
echo "QR_READY"
sleep 20
echo "AIRSIGN-SELFTEST-END fails=$fails"
systemctl poweroff
