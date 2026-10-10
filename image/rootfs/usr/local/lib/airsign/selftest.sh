#!/bin/bash
# Self-test boot entry: checks the properties the design depends on and prints
# PASS/FAIL on the serial port and on screen (so it is useful on a real laptop
# too), draws a QR code on tty1 for the test host to photograph (QEMU
# screendump), shows the results again, then powers off.
set -u
SERIAL=/dev/ttyS0
[ -w "$SERIAL" ] && stty -F "$SERIAL" 115200 >/dev/null 2>&1 || SERIAL=/dev/null
say() { printf '%s\n' "$*" | tee -a /run/selftest.txt >> "$SERIAL"; }

# Public BIP39 test mnemonic and a regtest request it signs; the expected
# signatures were produced by the host build and match Bitcoin Core's.
SEED="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
REQ=AS1ZGPH83W6PGQQYQQP6N0VEWY6R42NZL4HV7K4MR3NKK6ZM9YYW92GPTAMJMFK2Q4CELGQPQ8PAVTSQQSQQX703FSWQ9SKKEYTLCHVLU0TFTTHY3W93DWAU2FJANCDNTVCYKQUJ2U97YF70QX6CSYEVJM8SU
SIG=AS1Z0PM3RZFMFPQSK59MP4YFFUUVQYEFL0FVQKYN6L4ZDSF5HM9YA68689SFELJ8NHMZPCGJYYSWDMLML7E5U2C82JCC0G5JP7WXYAVK4TV

fails=0
check() {
  if eval "$2" >/dev/null 2>&1; then say "PASS  $1"; else say "FAIL  $1"; fails=$((fails + 1)); fi
}

# Secure Boot state: last byte of the SecureBoot EFI variable.
secure_boot() {
  local v=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
  [ -r "$v" ] && [ "$(od -An -tu1 -j4 -N1 "$v" | tr -d ' ')" = 1 ]
}
expected_root=$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^dm-verity-root-hash=filesystem.squashfs://p')
root_src=$(awk '$3 == "squashfs" && $2 ~ /\/filesystem\.squashfs$/ { print $1; exit }' /proc/mounts)
root_dm=$(basename "$root_src")
[ -e "/sys/block/$root_dm/dm/name" ] && root_dm=$(cat "/sys/block/$root_dm/dm/name")
verity_root=$(dmsetup table "$root_dm" 2>/dev/null | awk '$3 == "verity" { print $12 }')

: > /run/selftest.txt
sleep 3 # let USBGuard finish applying policy to devices present at boot
say "AIRSIGN-SELFTEST-BEGIN $(uname -r)"
say "secure boot: $(secure_boot && echo on || echo off)   verity root: ${verity_root:-none}"
say "net interfaces: $(ls /sys/class/net | tr '\n' ' ')"
say "block devices: $(ls /sys/block | tr '\n' ' ')"
say "live mounts: $(grep -E ' /run/live| / ' /proc/mounts | awk '{print $1":"$2":"$3}' | tr '\n' ' ')"
say "mem auto-init: $(dmesg | grep -o 'mem auto-init:.*' | head -1)"
say "usb devices: $(for d in /sys/bus/usb/devices/*/authorized; do printf '%s=%s ' "$(basename "$(dirname "$d")")" "$(cat "$d")"; done)"

check "booted through UEFI Secure Boot" "secure_boot"
check "system image mounted through dm-verity" "[ -n \"$verity_root\" ]"
check "verity root hash equals the one sealed in the UKI command line" "[ -n \"$expected_root\" ] && [ \"$verity_root\" = \"$expected_root\" ]"
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
  {
    echo "--- diagnostics"
    systemctl --no-pager --failed
    journalctl -b --no-pager -u usbguard -u airsign-lockdown | tail -n 25
    echo "root source: $root_src ($root_dm)"; dmsetup table 2>&1
    echo "--- end diagnostics"
  } >> "$SERIAL" 2>&1
fi

printf '\033[2J\033[H' > /dev/tty1
/usr/local/bin/airsign show "$SIG" --format qr > /dev/tty1
say "QR_READY"
sleep 15
printf '\033[2J\033[H' > /dev/tty1
cat /run/selftest.txt > /dev/tty1
say "AIRSIGN-SELFTEST-END fails=$fails"
echo "Powering off in 60 seconds." > /dev/tty1
sleep 60
systemctl poweroff
