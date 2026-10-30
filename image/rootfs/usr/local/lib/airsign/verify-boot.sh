#!/bin/sh
# Root-run guard for the offline signing service. Authentication and image
# integrity must be established before any mnemonic is accepted.
set -eu

fail() {
  echo "airsign: verified-boot preflight failed: $*" >&2
  exit 1
}

efi=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
[ -r "$efi" ] || fail "Secure Boot EFI state unavailable"
state=$(od -An -tu1 -j4 -N1 "$efi" | tr -d '[:space:]') || fail "cannot read Secure Boot state"
[ "$state" = 1 ] || fail "Secure Boot is OFF"

expected=$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^dm-verity-root-hash=filesystem.squashfs://p')
case "$expected" in
  ''|*[!0-9a-f]*) fail "missing or malformed verity root hash" ;;
esac
[ "${#expected}" -eq 64 ] || fail "verity root hash is not 32 bytes"

src=$(awk '$3 == "squashfs" && $2 ~ /\/filesystem\.squashfs$/ { print $1; exit }' /proc/mounts)
[ -n "$src" ] || fail "verified system image is not mounted"
case "$src" in
  /dev/mapper/*) name=${src#/dev/mapper/} ;;
  /dev/dm-*) name=$(cat "/sys/block/${src#/dev/}/dm/name" 2>/dev/null) || fail "cannot identify verity mapping" ;;
  *) fail "root image mounted directly from $src" ;;
esac
[ -n "$name" ] || fail "verity device name unavailable"
table=$(dmsetup table "$name" 2>/dev/null) || fail "cannot read device-mapper table"
set -- $table
[ "$#" -ge 12 ] || fail "incomplete device-mapper table"
[ "$3" = verity ] || fail "root image is not dm-verity protected"
[ "${12}" = "$expected" ] || fail "verity hash differs from signed kernel command line"
echo "airsign: Secure Boot and dm-verity verified before signer startup"
