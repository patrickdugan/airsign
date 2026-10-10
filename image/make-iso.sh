#!/usr/bin/env bash
# Assemble a UEFI-only hybrid ISO (boots from a USB stick or optical media):
#   ISO9660:  <iso-tree>          (/live/filesystem.squashfs and .verity)
#   ESP:      <esp-tree> as a FAT image, appended as GPT partition 2 and
#             referenced by the El Torito EFI boot entry
# Deterministic for a given input and SOURCE_DATE_EPOCH: fixed FAT volume ID,
# and every date (FAT entries, ISO files, volume, GPT) taken from the epoch.
#
#   SOURCE_DATE_EPOCH=... make-iso.sh <iso-tree> <esp-tree> <out.iso>
#
# Needs: xorriso, mtools, dosfstools, faketime.
set -euo pipefail

ISO_TREE=$(readlink -f "$1")
ESP_TREE=$(readlink -f "$2")
OUT=$3
SDE=${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH}
FROZEN=$(date -u -d "@$SDE" '+%Y-%m-%d %H:%M:%S')
STAMP=$(date -u -d "@$SDE" '+%Y%m%d%H%M%S00')
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
frozen() { TZ=UTC faketime -f "$FROZEN" "$@"; }

find "$ISO_TREE" "$ESP_TREE" -exec touch -h -d "@$SDE" {} +

# ESP: 10% plus 4 MiB of headroom over the files.
kib=$(( $(du -sk --apparent-size "$ESP_TREE" | cut -f1) * 11 / 10 + 4096 ))
frozen mkfs.fat -C --invariant -n AIRSIGN "$TMP/efi.img" "$kib" >/dev/null
(cd "$ESP_TREE" && find . -mindepth 1 -type d | LC_ALL=C sort) | while read -r d; do
  frozen mmd -i "$TMP/efi.img" "::${d#.}"
done
(cd "$ESP_TREE" && find . -type f | LC_ALL=C sort) | while read -r f; do
  frozen mcopy -m -i "$TMP/efi.img" "$ESP_TREE/${f#./}" "::${f#.}"
done

rm -f "$OUT"
if ! frozen xorriso -as mkisofs -o "$OUT" -V AIRSIGN -r -iso-level 3 \
  --modification-date="$STAMP" --set_all_file_dates "$STAMP" \
  -partition_offset 16 \
  -append_partition 2 C12A7328-F81F-11D2-BA4B-00A0C93EC93B "$TMP/efi.img" \
  -appended_part_as_gpt \
  -e --interval:appended_partition_2:all:: -no-emul-boot \
  "$ISO_TREE" -- -boot_image any gpt_disk_guid=volume_date_uuid 2>"$TMP/xorriso.log"; then
  cat "$TMP/xorriso.log" >&2
  exit 1
fi
