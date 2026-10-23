#!/usr/bin/env bash
# Sign a reproducible airsign build with your own Secure Boot db key and write
# a bootable signed ISO.
#
#   image/sign.sh <keys-dir> <build-out-dir> <signed.iso>
#
# <keys-dir> comes from image/keys.sh; <build-out-dir> from image/build.sh.
# Before signing, every input is checked against image/SHA256SUMS, the hashes
# the reproducible build publishes, so you sign exactly what anyone can
# rebuild. After signing, each signature is verified against your db
# certificate, and each signed binary is checked to have the same Authenticode
# digest (the hash that signature covers) as the published unsigned binary.
#
# Needs: sbsigntool, python3-pefile, plus what make-iso.sh needs.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
KEYS=$(readlink -f "$1")
IN=$(readlink -f "$2")
OUT=$3
SUMS=${SUMS:-$HERE/SHA256SUMS}
# shellcheck source=snapshot.env
. "$HERE/snapshot.env"
SOURCE_DATE_EPOCH=$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2} ${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}" +%s)
export SOURCE_DATE_EPOCH
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
die() { echo "sign.sh: $*" >&2; exit 1; }

# An old, correctly hashed ISO is still an old release. Require the build
# manifest to identify this exact commit and to match its published root hash.
REPO=$(cd "$HERE/.." && pwd)
[ -f "$IN/manifest.txt" ] || die "build manifest missing"
[ -f "$IN/ROOTHASH" ] || die "build root hash missing"
built_commit=$(awk '$1 == "commit" {print $2; exit}' "$IN/manifest.txt")
source_commit=$(git -C "$REPO" rev-parse HEAD) || die "source Git checkout unavailable"
[ "$built_commit" = "$source_commit" ] || die "build from $built_commit does not match checkout $source_commit"
git -C "$REPO" diff --quiet HEAD -- || die "source checkout has uncommitted changes"
[ "$(cat "$IN/ROOTHASH")" = "$(cat "$HERE/ROOTHASH")" ] || die "root hash differs from published image/ROOTHASH"

for f in airsign-live.iso airsign.efi systemd-bootx64.efi filesystem.squashfs filesystem.squashfs.verity vmlinuz initrd.img airsign; do
  want=$(awk -v f="$f" '$2 == f { print $1 }' "$SUMS")
  [ -n "$want" ] || die "no published hash for $f in $SUMS"
  [ "$(sha256sum "$IN/$f" | cut -d' ' -f1)" = "$want" ] || die "$f does not match the published hash; refusing to sign it"
done
for k in db.key db.crt PK.auth KEK.auth db.auth; do
  [ -f "$KEYS/$k" ] || die "missing $KEYS/$k (create keys with image/keys.sh)"
done

mkdir -p "$TMP/iso/live" "$TMP/esp/EFI/BOOT" "$TMP/esp/EFI/Linux" "$TMP/esp/loader/keys/airsign"
cp "$IN/filesystem.squashfs" "$IN/filesystem.squashfs.verity" "$TMP/iso/live/"
cp "$HERE/esp/loader/loader.conf" "$TMP/esp/loader/"
cp "$KEYS/PK.auth" "$KEYS/KEK.auth" "$KEYS/db.auth" "$TMP/esp/loader/keys/airsign/"

authenticode() {
  python3 - "$1" <<'PY'
import hashlib, sys, pefile
pe = pefile.PE(sys.argv[1], fast_load=True)
data = pe.__data__
csum = pe.OPTIONAL_HEADER.get_file_offset() + 64
sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
cert_dir = sec.get_file_offset()
h = hashlib.sha256()
h.update(data[:csum])
h.update(data[csum + 4:cert_dir])
h.update(data[cert_dir + 8:pe.OPTIONAL_HEADER.SizeOfHeaders])
end = pe.OPTIONAL_HEADER.SizeOfHeaders
for s in sorted(pe.sections, key=lambda s: s.PointerToRawData):
    if s.SizeOfRawData:
        h.update(data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
        end = max(end, s.PointerToRawData + s.SizeOfRawData)
tail_end = sec.VirtualAddress if sec.VirtualAddress else len(data)
h.update(data[end:tail_end])
print(h.hexdigest())
PY
}

sign_one() {
  local src=$1 dst=$2
  sbsign --key "$KEYS/db.key" --cert "$KEYS/db.crt" --output "$dst" "$src" 2>/dev/null
  sbverify --cert "$KEYS/db.crt" "$dst" >/dev/null 2>&1 || die "signature on $dst does not verify"
  [ "$(authenticode "$dst")" = "$(authenticode "$src")" ] || die "signed $dst covers different content than $src"
}
sign_one "$IN/systemd-bootx64.efi" "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
sign_one "$IN/airsign.efi" "$TMP/esp/EFI/Linux/airsign.efi"

bash "$HERE/make-iso.sh" "$TMP/iso" "$TMP/esp" "$OUT"
# Tests rebuild tampered variants from the signed trees.
if [ -n "${SIGN_TREES_OUT:-}" ]; then
  rm -rf "$SIGN_TREES_OUT" && mkdir -p "$SIGN_TREES_OUT"
  cp -a "$TMP/iso" "$TMP/esp" "$SIGN_TREES_OUT/"
fi
echo "signed ISO: $OUT"
echo "db certificate: $(openssl x509 -in "$KEYS/db.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
