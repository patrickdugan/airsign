#!/usr/bin/env bash
# Create your own Secure Boot key hierarchy for a dedicated airsign laptop.
#
#   image/keys.sh <dir> ["Common Name"]
#
# Writes PK, KEK and db as private key (.key), certificate (.crt/.der),
# EFI signature list (.esl) and signed update (.auth), plus owner.guid.
# The .auth files go on the signed stick, where systemd-boot can enroll them
# while the firmware is in Setup Mode. The .der files work with firmware menus
# that enroll certificates from a file.
#
# db.key is the key that decides what the laptop will boot. Keep the directory
# offline (an encrypted stick in a drawer), never on the online computer.
#
# Needs: openssl, efitools (cert-to-efi-sig-list, sign-efi-sig-list).
set -euo pipefail

D=$1
CN=${2:-airsign owner}
[ -e "$D/db.key" ] && { echo "$D already has keys; refusing to overwrite"; exit 1; }
mkdir -p "$D"
chmod 700 "$D"
cd "$D"
umask 077

cat /proc/sys/kernel/random/uuid > owner.guid
GUID=$(cat owner.guid)

for k in PK KEK db; do
  openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 7300 \
    -subj "/CN=$CN $k/" -keyout "$k.key" -out "$k.crt" 2>/dev/null
  openssl x509 -in "$k.crt" -outform DER -out "$k.der"
  cert-to-efi-sig-list -g "$GUID" "$k.crt" "$k.esl"
done
sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt PK PK.esl PK.auth >/dev/null
sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt KEK KEK.esl KEK.auth >/dev/null
sign-efi-sig-list -g "$GUID" -k KEK.key -c KEK.crt db db.esl db.auth >/dev/null
chmod 644 ./*.crt ./*.der ./*.esl ./*.auth owner.guid

echo "keys in $D (owner $GUID)"
openssl x509 -in db.crt -noout -subject -fingerprint -sha256
