#!/usr/bin/env bash
# End-to-end check against Bitcoin Core on regtest:
#   Core watch-only wallet  -> PSBT -> airsign request -> (words / two-letter /
#   QR via zbarimg) -> airsign sign -> airsign combine -> Core accepts and mines.
# Then Core, holding the same private key, re-signs the PSBT on its own and the
# two transactions must be byte-identical (deterministic BIP340 nonces).
#
# Needs: bitcoind/bitcoin-cli (CORE_BIN), an airsign built with --features dev
# (AIRSIGN), python3, zbarimg.
set -euo pipefail

CORE_BIN=${CORE_BIN:-/root/opt/bitcoin-31.1/bin}
AIRSIGN=${AIRSIGN:-/root/build/airsign-cargo/release/airsign}
OUT=${OUT:-$(pwd)/e2e-out}
DD=$(mktemp -d /tmp/airsign-e2e.XXXXXX)
mkdir -p "$OUT"
PORT=18543

cli() { "$CORE_BIN/bitcoin-cli" -regtest -datadir="$DD" -rpcport=$PORT "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
cleanup() { cli stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$DD"; }
trap cleanup EXIT
pass() { echo "PASS  $*"; }
die() { echo "FAIL  $*"; exit 1; }

"$CORE_BIN/bitcoind" -regtest -datadir="$DD" -rpcport=$PORT -port=18544 -listen=0 -daemon \
  -fallbackfee=0.0002 >/dev/null
cli -rpcwait getblockchaininfo >/dev/null
echo "bitcoind $("$CORE_BIN/bitcoind" -version | head -1 | awk '{print $5}') on regtest"

cli -named createwallet wallet_name=miner >/dev/null
MINE=$(cli -rpcwallet=miner getnewaddress)
cli generatetoaddress 101 "$MINE" >/dev/null

# BIP39 test mnemonic; the signer only ever reads it from this file here.
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" > "$DD/seed.txt"

# 1. Offline: export the watch-only account. Online: turn it into descriptors.
ACCT=$("$AIRSIGN" account --mnemonic-file "$DD/seed.txt" --network regtest --format as1 2>/dev/null)
"$AIRSIGN" account --mnemonic-file "$DD/seed.txt" --network regtest --format words 2>/dev/null > "$OUT/account_words.txt"
"$AIRSIGN" descriptors @"$OUT/account_words.txt" > "$DD/desc.txt"
RECV=$(sed -n 1p "$DD/desc.txt"); CHANGE=$(sed -n 2p "$DD/desc.txt"); IMPORT=$(sed -n 3p "$DD/desc.txt")
CORE_SUM=$(cli getdescriptorinfo "${RECV%#*}" | json 'd["checksum"]')
[ "$CORE_SUM" = "${RECV#*#}" ] && pass "descriptor checksum matches Core's ($CORE_SUM)" || die "checksum $CORE_SUM vs ${RECV#*#}"
cli -named createwallet wallet_name=watch disable_private_keys=true blank=true >/dev/null
cli -rpcwallet=watch importdescriptors "$IMPORT" | json 'all(x["success"] for x in d)' | grep -q True \
  && pass "Core imported the watch-only account from the word transcript" || die "importdescriptors"

# 2. Fund the watch-only wallet with three coins.
for amt in 0.5 0.7 1.1; do
  cli -rpcwallet=miner sendtoaddress "$(cli -rpcwallet=watch getnewaddress '' bech32m)" $amt >/dev/null
done
cli generatetoaddress 1 "$MINE" >/dev/null

run_case() {
  local name=$1 outputs=$2
  echo "--- case: $name"
  local PSBT
  PSBT=$(cli -rpcwallet=watch walletcreatefundedpsbt '[]' "$outputs" 0 '{"fee_rate":12}' | json 'd["psbt"]')
  echo "$PSBT" > "$OUT/$name.psbt"

  # 3. Online: compress the PSBT into a signing request.
  "$AIRSIGN" request --network regtest --psbt "$PSBT" 2>/dev/null > "$OUT/$name.request.txt"
  local REQ; REQ=$(tail -1 "$OUT/$name.request.txt")
  "$AIRSIGN" show "$REQ" --format words > "$OUT/$name.request_words.txt"
  "$AIRSIGN" show "$REQ" --format minimal > "$OUT/$name.request_minimal.txt"

  # 4. QR: render a PBM, decode it with zbar, compare.
  "$AIRSIGN" show "$REQ" --pbm "$DD/req.pbm"
  local SCANNED; SCANNED=$(zbarimg --raw -q "$DD/req.pbm")
  [ "$SCANNED" = "$REQ" ] && pass "zbar decodes the request QR exactly" || die "QR mismatch"

  # 5. Offline: sign from each transport; all three must give the same answer.
  "$AIRSIGN" sign --mnemonic-file "$DD/seed.txt" --request @"$OUT/$name.request_words.txt" --yes --format as1 2>"$OUT/$name.review.txt" > "$DD/s1"
  "$AIRSIGN" sign --mnemonic-file "$DD/seed.txt" --request @"$OUT/$name.request_minimal.txt" --yes --format as1 2>/dev/null > "$DD/s2"
  "$AIRSIGN" sign --mnemonic-file "$DD/seed.txt" --request "$SCANNED" --yes --format words 2>/dev/null > "$OUT/$name.signatures_words.txt"
  cmp -s "$DD/s1" "$DD/s2" && pass "words and two-letter transcripts sign identically" || die "transport mismatch"
  "$AIRSIGN" show "$(cat "$DD/s1")" --pbm "$DD/sig.pbm"
  [ "$(zbarimg --raw -q "$DD/sig.pbm")" = "$(cat "$DD/s1")" ] && pass "zbar decodes the signature QR exactly" || die "sig QR"

  # 6. Online: combine from the hand-typed word form.
  "$AIRSIGN" combine --psbt "$PSBT" --signatures @"$OUT/$name.signatures_words.txt" 2>/dev/null > "$DD/tx.hex"
  cli testmempoolaccept "[\"$(cat "$DD/tx.hex")\"]" | json 'd[0]["allowed"]' | grep -q True \
    && pass "Core testmempoolaccept: allowed" || { cli testmempoolaccept "[\"$(cat "$DD/tx.hex")\"]"; die "mempool"; }

  # 7. Audit: Core signs the same PSBT with the same key on its own.
  local CORE_HEX
  CORE_HEX=$(cli -rpcwallet=auditor walletprocesspsbt "$PSBT" true DEFAULT true true | json 'd["hex"]')
  [ "$CORE_HEX" = "$(cat "$DD/tx.hex")" ] && pass "Bitcoin Core's own signatures are byte-identical to airsign's" \
    || die "Core signed differently"

  # 8. A one-word typo in the signatures is caught at its line.
  python3 - "$OUT/$name.signatures_words.txt" "$DD/bad.txt" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
parts = lines[2].split()
parts[3] = "zoom" if parts[3] != "zoom" else "able"
lines[2] = " ".join(parts)
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
PY
  if "$AIRSIGN" combine --psbt "$PSBT" --signatures @"$DD/bad.txt" 2>"$DD/err" >/dev/null; then die "typo accepted"; fi
  grep -q "line 3" "$DD/err" && pass "typo caught: $(cat "$DD/err" | sed 's/^error: //')" || { cat "$DD/err"; die "typo message"; }

  local TXID; TXID=$(cli sendrawtransaction "$(cat "$DD/tx.hex")")
  cli generatetoaddress 1 "$MINE" >/dev/null
  [ "$(cli -rpcwallet=watch gettransaction "$TXID" | json 'd["confirmations"]')" = 1 ] && pass "confirmed $TXID" || die "not mined"

  python3 - "$PSBT" "$OUT/$name.request.txt" "$OUT/$name.signatures_words.txt" "$DD/s1" "$name" >> "$OUT/sizes.tsv" <<'PY'
import sys, base64
psbt, req, sigw, sig1, name = sys.argv[1:]
lines = open(req).read().splitlines()
head = lines[0].split()          # '# 95 bytes; 117 words in 13 lines; ...'
# per line: the line number token stands in for the check word after ':'
sig_words = sum(len(l.split(':')[0].split()) for l in open(sigw).read().splitlines() if ':' in l)
print('\t'.join(map(str, [name, len(psbt), len(base64.b64decode(psbt)), head[1], head[3], len(lines[-1]),
                          len(open(sig1).read().strip()), sig_words])))
PY
}

cli -named createwallet wallet_name=auditor blank=true >/dev/null
PRIV_R=$("$AIRSIGN" dev-private-descriptors --mnemonic-file "$DD/seed.txt" --network regtest | sed -n 1p)
PRIV_C=$("$AIRSIGN" dev-private-descriptors --mnemonic-file "$DD/seed.txt" --network regtest | sed -n 2p)
cli -rpcwallet=auditor importdescriptors "[{\"desc\":\"$PRIV_R\",\"timestamp\":\"now\",\"active\":true,\"internal\":false,\"range\":[0,999]},{\"desc\":\"$PRIV_C\",\"timestamp\":\"now\",\"active\":true,\"internal\":true,\"range\":[0,999]}]" \
  | json 'all(x["success"] for x in d)' | grep -q True || die "auditor import"

printf "case\tpsbt_b64_chars\tpsbt_bytes\trequest_bytes\trequest_words\trequest_qr_chars\tsig_qr_chars\tsig_words\n" > "$OUT/sizes.tsv"
run_case one_input  "[{\"$(cli -rpcwallet=miner getnewaddress '' bech32m)\":0.2}]"
run_case three_inputs "[{\"$(cli -rpcwallet=miner getnewaddress '' bech32m)\":1.5},{\"$(cli -rpcwallet=miner getnewaddress '' bech32)\":0.3}]"

BAL=$(cli -rpcwallet=watch getbalances | json 'd["mine"]["trusted"]')
echo "watch-only wallet balance after both spends (change found by Core): $BAL"

# Wrong seed is refused before anything is shown.
echo "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" > "$DD/other.txt"
if "$AIRSIGN" sign --mnemonic-file "$DD/other.txt" --request @"$OUT/one_input.request_words.txt" --yes 2>"$DD/err" >/dev/null; then die "wrong seed signed"; fi
pass "wrong seed refused: $(grep -o 'this request is for wallet [0-9a-f]* but the seed you entered is wallet [0-9a-f]*' "$DD/err")"

echo; column -t -s $'\t' "$OUT/sizes.tsv"
