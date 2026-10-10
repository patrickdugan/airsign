# airsign: design

airsign is a single static Linux binary and a bootable USB image built around it.
The image boots an amnesic, network-less text console on any x86-64 laptop. That
console generates seeds and signs taproot transactions. Requests and signatures
cross the air gap as one static QR code or as short lines of four-letter words,
and never on a USB stick.

```
 ONLINE (assumed compromised)                         OFFLINE (airsign live USB, RAM only)
 ┌──────────────────────────────┐   QR / typed words   ┌─────────────────────────────────┐
 │ Bitcoin Core watch-only      │ ───── request ─────▶ │ seed typed or SeedQR-scanned    │
 │  walletcreatefundedpsbt      │      ~96 bytes       │ request rebuilt into a full tx  │
 │ airsign request  (PSBT → R)  │                      │ change re-derived, fee computed │
 │ airsign combine  (S → tx)    │ ◀── signatures ───── │ BIP340 sign (Core-identical)    │
 │  sendrawtransaction          │   64 bytes / input   │ power off → RAM zeroed          │
 └──────────────────────────────┘                      └─────────────────────────────────┘
```

## Threat model

* The online computer is hostile. It can lie about anything it sends and can
  show the user anything.
* The offline computer is a commodity laptop of unknown history. Its internal
  disk may hold malware, and it may have radios.
* The seed exists on paper or steel, and in the offline machine's RAM for the
  length of one session.
* Out of scope: firmware or hardware implants (BIOS, Intel ME, keyboard
  controllers), physical side channels (EM, acoustic), and an attacker at the
  machine during a session.

## The live system ("Tails-like", but narrower)

| Property | Mechanism | Checked by |
|---|---|---|
| Nothing persists | `toram`: the stick is copied into RAM. The root is squashfs plus a tmpfs overlay, and no disk is ever mounted. | self-test: medium not mounted from the stick |
| RAM is wiped at shutdown | `init_on_free=1 init_on_alloc=1` (the same mechanism Tails uses today). "Shut down" powers off through systemd, so every page is freed and zeroed. | self-test: `mem auto-init: … heap free:on` |
| No network, ever | `drivers/net`, wireless, Bluetooth, NFC, CAN, InfiniBand, Thunderbolt and FireWire module trees are **deleted** from the image. There is no firmware and no network manager. The signer runs with `PrivateNetwork=yes` and AF_UNIX only. | self-test with e1000e + virtio NICs attached: only `lo` exists |
| Internal disks invisible | `module_blacklist=ahci,nvme,mmc_block,…` on the kernel line, so the kernel refuses to load them, including in the initramfs | self-test with SATA + NVMe disks attached: none visible |
| No USB-stick channel | USBGuard allows only devices whose *every* interface is HID, hub or video/audio (webcam). The boot stick itself is refused once the system is in RAM, and `usb_storage`/`uas` are blocked in `/run/modprobe.d`. | self-test: no `sd*`; `modprobe usb_storage` fails |
| Nothing to log in to | gettys masked, `NAutoVTs=0`, root locked, airsign runs as an unprivileged user on tty1 | self-test |
| Secrets stay in-process | `mlockall`, no core dumps, `PR_SET_DUMPABLE=0`, `ptrace_scope=3`, kernel `lockdown=confidentiality`, `Zeroizing` buffers for words and seeds | self-test (lockdown); code |

The image has no Xorg or Wayland. The QR code is drawn in the text console with
half-block characters, and the test photographs the real console (QEMU
`screendump`) and decodes it with zbar.

**Disk wiping.** Tails does not wipe disks. It simply never touches them, and
airsign's signing mode goes further and cannot see them. A separate boot entry,
*ERASE this computer's internal drives*, exists for dedicating a laptop. For
each internal drive it asks the operator to type the drive's name. It then runs
the strongest erase available: NVMe user-data erase, else secure discard, else
discard. It reads the drive back, and if any data remains it overwrites every
byte with zeros and verifies again. The USB stick is never offered. One limit
is stated on screen: an SSD's spare area is reached only by the controller-level
erase, and no overwrite can prove it gone.

## The transport: shrink the payload, then pick an alphabet

"Higher than base 64" is the right instinct aimed at the wrong lever. A base-64
PSBT is long mainly because a PSBT is big: it carries the unsigned transaction,
each input's UTXO, BIP32 origins for every key, and often whole previous
transactions. Changing the alphabet alone saves at most a few percent. The win
comes from sending only what the signer cannot work out for itself:

* **Own scripts are never sent.** Each input is `txid, vout, amount, path`, and
  the signer derives the spent script from the path. Change is sent as a path,
  so the coordinator *cannot express* "change" to a script the signer didn't
  derive.
* **Amounts are sent and committed.** BIP341 signs every input's amount and
  script, so a lying coordinator only gets invalid signatures, and the fee the
  signer shows (inputs minus outputs) is the real fee.
* **Common output types are templates** (`p2tr` is 32 bytes, not 34). Integers
  are LEB128, and nSequence and version have short codes.

Measured on Bitcoin Core 31.1 regtest PSBTs (`scripts/e2e_regtest.sh`):

| Spend | Core PSBT, base 64 | airsign request | as QR text | as words | signatures back |
|---|---|---|---|---|---|
| 1 input → pay + change | 516 chars (385 B) | **96 B** | 157 chars, QR v7 | 110 words (13 lines) | 107 chars / 75 words |
| 3 inputs → 2 pays + change | 1044 chars (783 B) | **197 B** | 319 chars, QR v11 | 224 words (25 lines) | 312 chars / 220 words |

**Then the alphabet.** For people, what matters is how much is transferred per
unit of attention, and whether a mistake is caught where it happens:

* **Words: Bytewords** (base 256; Blockchain Commons BCR-2020-012, the word
  form of the UR standard). Each word is four letters, and the first and last
  letters are unique, so each word can be typed as **two letters**. That is 4
  bits per keystroke against base 64's 6, but with no case, no 0/O/l/1 confusion,
  and no punctuation.
* **Why not BIP39 words** (11 bits/word, denser)? On the return path the user
  types these words into the *online* machine. Teaching people to type BIP39
  words into an internet-connected computer prepares them for the classic
  "re-enter your recovery phrase" attack. A different vocabulary keeps
  "typing seed words online" an alarming act.
* **Line checks.** Eight words per line plus one check word:
  `check = (line# ⊕ 0xA5) ⊕ Σ 2^(i+1)·bᵢ` in GF(2⁸). The weights are distinct
  and nonzero, so **every** single wrong word (check word included), **every**
  swap of two words, and **every** line typed at the wrong position (anywhere
  within 256 lines) is caught on that line. That is a
  proof, not a probability, and it is exhaustively tested. A leading length
  word tells the typist how many lines to expect, and the frame also carries a
  CRC32.
* **QR form:** the same frame in the bech32 base-32 alphabet, in upper case, so
  the code is drawn in QR *alphanumeric* mode (5.5 bits per character). The
  string is also typeable as a fallback. Because the payload is small, a single
  static QR is enough: no animated multi-part codes and no fountain codes, so
  any cheap webcam or phone can read it.
* Return frames carry no CRC. Each 64-byte signature is verified against the
  PSBT's own sighash, which is a 2⁻¹²⁸ check. A failure names the lines to
  recheck.

Recommended use: request by QR (online screen → offline webcam), signatures by
QR (offline screen → any phone or laptop camera). Words are the fallback for a
machine with no camera, or for a policy of no USB devices beyond a keyboard.

## Signing

* BIP86 single-key taproot only (v1). Uses rust-bitcoin's sighash and
  libsecp256k1, the same C library as Bitcoin Core.
* **Deterministic nonces, identical to Bitcoin Core.** Core signs BIP340 with an
  all-zero `aux_rand` (`script/sign.cpp`, `CreateSchnorrSig`). airsign does the
  same (`sign_schnorr_no_aux_rand`). The test imports the same key into Core,
  has Core sign the same PSBT, and requires **byte-identical transactions**. So
  a seed-leaking nonce channel (the 2024 "Dark Skippy" attack) cannot hide in an
  airsign signature: anyone holding the key can re-sign in Core and diff.
* The review screen shows outputs (addresses grouped by four), change marked as
  "derived here", fee in sat and sat/vB (exact vsize), locktime and RBF. Warnings
  (very high fee, dust, non-standard scripts, change at an index ≥ 10,000 where
  wallets won't look) require typing `sign anyway`.
* A wrong seed or passphrase is caught before anything is shown: the request
  names the wallet fingerprint.
* Keygen uses the OS RNG, optionally mixed with dice. In dice-only mode the seed
  is SHA-256 of the rolls (Coldcard's rule), so it can be checked on another
  computer with `printf %s ROLLS | sha256sum`. Standard SeedQR output and input
  are supported. The user must re-type three random words before the seed is
  accepted.

## Why not just run Bitcoin-Qt offline?

Core is the best-reviewed Bitcoin code there is. This design keeps Core where it
is strongest: online, watch-only, choosing coins and estimating fees,
broadcasting, and auditing airsign's signatures. It replaces the offline half,
where Core was never designed for this job.

| | Bitcoin-Qt as the offline signer | airsign |
|---|---|---|
| Key at rest | wallet.dat on the offline machine's disk | none: seed on steel/paper, in RAM for one session |
| After the session | OS, swap, logs, wallet remain on disk | power off zeroes RAM; no disk was ever visible |
| Crossing the gap | PSBT file on a USB stick (Core has no camera input; typing 500–1000+ base-64 characters with no checksum is impractical) | one static QR, or ~110 checked words; USB storage blocked by policy |
| Parser exposed to the hostile side | USB mass storage + filesystem in the kernel, plus the PSBT parser | a fixed ~100-byte grammar with bounds on every field |
| Change verification | what the wallet infers from the PSBT | structural: change is a path the signer derives |
| Seed backup | wallet file or 111-char base58 xprv | BIP39 words, SeedQR, verifiable dice |
| Code on the offline side | full node, P2P, Qt GUI, wallet DB, general-purpose OS | 2.5 MB static binary on a stripped, network-less image |
| Signature auditability | deterministic (aux = 0) | **identical to Core's**, proven by test |
| Script coverage | everything Core supports | BIP86 single-key taproot only (v1) |
| Review maturity | years, many reviewers | new code: the request codec and UI need outside review |

The honest summary: airsign's advantages come from the environment (amnesia,
no disk, no network, no USB storage) and from the channel (small, checked,
optical). Its cryptographic core is deliberately *not* novel. The same library
is used and the outputs are byte-identical, so the new code can be audited
against Core instead of trusted.

## Verified

* `cargo test`: 19 unit tests. These cover the Bytewords reference vector, the
  BIP380 checksum vector, exhaustive substitution/transposition/misplaced-line
  detection for the line checks, LEB128 minimality, base-32 padding, frame CRC
  corruption, request round-trips for every script template, duplicate inputs,
  dice, and SeedQR.
* `scripts/e2e_regtest.sh` against Bitcoin Core 31.1: Core imports the
  watch-only account from a word transcript, and the descriptor checksum agrees
  with `getdescriptorinfo`. For 1-input and 3-input spends: zbar decodes both
  QR codes exactly; words, two-letter words and QR all sign identically; Core
  `testmempoolaccept` accepts the result, mines it, and finds the change.
  Core's own signature is byte-identical. A one-word typo is caught at its line,
  and a wrong seed is refused.
* `image/test_qemu.py`, QEMU/KVM, booting from a virtual USB stick with a SATA
  disk, an NVMe disk, an e1000e and a virtio NIC attached: 27/27.
  * The in-image self-test confirms every row of the live-system table above.
  * The QR on the real text console (VGA text mode) is photographed and
    decoded.
  * A full UEFI + GRUB signing session is typed on the virtual keyboard: seed as
    4-letter prefixes, request as two-letter words. The signatures match Core,
    and Shut down powers off.
  * Legacy BIOS boot works.
  * The wipe entry leaves both disks all zeros. The SATA disk's discard
    "succeeded" but left data behind; the read-back caught it and the zero pass
    finished the job.

One caveat found while testing: at power-off, systemd cannot unmount the live
root, so the tmpfs overlay is not freed and therefore not zeroed by
`init_on_free`. Tails handles this by returning to the initramfs. airsign never
writes seeds, passphrases or requests to any file, so the overlay holds nothing
secret, but returning to the initramfs is on the list below.

## Trusting the stick

**What a tampered image could do, and what already stops it.** Assume the
stick carries a modified build:

| Attack by a modified signer | Caught or prevented by |
|---|---|
| Sign a different transaction from the one shown | `airsign combine` checks every signature against *your* PSBT's sighash on the online side; a signature for anything else is rejected |
| Leak the seed through nonce choice in the signatures | Signatures are deterministic and Core-identical: re-sign the PSBT in Core with the same key and compare (an occasional spot check is enough to make cheating risky) |
| Generate a predictable seed | Dice-only keygen: the entropy is `sha256(rolls)`, which you check on any other computer, and from it the BIP39 words |
| Export an attacker's xpub as "your" watch-only wallet | At setup, compare the first receive address with an independent wallet (hardware wallet, Sparrow) restored from the same words |
| Leak the seed some other way: hidden bits in the QR rendering, screen or LED or sound side channels, a network driver put back | **Not caught by anything above.** This is why the image itself must be verifiable |

**Hash checksum: necessary, not sufficient.** A SHA-256 of the ISO means
something only if (a) the build is reproducible, so independent people can
rebuild it bit for bit and sign the same hash (as Bitcoin Core does with Guix
and Tails does for its ISO), and (b) the check covers the bytes that actually
boot. Hashing the stick from another computer does not give you (b). That
computer may be compromised. Worse, a malicious USB controller can return the
clean image to a sequential read and different blocks to the BIOS at boot.
The build now gives you (a) (step 1 below). (b) needs verified boot.

**A succinct proof of the build: a real upgrade in trust, not buildable
yet.** Nothing here is secret, so zero-knowledge as such adds nothing. What a
STARK or zkVM proof would add is succinctness, and that matters.
Reproducible builds checked by N independent builders still leave you
trusting that at least one of them honestly rebuilt and compared. A proof that
"`build.sh` on commit C and snapshot S outputs these hashes" takes the builders
out of the trust base entirely, and checks in milliseconds on any device.

Three things stand between that and today:

1. **Scale.** The build runs rustc over about 40 crates, dpkg over about 200
   packages and xz over about 600 MB. That is roughly 10¹²–10¹³ instructions,
   and it needs a full Linux userland (files, processes). zkVMs run
   bare-metal programs, so the build would run under an emulated Linux inside
   the zkVM. That multiplies the work again, and puts one proof at weeks of GPU
   cluster time per release. (Rough estimates.)
2. **It depends on the reproducible build.** The proven computation has to be
   a deterministic function of public inputs, which is exactly what
   `image/build.sh` now is.
3. **It does not reach the laptop.** The proof is about hashes, so verified
   boot is still what makes the laptop refuse anything else.

A sliced version is within reach sooner. Prove only the *assembly*: "this
dm-verity root hash is the hash tree of a filesystem whose files are exactly
the files of these Debian-signed packages plus this repository's files." That
statement is hashing and decompression, with no compilers. The compiled
binaries (airsign, the kernel) would stay covered by builder signatures.

**What closes the gap: verify at boot, from a root of trust outside the
stick.** A stick cannot vouch for itself, because a modified image would
modify its own verifier too.

1. **Reproducible build: done.** `image/build.sh` builds everything inside a
   chroot made from one pinned `snapshot.debian.org` snapshot, with every
   timestamp set to the snapshot time. The expected hashes are in
   `image/SHA256SUMS`. Two builds, each from a newly created builder and run at
   different times, matched byte for byte for all five outputs. Four sources of
   variation had to go:
   * random NVMe-oF host IDs written by nvme-cli's postinst;
   * GRUB's wall-clock `/.disk/<time>.uuid` file;
   * timestamps on the temporary files grub-mkrescue writes;
   * mksquashfs refusing explicit times when `SOURCE_DATE_EPOCH` is set.

   Still to do: rebuilders on other machines, and signed hashes.
2. **dm-verity on the squashfs**, with the root hash on the kernel command
   line. Every block is checked against the hash tree as it is read, including
   during the `toram` copy, so a lying controller cannot substitute blocks.
3. **A signed Unified Kernel Image (kernel + initramfs + that command line)**,
   with *your own* Secure Boot keys enrolled in the dedicated laptop. The
   firmware then refuses any modified kernel, initramfs or command line, and
   (2) covers the rest. The trust anchor becomes the laptop's firmware keys,
   which you set once, not the stick.
4. **Optional anti-evil-maid.** A secret sealed in the laptop's TPM to those
   boot measurements (tpm2-totp or a phrase you chose) is shown at startup. A
   changed boot chain cannot unseal it, so you see the difference before typing
   a seed.

## Not done / next

* Secure Boot: the GRUB EFI image is unsigned, so disable Secure Boot or boot in
  legacy mode. The plan is the signed UKI + dm-verity in "Trusting the stick".
* Independent rebuilders. So far the image has been reproduced only on one
  machine (WSL2 with an Ubuntu 24.04 host). It needs builders on other machines
  and other host distributions, each signing `image/SHA256SUMS`.
* Multisig / miniscript: the request format has room (flags bits 4–7).
* Taproot lets the request carry `sha_prevouts` instead of outpoints, which
  saves about 33 bytes per extra input. This was deliberately not done: it would
  mean hand-rolled sighash code instead of rust-bitcoin's.
* A webcam is a USB device with firmware. The no-camera policy (keyboard in,
  screen out) is fully supported.
* Shutdown: return to the initramfs (as Tails does) so the RAM overlay is
  unmounted and freed too.
* Camera scanning (`zbarcam`) is wired in but untested on real hardware. The
  QEMU suite covers QR *display* and keyboard entry, not webcam input.
