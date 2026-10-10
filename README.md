# airsign

An air-gapped signer for single-key taproot (BIP86) Bitcoin wallets. It has two
parts:

* **The live USB image** boots any x86-64 laptop into RAM, with no network
  drivers, no access to internal disks, and USB storage refused. It runs the
  signer on the text console and wipes memory at power-off.
* **One static binary** (`airsign`, 2.5 MB, musl). The same binary is the
  offline signer and the online helper that sits next to a Bitcoin Core
  watch-only wallet.

Requests and signatures cross the gap as **one static QR code** or as **lines of
four-letter words** (each word can be typed with two letters), never on a USB
stick. A one-input spend is 96 bytes: 157 QR characters or 110 words, where
Core's base-64 PSBT for it is 516 characters. See [DESIGN.md](DESIGN.md) for why,
and for the comparison with running Bitcoin-Qt offline.

> **Status: experimental, not audited.** Use it on regtest, signet or testnet.
> The image build is reproducible: rebuild it and compare against
> [`image/SHA256SUMS`](image/SHA256SUMS). Verified boot (dm-verity and a signed
> kernel image) is not done yet, so nothing checks that the bytes a laptop
> boots are the ones that were hashed.
> [DESIGN.md, "Trusting the stick"](DESIGN.md#trusting-the-stick) describes what
> a tampered stick could and could not do, and the plan to close that gap.

## Use

Online machine (Bitcoin Core 31+, watch-only):

```bash
airsign descriptors AS1...                      # account from the signer -> importdescriptors JSON
bitcoin-cli -rpcwallet=watch walletcreatefundedpsbt '[]' '[{"bc1p...":0.1}]'
airsign request --network main --psbt <base64>  # prints words, two-letter words, and the QR string
airsign combine --psbt <base64> --signatures AS1...   # raw tx hex, ready for sendrawtransaction
```

Offline machine: boot the stick and pick **Sign a transaction**. Enter the seed
(four letters per word, or scan a SeedQR), then the request (scan, type the
words line by line, or paste `AS1...`). Check the review screen and type `sign`.
Scan the signature QR with any phone or webcam, or type its words.

Every frame argument also accepts `@file` or `-` (stdin). Run `airsign help`
for the full command list.

## Build and test

```bash
cargo test                                                     # unit tests
sudo image/build.sh out/                                       # reproducible ISO (see below)
cargo build --release --features dev && scripts/e2e_regtest.sh # against bitcoind (CORE_BIN=...)
image/test_qemu.py out/airsign-live.iso qemu-out/              # boots the ISO in QEMU/KVM
cargo build --release --target x86_64-unknown-linux-musl       # portable static binary for the online side
```

**Reproducible build.** `image/build.sh` runs debootstrap on the host once, to
create a builder chroot from the Debian snapshot pinned in
[`image/snapshot.env`](image/snapshot.env). Everything else runs inside that
chroot at fixed paths, using only the snapshot's tools:

* rustc and gcc compile airsign, with crates pinned by `Cargo.lock`;
* debootstrap builds the image root;
* squashfs-tools, xorriso and GRUB assemble the squashfs and the ISO.

Every timestamp is set to the snapshot time. The build writes `out/SHA256SUMS`
covering the ISO, squashfs, kernel, initrd and airsign binary. That file should
equal the committed [`image/SHA256SUMS`](image/SHA256SUMS). If two people build
the same commit and get the same `SHA256SUMS`, neither had to trust the other's
machine. Host requirements: Linux with root, `debootstrap`,
`debian-archive-keyring`, `git`, and network access.

Write the ISO to a stick with `dd if=airsign-live.iso of=/dev/sdX bs=4M`, or
with any image writer. The boot menu offers the signer (default), a serial
self-test, and **ERASE this computer's internal drives**, which asks before
each drive.

Secure Boot must be off for now. The GRUB EFI binary is unsigned (see DESIGN.md
"Not done").

## Results (2026-10-10)

* Unit tests: 19 passed.
* Bitcoin Core 31.1 regtest (`scripts/e2e_regtest.sh`), 1-input and 3-input
  spends:
  * Core accepted and mined them, and Core found the change.
  * Core's own signatures for the same PSBT and key were byte-identical.
  * zbar decoded both QR codes exactly.
  * Words, two-letter words and QR signed identically.
  * A one-word typo was caught at its line, and a wrong seed was refused.
* Reproducible build (`image/build.sh`, snapshot 20261009T000000Z): two builds,
  each from a newly created builder and run at different times, produced
  identical ISO, squashfs, kernel, initramfs and airsign binary. Both builds ran
  on one machine; no independent rebuilder yet.
* QEMU/KVM, booting the reproducible ISO from a virtual USB stick with SATA +
  NVMe disks and two NICs attached (`image/test_qemu.py`): 27/27 passed.
  * In-image self-test: only `lo` exists; no disk is visible; the boot stick is
    deauthorized after boot; `init_on_free` is on; kernel lockdown is set to
    confidentiality; there is no swap and no getty; and signatures match Core.
  * The QR drawn on the real text console decoded correctly from a screen
    capture.
  * UEFI + GRUB: a full signing session typed on the virtual keyboard produced
    Core-identical signatures, and "Shut down" powered off.
  * Legacy BIOS boot works.
  * The wipe entry left both disk images all zeros. The SATA disk needed the
    zero-pass fallback after discard left data behind.
