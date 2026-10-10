# airsign

An air-gapped signer for single-key taproot (BIP86) Bitcoin wallets. It has two
parts:

* **The live USB image** boots a UEFI x86-64 laptop into RAM:
  * the boot is verified by Secure Boot with your own keys, and the system
    image by dm-verity;
  * there are no network drivers, no access to internal disks, and USB
    storage is refused;
  * it runs the signer on the text console and wipes memory at power-off.
* **One program** (`airsign`). It is both the offline signer (inside the
  image, built by the reproducible build) and the online helper that sits next
  to a Bitcoin Core watch-only wallet (a portable 2.5 MB static musl build).

Requests and signatures cross the gap as **one static QR code** or as **lines of
four-letter words** (each word can be typed with two letters), never on a USB
stick. A one-input spend is 96 bytes: 157 QR characters or 110 words, where
Core's base-64 PSBT for it is 516 characters. See [DESIGN.md](DESIGN.md) for why,
and for the comparison with running Bitcoin-Qt offline.

> **Status: experimental, not audited.** Use it on regtest, signet or testnet.
> The image build is reproducible (compare against
> [`image/SHA256SUMS`](image/SHA256SUMS)), and boot is verified with your own
> Secure Boot keys plus dm-verity. That has been tested in QEMU/OVMF, not yet
> on a physical laptop's firmware. See
> [DESIGN.md, "Trusting the stick"](DESIGN.md#trusting-the-stick).

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
sudo image/build.sh out/                                       # reproducible, unsigned build (see below)
image/keys.sh ~/airsign-keys                                   # your Secure Boot keys (once; keep offline)
image/sign.sh ~/airsign-keys out/ airsign-signed.iso           # the stick your laptop will verify
cargo build --release --features dev && scripts/e2e_regtest.sh # against bitcoind (CORE_BIN=...)
image/test_qemu.py out/ keys/ qemu-out/                        # QEMU/OVMF suite (see the file header)
cargo build --release --target x86_64-unknown-linux-musl       # portable static binary for the online side
```

**Reproducible build.** `image/build.sh` runs debootstrap on the host once, to
create a builder chroot from the Debian snapshot pinned in
[`image/snapshot.env`](image/snapshot.env). Everything else runs inside that
chroot at fixed paths, using only the snapshot's tools:

* rustc and gcc compile airsign, with crates pinned by `Cargo.lock`;
* debootstrap builds the image root;
* veritysetup builds the dm-verity hash tree;
* ukify builds the unsigned UKI, with systemd-boot as the loader;
* xorriso and mtools assemble a UEFI-only ISO.

Every timestamp is set to the snapshot time. The build writes `out/SHA256SUMS`
covering the ISO, UKI, systemd-boot, squashfs, hash tree, kernel, initrd and
airsign binary, plus `out/ROOTHASH`. Both should equal the committed
[`image/SHA256SUMS`](image/SHA256SUMS) and [`image/ROOTHASH`](image/ROOTHASH).
If two people build the same commit and get the same `SHA256SUMS`, neither had
to trust the other's machine. Host requirements: Linux with root,
`debootstrap`, `debian-archive-keyring`, `git`, and network access.

**Verified boot on a dedicated laptop** (UEFI only; Secure Boot with only your
keys):

1. On a trusted machine, run `image/keys.sh` once and keep the directory
   offline. Then run `image/sign.sh`. It refuses to sign anything that doesn't
   match the published hashes.
2. Write `airsign-signed.iso` to a stick (`dd … bs=4M`, or any image writer).
3. In the laptop's firmware setup:
   * disable CSM/legacy boot;
   * set an admin password;
   * clear the Secure Boot keys (Setup Mode).
4. Boot the stick and choose **Enroll Secure Boot keys: airsign** in the menu.
   The laptop reboots with Secure Boot enforcing only your keys. This removes
   Microsoft's keys too, so prefer a laptop with integrated graphics (see
   DESIGN.md).
5. Every boot, the airsign menu's top line should read
   `Secure Boot ON | system image root <first 16 hex digits of image/ROOTHASH>`.

The boot menu offers the signer (default), a **self-test** (results on screen
and on the serial port), and **ERASE this computer's internal drives**, which
asks before each drive. The unsigned ISO from `out/` also boots with Secure
Boot off. The image is then still checked against its root hash, but nothing
vouches for the kernel or the command line.

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
  one of them from a newly created builder, run at different times, produced
  identical outputs. That covers the ISO, UKI, systemd-boot, squashfs, verity
  hash tree, kernel, initramfs and airsign binary, and therefore the same
  `ROOTHASH`. Both builds ran on one machine; no independent rebuilder yet.
* `image/test_qemu.py`, booting from a virtual USB stick with SATA + NVMe disks
  and two NICs attached:
  * **KVM, 36/36:**
    * a full signing session typed on the virtual keyboard gave Core-identical
      signatures, and "Shut down" powered off;
    * the wipe left both disks reading back as all zeros (the SATA disk needed
      the zero-pass fallback after discard left data behind);
    * a stick with one byte of the system image changed was refused before
      anything from it ran, and so was a stick whose hash tree had been deleted;
    * the unsigned ISO with Secure Boot off booted and still verified its image.
  * **OVMF with Secure Boot enforcing, SMM build under TCG:**
    * the self-test reports Secure Boot on, a dm-verity root equal to the
      published `ROOTHASH`, only `lo`, no disks, the boot stick deauthorized,
      `init_on_free`, lockdown, no swap and no getty;
    * the QR on the text console decoded correctly from a screen capture;
    * the firmware refused a UKI changed after signing, a UKI signed with
      another key, and the unsigned ISO;
    * from Setup Mode, "Enroll Secure Boot keys: airsign" enrolled the owner's
      keys from the stick, and the next boot ran with Secure Boot on.
