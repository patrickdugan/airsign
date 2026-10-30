# Airsign security and release policy

**Security status: experimental and unaudited. Use regtest/signet/testnet for
development. Do not entrust substantial mainnet coins to a new build until the
release evidence and physical signing/recovery tests below are complete.**

## Scope and trust boundaries

Airsign is a single-key BIP86 Taproot signer. The online computer builds the
PSBT and broadcasts the transaction. Its compromise can expose wallet history
and submit hostile transaction proposals. It should never learn a mnemonic,
BIP39 passphrase or extended private key.

The offline image holds a seed only for a signing session. It depends on
firmware implementing owner-key-only UEFI Secure Boot, a signed kernel/initramfs
and command line, dm-verity protecting the system image, a successful RAM-only
boot, USBGuard and disabled storage/network drivers. Reproducible artifacts and
owner key custody are prerequisites, not substitutes for inspecting the source.

Only AS1 QR data or checked word transcripts cross the air gap. The full PSBT
stays online; it is decoded and compressed there. Every recipient, amount,
change derivation and fee must be checked on the independent offline screen
before the operator types `sign`. Long reviews are split into bounded pages
and require explicit `next` acknowledgment before the final signing prompt;
outputs or warnings must never be silently scrolled off the console.

### Limitations and residual threats

- The firmware, CPU, display, keyboard and USB camera must be trustworthy.
  USBGuard's permitted HID, hub, video and audio classes are still bidirectional
  USB interfaces. A hostile peripheral can affect input or leak information.
- Reproducibility and deterministic BIP340 signatures constrain hidden code
  changes and nonce exfiltration only to the degree that the source, build and
  signing binary are independently verified.
- No software-only boot procedure rules out firmware implants, physical
  side-channel attacks, cold-boot memory remanence or compromised operators.
- A previously online-generated seed remains potentially exposed. A cold-wallet
  migration must create a **different seed inside the trusted offline boot**.
- The signer cannot cosign a conventional BitGo 2-of-3 multisig wallet.
  Migration between these policies requires an ordinary authorized on-chain
  transaction.
- The **ERASE internal drives** boot profile is destructive. Use only with
  explicit intention and confirmed backups, preferably on a dedicated test
  laptop. The signing profile does not require internal disks to be wiped.

## Security acceptance requirements

### A. Freeze and independently build a release

1. Record the full commit SHA and inspect the Rust sources, boot/initramfs
   scripts, build scripts, systemd services and `Cargo.lock`.
2. Build the same clean commit on two independent trusted Linux builders with
   the pinned Debian snapshot, and compare every artifact's SHA-256 and
   `ROOTHASH`. The supplied build recipe is `sudo image/build.sh out/`.
3. Review and commit updated `image/SHA256SUMS` and `image/ROOTHASH`. Any
   source or image change invalidates the previous hashes.
4. Sign only checked artifacts using owner-controlled Secure Boot keys kept
   outside the online Bitcoin coordinator. `image/sign.sh` refuses stale
   manifests and mismatched checksums.
5. Check that the published artifacts and exact source commit correspond to
   the binaries actually flashed. A GitHub CI success alone is insufficient.

### B. Boot-integrity negative tests

On the exact prospective release image, execute `image/test_qemu.py` with
owner/attacker key sets. Include the SMM-enabled Secure Boot tests as well as
the signing and disk-wipe fixtures on disposable virtual disks.

- Owner-signed boot: signer preflight accepts only with Secure Boot ON and an
  active dm-verity root matching the sealed command line.
- Unsigned diagnostic boot: the image self-test can run, while the signer
  preflight must reject it.
- Changed squashfs byte, missing verity tree, changed UKI, foreign-signed UKI
  and unsigned UKI: each must fail at its expected boundary.
- Effective `toram`: `/run/live/medium` must actually be a tmpfs mount.
- Network interfaces: only loopback; internal storage absent; USB storage
  drivers unloaded, with USBGuard active.
- Failed USBGuard start, module unload or udev policy reload: the signer
  service must stay unavailable. Test failure cases independently.

The expanded image self-test exercises the signer boot preflight and checks
tmpfs and storage-module state. Passing those tests in a VM cannot replace a
physical-laptop check.

### C. Commission a dedicated laptop

1. Pick a machine whose firmware can enroll only your PK/KEK/db trust chain.
   Preserve recovery material for the machine's previous OS before clearing
   firmware keys. Disable legacy/CSM boot.
2. Confirm the firmware's Secure Boot mode and certificate enrollment through
   firmware setup. Boot the signed owner-key image.
3. Run the image self-test and retain the full reported verity root, actual
   RAM-only mount, interfaces, storage devices and USBGuard results.
4. Exercise a known keyboard/camera and test a disallowed USB storage device.
   Remove unrelated peripherals. Verify that opening the signer fails if any
   required boot preflight is incomplete.
5. Power cycle. Verify the same security evidence a second time before
   entering a mnemonic.

### D. Recovery and Sparrow interoperability on signet

1. Generate a new seed on the verified offline laptop and write a physical
   backup. Re-enter every word. Power off fully, reboot and restore from the
   backup (including the exact BIP39 passphrase if used).
2. Independently derive the first receive address offline, and match every
   character and BIP86 path to the newly configured Sparrow watch-only wallet.
   In Sparrow, use Taproot (P2TR) and import the account descriptor/xpub with
   its master fingerprint and derivation. Compare receiving and change paths.
3. Fund a small signet UTXO. Export a PSBT from Sparrow **as binary**, then run
   `airsign request --network signet --psbt @file.psbt --format as1` on the
   **online** computer. Compare its displayed outputs and fee to the independent
   offline review.
4. Carry the AS1 request as QR or typed words; sign offline; return AS1
   signatures to the online machine. Combine using
   `airsign combine --psbt @file.psbt --signatures AS1... --psbt-out signed.psbt
   --psbt-out-format binary`.
5. Re-import the finalized PSBT in Sparrow. Verify expected transaction
   identity, output addresses, change and fees; broadcast on signet.
   Demonstrate recovery and a second spend after power cycling.
6. Complete an independent security audit and examine every discrepancy before
   considering mainnet use.

## Evidence labels

Use separate labels for **code inspected**, **unit tests passed**,
**Core regtest executed**, **QEMU/OVMF executed**, **physical signet executed**
and **independent security review**. Require commit SHAs and test receipts;
previous results on a different commit do not validate a changed image.

Known acceptance blocker on the October 24, 2026 draft hardening PR:
`image/SHA256SUMS` and `image/ROOTHASH` correspond to an older image.
New source changes require rebuilding, independent reproduction, new boot
tests and physical testing before any security release.
