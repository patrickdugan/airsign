#!/usr/bin/env python3
"""Verified-boot test suite for the airsign image, under QEMU/KVM with OVMF.

usage: test_qemu.py <build-out-dir> <keys-dir> <outdir> [tests]

  <build-out-dir>  output of image/build.sh (unsigned pieces + unsigned ISO)
  <keys-dir>       holds owner/ and attacker/ key sets made by image/keys.sh
  tests            letters, default "SIWTFU"

Every boot is from a virtual USB stick with a SATA disk, an NVMe disk and two
network cards attached. Unless noted, the firmware is OVMF with Secure Boot on
and ONLY the owner's PK/KEK/db enrolled (no Microsoft keys).

  S  self-test entry: in-image checks (Secure Boot, dm-verity root hash, no
     network, no disks, ...) and a QR drawn on the text console, photographed
     with screendump and decoded with zbarimg
  I  default entry: a full signing session typed on the virtual keyboard; the
     signature QR must decode to Bitcoin Core's signatures; "Shut down" powers off
  W  wipe entry, driven over its serial mirror: both disk images must read back
     as zeros
  T  tampered system image, refused by the initramfs check:
     T1 one byte of the system image changed  -> powers off
     T2 the .verity hash tree deleted          -> powers off
        (live-boot on its own would mount the image unverified)
  F  tampered or foreign boot code, refused by the firmware. Needs firmware
     that enforces Secure Boot: OVMF_SMM=1 (and, under nested virtualization
     such as WSL2, QEMU_ACCEL=tcg):
     T3 the signed UKI changed after signing
     T4 boot code signed with someone else's key
     T5 the unsigned ISO
  K  firmware in Setup Mode + signed stick: "Enroll Secure Boot keys: airsign"
     from the menu, then the next boot must run with Secure Boot on (SMM build)
  U  the unsigned ISO with Secure Boot off remains diagnostic-only:
     dm-verity verifies the image but the signer preflight must refuse it
  X  explore: screenshots of the first seconds of a signed boot (calibration)

Needs: qemu-system-x86_64 (KVM), OVMF (secboot build), virt-fw-vars, zbarimg,
xorriso, and what image/sign.sh and image/make-iso.sh need.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

BUILD = os.path.abspath(sys.argv[1])
KEYS = os.path.abspath(sys.argv[2])
OUT = os.path.abspath(sys.argv[3])
WHICH = sys.argv[4] if len(sys.argv) > 4 else "SIWTFU"
HERE = os.path.dirname(os.path.abspath(__file__))
AIRSIGN = os.environ.get("AIRSIGN", os.path.join(BUILD, "airsign"))
# OVMF's "secboot" build also requires SMM, which protects the variable store
# from the OS. KVM under nested virtualization (WSL2 on Hyper-V) fails on SMM
# entry, so by default use the build that enforces Secure Boot signature checks
# the same way but without SMM. OVMF_SMM=1 selects the SMM build on bare metal.
SMM = os.environ.get("OVMF_SMM") == "1"
# QEMU_ACCEL=tcg runs without KVM (needed for SMM on such hosts); everything is
# then several times slower, so timeouts scale by SLOW.
ACCEL = os.environ.get("QEMU_ACCEL", "kvm")
SLOW = 6 if ACCEL == "tcg" else 1
CODE = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd" if SMM else "/usr/share/OVMF/OVMF_CODE_4M.fd"
BLANK_VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"
os.makedirs(OUT, exist_ok=True)
W = tempfile.mkdtemp(prefix="airsign-qemu-")
SEED_PREFIXES = "aban " * 11 + "abou"
FIXTURE = open(os.path.join(HERE, "rootfs/usr/local/lib/airsign/selftest.sh")).read()
REQ = re.search(r"^REQ=(\S+)", FIXTURE, re.M).group(1)
SIG = re.search(r"^SIG=(\S+)", FIXTURE, re.M).group(1)
ROOTHASH = open(os.path.join(BUILD, "ROOTHASH")).read().strip()
# systemd-boot lists the three UKI profiles in order.
ENTRY = {"signer": 0, "selftest": 1, "wipe": 2}
results = []


def record(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail else ""), flush=True)


def run(*cmd, env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run(cmd, check=True, capture_output=True, text=True, env=e).stdout


# --- artifacts ------------------------------------------------------------------------------
def sign(keyset, iso, trees=None):
    env = {"SUMS": os.path.join(BUILD, "SHA256SUMS")}
    if trees:
        env["SIGN_TREES_OUT"] = trees
    run("bash", os.path.join(HERE, "sign.sh"), os.path.join(KEYS, keyset), BUILD, iso, env=env)


def make_iso(iso_tree, esp_tree, out):
    sde = run("bash", "-c", f". {HERE}/snapshot.env; s=$SNAPSHOT; "
              'date -u -d "${s:0:4}-${s:4:2}-${s:6:2} ${s:9:2}:${s:11:2}:${s:13:2}" +%s').strip()
    run("bash", os.path.join(HERE, "make-iso.sh"), iso_tree, esp_tree, out, env={"SOURCE_DATE_EPOCH": sde})


def iso_file_extent(iso, path):
    """(byte offset, size) of a file inside an ISO image."""
    rep = run("xorriso", "-indev", iso, "-find", path, "-exec", "report_lba")
    m = re.search(r"File data lba:\s*\d+\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", rep)
    return int(m.group(1)) * 2048, int(m.group(3))


def flip_byte(path, offset):
    with open(path, "r+b") as f:
        f.seek(offset)
        b = f.read(1)
        f.seek(offset)
        f.write(bytes([b[0] ^ 0x55]))


def make_vars(name, keyset=None):
    path = f"{W}/{name}.vars"
    if keyset is None:
        shutil.copy(BLANK_VARS, path)
        return path
    k = os.path.join(KEYS, keyset)
    guid = open(os.path.join(k, "owner.guid")).read().strip()
    run("virt-fw-vars", "--input", BLANK_VARS, "--output", path,
        "--set-pk", guid, f"{k}/PK.crt", "--add-kek", guid, f"{k}/KEK.crt",
        "--add-db", guid, f"{k}/db.crt", "--no-microsoft", "--secure-boot")
    return path


def fresh_disks():
    pattern = (b"SECRET-KEY-MATERIAL-" * 52429)[: 1024 * 1024]
    for d in ("sata", "nvme"):
        with open(f"{W}/{d}.img", "wb") as f:
            for _ in range(64):
                f.write(pattern)


# --- one VM ---------------------------------------------------------------------------------
class Qemu:
    def __init__(self, tag, iso, vars_template):
        self.tag = tag
        self.mon_path = f"{W}/{tag}.mon"
        self.ser_path = f"{W}/{tag}.ser"
        vars_file = f"{W}/{tag}.vars"
        shutil.copy(vars_template, vars_file)
        machine = [f"q35,smm=on,accel={ACCEL}", "-global", "driver=cfi.pflash01,property=secure,value=on"] \
            if SMM else [f"q35,smm=off,accel={ACCEL}"]
        args = [
            "qemu-system-x86_64", "-machine", *machine,
            "-cpu", "host" if ACCEL == "kvm" else "max", "-m", "3072", "-smp", "2",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={CODE}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
            "-device", "qemu-xhci,id=xhci",
            "-drive", f"if=none,id=stick,format=raw,file={iso},readonly=on",
            "-device", "usb-storage,bus=xhci.0,drive=stick,bootindex=0",
            "-drive", f"if=none,id=sata,format=raw,file={W}/sata.img",
            "-device", "ide-hd,drive=sata,bus=ide.0",
            "-drive", f"if=none,id=nvme,format=raw,file={W}/nvme.img",
            "-device", "nvme,drive=nvme,serial=AIRSIGNNVME1",
            "-netdev", "user,id=n0,restrict=on", "-device", "e1000e,netdev=n0",
            "-netdev", "user,id=n1,restrict=on", "-device", "virtio-net-pci,netdev=n1",
            "-vga", "std", "-display", "none",
            "-monitor", f"unix:{self.mon_path},server=on,wait=off",
            "-chardev", f"socket,id=ser0,path={self.ser_path},server=on,wait=off", "-serial", "chardev:ser0",
        ]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=open(f"{OUT}/{tag}.qemu.log", "w"))
        for _ in range(100):
            if os.path.exists(self.mon_path) and os.path.exists(self.ser_path):
                break
            time.sleep(0.05)
        self.mon = socket.socket(socket.AF_UNIX)
        self.mon.connect(self.mon_path)
        self._mon_read()
        self.ser = socket.socket(socket.AF_UNIX)
        self.ser.connect(self.ser_path)
        self.ser.settimeout(0.2)
        self.serial_log = open(f"{OUT}/{tag}.serial.log", "wb")
        self.buf = b""
        self.all = b""

    def _mon_read(self):
        data = b""
        self.mon.settimeout(90)
        while not data.endswith(b"(qemu) "):
            chunk = self.mon.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def mon_cmd(self, c):
        self.mon.sendall(c.encode() + b"\n")
        return self._mon_read()

    def screenshot(self, name):
        path = f"{OUT}/{name}.png"
        self.mon_cmd(f"screendump {path} -f png")
        time.sleep(0.5)
        return path

    def screen(self):
        """(width, height, rgb bytes) of the current screen."""
        path = f"{W}/{self.tag}-probe.ppm"
        self.mon_cmd(f"screendump {path}")
        for _ in range(20):
            if os.path.exists(path) and os.path.getsize(path) > 0:
                break
            time.sleep(0.1)
        data = open(path, "rb").read()
        os.remove(path)
        parts = data.split(b"\n", 3)
        w, h = map(int, parts[1].split())
        return w, h, parts[3]

    def lit(self, box):
        w, h, px = self.screen()
        x0, y0, x1, y1 = box
        n = 0
        for y in range(y0, min(y1, h)):
            row = px[(y * w + x0) * 3:(y * w + min(x1, w)) * 3]
            n += sum(1 for i in range(0, len(row), 3) if row[i] > 128)
        return n

    def boot_menu_bar(self):
        """True when systemd-boot's highlighted entry (a wide light bar) is on screen."""
        w, h, px = self.screen()
        for y in range(0, h, 4):
            row = px[y * w * 3:(y + 1) * w * 3]
            best = run_len = 0
            for i in range(0, len(row), 3):
                if row[i] > 150 and row[i + 1] > 150 and row[i + 2] > 150:
                    run_len += 1
                    best = max(best, run_len)
                else:
                    run_len = 0
            if best > w // 4:
                return True
        return False

    def choose(self, entry, timeout=60):
        """Pick a systemd-boot entry by position once the menu is up."""
        end = time.time() + timeout * SLOW
        while time.time() < end:
            self.pump()
            if self.boot_menu_bar():
                time.sleep(0.3)
                for _ in range(ENTRY[entry]):
                    self.mon_cmd("sendkey down")
                    time.sleep(0.15)
                self.mon_cmd("sendkey ret")
                return True
            time.sleep(0.3)
        return False

    def wait_for_airsign_menu(self, timeout=240):
        """airsign's option lines on the left, nothing on the right half, twice in a row."""
        end, seen = time.time() + timeout, 0
        while time.time() < end:
            ready = self.lit((0, 48, 360, 120)) > 400 and self.lit((460, 48, 700, 120)) < 50
            seen = seen + 1 if ready else 0
            if seen >= 2:
                return True
            time.sleep(2)
        return False

    KEYS = {" ": "spc", "\n": "ret", "-": "minus", ".": "dot", "/": "slash"}

    def type(self, text, delay=0.04):
        for ch in text:
            key = self.KEYS.get(ch) or (f"shift-{ch.lower()}" if ch.isupper() else ch)
            self.mon_cmd(f"sendkey {key}")
            time.sleep(delay)

    def pump(self):
        try:
            while True:
                chunk = self.ser.recv(65536)
                if not chunk:
                    break
                self.serial_log.write(chunk)
                self.serial_log.flush()
                self.buf += chunk
                self.all += chunk
        except (socket.timeout, BlockingIOError, OSError):
            pass

    def expect(self, pattern, timeout=180):
        end = time.time() + timeout * SLOW
        rx = re.compile(pattern.encode())
        while time.time() < end:
            self.pump()
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            if self.proc.poll() is not None:
                return None
        return None

    def wait_exit(self, timeout=90):
        end = time.time() + timeout * SLOW
        while time.time() < end:
            self.pump()
            if self.proc.poll() is not None:
                return True
            time.sleep(0.2)
        return False

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


def decode_qr(png):
    r = subprocess.run(["zbarimg", "--raw", "-q", png], capture_output=True, text=True)
    return r.stdout.strip()


def clean(text):
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


# --- tests ----------------------------------------------------------------------------------
def explore(iso, vars_t):
    fresh_disks()
    q = Qemu("X-explore", iso, vars_t)
    try:
        t0 = time.time()
        for i in range(30):
            q.screenshot(f"X-{i:02d}")
            print(f"      t={time.time() - t0:.0f}s menu-bar={q.boot_menu_bar()}", flush=True)
            time.sleep(2.5)
    finally:
        q.kill()


def debug_entry(iso, vars_t, entry="selftest"):
    fresh_disks()
    q = Qemu("E-debug", iso, vars_t)
    try:
        print(f"      chose {entry}: {q.choose(entry)}", flush=True)
        for i in range(18):
            time.sleep(10)
            q.pump()
            q.screenshot(f"E-{i:02d}")
            print(f"      t={10 * (i + 1)}s serial bytes={len(q.all)}", flush=True)
            if q.proc.poll() is not None:
                break
    finally:
        q.kill()


def test_selftest(iso, vars_t, tag="S-selftest", expect_sb=True):
    fresh_disks()
    q = Qemu(tag, iso, vars_t)
    try:
        record(f"{tag}: systemd-boot menu shown, self-test entry chosen", q.choose("selftest"))
        ok = q.expect(r"AIRSIGN-SELFTEST-BEGIN", 240) is not None
        record(f"{tag}: self-test started", ok)
        if not ok:
            return
        if q.expect(r"QR_READY", 120):
            time.sleep(1)
            got = decode_qr(q.screenshot(f"{tag}-tty1-qr"))
            record(f"{tag}: QR on the text console decodes to the expected signatures", got == SIG, got[:24] + "...")
        q.expect(r"AIRSIGN-SELFTEST-END", 60)
        time.sleep(1)
        q.screenshot(f"{tag}-results-on-screen")
        text = clean(q.all.decode(errors="replace"))
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("PASS  ", "FAIL  ")):
                name, ok = line[6:], line.startswith("PASS")
                if name in ("booted through UEFI Secure Boot",
                            "signer verified-boot preflight accepts this image") and not expect_sb:
                    record(f"{tag}: [in image] {name} refused the unsigned boot, as expected", not ok)
                else:
                    record(f"{tag}: [in image] {name}", ok)
            elif line.startswith(("secure boot:", "net interfaces:", "block devices:", "usb devices:")):
                print("      " + line, flush=True)
        verity = re.search(r"verity root: (\w+)", text)
        record(f"{tag}: running image's verity root equals the published ROOTHASH",
               bool(verity) and verity.group(1) == ROOTHASH)
        record(f"{tag}: powered off by itself", q.wait_exit(150))
    finally:
        q.kill()


def test_session(iso, vars_t):
    tag = "I-session"
    fresh_disks()
    q = Qemu(tag, iso, vars_t)
    try:
        q.choose("signer")
        record(f"{tag}: boots to the airsign menu", q.wait_for_airsign_menu())
        q.screenshot(f"{tag}-1-menu")
        q.type("1\n")
        time.sleep(0.5)
        q.type("12\n")
        q.type(SEED_PREFIXES + "\n")
        time.sleep(1)
        q.type("\n")
        time.sleep(1)
        minimal = run(AIRSIGN, "show", REQ, "--format", "minimal")
        for line in minimal.splitlines():
            letters = re.sub(r"[^a-z]", "", line.split("  ", 1)[1] if "  " in line.strip() else line)
            q.type(letters + "\n", delay=0.02)
            time.sleep(0.3)
        time.sleep(1.5)
        q.screenshot(f"{tag}-2-review")
        q.type("sign\n")
        time.sleep(3)
        got = decode_qr(q.screenshot(f"{tag}-3-signature-qr"))
        record(f"{tag}: signatures from a typed session match Bitcoin Core's", got == SIG, got[:24] + "...")
        q.type("\n")
        time.sleep(1.5)
        q.type("4\n")
        record(f"{tag}: 'Shut down' powers the machine off", q.wait_exit(60))
    finally:
        q.kill()


def test_wipe(iso, vars_t):
    tag = "W-wipe"
    fresh_disks()
    q = Qemu(tag, iso, vars_t)
    try:
        q.choose("wipe")
        for _ in range(2):
            m = q.expect(r"Type the drive name \((\w+)\) to erase it", 240)
            if not m:
                break
            time.sleep(0.5)
            q.type(m.group(1).decode() + "\n")
        q.expect(r"Press Enter to power off", 600)
        time.sleep(0.5)
        q.type("\n")
        record(f"{tag}: powered off after erasing", q.wait_exit(90))
    finally:
        q.kill()
    for d in ("sata", "nvme"):
        data = open(f"{W}/{d}.img", "rb").read()
        record(f"{tag}: {d} disk image reads back as all zeros", data.count(0) == len(data),
               f"{len(data) - data.count(0)} nonzero bytes")
    for line in clean(q.all.decode(errors="replace")).splitlines():
        if line.strip().startswith(("Drive ", "NVMe", "secure discard", "discard", "read-back", "VERIFIED", "WARNING")):
            print("      " + line.strip(), flush=True)


def test_enroll(iso):
    """Setup Mode firmware + signed stick: enroll the owner's keys from the boot
    menu, then the next boot must be Secure Boot enforcing those keys."""
    tag = "K-enroll"
    fresh_disks()
    q = Qemu(tag, iso, BLANK_VARS)
    try:
        end = time.time() + 120 * SLOW
        while time.time() < end and not q.boot_menu_bar():
            q.pump()
            time.sleep(1)
        q.mon_cmd("sendkey down")  # stop the countdown
        time.sleep(3 * SLOW)
        # In Setup Mode systemd-boot lists "Enroll Secure Boot keys: airsign"
        # last (this firmware does not mirror the menu text to serial, so the
        # screenshot is the record of it).
        q.screenshot(f"{tag}-1-setup-mode-menu")
        q.mon_cmd("sendkey end")
        time.sleep(1)
        q.screenshot(f"{tag}-2-enroll-selected")
        q.mon_cmd("sendkey ret")
        # Do not touch the keyboard during systemd-boot's enrollment countdown;
        # it then writes PK/KEK/db and resets the machine. Watch the menu go
        # away (countdown, reset, firmware) and pick the self-test as soon as it
        # comes back, before its 5 s timeout boots the default entry.
        end = time.time() + 120 * SLOW
        while time.time() < end and q.boot_menu_bar():
            time.sleep(0.5)
        q.screenshot(f"{tag}-3-enrolling")
        record(f"{tag}: after enrolling and resetting, the menu comes back", q.choose("selftest", timeout=180))
        ok = q.expect(r"AIRSIGN-SELFTEST-BEGIN", 300) is not None
        sb = q.expect(r"secure boot: (\w+)", 60)
        record(f"{tag}: keys enrolled from the stick; next boot runs with Secure Boot on",
               ok and sb is not None and sb.group(1) == b"on", sb.group(1).decode() if sb else "no self-test")
    finally:
        q.kill()


def test_refused_by_initramfs(tag, iso, vars_t, why):
    fresh_disks()
    q = Qemu(tag, iso, vars_t)
    try:
        q.choose("selftest")
        m = q.expect(r"SYSTEM IMAGE FAILED VERIFICATION: ([^\r\n]*)", 240)
        record(f"{tag}: refused before the system started ({why})", m is not None,
               m.group(1).decode(errors="replace") if m else "no refusal seen")
        q.screenshot(f"{tag}-screen")
        record(f"{tag}: nothing from the image ran", b"AIRSIGN-SELFTEST-BEGIN" not in q.all)
        record(f"{tag}: powered off", q.wait_exit(120))
    finally:
        q.kill()


def test_refused_by_firmware(tag, iso, vars_t, why):
    fresh_disks()
    q = Qemu(tag, iso, vars_t)
    try:
        q.choose("selftest", timeout=30)
        end = time.time() + 40 * SLOW
        while time.time() < end:
            q.pump()
            time.sleep(0.5)
        q.screenshot(f"{tag}-screen")
        record(f"{tag}: firmware did not start Linux ({why})",
               b"Linux version" not in q.all and b"AIRSIGN" not in q.all)
    finally:
        q.kill()


try:
    owner_vars = make_vars("owner-sb", "owner")
    blank_vars = make_vars("blank")
    signed = f"{W}/signed.iso"
    trees = f"{W}/trees"
    sign("owner", signed, trees)
    print(f"signed ISO built with the owner's db key; verity root {ROOTHASH[:16]}...", flush=True)

    if "X" in WHICH:
        explore(signed, owner_vars)
    if "Y" in WHICH:
        explore(signed, blank_vars)
    if "E" in WHICH:
        debug_entry(signed, owner_vars)
    if "S" in WHICH:
        print("--- S: self-test entry, Secure Boot on (owner keys only)", flush=True)
        test_selftest(signed, owner_vars)
    if "I" in WHICH:
        print("--- I: default entry, typed signing session", flush=True)
        test_session(signed, owner_vars)
    if "W" in WHICH:
        print("--- W: wipe entry", flush=True)
        test_wipe(signed, owner_vars)
    if "T" in WHICH:
        print("--- T: tampered sticks", flush=True)
        t1 = f"{W}/t1.iso"
        shutil.copy(signed, t1)
        off, size = iso_file_extent(t1, "/live/filesystem.squashfs")
        flip_byte(t1, off + size // 2)
        test_refused_by_initramfs("T1-image-byte", t1, owner_vars, "one byte of the system image changed")

        t2tree = f"{W}/t2-iso"
        shutil.copytree(f"{trees}/iso", t2tree)
        os.remove(f"{t2tree}/live/filesystem.squashfs.verity")
        t2 = f"{W}/t2.iso"
        make_iso(t2tree, f"{trees}/esp", t2)
        test_refused_by_initramfs("T2-no-hash-tree", t2, owner_vars, "the dm-verity hash tree was deleted")
    if "F" in WHICH:
        print("--- F: tampered or foreign boot code, refused by the firmware", flush=True)
        t3esp = f"{W}/t3-esp"
        shutil.copytree(f"{trees}/esp", t3esp)
        uki = f"{t3esp}/EFI/Linux/airsign.efi"
        flip_byte(uki, os.path.getsize(uki) // 2)
        t3 = f"{W}/t3.iso"
        make_iso(f"{trees}/iso", t3esp, t3)
        test_refused_by_firmware("T3-uki-modified", t3, owner_vars, "UKI changed after signing")

        t4 = f"{W}/t4.iso"
        sign("attacker", t4)
        test_refused_by_firmware("T4-wrong-key", t4, owner_vars, "UKI signed with someone else's key")

        test_refused_by_firmware("T5-unsigned", os.path.join(BUILD, "airsign-live.iso"), owner_vars,
                                 "unsigned ISO")
    if "K" in WHICH:
        print("--- K: key enrollment from the stick in Setup Mode", flush=True)
        test_enroll(signed)
    if "U" in WHICH:
        print("--- U: unsigned ISO, Secure Boot off", flush=True)
        test_selftest(os.path.join(BUILD, "airsign-live.iso"), blank_vars, tag="U-unsigned-sb-off", expect_sb=False)
finally:
    shutil.rmtree(W, ignore_errors=True)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
