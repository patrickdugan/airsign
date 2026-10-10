#!/usr/bin/env python3
"""Boot the airsign ISO in QEMU the way it boots on a laptop: from a USB stick,
with a SATA disk, an NVMe disk and two network cards attached.

  A  self-test entry (serial): properties checked from inside; the QR drawn on
     tty1 is captured with screendump and decoded with zbarimg.
  B  UEFI + GRUB default entry: a whole signing session typed on the virtual
     keyboard (seed by 4-letter prefixes, request as two-letter words), the
     signature QR photographed and decoded, then "Shut down" must power off.
  C  legacy BIOS + GRUB: reaches the menu and powers off from it.
  D  wipe entry: confirms each internal disk over the console, then the host
     checks both disk images read back as zeros.

usage: test_qemu.py ISO OUTDIR    (needs qemu-system-x86_64, xorriso, zbarimg, OVMF)
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ISO, OUT = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
HERE = os.path.dirname(os.path.abspath(__file__))
AIRSIGN = os.environ.get("AIRSIGN", "/root/build/airsign-cargo/x86_64-unknown-linux-musl/release/airsign")
os.makedirs(OUT, exist_ok=True)
W = tempfile.mkdtemp(prefix="airsign-qemu-")
SEED_PREFIXES = "aban " * 11 + "abou"
FIXTURE = open(os.path.join(HERE, "rootfs/usr/local/lib/airsign/selftest.sh")).read()
REQ = re.search(r"^REQ=(\S+)", FIXTURE, re.M).group(1)
SIG = re.search(r"^SIG=(\S+)", FIXTURE, re.M).group(1)
results = []


def record(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail else ""), flush=True)


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


run("xorriso", "-osirrox", "on", "-indev", ISO,
    "-extract", "/live/vmlinuz", f"{W}/vmlinuz",
    "-extract", "/live/initrd.img", f"{W}/initrd.img",
    "-extract", "/boot/grub/grub.cfg", f"{W}/grub.cfg")
grub = open(f"{W}/grub.cfg").read()
COMMON = re.search(r'^set common="(.*)"', grub, re.M).group(1)
BLOCK = re.search(r'^set block="(.*)"', grub, re.M).group(1)


def fresh_disks():
    pattern = b"SECRET-KEY-MATERIAL-" * 52429
    for d in ("sata", "nvme"):
        with open(f"{W}/{d}.img", "wb") as f:
            for _ in range(64):
                f.write(pattern[: 1024 * 1024])


class Qemu:
    def __init__(self, tag, firmware="bios", kernel_args=None):
        self.tag = tag
        self.mon_path = f"{W}/{tag}.mon"
        self.ser_path = f"{W}/{tag}.ser"
        args = [
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-m", "3072", "-smp", "2",
            "-device", "qemu-xhci,id=xhci",
            "-drive", f"if=none,id=stick,format=raw,file={ISO},readonly=on",
            # Direct kernel boot claims bootindex 0 for itself.
            "-device", "usb-storage,bus=xhci.0,drive=stick" + (",bootindex=0" if kernel_args is None else ""),
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
        if firmware == "uefi":
            shutil.copy("/usr/share/OVMF/OVMF_VARS_4M.fd", f"{W}/{tag}.vars")
            args += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                     "-drive", f"if=pflash,format=raw,file={W}/{tag}.vars"]
        if kernel_args is not None:
            args += ["-kernel", f"{W}/vmlinuz", "-initrd", f"{W}/initrd.img", "-append", kernel_args]
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

    def _mon_read(self):
        data = b""
        self.mon.settimeout(10)
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

    def lit_pixels(self, box):
        """Bright pixels inside box=(x0, y0, x1, y1) of the current screen (PPM dump)."""
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
        px = parts[3]
        x0, y0, x1, y1 = box
        n = 0
        for y in range(y0, min(y1, h)):
            row = px[(y * w + x0) * 3:(y * w + min(x1, w)) * 3]
            n += sum(1 for i in range(0, len(row), 3) if row[i] > 128)
        return n

    def wait_for_menu(self, timeout=240):
        """The menu's four option lines (rows 32-100 px, left side only) must be drawn
        twice in a row. GRUB's menu also has text there but its highlight bar runs
        across the screen, so the right half must stay dark. Keys sent before
        airsign owns tty1 are flushed, so typing early loses them."""
        end, seen = time.time() + timeout, 0
        while time.time() < end:
            ready = self.lit_pixels((0, 32, 360, 100)) > 400 and self.lit_pixels((400, 32, 700, 100)) < 50
            seen = seen + 1 if ready else 0
            if seen >= 2:
                return True
            time.sleep(2)
        return False

    KEYS = {" ": "spc", "\n": "ret", "-": "minus", ".": "dot", "/": "slash", ":": "shift-semicolon"}

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
        except (socket.timeout, BlockingIOError, OSError):
            pass

    def expect(self, pattern, timeout=180):
        end = time.time() + timeout
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

    def send(self, text):
        self.ser.sendall(text.encode())

    def wait_exit(self, timeout=90):
        try:
            self.proc.wait(timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


def decode_qr(png):
    r = subprocess.run(["zbarimg", "--raw", "-q", png], capture_output=True, text=True)
    return r.stdout.strip()


def test_selftest():
    print("--- A: self-test entry (direct kernel boot, legacy BIOS)", flush=True)
    fresh_disks()
    q = Qemu("A-selftest", kernel_args=f"{COMMON} {BLOCK} airsign.selftest=1 console=tty0 console=ttyS0,115200")
    try:
        ok = q.expect(r"AIRSIGN-SELFTEST-BEGIN", 240) is not None
        record("self-test started", ok)
        if not ok:
            return
        if q.expect(r"QR_READY", 120):
            time.sleep(1)
            png = q.screenshot("A-tty1-qr")
            got = decode_qr(png)
            record("QR drawn on the text console decodes to the expected signatures", got == SIG, got[:24] + "...")
        q.expect(r"AIRSIGN-SELFTEST-END", 60)
        log = open(f"{OUT}/A-selftest.serial.log", "rb").read().decode(errors="replace")
        for line in log.splitlines():
            line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
            if line.startswith(("PASS  ", "FAIL  ")):
                record("[in image] " + line[6:], line.startswith("PASS"))
            elif line.split(":")[0] in ("net interfaces", "block devices", "live mounts", "mem auto-init", "usb devices"):
                print("      " + line, flush=True)
        record("powered off by itself", q.wait_exit(90))
    finally:
        q.kill()


def test_interactive(firmware):
    tag = f"B-{firmware}-session"
    print(f"--- B: {firmware.upper()} + GRUB default entry, full signing session on the keyboard", flush=True)
    fresh_disks()
    q = Qemu(tag, firmware=firmware)
    try:
        record(f"{firmware}: boots through GRUB to the airsign menu", q.wait_for_menu())
        q.screenshot(f"{tag}-1-menu")
        q.type("1\n")
        time.sleep(0.5)
        q.type("12\n")
        q.type(SEED_PREFIXES + "\n")
        time.sleep(1)
        q.type("\n")  # empty BIP39 passphrase
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
        png = q.screenshot(f"{tag}-3-signature-qr")
        got = decode_qr(png)
        record(f"{firmware}: signatures QR from a typed session matches Bitcoin Core's", got == SIG, got[:24] + "...")
        q.type("\n")  # leave the QR view
        time.sleep(1.5)
        q.screenshot(f"{tag}-4-back-at-menu")
        q.type("4\n")  # Shut down
        t0 = time.time()
        off = q.wait_exit(150)
        print(f"      power-off took {time.time() - t0:.0f} s", flush=True)
        if not off:
            q.screenshot(f"{tag}-5-after-shutdown")
        record(f"{firmware}: 'Shut down' powers the machine off", off)
    finally:
        q.kill()


def test_bios_menu():
    tag = "C-bios-menu"
    print("--- C: legacy BIOS + GRUB default entry", flush=True)
    fresh_disks()
    q = Qemu(tag, firmware="bios")
    try:
        record("bios: boots through GRUB to the airsign menu", q.wait_for_menu())
        q.screenshot(f"{tag}-menu")
        q.type("4\n")
        record("bios: boots to the menu and powers off from it", q.wait_exit(60))
    finally:
        q.kill()


def test_wipe():
    print("--- D: wipe entry against throwaway SATA and NVMe disks", flush=True)
    fresh_disks()
    q = Qemu("D-wipe", kernel_args=f"{COMMON} airsign.wipe=1 console=tty0 console=ttyS0,115200")
    try:
        for _ in range(2):
            m = q.expect(r"Type the drive name \((\w+)\) to erase it", 240)
            if not m:
                break
            q.send(m.group(1).decode() + "\n")
        q.expect(r"Press Enter to power off", 600)
        q.send("\n")
        record("wipe: powered off after erasing", q.wait_exit(90))
    finally:
        q.kill()
    for d in ("sata", "nvme"):
        data = open(f"{W}/{d}.img", "rb").read()
        record(f"wipe: {d} disk image reads back as all zeros", data.count(0) == len(data),
               f"{len(data) - data.count(0)} nonzero bytes")
    log = open(f"{OUT}/D-wipe.serial.log", "rb").read().decode(errors="replace")
    for line in log.splitlines():
        if line.strip().startswith(("Drive ", "NVMe", "secure discard", "discard", "read-back", "VERIFIED", "WARNING", "---")):
            print("      " + line.strip(), flush=True)


def debug_shutdown():
    """Default entry with systemd talking on the serial port, then 'Shut down'."""
    print("--- E: debug shutdown with serial console", flush=True)
    fresh_disks()
    q = Qemu("E-debug", kernel_args=f"{COMMON} {BLOCK} console=tty0 console=ttyS0,115200 "
             "systemd.show_status=true systemd.log_level=info loglevel=6")
    try:
        q.expect(r"Reached target.*Multi-User", 120)
        time.sleep(3)
        q.screenshot("E-before")
        q.type("4\n")
        time.sleep(3)
        q.screenshot("E-after")
        end = time.time() + 60
        while time.time() < end and q.proc.poll() is None:
            q.pump()
        record("debug: powered off", q.proc.poll() is not None)
    finally:
        q.kill()
    log = open(f"{OUT}/E-debug.serial.log", "rb").read().decode(errors="replace")
    print("\n".join(re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", l) for l in log.splitlines()[-40:]))


try:
    which = sys.argv[3] if len(sys.argv) > 3 else "ABCD"
    if "E" in which:
        debug_shutdown()
    if "A" in which:
        test_selftest()
    if "B" in which:
        test_interactive("uefi")
    if "C" in which:
        test_bios_menu()
    if "D" in which:
        test_wipe()
finally:
    shutil.rmtree(W, ignore_errors=True)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
