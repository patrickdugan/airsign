#!/usr/bin/env python3
"""Nonprivileged fault injection for the unmodified production shell logic.

Copies production scripts to a disposable filesystem, redirects only their
absolute OS paths into the fixture, and stubs commands that would otherwise
control the host. Never execute the original lockdown scripts on a CI host.
These tests are unit-level checks; the QEMU suite checks boot behavior.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
PROD = ROOT / "image/rootfs/usr/local/lib/airsign"


class FailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="airsign-fault-")
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.fakebin = self.d / "bin"
        self.fakebin.mkdir()
        self.proc = self.d / "proc"
        self.proc.mkdir()
        self.sys = self.d / "sys"
        self.sys.mkdir()
        self.udev = self.d / "run/modprobe.d"
        self.udev.mkdir(parents=True)
        self.tty = self.d / "tty1"
        self.tty.write_text("")
        self.power = self.d / "poweroff.called"
        self.cmdline = self.proc / "cmdline"
        self.cmdline.write_text("boot=live toram test=1\n")
        self.modules = self.proc / "modules"
        self.modules.write_text("")
        self.block = self.sys / "block"
        self.block.mkdir()
        for name in ("loop0", "dm-0"):
            (self.block / name).mkdir()
        for driver in ("usb-storage", "uas"):
            (self.sys / "bus/usb/drivers" / driver).mkdir(parents=True)

        self.mock("findmnt", """#!/bin/sh
case " $* " in
  *" FSTYPE "*) printf '%s\\n' "${TEST_FSTYPE:-tmpfs}";;
  *" SOURCE "*) printf 'tmpfs\\n';;
  *) exit 2;;
esac
""")
        self.mock("udevadm", """#!/bin/sh
[ "${TEST_UDEV_FAIL:-0}" != 1 ]
""")
        self.mock("systemctl", """#!/bin/sh
case "$1" in
  is-active) [ "${TEST_GUARD_STATE:-active}" = active ];;
  poweroff) : > "$TEST_POWER_FILE";;
  *) exit 2;;
esac
""")
        self.mock("modprobe", "#!/bin/sh\nexit 0\n")
        self.mock("sleep", "#!/bin/sh\nexit 0\n")

        self.env = dict(os.environ)
        self.env.update(
            PATH=str(self.fakebin) + os.pathsep + os.environ["PATH"],
            TEST_POWER_FILE=str(self.power),
            TEST_FSTYPE="tmpfs",
            TEST_UDEV_FAIL="0",
            TEST_GUARD_STATE="active",
        )

    def mock(self, name, source):
        p = self.fakebin / name
        p.write_text(source)
        p.chmod(0o700)

    def isolated_script(self, name):
        source = (PROD / name).read_text()
        if name == "lockdown.sh":
            replacements = {
                "/proc/cmdline": str(self.cmdline),
                "/run/modprobe.d": str(self.udev),
                "/dev/tty1": str(self.tty),
            }
        elif name == "unload-storage.sh":
            replacements = {
                "/proc/modules": str(self.modules),
                "/sys/block": str(self.block),
                "/sys/bus/usb/drivers": str(self.sys / "bus/usb/drivers"),
            }
        else:
            raise AssertionError("unexpected script")
        for old, new in replacements.items():
            self.assertIn(old, source, "production source path missing")
            source = source.replace(old, new)
        p = self.d / name
        p.write_text(source)
        return p

    def run_script(self, name):
        p = self.isolated_script(name)
        return subprocess.run(
            ["bash", str(p)], env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=8, check=False,
        )

    def test_lockdown_good_ram_boot(self):
        p = self.run_script("lockdown.sh")
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        policy = (self.udev / "airsign-no-usb-storage.conf").read_text()
        self.assertIn("install usb_storage /bin/false", policy)
        self.assertIn("install uas /bin/false", policy)

    def test_lockdown_missing_toram_refuses(self):
        self.cmdline.write_text("boot=live\n")
        p = self.run_script("lockdown.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(self.power.exists())
        self.assertFalse((self.udev / "airsign-no-usb-storage.conf").exists())

    def test_lockdown_not_in_ram_refuses(self):
        self.env["TEST_FSTYPE"] = "ext4"
        p = self.run_script("lockdown.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(self.power.exists())

    def test_lockdown_udev_reload_failure_refuses(self):
        self.env["TEST_UDEV_FAIL"] = "1"
        p = self.run_script("lockdown.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("udev did not reload", p.stdout)

    def test_unload_clean_boot_allows(self):
        p = self.run_script("unload-storage.sh")
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)

    def test_unload_loaded_driver_refuses(self):
        self.modules.write_text("usb_storage 4096 1 - Live 0x0\n")
        p = self.run_script("unload-storage.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("driver still loaded", p.stderr)

    def test_unload_unreadable_module_state_refuses(self):
        self.modules.unlink()
        p = self.run_script("unload-storage.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot read /proc/modules", p.stderr)

    def test_unload_unexpected_usb_disk_refuses(self):
        (self.block / "sda").mkdir()
        p = self.run_script("unload-storage.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("unexpected block device sda", p.stderr)

    def test_unload_unexpected_nvme_disk_refuses(self):
        (self.block / "nvme0n1").mkdir()
        p = self.run_script("unload-storage.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("unexpected block device nvme0n1", p.stderr)

    def test_unload_unavailable_block_state_refuses(self):
        for child in self.block.iterdir():
            child.rmdir()
        self.block.rmdir()
        p = self.run_script("unload-storage.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("/sys/block unavailable", p.stderr)

    def test_unload_inactive_usbguard_refuses(self):
        self.env["TEST_GUARD_STATE"] = "inactive"
        p = self.run_script("unload-storage.sh")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("USBGuard is not active", p.stderr)

    def test_signer_unit_requires_guards(self):
        d = ROOT / "image/rootfs/etc/systemd/system"
        signer = (d / "airsign.service").read_text()
        self.assertIn("Requires=airsign-lockdown.service airsign-verify-boot.service airsign-unload-storage.service", signer)
        self.assertIn("BindsTo=usbguard.service", signer)
        self.assertIn("After=airsign-lockdown.service airsign-verify-boot.service usbguard.service airsign-unload-storage.service", signer)
        unload = (d / "airsign-unload-storage.service").read_text()
        self.assertIn("Requires=usbguard.service", unload)
        self.assertIn("Before=airsign.service", unload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
