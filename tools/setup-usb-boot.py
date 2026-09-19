#!/usr/bin/env python3
"""setup-usb-boot — make the NEXT reboot land directly on the USB live key.

Finds the USB's EFI partition, creates a firmware boot entry for it, and
sets BootNext — the firmware boots it once, then normal order resumes.
No F11, no timing, no BIOS navigation.

Usage: sudo -n python3 /home/cheurteen/hwlab-tools/setup-usb-boot.py
"""
import re
import subprocess
import sys

DEV = "/dev/sdb"


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)


# 1. refresh the kernel's view of the key (it was just re-flashed)
code, out = run(["partprobe", DEV])
code, out = run(["bash", "-c", "partx -u /dev/sdb 2>/dev/null; lsblk -rf /dev/sdb"])
print(out.strip())

# 2. locate the EFI (FAT) partition via blkid (lsblk udev cache is stale here)
efi_part, efi_index = None, None
code, out = run(["bash", "-c", "blkid /dev/sdb*"])
for line in out.splitlines():
    if 'TYPE="vfat"' in line:
        efi_part = line.split(":")[0]
        efi_index = efi_part.replace("/dev/sdb", "").lstrip("p")
        break
if not efi_part:
    print("ERROR: no EFI partition found on the key")
    sys.exit(1)
print(f"EFI partition: {efi_part}")

# 3. create a firmware boot entry for the USB's EFI bootloader
code, out = run(["efibootmgr", "-c", "-d", DEV, "-p", efi_index.lstrip("p") or "2",
                 "-L", "HWTruthUSB", "-l", "\\EFI\\BOOT\\BOOTX64.EFI"])
print(out.strip())
if code != 0:
    print("ERROR: efibootmgr failed")
    sys.exit(1)

# 4. find the new entry number and set it as BootNext
code, out = run(["efibootmgr"])
lines = out.splitlines()
bootnum = None
for line in lines:
    if "HWTruthUSB" in line and "*" in line:
        bootnum = line.split("*")[0].replace("Boot", "").strip()
        # AMI firmwares fail silently on a bare HD(2,MBR,...) path (no USB
        # prefix). If ours is bare, prefer the firmware's own full-path
        # entry for the SAME partition (same HD(...) signature).
        m = re.search(r"HD\(([^)]*)\)", line)
        if m and "PciRoot" not in line:
            for alt in lines:
                if ("USB(" in alt and f"HD({m.group(1)})" in alt
                        and "HWTruthUSB" not in alt and "*" in alt):
                    bootnum = alt.split("*")[0].replace("Boot", "").strip()
                    print(f"created entry is a bare path — using firmware "
                          f"full-path entry Boot{bootnum} instead")
                    break
        break
if not bootnum:
    print("ERROR: new entry not found")
    sys.exit(1)
code, out = run(["efibootmgr", "-b", bootnum, "-n", bootnum])
print(f"BootNext set to {bootnum} — the next reboot starts the USB once")

# 5. clean the stale USB entry afterwards is manual; one-shot is consumed at boot
print("READY: reboot normally — you will land on the Arch live session")
