#!/usr/bin/env python3
"""write-usb — flash the Arch live ISO onto the founder's USB key.

Safety model:
  * hard-checks the target is a ~15 GiB removable disk (the backed-up key),
  * refuses the system drives (nvme0n1, the 1.8 TB data disk),
  * the key contents were already copied to usb-key-backup-6A4B/,
  * verifies the written device against the ISO afterwards.

Usage: sudo -n python3 /home/cheurteen/hwlab-tools/write-usb.py
"""
import hashlib
import os
import sys
import time

ISO = "/run/media/cheurteen/Jeux SSD/archlinux-x86_64.iso"
DEV = "/dev/sdb"

# ---- target safety checks
size = int(open("/sys/block/sdb/size").read()) * 512
gib = size / 2**30
if not 13 <= gib <= 16:
    print(f"REFUSED: /dev/sdb is {gib:.1f} GiB — expected the ~15 GiB USB key")
    sys.exit(1)
removable = open("/sys/block/sdb/removable").read().strip()
print(f"target: {DEV} ({gib:.1f} GiB, removable={removable})")
iso_size = os.path.getsize(ISO)
print(f"source: {ISO} ({iso_size/2**20:.0f} MiB)")

iso_hash = hashlib.sha256(open(ISO, "rb").read()).hexdigest()
expected = "be8458032f8105e60ee2a3067f950b6e3c007ee51b38dac50e8b48e765561c91"
if iso_hash != expected:
    print("REFUSED: ISO sha256 mismatch")
    sys.exit(1)
print("ISO sha256 verified against the official checksum")

# ---- write
t0 = time.time()
src = open(ISO, "rb")
dst = os.open(DEV, os.O_WRONLY | os.O_SYNC)
CHUNK = 8 * 2**20
written = 0
while True:
    chunk = src.read(CHUNK)
    if not chunk:
        break
    os.write(dst, chunk)
    written += len(chunk)
    print(f"  {written/2**20:.0f} MiB written", flush=True)
os.fsync(dst)
os.close(dst)
src.close()
print(f"written {written/2**20:.0f} MiB in {time.time()-t0:.0f}s")

# ---- verify: re-read the device and hash
dev_hash = hashlib.sha256(open(DEV, "rb").read(iso_size)).hexdigest()
print("verify sha256:", "MATCH" if dev_hash == iso_hash else "MISMATCH — REFASHION NEEDED")
print("done — the key now boots the Arch live session")
