#!/usr/bin/env python3
"""extract-full-vbios — pull the full ~976 KiB VBIOS image out of a byte
pattern hit inside the BAR1 aperture scan (see scan-bar1-vbios.py).

Usage: echo <password> | sudo -S python3 tools/extract-full-vbios.py <phys_addr> [size]
Verifies the PCI image chain, then the tail tables at the pointer-resolved
offsets, and writes the image to day0/rom-full-<ts>/rom-full.rom.
"""
import hashlib
import struct
import sys
import time
from pathlib import Path

import mmap, os

ADDR = int(sys.argv[1], 0)
SIZE = int(sys.argv[2], 0) if len(sys.argv) > 2 else 999424
OUT = Path(__file__).resolve().parent.parent / "day0" / f"rom-full-{time.strftime('%Y%m%d-%H%M%S')}"
OUT.mkdir(parents=True, exist_ok=True)

R1 = '/sys/bus/pci/devices/0000:07:00.0/resource1'
fd = os.open(R1, os.O_RDONLY)
mm = mmap.mmap(fd, SIZE, offset=ADDR)  # caller passes BAR-relative offset
data = mm[:]
mm.close()
os.close(fd)

(OUT / "rom-full.rom").write_bytes(data)
print(f"saved {len(data)} bytes -> {OUT/'rom-full.rom'}")
print("sha256:", hashlib.sha256(data).hexdigest())
print("head:", data[:16].hex(" "))

off = 0
n = 0
total = 0
while off < len(data):
    if data[off:off + 2] != b"\x55\xaa":
        print(f"image {n}: no 55aa at {off:#x} — stopping"); break
    pcir = struct.unpack_from("<H", data, off + 0x18)[0]
    length = struct.unpack_from("<H", data, off + pcir + 0x10)[0] * 512
    indicator = data[off + pcir + 0x15]
    print(f"image {n}: {off:#x} len {length} code {data[off+pcir+0x14]:#04x} ind {indicator:#04x}")
    total += length; off += length; n += 1
    if indicator & 0x80: break
print(f"chain total {total} vs file {len(data)}")

for name, o, sig in [("power_budget", 551240, 0x30), ("fan_cooler", 554029, 0x10), ("fan_policy", 554087, 0x20)]:
    if o + 4 <= len(data):
        print(f"{name} @ {o}: {data[o:o+4].hex(' ')} (expect ver {sig:#04x})")
hits = [i for i in range(len(data) - 3) if data[i] == 0x20 and data[i+1] == 0x15 and data[i+2] == 0x01]
print("vP-state candidates:", [hex(h) for h in hits[:8]])
