#!/usr/bin/env python3
"""amd-spi-probe — read-only probe of the AMD FCH SPI controller.

Run:  sudo python3 tools/amd-spi-probe.py

Reads the SPI base from PCI 00:14.3 (1002:4385) offset 0xA0 and the
SPI_CNTRL0 register (bits 22 SpiAccessMacRomEn / 23 SpiHostAccessRomEn
— the flashrom gate, sb600spi.c:743). Nothing is written.
"""

import mmap
import os
import subprocess
import sys

bar_raw = int(subprocess.check_output(["setpci", "-s", "00:14.3", "0xA0.L"]).strip(), 16)
print(f"PCI 0xA0 raw: {bar_raw:#010x}")

if bar_raw == 0xFFFFFFFF:
    print("ROM ARMOR ACTIVE — the BAR reads all-1s (the ASUS SbRomArmor module")
    print("of the sibling lab's rings is intercepting the controller).")
    sys.exit(0)

base = bar_raw & 0xFFFFFFE0
print(f"SPI base: {base:#x}")

fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
mm = mmap.mmap(fd, 0x1000, offset=base & ~0xFFF)
off = base & 0xFFF
cntrl0 = struct.unpack_from("<I", mm, off)[0]
mm.close()
os.close(fd)

print(f"SPI_CNTRL0: {cntrl0:#010x}")
print(f"  bit22 SpiAccessMacRomEn : {(cntrl0 >> 22) & 1}")
print(f"  bit23 SpiHostAccessRomEn: {(cntrl0 >> 23) & 1}")
print(f"  bit19 SpiArbEnable      : {(cntrl0 >> 19) & 1}")
print(f"  bit31 SpiBusy           : {(cntrl0 >> 31) & 1}")

if (cntrl0 >> 22) & 1 and (cntrl0 >> 23) & 1:
    print("VERDICT: both bits are SET — the lock is NOT the blocker; re-run flashrom with -V for the next wall.")
else:
    print("VERDICT: at least one bit is CLEAR — this is the lock. The bypass is a")
    print(f"read-modify-write of SPI_CNTRL0 setting bits 22|23 (write {cntrl0 | 0xC000000:#010x}).")
