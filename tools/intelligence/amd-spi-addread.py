#!/usr/bin/env python3
"""amd-spi-addread — attempt to ADD opcode 0x13 (READ) to the FCH SPI
restricted/allowed command lists (base+0x04/0x08), then verify."""
import mmap, os, struct, subprocess
bar = int(subprocess.check_output(["setpci", "-s", "00:14.3", "0xA0.L"]).strip(), 16)
base = bar & 0xFFFFFFE0
fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
mm = mmap.mmap(fd, 0x1000, offset=base & ~0xFFF)
off = base & 0xFFF
def rd32(o): return struct.unpack_from("<I", mm, off+o)[0]
def wr32(o, v): struct.pack_into("<I", mm, off+o, v)
rc1, rc2 = rd32(0x04), rd32(0x08)
print(f"before: RC1={rc1:#010x} RC2={rc2:#010x}")
# try setting a free byte of RC2 to 0x13 (bytes 0,2,3 are free; byte1 holds 0x06)
target = (rc2 & ~0x0000FF00) | (0x13 << 8)
wr32(0x08, target)
v2 = rd32(0x08)
print(f"RC2 write 0x13 into byte1: wrote {target:#010x}, read back {v2:#010x}")
print("VERDICT:", "WRITE STUCK" if v2 == target else "write did NOT stick — SMU/EC-locked")
mm.close(); os.close(fd)
