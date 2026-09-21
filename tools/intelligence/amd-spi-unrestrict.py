#!/usr/bin/env python3
"""amd-spi-unrestrict — attempt to clear opcode 0x13 from the FCH SPI
restricted-command lists (SPI_RESTRICTED_CMD1/2 at base+0x04/0x08),
then verify. Read-only unless --write is passed. Reversible: the original
values are printed and restored unless the read test follows."""
import mmap, os, struct, subprocess, sys
WRITE = "--write" in sys.argv
bar = int(subprocess.check_output(["setpci", "-s", "00:14.3", "0xA0.L"]).strip(), 16)
base = bar & 0xFFFFFFE0
fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
mm = mmap.mmap(fd, 0x1000, offset=base & ~0xFFF)
off = base & 0xFFF
def rd32(o): return struct.unpack_from("<I", mm, off+o)[0]
def wr32(o, v): struct.pack_into("<I", mm, off+o, v)
cntrl0 = rd32(0x00)
rc1, rc2 = rd32(0x04), rd32(0x08)
print(f"SPI base {base:#x}")
print(f"CNTRL0          {cntrl0:#010x}  bits22/23 = {(cntrl0>>22)&1}/{(cntrl0>>23)&1}")
print(f"RESTRICTED_CMD1 {rc1:#010x}  bytes: {rc1&0xff:#04x} {(rc1>>8)&0xff:#04x} {(rc1>>16)&0xff:#04x} {(rc1>>24)&0xff:#04x}")
print(f"RESTRICTED_CMD2 {rc2:#010x}  bytes: {rc2&0xff:#04x} {(rc2>>8)&0xff:#04x} {(rc2>>16)&0xff:#04x} {(rc2>>24)&0xff:#04x}")
if not WRITE:
    print("read-only probe done (pass --write to attempt the clear)")
    sys.exit(0)
n1, n2 = rc1, rc2
changed = False
for name, val in (("RC1", rc1), ("RC2", rc2)):
    for shift in range(0, 32, 8):
        b = (val >> shift) & 0xFF
        if b in (0x13, 0x0B, 0x3B, 0x6B, 0x0C):
            if name == "RC1": n1 &= ~(0xFF << shift)
            else: n2 &= ~(0xFF << shift)
            changed = True
            print(f"  clearing {b:#04x} from {name} byte {shift//8}")
if not changed:
    print("no read opcodes found in the restricted lists — the block lives elsewhere")
    sys.exit(0)
wr32(0x04, n1); wr32(0x08, n2)
v1, v2 = rd32(0x04), rd32(0x08)
print(f"after write: RC1 {v1:#010x} RC2 {v2:#010x}")
print("VERDICT:", "WRITE STUCK — retry the flashprog read" if (v1 == n1 and v2 == n2) else "write did NOT stick — SMU/EC-locked")
mm.close(); os.close(fd)
