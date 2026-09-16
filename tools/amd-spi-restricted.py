#!/usr/bin/env python3
"""amd-spi-restricted — read the FCH SPI restricted-command and protect-range
registers (read-only), to see whether opcode 0x13 is listed and whether the
lists are RMW-writable. Run: sudo python3 tools/amd-spi-restricted.py"""
import mmap, os, struct, subprocess, sys
bar = int(subprocess.check_output(["setpci", "-s", "00:14.3", "0xA0.L"]).strip(), 16)
base = bar & 0xFFFFFFE0
fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
mm = mmap.mmap(fd, 0x1000, offset=base & ~0xFFF)
off = base & 0xFFF
def rd32(o): return struct.unpack_from("<I", mm, off+o)[0]
cntrl0 = rd32(0x00); rc1 = rd32(0x04); rc2 = rd32(0x08)
print(f"SPI base {base:#x}")
print(f"CNTRL0          {cntrl0:#010x}  bits22/23 = {(cntrl0>>22)&1}/{(cntrl0>>23)&1}")
print(f"RESTRICTED_CMD1 {rc1:#010x}  opcodes = {rc1&0xff:#04x} {(rc1>>8)&0xff:#04x} {(rc1>>16)&0xff:#04x} {(rc1>>24)&0xff:#04x}")
print(f"RESTRICTED_CMD2 {rc2:#010x}  opcodes = {rc2&0xff:#04x} {(rc2>>8)&0xff:#04x} {(rc2>>16)&0xff:#04x} {(rc2>>24)&0xff:#04x}")
for name, o in [("ROM_PROTECT0",0x70),("ROM_PROTECT1",0x74),("ROM_PROTECT2",0x78),("ROM_PROTECT3",0x7C)]:
    v = rd32(o)
    print(f"{name:14} {v:#010x}  base={(v>>17)&0x7fff:#06x} unit64K={(v>>16)&1} wp={(v>>24)&1} rp={(v>>25)&1}")
mm.close(); os.close(fd)
