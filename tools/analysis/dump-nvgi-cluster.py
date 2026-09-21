#!/usr/bin/env python3
"""dump-nvgi-cluster — hexdump the NVGI cluster found in RAM via /proc/kcore.
Usage: echo <password> | sudo -S python3 tools/dump-nvgi-cluster.py
"""
import struct

PHYS = 0x16fe8c000
SPAN = 0x2800

f = open('/proc/kcore', 'rb')
f.read(4)
f.seek(0x20)
phoff = struct.unpack('<Q', f.read(8))[0]
f.seek(0x36)
phentsize, phnum = struct.unpack('<HH', f.read(4))
segs = []
for i in range(phnum):
    f.seek(phoff + i * phentsize)
    ph = f.read(phentsize)
    if struct.unpack_from('<I', ph, 0)[0] != 1:
        continue
    p_offset = struct.unpack_from('<Q', ph, 8)[0]
    p_paddr = struct.unpack_from('<Q', ph, 24)[0]
    p_filesz = struct.unpack_from('<Q', ph, 32)[0]
    if p_paddr < (64 << 30):
        segs.append((p_paddr, p_offset, p_filesz))

def kread(phys, n):
    for base, poff, size in segs:
        if base <= phys and phys + n <= base + size:
            f.seek(poff + (phys - base))
            return f.read(n)
    return None

d = kread(PHYS, SPAN)
if d is None:
    print('not mapped')
else:
    for i in range(0, len(d), 32):
        line = d[i:i+32]
        printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in line)
        print(f'{PHYS+i:#x}: {line.hex(" ")}  {printable}')
