#!/usr/bin/env python3
"""scan-kcore-vbios — hunt for a cached full VBIOS in kernel-visible RAM via
/proc/kcore (ELF core). Not subject to /dev/mem's STRICT_DEVMEM limits.
Pure reads. Usage: echo <password> | sudo -S python3 tools/scan-kcore-vbios.py
"""
import struct
import sys
import time

HEAD = bytes.fromhex('55aa7feb4b37343030e94c1977cc5649')  # this board's ROM header
NVGI = b'NVGI'
BIT = b'\xff\xb8BIT\x00'
CHUNK = 1 << 26  # 64 MiB

f = open('/proc/kcore', 'rb')
assert f.read(4) == b'\x7fELF'
is64 = f.read(1)[0] == 2
f.seek(0x20 if is64 else 0x1c)
phoff = struct.unpack('<Q' if is64 else '<I', f.read(8 if is64 else 4))[0]
f.seek(0x36 if is64 else 0x2a)
phentsize, phnum = struct.unpack('<HH', f.read(4))
segs = []
for i in range(phnum):
    f.seek(phoff + i * phentsize)
    ph = f.read(phentsize)
    p_type = struct.unpack_from('<I', ph, 0)[0]
    if p_type != 1:  # PT_LOAD
        continue
    p_offset, p_vaddr = struct.unpack_from('<QQ', ph, 8)
    p_filesz = struct.unpack_from('<Q', ph, 32)[0]
    p_paddr = struct.unpack_from('<Q', ph, 24)[0]
    if p_paddr < (64 << 30):  # real RAM only, skip the sparse 32 TiB address space
        segs.append((p_offset, p_paddr, p_filesz))
total = sum(s[2] for s in segs)
print(f'{len(segs)} PT_LOAD segments, {total/2**30:.1f} GiB')

t0 = time.time()
head_hits, nvgi_hits, bit_hits = [], [], []
scanned = 0
for p_offset, p_paddr, p_filesz in segs:
    off = 0
    tail = b''
    while off < p_filesz:
        n = min(CHUNK, p_filesz - off)
        try:
            f.seek(p_offset + off)
            data = f.read(n)
        except OSError:
            break
        if len(data) == 0:
            break
        buf = tail + data
        p = buf.find(HEAD)
        while p != -1:
            head_hits.append(p_paddr + off - len(tail) + p)
            p = buf.find(HEAD, p + 1)
        p = buf.find(NVGI)
        while p != -1:
            nvgi_hits.append(p_paddr + off - len(tail) + p)
            p = buf.find(NVGI, p + 1)
        p = buf.find(BIT)
        while p != -1:
            bit_hits.append(p_paddr + off - len(tail) + p)
            p = buf.find(BIT, p + 1)
        tail = data[-32:]
        off += len(data)
        scanned += len(data)
print(f'scanned {scanned/2**30:.1f} GiB in {time.time()-t0:.1f}s')
print('ROM-header hits (phys):', [hex(h) for h in head_hits[:8]])
print('NVGI hits (phys):', [hex(h) for h in nvgi_hits[:8]])
print('BIT hits (phys):', [hex(h) for h in bit_hits[:8]])
