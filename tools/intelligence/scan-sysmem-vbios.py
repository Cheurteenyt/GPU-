#!/usr/bin/env python3
"""scan-sysmem-vbios — hunt for a cached full VBIOS image in SYSTEM RAM.
The GSP firmware (open kernel module) reads the whole VBIOS at init and may
keep it in a system-memory heap. iomem=relaxed allows /dev/mem reads of RAM.
Pure reads. Usage: echo <password> | sudo -S python3 tools/scan-sysmem-vbios.py
"""
import os
import time

HEAD = bytes.fromhex('55aa7feb4b37343030e94c1977cc5649')
BIT = b'\xff\xb8BIT\x00'
CHUNK = 1 << 26  # 64 MiB

ranges = []
for line in open('/proc/iomem'):
    name = line.split(':', 1)[1].strip() if ':' in line else ''
    if name in ('System RAM', 'Reserved'):
        a, b = line.split(':', 1)[0].split('-')
        ranges.append((int(a, 16), int(b, 16), name))
total = sum(b - a + 1 for a, b, _ in ranges)
print(f'{len(ranges)} candidate ranges, {total/2**30:.1f} GiB to scan')

fd = os.open('/dev/mem', os.O_RDONLY | os.O_SYNC)
t0 = time.time()
hits = []
bit_hits = []
scanned = 0
for a, b, name in ranges:
    off = a
    while off <= b:
        n = min(CHUNK, b - off + 1)
        try:
            data = os.pread(fd, n, off)
        except OSError as e:
            print(f'  range {a:#x}-{b:#x} [{name}]: pread fail at {off:#x}: {e}', flush=True)
            break
        if len(data) == 0:
            print(f'  range {a:#x}-{b:#x} [{name}]: EOF at {off:#x}', flush=True)
            break
        p = data.find(HEAD)
        while p != -1:
            hits.append((off + p, name))
            p = data.find(HEAD, p + 1)
        p = data.find(BIT)
        while p != -1:
            bit_hits.append((off + p, name))
            p = data.find(BIT, p + 1)
        scanned += len(data)
        off += n
    if True:
        print(f'range {a:#x}-{b:#x} [{name}]: {min(off,b+1)-a/1 if False else off-a:/,d}' if False else f'range {a:#x}-{b:#x} [{name}]: {off-a:,} B ok', flush=True)
os.close(fd)
print(f'scanned {scanned/2**30:.1f} GiB in {time.time()-t0:.1f}s')
print('ROM-header hits (physical):', [(hex(o), n) for o, n in hits[:12]])
print('BIT-token hits (physical):', [(hex(o), n) for o, n in bit_hits[:12]])
