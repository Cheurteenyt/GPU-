#!/usr/bin/env python3
"""scan-bar1-vbios — search the 8 GiB VRAM aperture (BAR1) for a cached
full VBIOS image kept by the driver. Pure reads; run as root:
    echo <password> | sudo -S python3 tools/scan-bar1-vbios.py
"""
import mmap, os, sys, time

BAR1 = 0  # offsets are BAR-relative on resource1
SIZE = 0x200000000          # 8 GiB aperture
CHUNK = 0x4000000           # 64 MiB read windows
HEAD = bytes.fromhex('55aa7feb4b37343030e94c1977cc5649')  # this board's ROM header
BIT = b'\xff\xb8BIT\x00'    # the BIT token signature used by the decoders

R1 = '/sys/bus/pci/devices/0000:07:00.0/resource1'
fd = os.open(R1, os.O_RDONLY)
t0 = time.time()
hits = []
bit_hits = []
mapped = 0
for i in range(SIZE // CHUNK):
    try:
        data = os.pread(fd, CHUNK, i * CHUNK)
    except OSError as e:
        print(f'chunk {i}: pread failed: {e}', flush=True)
        continue
    if len(data) < CHUNK:
        data = data + b'\xff' * (CHUNK - len(data))
    mapped += 1
    ff = data.count(0xFF) / len(data)
    if ff < 0.999:
        base = BAR1 + i * CHUNK
        for p in (data.find(HEAD), ):
            while p != -1:
                hits.append(base + p)
                p = data.find(HEAD, p + 1)
        p = data.find(BIT)
        while p != -1:
            bit_hits.append(base + p)
            p = data.find(BIT, p + 1)
        print(f'chunk {i} @ {base:#x}: ff={ff:.3f} head_hits={len(hits)} bit_hits={len(bit_hits)}', flush=True)
    mm.close()
os.close(fd)
print(f'scan done: {mapped}/{SIZE//CHUNK} chunks, {time.time()-t0:.1f}s')
print('ROM-header hits (VRAM physical):', [hex(o) for o in hits[:12]])
print('BIT-token hits (VRAM physical):', [hex(o) for o in bit_hits[:12]])
