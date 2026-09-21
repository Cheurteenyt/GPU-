#!/usr/bin/env python3
"""probe-bar1-access — find a working read path into the 8 GiB VRAM aperture.
Tries small preads and small mmaps at several offsets; prints a verdict.
Usage: echo <password> | sudo -S python3 tools/probe-bar1-access.py
"""
import mmap
import os

R1 = '/sys/bus/pci/devices/0000:07:00.0/resource1'

fd = os.open(R1, os.O_RDONLY)
print('--- pread 4096 at offsets ---')
for off in (0, 1 << 20, 1 << 28, 1 << 30, 1 << 31, 1 << 32, 0x1FF00000):
    try:
        d = os.pread(fd, 4096, off)
        ff = d.count(0xFF) / len(d)
        print(f'pread 4K @ {off:#x}: ok, ff={ff:.2f}, head={d[:8].hex()}')
    except OSError as e:
        print(f'pread 4K @ {off:#x}: {e}')

print('--- pread sizes at 0 ---')
for sz in (65536, 1 << 20, 1 << 24):
    try:
        os.pread(fd, sz, 0)
        print(f'pread {sz:#x} @ 0: ok')
    except OSError as e:
        print(f'pread {sz:#x} @ 0: {e}')

print('--- mmap 4096 at offsets ---')
for off in (0, 1 << 30, 1 << 32):
    try:
        mm = mmap.mmap(fd, 4096, offset=off)
        d = mm[:]
        mm.close()
        print(f'mmap 4K @ {off:#x}: ok, head={d[:8].hex()}')
    except (OSError, ValueError) as e:
        print(f'mmap 4K @ {off:#x}: {e}')
os.close(fd)
