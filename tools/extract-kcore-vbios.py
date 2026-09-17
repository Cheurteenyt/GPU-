#!/usr/bin/env python3
"""extract-kcore-vbios — pull the full VBIOS image from the RAM copies found
by scan-kcore-vbios.py. Maps each physical address through /proc/kcore's
PT_LOAD segments, extracts 999424 bytes, verifies chain + tail signatures,
saves every coherent copy to day0/kcore-vbios-<ts>/copy-<addr>.rom
Usage: echo <password> | sudo -S python3 tools/extract-kcore-vbios.py
"""
import hashlib
import struct
import time
from pathlib import Path

CANDIDATES = [0xbff9f058, 0xc6803024, 0xc69b3018, 0x2ad1e4750, 0x2be356200]
SIZE = 999424
OUT = Path(__file__).resolve().parent.parent / 'day0' / f'kcore-vbios-{time.strftime("%Y%m%d-%H%M%S")}'
OUT.mkdir(parents=True, exist_ok=True)

f = open('/proc/kcore', 'rb')
assert f.read(4) == b'\x7fELF'
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
    if p_paddr <= (64 << 30):
        segs.append((p_paddr, p_offset, p_filesz))

def kread(phys, n):
    for base, poff, size in segs:
        if base <= phys and phys + n <= base + size:
            f.seek(poff + (phys - base))
            return f.read(n)
    return None

for addr in CANDIDATES:
    data = kread(addr, SIZE)
    if data is None:
        print(f'{addr:#x}: not fully mapped in kcore, skipped')
        continue
    ok_head = data[:2] == b'\x55\xaa'
    ok_bit = data[0x1B0:0x1B4] == b'\xff\xb8BIT\x00'[:1] + b'\xb8BIT\x00' if False else data[0x1b1:0x1b5] == b'BIT\x00'
    chain, total, n = [], 0, 0
    off = 0
    while off < len(data) and data[off:off+2] == b'\x55\xaa':
        pcir = struct.unpack_from('<H', data, off + 0x18)[0]
        length = struct.unpack_from('<H', data, off + pcir + 0x10)[0] * 512
        indicator = data[off + pcir + 0x15]
        chain.append((n, off, length, data[off + pcir + 0x14], indicator))
        total += length; off += length; n += 1
        if indicator & 0x80: break
    sig = {
        'power_budget': data[551240] if len(data) > 551244 else None,
        'fan_cooler': data[554029] if len(data) > 554033 else None,
        'fan_policy': data[554087] if len(data) > 554091 else None,
    }
    coherent = (ok_head and total == SIZE and sig['power_budget'] == 0x30
                and sig['fan_cooler'] == 0x10 and sig['fan_policy'] == 0x20)
    sha = hashlib.sha256(data).hexdigest()
    print(f'{addr:#x}: head={ok_head} chain={[(c[1], c[2]) for c in chain]} total={total} '
          f'pb={sig["power_budget"]:#04x} fc={sig["fan_cooler"]:#04x} fp={sig["fan_policy"]:#04x} '
          f'coherent={coherent} sha256={sha[:16]}')
    name = OUT / f'copy-{addr:x}.rom'
    name.write_bytes(data)
    if coherent:
        print(f'  ^ COHERENT FULL IMAGE saved to {name}')

# cross-check every coherent copy against the 512 KiB BAR window
win = Path(__file__).resolve().parent.parent / 'day0' / 'rom-bar-window.bin'
if win.exists():
    w = win.read_bytes()[:157696]
    for rom in sorted(OUT.glob('copy-*.rom')):
        d = rom.read_bytes()
        print(f'{rom.name}: prefix match vs BAR window: {d[:len(w)] == w}')
