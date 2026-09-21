#!/usr/bin/env python3
"""lz-probe — empirical battery against the GSP bindata stream.
Tries LZ4-block decoding (no magic in that format), raw deflate, and
known-plaintext checks against the rm.elf we already hold.
"""
import struct
import zlib
from pathlib import Path

fw = Path('fwimage.bin').read_bytes()
STREAM = 0x12d1000
rm = Path('gsp-rm-17MB.bin').read_bytes()


def lz4_block(src, pos, out_limit=64 * 2**20):
    """Minimal LZ4 block decoder. Returns (output, end_pos) or raises."""
    out = bytearray()
    n = len(src)
    while pos < n and len(out) < out_limit:
        token = src[pos]; pos += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                b = src[pos]; pos += 1
                lit_len += b
                if b != 255:
                    break
        out += src[pos:pos + lit_len]
        pos += lit_len
        if pos >= n or len(out) >= out_limit:
            break
        offset = struct.unpack_from('<H', src, pos)[0]; pos += 2
        if offset == 0:
            raise ValueError('zero offset')
        match_len = (token & 0xF) + 4
        if (token & 0xF) == 15:
            while True:
                b = src[pos]; pos += 1
                match_len += b
                if b != 255:
                    break
        start = len(out) - offset
        if start < 0:
            raise ValueError('offset before start')
        for i in range(match_len):  # byte-wise: overlap allowed
            out.append(out[start + i])
    return bytes(out), pos


print('=== LZ4-block attempts at stream offsets ===')
base = STREAM
for skip in range(0, 24):
    try:
        out, end = lz4_block(fw, base + skip, out_limit=8 * 2**20)
        head = out[:16]
        elf = head[:4] == b'\x7fELF'
        print(f'skip {skip}: decoded {len(out):,} B, head {head.hex(" ")}{" <- ELF!" if elf else ""}')
        if elf:
            Path('bindata-decoded.bin').write_bytes(out)
            print('saved bindata-decoded.bin')
            break
    except (ValueError, IndexError, struct.error) as e:
        print(f'skip {skip}: reject ({e})')

print('=== raw deflate attempts ===')
for skip in range(0, 8):
    try:
        out = zlib.decompress(fw[base + skip:base + 2**22], -15)
        print(f'skip {skip}: deflate OK {len(out):,} B head {out[:8].hex()}')
        break
    except zlib.error:
        pass
else:
    print('deflate: no hit')

print('=== known-plaintext probe (rm.elf chunks in stream) ===')
probe = rm[0x1000:0x1010]  # 16 B from inside rm.elf
i = fw.find(probe, base)
print('rm.elf interior chunk found in stream:', hex(i) if i != -1 else 'no')
