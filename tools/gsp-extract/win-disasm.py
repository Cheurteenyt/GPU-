#!/usr/bin/env python3
"""win-disasm — disassemble a window of rm.elf around a file offset.
Usage: python3 win-disasm.py <file_off_hex> [size_hex] [label]
"""
import struct
import subprocess
import sys
import re
from pathlib import Path

d = Path('gsp-rm-17MB.bin').read_bytes()


def off2va(o):
    return o + 0x1000000 if o < 0xe9b000 else o - 0xe9b000 + 0x4000000


def disasm_window(file_off, size=0x400, label=''):
    start = file_off - 0x100
    code = d[start:start + size]
    vstart = off2va(start)
    OFFC = 0x78
    eh = bytearray(64)
    eh[0:4] = b'\x7fELF'; eh[4] = 2; eh[5] = 1; eh[6] = 1
    struct.pack_into('<HHI', eh, 16, 2, 243, 1)
    struct.pack_into('<QQQ', eh, 24, vstart, 64, 0)
    struct.pack_into('<IHHHHH', eh, 48, 1, 64, 56, 1, 0, 0)
    ph = struct.pack('<IIQQQQQQ', 1, 7, OFFC, vstart, vstart, len(code), len(code), 0x1000)
    Path('win.elf').write_bytes(bytes(eh) + ph + code)
    out = subprocess.run(['llvm-objdump', '-d', '--triple=riscv64-unknown-elf', 'win.elf'],
                         capture_output=True, text=True).stdout
    print(f'===== {label} (window {vstart:#x}-{vstart+size:#x}) =====')
    for l in out.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+(\S+)\s*(.*)', l)
        if m:
            print(f'{int(m.group(1),16):#x}: {m.group(2):<8} {m.group(3)}')


if __name__ == '__main__':
    off = int(sys.argv[1], 0)
    size = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x400
    label = sys.argv[3] if len(sys.argv) > 3 else ''
    disasm_window(off, size, label)
