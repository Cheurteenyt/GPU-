#!/usr/bin/env python3
"""v43-phdrs — parse les program headers de rm.elf (section headers zeroed)."""
import struct
import sys
from pathlib import Path

p = Path("/home/z/my-project/scratch-gsp/rm.elf")
d = p.read_bytes()
assert d[:4] == b"\x7fELF" and d[4] == 2 and d[5] == 1, "pas ELF64 LE"
e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
e_entry, = struct.unpack_from("<Q", d, 0x18)
print(f"entry {e_entry:#x}  phoff {e_phoff:#x}  phentsize {e_phentsize}  phnum {e_phnum}  filesize {len(d):#x}")

PT = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS",
      0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO",
      0x6474e553: "GNU_PROPERTY", 0x70000003: "RISCV_ATTR"}

for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    ptype, flags = struct.unpack_from("<II", d, o)
    off, va, pa, fsz, msz, algn = struct.unpack_from("<QQQQQQ", d, o + 8)
    fl = ("X" if flags & 1 else "-") + ("W" if flags & 2 else "-") + ("R" if flags & 4 else "-")
    name = PT.get(ptype, hex(ptype))
    print(f"  [{i}] {name:14} {fl} off {off:#011x} va {va:#012x} fsz {fsz:#010x} msz {msz:#010x} align {algn:#x}")
    if ptype == 1:
        # couverture des vtables 0x20357dd0 ?
        if va <= 0x20357dd0 < va + msz:
            print(f"      >>> couvre 0x20357dd0 (off cible = {off + 0x20357dd0 - va:#x})")
