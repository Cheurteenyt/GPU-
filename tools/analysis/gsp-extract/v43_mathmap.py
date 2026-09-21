#!/usr/bin/env python3
"""v43-mathmap — carte des sites arithmétiques (mul/div/rem 32-bit M-extension)
dans le texte rm.elf, densité par fenêtre 256 Ko + top sites individuels.
Le moteur d'interpolation VF / budget puissance vit là où mulhu/divu/remu s'entassent."""
import struct
import sys
from pathlib import Path
from collections import Counter

p = Path("/home/z/my-project/scratch-gsp/rm.elf")
d = p.read_bytes()
TEXT_VA, TEXT_SZ = 0x1000000, 0xE85000

# M-extension: opcode 0110011 (0x33), funct7=0000001, funct3: mul=0 mulh=1 mulhsu=2 mulhu=3 div=4 divu=5 rem=6 remu=7
FN = {0: "mul", 1: "mulh", 2: "mulhsu", 3: "mulhu", 4: "div", 5: "divu", 6: "rem", 7: "remu"}

def scan(step):
    sites = []
    for off in range(0, TEXT_SZ - 4, step):
        w = struct.unpack_from("<I", d, off)[0]
        if (w & 0x7F) == 0x33 and ((w >> 25) & 0x7F) == 1:
            f3 = (w >> 12) & 7
            sites.append((off + TEXT_VA, FN[f3]))
    return sites

step = 4 if len(sys.argv) > 1 and sys.argv[1] == "4" else 2
sites = scan(step)
print(f"{len(sites)} sites M-extension (step={step})")

# top d'op
c = Counter(op for _, op in sites)
print("répartition:", dict(c))

# densité par fenêtre 256 Ko
win = Counter()
for va, op in sites:
    if op in ("mulhu", "divu", "remu", "mulh"):
        win[(va >> 18) << 18] += 1
print("\nTOP fenêtres 256 Ko (mulhu/mulh/divu/remu):")
for base, n in win.most_common(16):
    print(f"  {base:#x}  {n}")

# fenêtre perf connue (0x16xxxxx-0x17xxxxx) en détail
print("\nFenêtres perf (0x1600000-0x1800000):")
for base, n in sorted(win.items()):
    if 0x1600000 <= base < 0x1800000:
        print(f"  {base:#x}  {n}")
