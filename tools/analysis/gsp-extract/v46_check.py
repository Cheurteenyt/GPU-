#!/usr/bin/env python3
"""v46-check — tranchage appariement 0x163270a + sites d'appel clés du ctor + fin ctor."""
import bisect
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
rm = RM.read_bytes()

def cstr(va, maxlen=72):
    off = va - 0x1000000
    if off < 0 or off >= len(rm):
        return None
    end = rm.find(b"\x00", off, off + maxlen)
    if end < 0:
        end = off + maxlen
    try:
        s = rm[off:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if len(s) >= 3 and all(32 <= ord(c) < 127 for c in s) else None

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]

def dump(lo, hi, title):
    print(f"\n--- {title} : {lo:#x}..{hi:#x} ---")
    i0 = bisect.bisect_left(addrs, lo)
    while i0 < len(rows) and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        print(f"  {a:#08x}  {m:10} {o}")
        i0 += 1

# 1) tranchage : fenêtre brute autour du lookup 0x1632714
dump(0x16326E8, 0x1632724, "TRANCHE lookup fin de parseur")

# 2) sites d'appel du constructeur : petit parseur VF x2 + post-grand-parseur
for site, name in ((0x16312F8, "ctor@petit-parseur-1"), (0x16314D6, "ctor@petit-parseur-2"),
                   (0x1632840, "ctor@post-grand-parseur")):
    dump(site - 0x2C, site + 0x14, name)

# 3) fin du constructeur (0x1456da4..0x1456f20)
dump(0x1456DA4, 0x1456F20, "ctor fin")

# 4) strings autour des deux candidates
print("\n--- cstr voisines ---")
for va in (0x1E71230, 0x1E71260, 0x1E71290, 0x1E76C30, 0x1E76C60, 0x1E76C90):
    print(f"  cstr({va:#x}) = {cstr(va)!r}")
