#!/usr/bin/env python3
"""v49-lists2 — vague 4.9 : les racines des listes.

a) s6 dans le grand parseur @ 0x1631568 : traçage arrière.
b) bloc 0x1767750-0x17678a0 (7 appels chercheur) : les roots.
c) teardown : confirmation root = [x+0x3CD0] (0x164b3d0-0x164b3f4).
d) les frames -0x310 : 0x16325d6 / 0x162ff1e / 0x17000a6 — origine du slot.
"""
import bisect
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]


def dump(lo, hi, title):
    print(f"\n=== {title} ===")
    i0 = bisect.bisect_left(addrs, lo)
    while i0 < len(rows) and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        print(f"  {a:#08x}  {m:10} {o}")
        i0 += 1


dump(0x1631480, 0x1631570, "grand parseur : formation de s6 avant 0x1631568")
dump(0x17676f0, 0x17678a0, "bloc 7 appels chercheur 0x17677xx")
dump(0x164b390, 0x164b3f8, "teardown : root des finders")
dump(0x16325a0, 0x16325da, "grand parseur : origine -0x310(a5) @ 0x16325d6")
dump(0x162fef0, 0x162ff22, "0x162ff1e : origine -0x310(a5)")
