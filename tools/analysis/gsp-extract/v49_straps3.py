#!/usr/bin/env python3
"""v49-straps3 — vague 4.9 : valeurs décodées des JT + origine du holder.

1. Corps des cases JT1 (0x1b3c62a-0x1b3c6d0) et JT2 (0x1b3c742-0x1b3c784).
2. Fonction contenant 0x1bd9888 : prologue, origine de s4 et [s4-0x510].
3. Le mot complet est re-stocké où ? (s5 → [s1+0x24..0x38] cartographie)
"""
import bisect
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]


def dump(lo, hi, title):
    print(f"=== {title} ===")
    i0 = bisect.bisect_left(addrs, lo)
    while i0 < n and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        print(f"  {a:#08x}  {m:10} {o}")
        i0 += 1
    print()


dump(0x1B3C62A, 0x1B3C6D2, "corps des cases JT1")
dump(0x1B3C742, 0x1B3C784, "corps des cases JT2")

# fonction contenant 0x1bd9888
di = bisect.bisect_left(addrs, 0x1BD9888)
fstart = None
for i in range(di, -1, -1):
    a, s, m, o = rows[i]
    p = [x.strip() for x in o.split(",")]
    if (m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
            and p[1] == "sp" and p[2].startswith("-")) or \
       (m == "c.addi16sp" and p and p[-1].startswith("-")):
        fstart = i
        break
print(f"fonction consommatrice : début {rows[fstart][0]:#08x}")
dump(rows[fstart][0], rows[fstart][0] + 0x90, "prologue consommateur")
