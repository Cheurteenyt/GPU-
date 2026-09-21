#!/usr/bin/env python3
"""v45-focus — dump d'une fenêtre du text.tsv (VAs hex lo hi), format lisible."""
import bisect
import sys
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]

lo, hi = int(sys.argv[1], 0), int(sys.argv[2], 0)
i0 = bisect.bisect_left(addrs, lo)
while i0 < len(rows) and rows[i0][0] <= hi:
    a, s, m, o = rows[i0]
    print(f"{a:#08x}  {m:10} {o}")
    i0 += 1
