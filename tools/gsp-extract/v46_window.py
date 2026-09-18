#!/usr/bin/env python3
"""v46-window — dump multi-fenêtres du grand parseur perf en un chargement.
Usage : python3 v46_window.py  (fenêtres codées ci-dessous)
"""
import bisect
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]

WINDOWS = [
    ("W1 contexte SET bit 9",        0x1631860, 0x1631A80),
    ("W2 RMDisablePStates+AllowMaxPerf", 0x1631DF6, 0x1631F80),
    ("W3 RMDisablePerfIntersect",    0x16322B0, 0x1632470),
    ("W4 PerfPmaControlReg (fin)",   0x16326F0, 0x16327A0),
]

for name, lo, hi in WINDOWS:
    print(f"\n========== {name} : {lo:#x}..{hi:#x} ==========")
    i0 = bisect.bisect_left(addrs, lo)
    while i0 < len(rows) and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        print(f"  {a:#08x}  {m:10} {o}")
        i0 += 1
