#!/usr/bin/env python3
"""v49-straps — vague 4.9, chantier 3 : la chaîne strap→code.

1. Références (auipc+addi / auipc+ld) aux jump-tables 0x1DEB210 / 0x1DEB280
   → fonctions utilisatrices.
2. Dump des utilisateurs (± contexte) : où le mot packé est lu.
3. Remontée : champs/registres alimentant le mot (ld amont).
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v49")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]


def parse(o):
    return [x.strip() for x in o.split(",")]


TARGETS = {0x1DEB210: "JT1_decode27", 0x1DEB280: "JT2_idPlus1"}

refs = {t: [] for t in TARGETS}
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m != "auipc" or len(p) != 2:
        continue
    hi20 = int(p[1], 0)
    for j in range(i + 1, min(i + 4, n)):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        used = False
        if mm in ("addi", "c.addi") and len(pp) == 3 and pp[0] == p[0] \
                and pp[1] == p[0]:
            try:
                t = (a + (hi20 << 12) + int(pp[2], 0)) & 0xFFFFFFFF
            except ValueError:
                break
            used = True
        elif mm in ("ld", "lw", "lbu") and len(pp) == 2 \
                and pp[1].endswith(f"({p[0]})"):
            try:
                disp = int(pp[1].split("(")[0] or "0", 16)
            except ValueError:
                break
            t = (a + (hi20 << 12) + disp) & 0xFFFFFFFF
            used = True
        if used and t in TARGETS:
            refs[t].append((hex(a), mm, oo, hex(t)))
        if used:
            break

for t, name in TARGETS.items():
    print(f"=== refs à {name} {t:#08x} ===")
    for r in refs[t]:
        print(f"  {r[0]}  {r[1]} {r[2]}  → {r[3]}")
    print(f"  {len(refs[t])} référence(s)\n")


def dump(lo, hi, title):
    print(f"=== {title} ===")
    i0 = bisect.bisect_left(addrs, lo)
    while i0 < n and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        print(f"  {a:#08x}  {m:10} {o}")
        i0 += 1
    print()


# contexte de chaque référence : -30 / +10 insns
for t in TARGETS:
    for site, mm, oo, _ in [(int(r[0], 16), r[1], r[2], r[3]) for r in refs[t]]:
        i0 = bisect.bisect_left(addrs, site)
        lo_i, hi_i = max(0, i0 - 26), min(n, i0 + 8)
        print(f"--- contexte {TARGETS[t]} @ {site:#08x} ---")
        for k in range(lo_i, hi_i):
            a, s, m, o = rows[k]
            print(f"  {a:#08x}  {m:10} {o}")
        print()

json.dump({TARGETS[t]: refs[t] for t in TARGETS},
          (OUT / "v49_straps.json").open("w"), indent=1)
