#!/usr/bin/env python3
"""v46-enum2 — enum N (type) des 52 requêtes : backward 16 insns (le N est posé
AVANT le prep 0x18E11F8), avec détection du prep lui-même.
Sortie : scratch-gsp/v45/v46_enum2.json + impression.
"""
import json
from collections import Counter
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
CTOR = 0x1456C7C
PREP = 0x18E11F8

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))

def parse(o):
    return [x.strip() for x in o.split(",")]

n = len(rows)

sites = []
for i, (a, s, m, o) in enumerate(rows):
    if m == "jal":
        p = parse(o)
        if len(p) == 2 and p[1].startswith("0x") and int(p[1], 16) == CTOR:
            sites.append((i, a))
    elif m == "auipc" and parse(o) and parse(o)[0] == "ra":
        p = parse(o)
        try:
            hi = int(p[1], 0) << 12
        except ValueError:
            continue
        for j in (i + 1, i + 2):
            if j >= n:
                break
            m2, o2 = rows[j][2], rows[j][3]
            if m2 == "jalr":
                p2 = parse(o2)
                if len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    if base + int(p2[2], 0) == CTOR:
                        sites.append((i, a))
                    break
            if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == "ra":
                break

print(f"{len(sites)} appelants")

enum = []
for i, a in sites:
    N, has_prep, li_a2_raw = None, False, None
    for j in range(i - 1, max(-1, i - 17), -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm == "auipc" and pp and pp[0] == "ra":
            try:
                hi = int(pp[1], 0) << 12
            except ValueError:
                continue
            for u in (j + 1, j + 2):
                if u >= n:
                    break
                m2, o2 = rows[u][2], rows[u][3]
                if m2 == "jalr":
                    p2 = parse(o2)
                    if len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                        base = aa + hi
                        if base >= 0x80000000:
                            base -= 0x100000000
                        if base + int(p2[2], 0) == PREP:
                            has_prep = True
                    break
                if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == "ra":
                    break
        if mm in ("li", "c.li") and len(pp) == 2 and pp[0] == "a2":
            try:
                v = int(pp[1], 0)
                if 0 <= v <= 0x80 and N is None:
                    N = v
                    li_a2_raw = hex(aa)
            except ValueError:
                pass
    enum.append({"site": hex(a), "N": N, "prep": has_prep, "N_at": li_a2_raw})

for e in enum:
    print(f"  {e['site']}  N={e['N']}  prep={e['prep']}  (li @ {e['N_at']})")

census = Counter(e["N"] for e in enum)
print("\ncensus N :", dict(sorted(census.items(), key=lambda kv: (kv[0] is None, kv[0] if kv[0] is not None else -1))))
print("prep utilisés :", sum(1 for e in enum if e["prep"]), "/", len(enum))

json.dump({"enum": enum, "census_N": {str(k): v for k, v in census.items()}},
          (V45 / "v46_enum2.json").open("w"), indent=1)
print(f"\n-> {V45/'v46_enum2.json'}")
