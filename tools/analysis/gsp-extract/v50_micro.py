#!/usr/bin/env python3
"""v50-micro — vague 4.10 : micro-fenêtres + anatomie du constructeur de classe.

1. TOUTES les formations d'adresse (auipc+addi / lui+addi) dont la VA tombe
   dans [0x12b5c80, 0x12b5d50] (wrapper) ou [0x12c7a10, 0x12c7a80]
   (pré-wrapper) — SANS filtre « début de fonction » : tags, milieux, +2.
2. Déroulé du constructeur 0x197a2ac autour des 4 formations de 0x12c718c
   ([s1+0x1a8]) : la classe du module (slots voisins remplis).
3. Census des stores sd x, 0x3af0(y) et sd x, 0x50(y) DANS les fonctions
   méga-constructeurs 0x19xxxxx (création holder/objet).

Sortie : stdout + scratch-gsp/v50/v50_micro.json
"""
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v50")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def func_start(idx):
    for i in range(idx, max(-1, idx - 4000), -1):
        m, o = rows[i][2], rows[i][3]
        p = parse(o)
        if (m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
                and p[1] == "sp" and p[2].startswith("-")) or \
           (m == "c.addi16sp" and p and p[-1].startswith("-")):
            return i
    return None


def dump(i0, i1, title):
    print(f"--- {title} ---")
    for j in range(max(0, i0), min(n, i1 + 1)):
        a, s, m, o = rows[j]
        print(f"  {a:#08x}  {m:10} {o}")
    print()


WINDOWS = {"wrapper": (0x12B5C80, 0x12B5D50), "pré-wrapper": (0x12C7A10, 0x12C7A80)}
micro = {k: [] for k in WINDOWS}
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("auipc", "lui", "c.lui"):
        continue
    p = parse(o)
    if len(p) != 2:
        continue
    reg, hi = p[0], p[1]
    try:
        hi_v = int(hi, 0)
    except ValueError:
        continue
    base = (a + (hi_v << 12)) & 0xFFFFFFFF if m == "auipc" else (hi_v << 12) & 0xFFFFFFFF
    for j in range(i + 1, min(i + 7, n)):
        m2, o2 = rows[j][2], rows[j][3]
        p2 = parse(o2)
        if m2 in ("addi", "addiw", "c.addi") and len(p2) == 3 and \
                p2[0] == reg and p2[1] == reg:
            try:
                lo = int(p2[2], 0)
            except ValueError:
                break
            va = (base + lo) & 0xFFFFFFFF
            for name, (lo_w, hi_w) in WINDOWS.items():
                if lo_w <= va <= hi_w:
                    micro[name].append((va, i, j))
            break
        if m2 in ("mv", "c.mv", "sd", "c.sd") and p2 and reg in p2[1:]:
            break

for name, lst in micro.items():
    lo_w, hi_w = WINDOWS[name]
    print(f"=== micro-fenêtre {name} [{lo_w:#08x},{hi_w:#08x}] : {len(lst)} formation(s) ===")
    for va, i, j in lst:
        fsi = func_start(i)
        own = rows[fsi][0] if fsi is not None else None
        print(f"  VA {va:#08x} formée @ {rows[i][0]:#08x} | fonction {own:#08x}"
              if own else f"  VA {va:#08x} formée @ {rows[i][0]:#08x} | fonction ?")

# ---- 2. constructeur de classe 0x197a2ac autour de 0x12c718c
print()
print("=== constructeur 0x197a2ac : la classe qui porte 0x12c718c ===")
for site in (0x197C05C, 0x197C720, 0x197CC18, 0x197D19E, 0x197DFCE):
    i = next(idx for idx, r in enumerate(rows) if r[0] == site)
    dump(i - 22, i + 6, f"formation VA {site:#08x}")

# ---- 3. stores 0x3af0 / 0x50 dans 0x19xxxxx
print("=== stores sd x, 0x3af0(y) dans les méga-constructeurs ===")
n_store = 0
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("sd", "c.sd"):
        continue
    p = parse(o)
    if len(p) != 2 or "0x3af0(" not in p[1]:
        continue
    fsi = func_start(i)
    own = rows[fsi][0] if fsi is not None else None
    if own and 0x1900000 <= own < 0x1A00000:
        print(f"  {a:#08x}  sd {o}   fonction {own:#08x}")
        n_store += 1
print(f"total : {n_store}")

json.dump({"micro": {k: [{"va": hex(v), "at": hex(rows[i][0])} for v, i, _ in v2]
                     for k, v2 in micro.items()}},
          (OUT / "v50_micro.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_micro.json'}")
