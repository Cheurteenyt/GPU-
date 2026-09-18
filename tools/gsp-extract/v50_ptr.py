#!/usr/bin/env python3
"""v50-ptr — vague 4.10 : les enregistreurs runtime des fonctions de la chaîne.

Zéro pointeur statique dans le fichier → les vtables se construisent au
runtime. Patron : auipc rx, hi ; addi rx, rx, lo  (rx = VA cible) puis
sd rx, off(ry)  (stockage dans la structure/vtable).

1. Census des paires auipc+addi résolvant vers 0x12c7a1e / 0x12b5c88 /
   0x1bd979c (fenêtre ≤ 6 insns, autres insns intercalées tolérées).
2. Contexte ±14 insns de chaque enregistreur : offset du store, structure
   de destination, fonction porteuse.

Sortie : stdout + scratch-gsp/v50/v50_ptr.json
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v50")

TARGETS = {0x12C7A1E: "pré-wrapper", 0x12B5C88: "wrapper", 0x1BD979C: "consommateur"}

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def sign32(v):
    return v - 0x100000000 if v >= 0x80000000 else v


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


# index des paires auipc(+addi suivante immédiate ou ≤ 6 insns)
reg_addr = {}  # (reg, base_va) -> index auipc  ; formé par auipc puis addi reg,reg,lo
pairs = []  # (idx_auipc, reg, va)
for i, (a, s, m, o) in enumerate(rows):
    if m != "auipc":
        continue
    p = parse(o)
    if len(p) != 2:
        continue
    reg, hi = p[0], p[1]
    try:
        hi_v = int(hi, 0) << 12
    except ValueError:
        continue
    base = (a + hi_v) & 0xFFFFFFFF
    for j in range(i + 1, min(i + 7, n)):
        m2, o2 = rows[j][2], rows[j][3]
        p2 = parse(o2)
        if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == reg and p2[1] == reg:
            try:
                lo = int(p2[2], 0)
            except ValueError:
                break
            va = (base + lo) & 0xFFFFFFFF
            pairs.append((i, reg, va, j))
            break
        if m2 in ("mv", "c.mv", "sd", "c.sd") and p2 and reg in p2[1:]:
            break

print(f"paires auipc+addi formant une VA : {len(pairs)}")
by_target = {name: [] for name in TARGETS.values()}
for i, reg, va, j in pairs:
    for t, name in TARGETS.items():
        if va == t:
            by_target[name].append((i, j, reg))
            break

recs = []
for name, lst in by_target.items():
    print(f"\n=== formation d'adresse vers {name} : {len(lst)} ===")
    for i, j, reg in lst:
        a = rows[i][0]
        fsi = func_start(i)
        own = rows[fsi][0] if fsi is not None else None
        print(f"  auipc {a:#08x} ({reg}) + addi {rows[j][0]:#08x} → VA cible"
              f"  | fonction porteuse {own:#08x}" if own else
              f"  auipc {a:#08x} ({reg}) | fonction porteuse ?")
        dump(j, min(j + 12, n), f"suivi du store (site {a:#08x})")
        recs.append({"target": name, "auipc": hex(a), "addi": hex(rows[j][0]),
                     "reg": reg, "func": hex(own) if own else None})

json.dump({"formations": recs}, (OUT / "v50_ptr.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_ptr.json'}")
