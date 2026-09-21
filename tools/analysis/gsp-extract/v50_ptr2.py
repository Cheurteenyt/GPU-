#!/usr/bin/env python3
"""v50-ptr2 — vague 4.10 : patron LUI+addi/addiw (formation non-PC-relative).

Les trois fonctions de la chaîne n'ont NI appelant direct, NI formation
auipc+addi, NI pointeur statique. Dernier patron de formation : lui rx, hi
puis addi/addiw rx, rx, lo (≤ 6 insns d'écart).

1. Census des paires lui+addi résolvant vers les 3 cibles.
2. Contexte de chaque site (fonction porteuse, store de destination).

Sortie : stdout + scratch-gsp/v50/v50_ptr2.json
"""
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


found = {name: [] for name in TARGETS.values()}
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("lui", "c.lui"):
        continue
    p = parse(o)
    if len(p) != 2:
        continue
    reg, hi = p[0], p[1]
    try:
        hi_v = int(hi, 0)
    except ValueError:
        continue
    base = (hi_v << 12) & 0xFFFFFFFF
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
            for t, name in TARGETS.items():
                if va == t:
                    found[name].append((i, j, reg))
                    break
            break
        if m2 in ("mv", "c.mv", "sd", "c.sd") and p2 and reg in p2[1:]:
            break

recs = []
for name, lst in found.items():
    print(f"=== formation lui+addi vers {name} : {len(lst)} ===")
    for i, j, reg in lst:
        a = rows[i][0]
        fsi = func_start(i)
        own = rows[fsi][0] if fsi is not None else None
        print(f"  lui {a:#08x} ({reg}) + addi {rows[j][0]:#08x} → {TARGETS and ''}{name}"
              f" | fonction porteuse {own:#08x}" if own else
              f"  lui {a:#08x} ({reg}) | fonction porteuse ?")
        dump(max(0, j - 6), min(j + 14, n),
             f"contexte formation {name} @ {a:#08x}")
        recs.append({"target": name, "lui": hex(a), "addi": hex(rows[j][0]),
                     "reg": reg, "func": hex(own) if own else None})

json.dump({"formations": recs}, (OUT / "v50_ptr2.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_ptr2.json'}")
