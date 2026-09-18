#!/usr/bin/env python3
"""v50-holder2 — census BRUT de tous les accès au champ holder +0x3AF0.

Simplification : tout ld/sd/lw/sw dont l'offset est -0x510 ou +0x3af0
(le motif d'adressage lui-4/+(-0x510) n'est pas imposé — on filtre après).

Pour chaque site : fonction porteuse, instruction, marqueur « lui 4 dans
les 6 insns précédentes » (adresse = base + 0x4000 → champ +0x3AF0).

Sortie : stdout + scratch-gsp/v50/v50_holder2.json
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


LOADS = {"ld", "c.ld", "lw", "c.lw", "lwu", "ldu"}
STORES = {"sd", "c.sd", "sw", "c.sw"}

hits = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in LOADS | STORES:
        continue
    p = parse(o)
    if len(p) != 2 or "(" not in p[1]:
        continue
    off = p[1][:p[1].rindex("(")]
    try:
        offv = int(off, 0)
    except ValueError:
        continue
    if offv in (-0x510, 0x3AF0):
        fsi = func_start(i)
        own = rows[fsi][0] if fsi is not None else None
        # lui 4 dans les 6 insns précédentes ?
        pre4 = False
        for j in range(max(0, i - 6), i):
            if rows[j][2] in ("c.lui", "lui") and \
                    rows[j][3].split(",")[-1].strip() in ("4", "0x4"):
                pre4 = True
                break
        hits.append((a, m, o, own, pre4))

print(f"accès au champ -0x510/+0x3AF0 : {len(hits)}")
for a, m, o, own, pre4 in hits:
    name = f"{own:#08x}" if own else "?"
    tag = " [lui4]" if pre4 else ""
    print(f"  {a:#08x}  {m:6} {o:24} fonction {name}{tag}")

json.dump({"hits": [{"addr": hex(a), "insn": f"{m} {o}",
                     "func": hex(own) if own else None, "lui4": pre4}
                    for a, m, o, own, pre4 in hits]},
          (OUT / "v50_holder2.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_holder2.json'}")
