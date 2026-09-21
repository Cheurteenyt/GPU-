#!/usr/bin/env python3
"""v47-registr — trouve les ENREGISTREURS des callbacks de l'état RM.

Méthode : tous les sd <reg>, 0x460(<base>) / 0x288(<base>) / 0x1a8(<base>)
où <reg> provient d'un couple auipc+addi (fonction liée, cible résolue par
script). Croisement : la fonction qui enregistre 0x169455c à +0x460 est-elle
aussi celle qui écrit +0x288 ?
Sortie : v47_registr.json + résumé.
"""
import json
import re
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v47")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def linked_value(i, back=10):
    """Si rows[i] est un sd reg, off(base) avec reg = auipc+addi récent,
    retourne (cible, auipc_addr). Sinon None."""
    a, s, m, o = rows[i]
    if m != "sd":
        return None
    p = parse(o)
    if len(p) != 2:
        return None
    reg = p[0]
    for j in range(i - 1, max(0, i - back) - 1, -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm == "addi" and len(pp) == 3 and pp[0] == reg:
            src = pp[1]
            for k in range(j - 1, max(0, j - 3) - 1, -1):
                ka, ks, km, ko = rows[k]
                kp = parse(ko)
                if km == "auipc" and len(kp) == 2 and kp[0] == src:
                    try:
                        hi12 = int(kp[1], 0) << 12
                        lo12 = int(pp[2], 0)
                    except ValueError:
                        return None
                    base = ka + hi12
                    if base >= 0x80000000:
                        base -= 0x100000000
                    return (base + lo12, ka)
            return None
        if mm == "auipc" and len(pp) == 2 and pp[0] == reg:
            return None
    return None


OFFS = {"0x460": 0x460, "0x288": 0x288, "0x1a8": 0x1A8}
found = {k: [] for k in OFFS}
for i, (a, s, m, o) in enumerate(rows):
    if m != "sd":
        continue
    for key, off in OFFS.items():
        if re.search(rf",\s*{key}\(", o):
            lv = linked_value(i)
            if lv:
                found[key].append({"site": hex(a), "fn": hex(lv[0]), "auipc": hex(lv[1])})
            break

for key, lst in found.items():
    print(f"\n=== enregistrements sd …,{key}(...) liés : {len(lst)} ===")
    from collections import Counter
    cnt = Counter(x["fn"] for x in lst)
    for fn, c in cnt.most_common(12):
        print(f"    cible {fn} ×{c}")

# croisement : fonctions qui écrivent à la fois +0x460 et +0x288
f460 = {x["fn"] for x in found["0x460"]}
f288 = {x["fn"] for x in found["0x288"]}
both = sorted(f460 & f288)
print(f"\n=== fonctions écrivant +0x460 ET +0x288 : {len(both)} ===")
for f in both:
    sites460 = [x["site"] for x in found["0x460"] if x["fn"] == f]
    sites288 = [x["site"] for x in found["0x288"] if x["fn"] == f]
    print(f"    fn? {f} : +0x460 @ {sites460}  +0x288 @ {sites288}")

# qui enregistre 0x169455c ?
print("\n=== enregistreurs de 0x169455c (callback petit parseur) ===")
for x in found["0x460"]:
    if x["fn"] == "0x169455c":
        print(f"    site {x['site']}  (auipc {x['auipc']})")

json.dump(found, (OUT / "v47_registr.json").open("w"), indent=1)
print("-> v47_registr.json")
