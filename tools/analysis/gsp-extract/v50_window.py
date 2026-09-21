#!/usr/bin/env python3
"""v50-window — vague 4.10 : cartographie du module 0x12b5xxx-0x12c7xxx.

0x12c7a1e n'a aucune référence par les quatre patrons classiques. Stratégie
inverse : quels DÉBUTS DE FONCTION du voisinage sont référencés par des
formations d'adresse (auipc+addi / lui+addi) ? Les hits reconstruisent les
vtables runtime du module.

1. Prologues de fonctions dans [0x12b4000, 0x12c9000].
2. Toutes les formations d'adresse du firmware (154 567 paires) dont la VA
   tombe sur un début de fonction de cette fenêtre.
3. Contexte de chaque formation : fonction porteuse + store destination.
4. Regroupement par (fonction porteuse, registre de base du store) :
   reconstruction des vtables.

Sortie : stdout + scratch-gsp/v50/v50_window.json
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v50")
WIN_LO, WIN_HI = 0x12B4000, 0x12C9000

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


# ---- 1. fonctions de la fenêtre
di0 = bisect.bisect_left([r[0] for r in rows], WIN_LO)
funcs = []
i = di0
while i < n and rows[i][0] < WIN_HI:
    fsi = func_start(i)
    if fsi is not None and rows[fsi][0] == rows[i][0]:
        pass
    # heuristique : un prologue dans la fenêtre marque un début de fonction
    m, o = rows[i][2], rows[i][3]
    p = parse(o)
    is_pro = ((m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
               and p[1] == "sp" and p[2].startswith("-"))
              or (m == "c.addi16sp" and p and p[-1].startswith("-")))
    if is_pro:
        funcs.append(rows[i][0])
    i += 1
func_set = set(funcs)
print(f"fonctions (prologues) dans la fenêtre : {len(funcs)}")

# ---- 2. formations d'adresse globales → filtrées sur la fenêtre
hits = []  # (va_cible, idx_auipc/lui, idx_addi, reg)
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
    if m == "auipc":
        base = (a + (hi_v << 12)) & 0xFFFFFFFF
    else:
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
            if WIN_LO <= va < WIN_HI and va in func_set:
                hits.append((va, i, j, reg))
            break
        if m2 in ("mv", "c.mv", "sd", "c.sd") and p2 and reg in p2[1:]:
            break

print(f"formations d'adresse vers un début de fonction de la fenêtre : {len(hits)}")

# ---- 3-4. contexte + regroupement
def dump(i0, i1, title):
    print(f"--- {title} ---")
    for j in range(max(0, i0), min(n, i1 + 1)):
        a, s, m, o = rows[j]
        print(f"  {a:#08x}  {m:10} {o}")
    print()


groups = {}
for va, i, j, reg in hits:
    fsi = func_start(i)
    own = rows[fsi][0] if fsi is not None else None
    # store qui suit l'addi : sd reg, off(base) dans les 4 insns suivantes
    store = None
    for k in range(j + 1, min(j + 5, n)):
        m2, o2 = rows[k][2], rows[j][3] if False else rows[k][3]
        p2 = parse(o2)
        if m2 in ("sd", "c.sd", "sw", "c.sw") and len(p2) == 2 and p2[0] == reg:
            store = (rows[k][0], p2[1])
            break
    groups.setdefault(own, []).append((va, rows[i][0], store, reg))

for own, lst in sorted(groups.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
    name = f"{own:#08x}" if own else "? (hors prologue)"
    print(f"\n=== fonction porteuse {name} : {len(lst)} formation(s) ===")
    for va, site, store, reg in lst:
        st = f" → store @{store[0]:#08x} [{store[1]}]" if store else ""
        print(f"  VA {va:#08x}  formée @ {site:#08x} ({reg}){st}")

json.dump({"functions_in_window": len(funcs),
           "hits": [{"va": hex(va), "formed_at": hex(site),
                     "func": hex(own) if own else None,
                     "store": (hex(store[0]), store[1]) if store else None}
                    for own, lst in groups.items() for va, site, store, _ in lst]},
          (OUT / "v50_window.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_window.json'}")
