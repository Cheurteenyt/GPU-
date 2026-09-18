#!/usr/bin/env python3
"""v50-slot28 — vague 4.10 : la famille du lecteur et son implémentation.

Le consommateur/wrapper appellent [vtbl+0x28](obj, 0x68Axxx+off) → mot.
1. Census GLOBAL des appels via ce slot : ld x, 0x28(y) puis jalr (≤4 insns).
   Chaque site : fonction porteuse + origine de l'objet (a0).
2. Patron de l'implémentation lecteur : fonctions courtes qui font
   base = [obj+X] ; addr = base + a1 ; val = lwu/ldu [addr] ; ret.
   Scan du triad ld/add/lwu dans les fenêtres de 8 insns.
3. Croisement : quels slots de vtable les sites d'appel utilisent
   (+0x28 exclusif ? ou famille +0x20/+0x28/+0x30...).

Sortie : stdout + scratch-gsp/v50/v50_slot28.json
"""
import bisect
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


# ---- 1. census appels via ld x, 0x28(y) ; jalr
sites = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m in ("c.ld", "ld") and len(p) == 2 and p[1].startswith("0x28("):
        reg = p[0]
        for j in range(i + 1, min(i + 5, n)):
            m2, o2 = rows[j][2], rows[j][3]
            p2 = parse(o2)
            if m2 in ("c.jalr", "jalr") and p2 and p2[0] == reg:
                sites.append((i, a, j, reg))
                break
            if m2 in ("mv", "c.mv") and p2 and p2[0] == reg:
                break

print(f"appels via slot +0x28 (ld puis jalr) : {len(sites)}")
per_func = {}
for i, a, j, reg in sites:
    fsi = func_start(i)
    own = rows[fsi][0] if fsi is not None else None
    per_func.setdefault(own, []).append(a)
print("répartition par fonction porteuse :")
for own, lst in sorted(per_func.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
    name = f"{own:#08x}" if own else "?"
    print(f"  {name}: {len(lst)} site(s)  {[hex(x) for x in lst[:6]]}")

# ---- 2. patron lecteur : ld x, off(y) ; add x, x, a1 ; lwu/ldu/lw a0, 0(x)
readers = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m != "ld" or len(p) != 2:
        continue
    reg, src = p[0], p[1]
    if not src.endswith(")"):
        continue
    base = src[:src.rindex("(")]
    if base not in ("a0", "0(a0)", "s1", "s2", "s3", "s4"):
        continue
    for j in range(i + 1, min(i + 4, n)):
        m2, o2 = rows[j][2], rows[j][3]
        p2 = parse(o2)
        if m2 in ("add", "addw") and len(p2) == 3 and p2[0] == reg and \
                p2[1] == reg and p2[2] == "a1":
            for k in range(j + 1, min(j + 4, n)):
                m3, o3 = rows[k][2], rows[k][3]
                p3 = parse(o3)
                if m3 in ("lwu", "ldu", "lw", "c.lw", "ld") and len(p3) == 2 and \
                        p3[0] == "a0" and p3[1] in (f"0({reg})", f"0x0({reg})"):
                    fsi = func_start(i)
                    own = rows[fsi][0] if fsi is not None else None
                    readers.append((a, own, rows[k][0]))
                    break
            break

print(f"\nlecteurs candidats (ld base; add base,a1; lwu a0) : {len(readers)}")
uniq_r = {}
for a, own, at in readers:
    uniq_r.setdefault(own, []).append(a)
for own, lst in sorted(uniq_r.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
    name = f"{own:#08x}" if own else "?"
    print(f"  fonction {name}: {[hex(x) for x in lst]}")

json.dump({"slot28_calls": {hex(k if k else 0): [hex(x) for x in v]
                            for k, v in per_func.items()},
           "reader_candidates": {hex(k if k else 0): [hex(x) for x in v]
                                 for k, v in uniq_r.items()}},
          (OUT / "v50_slot28.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_slot28.json'}")
