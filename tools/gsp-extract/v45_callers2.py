#!/usr/bin/env python3
"""v45-callers2 — census COMPLET des appelants du setter 0x1630c48, y compris
les paires auipc+jalr (le 1er passage n'avait vu que jal direct -> 0 site).

Une paire d'appel = auipc ra, hi  puis (≤ 2 insns)  jalr ra, ra, lo
cible = va(auipc) + (hi<<12) + lo (hi signé 32b).
Pour chaque site : marche arrière 80 insns avec suivi de registres concrets
pour résoudre a0/a1/a2(bit)/a3(direction). Idem pour la cible secondaire
0x164a1c4 vue dans la même fonction (a2=1).

Sortie : scratch-gsp/v45/setter_callers2.json
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
TARGETS = {0x1630C48: "setter requestCapabilityChange", 0x164A1C4: "secondaire 0x164a1c4"}
WIN = 80

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
print(f"chargé {len(rows)} instructions")

def parse(o):
    return [x.strip() for x in o.split(",")]

KIND_LI = {"li", "c.li"}
KIND_ADDI = {"addi", "c.addi"}
KIND_MV = {"mv", "c.mv"}


def resolve_callers(target):
    sites = []
    census = Counter()
    n = len(rows)
    for i, (a, s, m, o) in enumerate(rows):
        if m != "auipc":
            continue
        p = parse(o)
        if len(p) != 2 or p[0] != "ra":
            continue
        try:
            hi = int(p[1], 0) << 12
        except ValueError:
            continue
        # jalr ra, ra, lo dans les 2 instructions suivantes
        for j in (i + 1, i + 2):
            if j >= n:
                break
            a2, s2, m2, o2 = rows[j]
            if m2 == "jalr":
                p2 = parse(o2)
                if len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                    try:
                        lo = int(p2[2], 0)
                    except ValueError:
                        break
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    tgt = base + lo
                    if tgt == target:
                        sites.append((i, a))
                    break
            if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == "ra":
                break

    out = []
    for i, a in sites:
        regs = {}
        found = {}
        lo_i = max(0, i - WIN)
        for j in range(i - 1, lo_i - 1, -1):
            aa, ss, mm, oo = rows[j]
            pp = parse(oo)
            if mm in KIND_LI and len(pp) == 2:
                d = pp[0]
                if d not in found:
                    try:
                        regs[d] = int(pp[1], 0)
                    except ValueError:
                        regs[d] = None
            elif mm in KIND_ADDI and len(pp) == 3:
                d, src = pp[0], pp[1]
                if d not in found:
                    try:
                        imm = int(pp[2], 0)
                    except ValueError:
                        regs[d] = None
                        continue
                    if src in ("zero", "x0", "w0"):
                        regs[d] = imm
                    elif src == d and regs.get(d) is not None:
                        regs[d] = regs[d] + imm
                    else:
                        regs[d] = None
            elif mm in KIND_MV and len(pp) == 2:
                d, src = pp[0], pp[1]
                if d not in found:
                    regs[d] = regs.get(src)
            for r in ("a0", "a1", "a2", "a3"):
                if r not in found and r in regs:
                    found[r] = (regs[r], i - j)
            if len(found) == 4:
                break
        bit = found.get("a2", (None, None))[0]
        census[bit] += 1
        out.append({
            "site": hex(a),
            "call_at": rows[i + 1][0] if i + 1 < len(rows) else None,
            "dist": {k: v[1] for k, v in found.items()},
            "a0": found.get("a0", (None, None))[0],
            "a1": found.get("a1", (None, None))[0],
            "a2": bit,
            "a3": found.get("a3", (None, None))[0],
        })
    return out, census


allout = {}
for tgt, name in TARGETS.items():
    sites, census = resolve_callers(tgt)
    print(f"\n=== {name} ({tgt:#x}) : {len(sites)} appelant(s) auipc+jalr ===")
    for bit, cnt in sorted(census.items(), key=lambda kv: (kv[0] is None, kv[0] if kv[0] is not None else -1)):
        print(f"  a2(bit) = {bit}: {cnt} site(s)")
    for st in sites:
        print(f"  site {st['site']}  bit={st['a2']} dir={st['a3']} a0={st['a0']} a1={st['a1']}")
    allout[hex(tgt)] = {"name": name, "sites": sites, "census": {str(k): v for k, v in census.items()}}

json.dump(allout, (V45 / "setter_callers2.json").open("w"), indent=1)
print(f"\n-> {V45/'setter_callers2.json'}")
