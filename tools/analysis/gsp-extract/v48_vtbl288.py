#!/usr/bin/env python3
"""v48-vtbl288 — vague 4.8, chantier 1 quater : stores à [x+0x288] dont la
VALEUR vient d'un `ld` depuis une adresse auipc-résolue (slot de vtable).

La 4.7 n'avait résolu que les valeurs CONSTANTES (auipc+addi). Ici : valeur =
ld Y, off(base2) avec base2 = auipc-résolu → l'ADRESSE DE SLOT est nommée,
même si le contenu rodata reste chiffré. Filtre : base du store ≠ sp.
Sortie : stdout + v48_vtbl288.json.
"""
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v48")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
idx = {r[0]: i for i, r in enumerate(rows)}
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def resolve_auipc(i, reg, off_add=0):
    """Base auipc pour reg à l'index i (recherche en arrière ≤6), + off_add."""
    for k in range(i - 1, max(0, i - 6) - 1, -1):
        ka, ks, km, ko = rows[k]
        kp = parse(ko)
        if km == "auipc" and len(kp) == 2 and kp[0] == reg:
            base = ka + (int(kp[1], 0) << 12)
            if base >= 0x80000000:
                base -= 0x100000000
            return base + off_add
        # addi au milieu : base = auipc-base + addi
        if km == "addi" and len(kp) == 3 and kp[0] == reg and is_reg(kp[1]):
            sub = resolve_auipc(k, kp[1], int(kp[2], 0))
            if sub is not None:
                return sub
    return None


def is_reg(x):
    return not (x.startswith("0x") or x.startswith("-") or x[:1].isdigit())


hits = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("sd", "sw"):
        continue
    p = parse(o)
    if len(p) != 2 or not p[1].endswith("0x288("):
        continue
    b = p[1].split("(")[1].rstrip(")")
    if b == "sp":
        continue  # spill de pile
    valreg = p[0]
    # en arrière : valreg ← ld valreg, off(base2)
    for j in range(i - 1, max(0, i - 8) - 1, -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm == "ld" and len(pp) == 2 and pp[0] == valreg and "(" in pp[1]:
            b2 = pp[1].split("(")[1].rstrip(")")
            off2 = pp[1].split("(")[0]
            if b2 == "sp":
                break
            slot = resolve_auipc(j, b2, int(off2, 0) if off2 else 0)
            if slot is not None:
                hits.append({"store": hex(a), "ld_site": hex(aa),
                             "slot": hex(slot), "insn": f"ld {oo}"})
            break
        if mm in ("auipc", "lui") and pp and pp[0] == valreg:
            break  # valeur constante, déjà couvert par v47
        if mm in ("mv", "c.mv", "addi") and pp and pp[0] == valreg:
            valreg = pp[1] if len(pp) >= 2 else valreg
            continue

print(f"=== stores 0x288 (hors sp) alimentés par ld de slot auipc-résolu : {len(hits)} ===")
from collections import Counter
cnt = Counter(h["slot"] for h in hits)
for slot, c in cnt.most_common():
    sites = [h["store"] for h in hits if h["slot"] == slot]
    print(f"  slot {slot} ×{c} : stores {sites}")
(OUT / "v48_vtbl288.json").open("w").write(json.dumps(hits, indent=1))
print("\nv48-vtbl288 terminé.")
