#!/usr/bin/env python3
"""v48-ctor2 — vague 4.8, chantier 1 bis : slice arrière large pour les
écrivains de [state+0x88130] et des champs voisins de l'état RM.

Méthode : pour chaque store sd/sw V, 0x130(B) dans X-R, remontée par worklist
(≤ 40 insns) : lui R, 0x88 → HIT ; add/addi/mv/c.add/c.mv → substitution ;
ld/auipc/autre → abandon. Rapport des HIT avec fenêtre de contexte.
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v48")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def slice_lui88(store_i, base_reg):
    """Remonte la chaîne de définitions de base_reg ; True si lui X, 0x88."""
    regs = {base_reg}
    for j in range(store_i - 1, max(0, store_i - 40) - 1, -1):
        a, s, m, o = rows[j]
        p = parse(o)
        if not p:
            continue
        if m == "lui" and len(p) == 2 and p[0] in regs:
            return True if p[1] == "0x88" else False
        if m in ("add", "addi", "c.add", "c.addi", "mv", "c.mv") and p[0] in regs:
            if len(p) == 3:
                regs.discard(p[0])
                regs.add(p[1])
                if p[1] != p[0]:
                    regs.add(p[1])
                regs.add(p[1])
                # add rd, rs1, rs2 → sources rs1 rs2
                regs.discard(p[0])
                regs.add(p[1])
                if len(p) == 3:
                    regs.add(p[2] if p[2] != p[1] else p[1])
                # simplification : garder rs1 et rs2
                regs.update(x for x in p[1:3] if x not in ("sp", "zero"))
            if len(p) == 2:  # mv / c.add rd, rs
                regs.discard(p[0])
                regs.add(p[1])
            continue
        if m in ("ld", "lw", "lbu", "lhu", "auipc") and p[0] in regs:
            return False
    return False


hits = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("sd", "sw"):
        continue
    p = parse(o)
    if len(p) != 2 or not p[1].endswith("0x130("):
        continue
    b = p[1].split("(")[1].rstrip(")")
    if b in ("sp", "zero"):
        continue
    if slice_lui88(i, b):
        hits.append(a)

print(f"=== écrivains (slice large) de [state+0x88130] : {len(hits)} ===")
for h in hits:
    print(f"  {h:#08x}")
(OUT / "v48_88130_writers2.json").open("w").write(json.dumps(
    [hex(h) for h in hits], indent=1))

# fenêtre de contexte pour les 3 premiers
for st in hits[:3]:
    i = bisect.bisect_left(addrs, st)
    lo, hi = max(0, i - 50), min(n, i + 50)
    lines = []
    for j in range(lo, hi):
        aa, ss, mm, oo = rows[j]
        lines.append(f"  {aa:#08x}  {mm:10} {oo}")
    (OUT / f"v48_w88130_{st:x}.dump").write_text("\n".join(lines) + "\n")
    print(f"\n--- contexte {st:#x} → v48_w88130_{st:x}.dump ---")
    print("\n".join(lines[max(0, len(lines)//2 - 12):len(lines)//2 + 12]))

print("\nv48-ctor2 terminé.")
