#!/usr/bin/env python3
"""v47-explore2 — corrige les sondes B et C de v47_explore (formats piégeux :
offsets HEXADÉCIMAUX dans les operands, appels lointains = auipc+jalr).

B' : accès [reg+0x288] (callback PerfPmaControlReg) — offsets hex.
C' : census auipc+jalr vers la passe P-states 0x1b3c4f4, vers le dispatcher
     moteur 0x1634a38, et vers l'entrée de boucle P-states 0x1631880.
"""
import re
import sys
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v47")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
print(f"TSV chargé : {n} instructions", file=sys.stderr)


def scan_mem_hex(off):
    pat = re.compile(rf",\s*{off:#x}\(")
    return [(a, m, o) for a, s, m, o in rows if pat.search(o)]


def resolve_callers(target):
    """Paires auipc ra, hi / jalr ra, ra, lo → cible == target."""
    sites = []
    for i, (a, s, m, o) in enumerate(rows):
        if m != "auipc":
            continue
        p = [x.strip() for x in o.split(",")]
        if len(p) != 2 or p[0] != "ra":
            continue
        try:
            hi = int(p[1], 0) << 12
        except ValueError:
            continue
        for j in (i + 1, i + 2):
            if j >= n:
                break
            a2, s2, m2, o2 = rows[j]
            if m2 == "jalr":
                p2 = [x.strip() for x in o2.split(",")]
                if len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                    try:
                        lo = int(p2[2], 0)
                    except ValueError:
                        break
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    if base + lo == target:
                        sites.append((i, a))
                    break
            if m2 in ("mv", "c.mv") and [x.strip() for x in o2.split(",")] and [x.strip() for x in o2.split(",")][0] == "ra":
                break
    return sites


# ---------------------------------------------------------------- B' : +0x288
hits = scan_mem_hex(0x288)
stores = [(a, m, o) for a, m, o in hits if m.startswith("s")]
loads = [(a, m, o) for a, m, o in hits if m.startswith("l")]
print(f"[B'] accès [reg+0x288] : {len(hits)} (stores {len(stores)}, loads {len(loads)})")
lines = ["STORES:"] + [f"  {a:#08x}  {m:8} {o}" for a, m, o in stores] + \
        ["LOADS:"] + [f"  {a:#08x}  {m:8} {o}" for a, m, o in loads]
(OUT / "v47_B_288.txt").write_text("\n".join(lines) + "\n")
for a, m, o in stores[:30]:
    print(f"    S {a:#08x}  {m} {o}")
for a, m, o in loads[:20]:
    print(f"    L {a:#08x}  {m} {o}")

# ---------------------------------------------------------------- C' : appelants
for tgt, name in ((0x1B3C4F4, "passe P-states"),
                  (0x1634A38, "dispatcher moteur"),
                  (0x1631880, "entrée boucle P-states (hyp.)")):
    sites = resolve_callers(tgt)
    print(f"[C'] {name} {tgt:#x} : {len(sites)} appelant(s) auipc+jalr")
    for i, a in sites:
        print(f"    {a:#08x} (auipc)")
    (OUT / f"v47_C_callers_{tgt:x}.txt").write_text(
        "\n".join(f"  {a:#08x}" for i, a in sites) + "\n")
print("v47-explore2 terminé.")
