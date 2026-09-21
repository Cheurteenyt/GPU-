#!/usr/bin/env python3
"""v45-callers — census des appelants du setter requestCapabilityChange
(0x1630c48, établi vague 4.4), bit d'entrée par bit.

Pour chaque `jal ra, 0x1630c48` : marche arrière ≤ 80 instructions avec
suivi de registres concrets (li/c.li/addi/c.addi/mv/c.mv, base x0) pour
résoudre a0 (obj), a1 (state), a2 (bit_index), a3 (direction) au moment
de l'appel. Les jalr indirects sont comptés à part (non résolus).

Sortie : scratch-gsp/v45/setter_callers.json
  {census: {bit: n_sites}, sites: [{site, dist, a0, a1, a2, a3, jalr_reg}]}
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
SETTER = 0x1630C48
WIN = 80

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))

print(f"chargé {len(rows)} instructions")

adr2idx = {r[0]: i for i, r in enumerate(rows)}

CALL = ("jal", "c.jal")
sites_jal = defaultdict(list)   # target -> [idx]
jalr_sites = []
for i, (a, s, m, o) in enumerate(rows):
    if m in CALL:
        parts = [p.strip() for p in o.split(",", 1)]
        if len(parts) == 2 and parts[1].startswith("0x"):
            try:
                tgt = int(parts[1], 16)
            except ValueError:
                continue
            sites_jal[tgt].append(i)
    elif m in ("jalr", "c.jalr", "jr", "c.jr"):
        jalr_sites.append(i)

print(f"jal vers {len(sites_jal)} cibles distincts ; cibles jalr/jr indirectes: {len(jalr_sites)}")

KIND_LI = {"li", "c.li"}
KIND_ADDI = {"addi", "c.addi"}
KIND_MV = {"mv", "c.mv"}


def reg_val(dest, mnem, ops, regs):
    """applique l'écriture d'un registre au dictionnaire regs ; renvoie True si écriture."""
    p = [x.strip() for x in ops.split(",")]
    if not p or p[0] != dest:
        return False
    if mnem in KIND_LI and len(p) == 2:
        try:
            regs[dest] = int(p[1], 0)
        except ValueError:
            regs[dest] = None
        return True
    if mnem in KIND_ADDI and len(p) == 3:
        src = p[1]
        try:
            imm = int(p[2], 0)
        except ValueError:
            return True
        if src in ("zero", "x0", "w0"):
            regs[dest] = imm
        elif src == dest and regs.get(dest) is not None:
            regs[dest] = regs[dest] + imm
        else:
            regs[dest] = None
        return True
    if mnem in KIND_MV and len(p) == 2:
        src = p[1]
        regs[dest] = regs.get(src) if src != dest else regs.get(dest)
        return True
    return False


sites = []
census = Counter()
for i in sites_jal.get(SETTER, []):
    regs = {}
    found = {}
    lo = max(0, i - WIN)
    for j in range(i - 1, lo - 1, -1):
        a, s, m, o = rows[j]
        # marche arrière : on résout les 4 registres d'arguments
        for r in ("a0", "a1", "a2", "a3"):
            if r not in found and reg_val(r, m, o, regs):
                pass  # reg_val écrit regs[r] ; on fige la valeur à la 1re écriture EN REMONTANT
        for r in ("a0", "a1", "a2", "a3"):
            if r not in found and r in regs:
                found[r] = (regs[r], i - j)
        if len(found) == 4:
            break
    bit = found.get("a2", (None, None))[0]
    census[bit] += 1
    sites.append({
        "site": hex(rows[i][0]),
        "dist": {k: v[1] for k, v in found.items()},
        "a0": found.get("a0", (None, None))[0],
        "a1": found.get("a1", (None, None))[0],
        "a2": bit,
        "a3": found.get("a3", (None, None))[0],
    })

print("\n=== CENSUS bit_index (a2) des appelants du setter ===")
for bit, n in sorted(census.items(), key=lambda kv: (kv[0] is None, kv[0] if kv[0] is not None else -1)):
    print(f"  bit {bit}: {n} site(s)")

out = {"setter": hex(SETTER), "n_sites_jal": len(sites_jal.get(SETTER, [])),
       "n_jalr_indirect": len(jalr_sites), "census": {str(k): v for k, v in census.items()},
       "sites": sites}
(V45 / "setter_callers.json").write_text(json.dumps(out, indent=1))
print(f"\n-> {V45/'setter_callers.json'} ({len(sites)} sites)")
