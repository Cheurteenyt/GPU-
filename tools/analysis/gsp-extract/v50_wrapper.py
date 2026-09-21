#!/usr/bin/env python3
"""v50-wrapper — vague 4.10, chantier 1 : la remontée du domaine.

1. Déroulé complet du wrapper 0x12b5c88 (prologue → épilogue).
2. Census de ses appelants (auipc+jalr résolus + call/jal/tail).
3. Pour chaque appelant : fonction porteuse + fenêtre -60 insns
   avec suivi naïf de registres (origine de a0/a1/a2/a3).

Sortie : stdout + scratch-gsp/v50/v50_wrapper.json
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v50")
WRAP = 0x12B5C88

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]


def parse(o):
    return [x.strip() for x in o.split(",")]


def func_start(idx):
    """Marche arrière jusqu'au prologue (addi sp,sp,-N ou c.addi16sp)."""
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


# ---- 1. déroulé du wrapper
di = bisect.bisect_left(addrs, WRAP)
fs = func_start(di)
assert fs is not None, "prologue du wrapper introuvable"
# épilogue : premier ret au niveau ~ (heuristique : premiers `ret` après
# des stores de restauration) — on dump toute la fonction suivante bornée
fe = fs
for j in range(fs, min(fs + 600, n)):
    if rows[j][2] in ("ret", "c.ret"):
        fe = j
print(f"=== wrapper {WRAP:#08x} : fonction {rows[fs][0]:#08x} .. {rows[fe][0]:#08x}"
      f" ({fe - fs + 1} insns) ===")
dump(fs, fe, "corps du wrapper")

# ---- 2. census appelants
callers = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m == "auipc" and len(p) == 2 and p[0] == "ra":
        try:
            hi = int(p[1], 0)
        except ValueError:
            continue
        for j in (i + 1, i + 2):
            if j >= n:
                break
            m2, o2 = rows[j][2], rows[j][3]
            p2 = parse(o2)
            if m2 == "jalr" and len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                try:
                    lo = int(p2[2], 0)
                except ValueError:
                    break
                base = a + (hi << 12)
                if base >= 0x80000000:
                    base -= 0x100000000
                if (base + lo) == WRAP:
                    callers.append((i, a))
                break
            if m2 in ("mv", "c.mv") and p2 and p2[0] == "ra":
                break
    elif m in ("call", "tail", "jal") and p:
        try:
            t = int(p[-1], 0)
        except ValueError:
            continue
        if m == "jal" and -0x100000 < t < 0x100000:
            t = a + t
        if t == WRAP:
            callers.append((i, a))

print(f"=== appelants du wrapper : {len(callers)} ===")
for i, a in callers:
    fsx = func_start(i)
    own = rows[fsx][0] if fsx is not None else None
    print(f"  site {a:#08x}  (fonction porteuse {own:#08x})" if own
          else f"  site {a:#08x}  (fonction porteuse ?)")

# ---- 3. contexte par appelant
KIND_LI = {"li", "c.li"}
KIND_ADDI = {"addi", "c.addi"}
KIND_MV = {"mv", "c.mv"}
WIN = 60
out = []
for i, a in callers:
    regs = {}
    found = {}
    for j in range(i - 1, max(-1, i - 1 - WIN), -1):
        mm, oo = rows[j][2], rows[j][3]
        p = parse(oo)
        if mm in KIND_LI and len(p) == 2:
            d = p[0]
            if d not in found:
                try:
                    regs[d] = int(p[1], 0)
                except ValueError:
                    regs[d] = None
        elif mm in KIND_ADDI and len(p) == 3:
            d, src = p[0], p[1]
            if d not in found:
                try:
                    imm = int(p[2], 0)
                except ValueError:
                    regs[d] = None
                    continue
                if src in ("zero", "x0"):
                    regs[d] = imm
                elif src == d and regs.get(d) is not None:
                    regs[d] = (regs[d] + imm) & 0xFFFFFFFFFFFFFFFF
                else:
                    regs[d] = None
        elif mm in KIND_MV and len(p) == 2:
            d, src = p[0], p[1]
            if d not in found:
                regs[d] = regs.get(src)
        for r in ("a0", "a1", "a2", "a3"):
            if r not in found and r in regs:
                found[r] = (regs[r], i - j)
        if len(found) == 4:
            break
    fsx = func_start(i)
    rec = {
        "site": hex(a),
        "func": hex(rows[fsx][0]) if fsx is not None else None,
        "args": {k: (hex(v[0]) if isinstance(v[0], int) else v[0], v[1])
                 for k, v in found.items()},
    }
    out.append(rec)
    print(f"\n--- contexte site {a:#08x} (fonction {rec['func']}) ---")
    dump(max(fs, i - WIN) if fsx is None else max(fsx, i - 24), i + 2,
         "source des arguments")

json.dump({"wrapper": hex(WRAP),
           "callers": out}, (OUT / "v50_wrapper.json").open("w"),
          indent=1, default=str)
print(f"-> {OUT / 'v50_wrapper.json'}")
