#!/usr/bin/env python3
"""v50-domain — vague 4.10, chantier 1 : remontée au-dessus du pré-wrapper.

1. Déroulé COMPLET du wrapper 0x12b5c88 (critère d'épilogue élargi :
   ret / c.ret / jr ra / c.jr ra — fenêtre 2000).
2. Déroulé complet du pré-wrapper 0x12c7a1e (l'unique appelant du wrapper).
3. Census des appelants du pré-wrapper + fonction porteuse de chaque site
   + suivi des arguments (a0..a3).
4. Remontée d'un niveau de plus : census des appelants de CHAQUE fonction
   porteuse trouvée en 3 (l'ordonnanceur de domaines).

Sortie : stdout + scratch-gsp/v50/v50_domain.json
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v50")
WRAP = 0x12B5C88
PRE = 0x12C7A1E

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]
EPILOGUE = {"ret", "c.ret", "jr", "c.jr", "tail", "c.tail"}


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


def func_end(fs, cap=2000):
    """Première sortie probable : ret/c.ret/jr ra après le prologue."""
    last = fs
    for j in range(fs + 1, min(fs + cap, n)):
        m, o = rows[j][2], rows[j][3]
        last = j
        if m in ("ret", "c.ret"):
            return j
        if m in ("jr", "c.jr") and parse(o) == ["ra"]:
            return j
    return last


def dump(i0, i1, title):
    print(f"--- {title} ---")
    for j in range(max(0, i0), min(n, i1 + 1)):
        a, s, m, o = rows[j]
        print(f"  {a:#08x}  {m:10} {o}")
    print()


def census(target):
    """Tous les sites d'appel directs (auipc+jalr, call/tail, jal)."""
    sites = []
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
                    if (base + lo) == target:
                        sites.append((i, a))
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
            if t == target:
                sites.append((i, a))
    return sites


# ---- 1-2. déroulés complets
for tgt, name in ((WRAP, "wrapper"), (PRE, "pré-wrapper")):
    di = bisect.bisect_left(addrs, tgt)
    fs = func_start(di)
    fe = func_end(fs)
    print(f"=== {name} {tgt:#08x} : fonction {rows[fs][0]:#08x}..{rows[fe][0]:#08x}"
          f" ({fe - fs + 1} insns) ===")
    dump(fs, fe, f"{name} complet")

# ---- 3. appelants du pré-wrapper
sites = census(PRE)
print(f"=== appelants du pré-wrapper {PRE:#08x} : {len(sites)} ===")
funcs = []
for i, a in sites:
    fsx = func_start(i)
    own = rows[fsx][0] if fsx is not None else None
    funcs.append(own)
    print(f"  site {a:#08x}  fonction porteuse {own:#08x}" if own
          else f"  site {a:#08x}  (fonction porteuse ?)")
print()

for (i, a), own in zip(sites, funcs):
    dump(max(0, i - 26), i + 2, f"appelant site {a:#08x} (fonction {own:#08x})")

# ---- 4. remontée : appelants de chaque fonction porteuse
uniq = sorted({f for f in funcs if f})
levels = {}
for f in uniq:
    di = bisect.bisect_left(addrs, f)
    fsf = func_start(di)
    if fsf is None:
        continue
    fef = func_end(fsf)
    sub = census(f)
    print(f"=== fonction porteuse {f:#08x} : {len(sub)} appelant(s) direct(s) ===")
    for i, a in sub:
        fso = func_start(i)
        own = rows[fso][0] if fso is not None else None
        print(f"  site {a:#08x}  fonction porteuse {own:#08x}" if own
              else f"  site {a:#08x}  (fonction porteuse ?)")
    print()
    levels[hex(f)] = {
        "func_range": [hex(rows[fsf][0]), hex(rows[fef][0])],
        "callers": [{"site": hex(a),
                     "func": hex(rows[func_start(i)][0]) if func_start(i) is not None else None}
                    for i, a in sub],
    }

json.dump({"pre_wrapper": hex(PRE), "levels": levels},
          (OUT / "v50_domain.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_domain.json'}")
