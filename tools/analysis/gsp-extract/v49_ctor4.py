#!/usr/bin/env python3
"""v49-ctor4 — vague 4.9 : origine de l'état RM racine + loaders de stubs +0x288.

1. Vrai prologue du grand parseur (scan arrière depuis 0x1631300) et
   initialisation de s1/s2 (deux premiers écrans du dump).
2. Appelants du grand parseur (cible résolue dans [entrée-0x20, entrée]).
3. Stores `sd v, 0x288(base)` où v = auipc+addi → fenêtre stub
   (0x1915574±0x80, 0x193cc44±0x80) : sites exacts + dérivation de base.
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v49")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]


def parse(o):
    return [x.strip() for x in o.split(",")]


def is_reg(x):
    return not (x[:1].isdigit() or x[0] == "-")


def dump(lo, hi, title):
    print(f"\n=== {title} ===")
    i0 = bisect.bisect_left(addrs, lo)
    out = []
    while i0 < n and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        out.append(f"  {a:#08x}  {m:10} {o}")
        i0 += 1
    print("\n".join(out))
    return out


# ---------------- 1 : vrai prologue du grand parseur
gi = bisect.bisect_left(addrs, 0x1631300)
pstart = None
for i in range(gi, -1, -1):
    a, s, m, o = rows[i]
    p = parse(o)
    if (m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
            and p[1] == "sp" and p[2].startswith("-")) or \
       (m == "c.addi16sp" and p and p[-1].startswith("-")):
        pstart = i
        break
print(f"vrai prologue grand parseur : {rows[pstart][0]:#08x}")
dump(rows[pstart][0], rows[pstart][0] + 0x50, "début réel + init s1/s2")

# ---------------- 2 : appelants (entrées candidate : prologue et 0x1631300)
print("\n=== appelants du grand parseur ===")
cands = {rows[pstart][0], 0x1631300}
inc = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    t = None
    if m in ("call", "tail") and p:
        try:
            t = int(p[-1], 0)
        except ValueError:
            t = None
    elif m == "jal" and len(p) == 2:
        try:
            tt = int(p[1], 0)
            t = a + tt if -0x100000 < tt < 0x100000 else None
        except ValueError:
            t = None
    if t in cands:
        inc.append((a, m, o, t))
for a, m, o, t in inc:
    print(f"  {a:#08x}  {m} {o}  → {t:#08x}")
print(f"  {len(inc)} appel(s)")

# ---------------- 3 : loaders de stubs dans +0x288
STUBS = [(0x1915574 - 0x80, 0x1915574 + 0x80),
         (0x193cc44 - 0x80, 0x193cc44 + 0x80)]
print("\n=== stores +0x288 de pointeurs-stub (auipc+addi → sd) ===")
sites = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m != "auipc" or len(p) != 2 or not is_reg(p[0]):
        continue
    rd, hi20 = p[0], int(p[1], 0)
    val = None
    for j in range(i + 1, min(i + 4, n)):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm in ("addi", "c.addi") and len(pp) == 3 and pp[0] == rd \
                and pp[1] == rd:
            try:
                val = (a + (hi20 << 12) + int(pp[2], 0)) & 0xFFFFFFFF
            except ValueError:
                val = None
            break
        if mm == "c.ldsp" or mm == "ld":
            break
    if val is None:
        continue
    if not any(lo <= val <= hi for lo, hi in STUBS):
        continue
    # chercher le store qui suit avec rd comme valeur et disp 0x288
    for j in range(i + 1, min(i + 10, n)):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm in ("sd", "sw") and len(pp) == 2 and pp[0] == rd \
                and pp[1].endswith("0x288("):
            base = pp[1].split("(")[1].rstrip(")")
            sites.append({"auipc": hex(a), "val": hex(val),
                          "store": hex(aa), "insn": f"{mm} {oo}", "base": base})
            break
        if is_reg(pp[0]) and pp[0] == rd:
            break
for st in sites:
    print(f"  store {st['store']}  base {st['base']}  val {st['val']}"
          f"  (auipc {st['auipc']})")
print(f"  {len(sites)} site(s)")

json.dump({"gp_prologue": hex(rows[pstart][0]),
           "gp_callers": [(hex(a), m, o) for a, m, o, t in inc],
           "stub288_stores": sites},
          (OUT / "v49_ctor4.json").open("w"), indent=1)
print("\n→ v49_ctor4.json")
