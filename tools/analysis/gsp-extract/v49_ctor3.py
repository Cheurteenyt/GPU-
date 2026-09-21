#!/usr/bin/env python3
"""v49-ctor3 — vague 4.9 : chasse du writeur du callback PMA [+état+0x288].

1. Contexte ±14 insns autour des deux familles dominantes de stores +0x288
   (0x1915574, 0x193cc44) — dérivation de la base (global fixe ?).
2. Références « adresse prise » de l'entrée destructeur 0x164b388
   (auipc+addi résolus, call/jal, sd d'adresse).
3. Prologue du grand parseur 0x1631300-0x1631340 : origine de s1.
"""
import bisect
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


# -------------------------------- 1 : familles dominantes de stores +0x288
for site in (0x1915574, 0x193CC44):
    dump(site - 0x38, site + 0x30, f"contexte store +0x288 @ {site:#08x}")

# -------------------------------- 2 : adresse prise de 0x164b388
TARGET = 0x164B388
print(f"\n=== références à {TARGET:#08x} ===")
hits = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    # auipc rd, hi ; addi rd, rd, lo  → résolution
    if m == "auipc" and len(p) == 2 and is_reg(p[0]):
        rd, hi20 = p[0], int(p[1], 0)
        for j in range(i + 1, min(i + 4, n)):
            aa, ss, mm, oo = rows[j]
            pp = parse(oo)
            if mm in ("addi", "c.addi") and len(pp) == 3 and pp[0] == rd \
                    and pp[1] == rd:
                try:
                    lo12 = int(pp[2], 0)
                except ValueError:
                    break
                t = (a + (hi20 << 12) + lo12) & 0xFFFFFFFF
                if t == TARGET:
                    hits.append((hex(a), f"auipc+{mm}", hex(t)))
                break
            if not (mm in ("ld", "lw", "lbu", "lhu") and len(pp) == 2
                    and pp[1].endswith(f"({rd})")):
                break
    if m in ("call", "tail", "jal") and p:
        try:
            last = p[-1]
            t = int(last, 0)
            if m in ("jal",) and -0x100000 < t < 0x100000:
                t = a + t
            if t == TARGET:
                hits.append((hex(a), m, o))
        except ValueError:
            pass
for h in hits:
    print(f"  {h[0]}  {h[1]}  {h[2]}")
print(f"  {len(hits)} référence(s)")

# -------------------------------- 3 : origine de s1 dans le grand parseur
dump(0x1631300, 0x1631360, "prologue grand parseur (s1/s2)")
