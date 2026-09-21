#!/usr/bin/env python3
"""v45-func — analyse au niveau fonction d'une adresse.

Délimitation : marche arrière jusqu'au prologue (sd ra, N(sp) ou addi sp,-N
après un alignement), marche avant jusqu'à l'épilogue (c.jr ra / ret après
restauration). Extrait : formations de strings (auipc+addi, lui+addi),
cibles d'appel (jal + auipc+jalr), li<=0x7ff,stores 0x400-family.

Usage : python3 v45_func.py <va_hex> [...]
Sortie : stdout + scratch-gsp/v45/funcs.json
"""
import bisect
import json
import sys
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]

def idx_of(va):
    i = bisect.bisect_left(addrs, va)
    return i if i < len(rows) and rows[i][0] == va else None

def parse(o):
    return [x.strip() for x in o.split(",")]

def analyze(va):
    i0 = idx_of(va)
    if i0 is None:
        return None
    # --- début : marche arrière max 4000 insns, prologue = addi sp, sp, -N ---
    start = i0
    j = i0
    while j > max(0, i0 - 4000):
        a, s, m, o = rows[j]
        if m == "addi" and o.startswith("sp, sp, -"):
            start = j
            break
        j -= 1
    else:
        start = max(0, i0 - 400)
    # --- fin : avance max 6000 insns, épilogue = c.jr ra / ret ---
    end = i0
    n = len(rows)
    k = i0
    while k < min(n, i0 + 6000):
        a, s, m, o = rows[k]
        if m in ("c.jr", "ret", "jr") and (m != "jr" or o == "ra"):
            end = k
            break
        k += 1
    else:
        end = min(n - 1, i0 + 600)

    strings_formed, calls, smalls, pokes = [], [], [], []
    for t in range(start, end + 1):
        a, s, m, o = rows[t]
        p = parse(o)
        if m in ("auipc", "lui") and len(p) == 2:
            try:
                hi = int(p[1], 0) << 12
            except ValueError:
                continue
            rd = p[0]
            base = a + hi if m == "auipc" else hi
            if base >= 0x80000000:
                base -= 0x100000000
            for u in range(t + 1, min(t + 9, end + 1)):
                a2, s2, m2, o2 = rows[u]
                p2 = parse(o2)
                if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == rd and p2[1] == rd:
                    try:
                        formed = base + int(p2[2], 0)
                    except ValueError:
                        break
                    if 0x1D00000 <= formed <= 0x1E9F000 or 0x20200000 <= formed <= 0x20400000:
                        strings_formed.append((hex(a), hex(formed)))
                    break
                if p2 and p2[0] == rd:
                    break
        if m == "jal" and len(p) == 2 and p[1].startswith("0x"):
            try:
                calls.append((hex(a), "jal", hex(int(p[1], 16))))
            except ValueError:
                pass
        if m == "auipc" and len(p) == 2 and p[0] == "ra":
            try:
                hi = int(p[1], 0) << 12
            except ValueError:
                continue
            for u in (t + 1, t + 2):
                if u > end:
                    break
                a2, s2, m2, o2 = rows[u]
                p2 = parse(o2)
                if m2 == "jalr" and len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                    try:
                        lo = int(p2[2], 0)
                    except ValueError:
                        break
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    calls.append((hex(a), "a+j", hex(base + lo)))
                    break
                if p2 and p2[0] == "ra":
                    break
        if m in ("li", "c.li") and len(p) == 2:
            try:
                v = int(p[1], 0)
                if 0 <= v <= 0x7FF:
                    smalls.append((hex(a), p[0], v))
            except ValueError:
                pass
        if m == "lui" and len(p) == 2 and p[1] in ("0x111", "0x400"):
            pokes.append((hex(a), m, o))

    return {
        "va": hex(va),
        "start": hex(rows[start][0]),
        "end": hex(rows[end][0]),
        "size": rows[end][0] - rows[start][0],
        "strings": strings_formed,
        "calls": calls,
        "li": smalls,
        "pokes": pokes,
    }


targets = [int(x, 0) for x in sys.argv[1:]]
out = {}
for va in targets:
    r = analyze(va)
    if r:
        out[hex(va)] = r
        print(f"\n### site {r['va']}  fonction {r['start']}..{r['end']} ({r['size']:#x} o)")
        print(f"  strings : {r['strings']}")
        print(f"  appels  : {r['calls']}")
        print(f"  li<=7ff : {r['li'][:24]}")
        print(f"  pokes   : {r['pokes']}")

json.dump(out, (V45 / "funcs.json").open("w"), indent=1)
print(f"\n-> {V45/'funcs.json'}")
