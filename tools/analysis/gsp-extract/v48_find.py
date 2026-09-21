#!/usr/bin/env python3
"""v48-find — vague 4.8, chantier 2 suite : 0x1b3c4f0 = list-find-by-key.

1. Re-vérification du site 0x163197e (boucle P-states) : cible exacte + usage
   du résultat (fenêtre 0x1631930-0x1631a70 avec cibles).
2. Décodage des jump-tables des deux mappers (rodata lisible) :
   - mapper 1 : dispatch 0x1b3c5ec, table à 0x1DEB210 (27 entrées)
   - mapper 2 : dispatch 0x1b3c708, table à 0x1DEB280 (9 entrées)
   mots signés relatifs à la base de table ; cible → valeur du c.li amont.
3. Appelants des deux mappers (auipc+jalr) pour le contexte.
"""
import bisect
import struct
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


def resolve_auipc_jalr(i):
    a, s, m, o = rows[i]
    p = parse(o)
    if m == "jalr" and len(p) == 3 and p[0] == p[1]:
        for k in (i - 1, i - 2):
            if k < 0:
                break
            ka, ks, km, ko = rows[k]
            kp = parse(ko)
            if km == "auipc" and len(kp) == 2 and kp[0] == p[1]:
                base = ka + (int(kp[1], 0) << 12)
                if base >= 0x80000000:
                    base -= 0x100000000
                return base + int(p[2], 0)
    return None


# ------------------------------------------------ 1 : usage au site P-states
print("=== 1. fenêtre boucle P-states 0x1631930-0x1631a70 (cibles résolues) ===")
BR = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez", "j", "c.j"}


def branch_target(m, o, a):
    if m not in BR:
        return None
    last = parse(o)[-1]
    try:
        val = int(last, 16) if last.startswith("0x") else int(last)
    except ValueError:
        return None
    return a + val if -0x100000 < val < 0x100000 else None


i0 = bisect.bisect_left(addrs, 0x1631930)
lines = []
while i0 < n and rows[i0][0] <= 0x1631A70:
    a, s, m, o = rows[i0]
    t = branch_target(m, o, a)
    tag = f"   → {t:#x}" if t else ""
    if m == "jalr":
        r = resolve_auipc_jalr(i0)
        if r:
            tag = f"   → {r:#x}"
    lines.append(f"  {a:#08x}  {m:10} {o}{tag}")
    i0 += 1
(OUT / "v48_pstate_loop.dump").write_text("\n".join(lines) + "\n")
print("\n".join(lines))

# ------------------------------------------------ 2 : jump tables
print("\n=== 2. décodage des jump-tables des mappers ===")
d = Path("/home/z/my-project/scratch-gsp/rm.elf").read_bytes()


def read_table(va, count, label):
    off = va - 0x1000000  # premier LOAD : va 0x1000000 @ fichier 0
    words = struct.unpack_from(f"<{count}i", d, off)
    print(f"  {label} @ {va:#x} (fichier {off:#x}) :")
    out = []
    for idx, w in enumerate(words):
        tgt = va + w
        out.append((idx, tgt))
        print(f"    [{idx:2d}] mot {w:8d} → cible {tgt:#x}")
    return out


# mapper 1 : auipc a4, 0x2af @0x1b3c616 ; addi a4, a4, -0x406 → table
t1_base = 0x1B3C616 + 0x2AF000 - 0x406
# mapper 2 : auipc a4, 0x2af @0x1b3c730 ; addi a4, a4, -0x4b0
t2_base = 0x1B3C730 + 0x2AF000 - 0x4B0
# vérification par script de l'arithmétique (leçon Task 70)
print(f"  base mapper 1 = {t1_base:#x} ; base mapper 2 = {t2_base:#x}")

# cibles → valeurs (c.li a0/a5, imm) — extraction automatique autour des sites
li_vals = {}
i0 = bisect.bisect_left(addrs, 0x1B3C67C)
while i0 < n and rows[i0][0] <= 0x1B3C6C6:
    a, s, m, o = rows[i0]
    p = parse(o)
    if m == "c.li" and len(p) == 2 and p[0] == "a0":
        li_vals[a] = int(p[1], 0)
    i0 += 1
i0 = bisect.bisect_left(addrs, 0x1B3C742)
while i0 < n and rows[i0][0] <= 0x1B3C780:
    a, s, m, o = rows[i0]
    p = parse(o)
    if m == "c.li" and len(p) == 2 and p[0] == "a5":
        li_vals[a] = int(p[1], 0)
    i0 += 1

print("\n  --- mapper 1 (indices 0-0x1b) ---")
t1 = read_table(t1_base, 27, "table 1")
map1 = {}
for idx, tgt in t1:
    # remonte depuis la cible pour trouver le c.li a0 (≤4 insns, en sautant les c.j)
    j = bisect.bisect_left(addrs, tgt)
    val = None
    for k in range(j, min(j + 4, n)):
        a, s, m, o = rows[k]
        p = parse(o)
        if m == "c.li" and p and p[0] == "a0":
            val = int(p[1], 0)
            break
        if m in ("j", "c.j"):
            t = branch_target(m, o, a)
            if t:
                j2 = bisect.bisect_left(addrs, t)
                k = j2 - 1  # continue depuis la cible du saut
    map1[idx] = val
    print(f"    index {idx:2d} ({idx:#04x}) → code {val if val is None else hex(val)}")

print("\n  --- mapper 2 (indices 0-8) ---")
t2 = read_table(t2_base, 9, "table 2")
map2 = {}
for idx, tgt in t2:
    j = bisect.bisect_left(addrs, tgt)
    val = None
    for k in range(j, min(j + 4, n)):
        a, s, m, o = rows[k]
        p = parse(o)
        if m == "c.li" and p and p[0] == "a5":
            val = int(p[1], 0)
            break
        if m in ("j", "c.j"):
            t = branch_target(m, o, a)
            if t:
                j2 = bisect.bisect_left(addrs, t)
                k = j2 - 1
    map2[idx] = val
    print(f"    index {idx:2d} ({idx:#04x}) → code {val if val is None else hex(val)}")

# ------------------------------------------------ 3 : appelants des mappers
print("\n=== 3. appelants des mappers 0x1b3c5ec / 0x1b3c708 ===")
for target, name in ((0x1B3C5EC, "mapper1"), (0x1B3C708, "mapper2")):
    sites = []
    for i, (a, s, m, o) in enumerate(rows):
        if m != "auipc":
            continue
        p = parse(o)
        if len(p) != 2:
            continue
        for j in (i + 1, i + 2):
            if j >= n:
                break
            a2, s2, m2, o2 = rows[j]
            if m2 == "jalr":
                p2 = parse(o2)
                if len(p2) == 3 and p2[0] == p2[1]:
                    hi = int(p[1], 0) << 12
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    if base + int(p2[2], 0) == target:
                        sites.append(hex(a))
                    break
                break
    print(f"  {name} {target:#x} : {len(sites)} appelant(s) : {sites[:12]}")

json.dump({"mapper1": {str(k): v for k, v in map1.items()},
           "mapper2": {str(k): v for k, v in map2.items()}},
          (OUT / "v48_mappers.json").open("w"), indent=1, default=str)
print("\nv48-find terminé.")
