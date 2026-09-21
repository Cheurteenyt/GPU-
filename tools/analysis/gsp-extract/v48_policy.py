#!/usr/bin/env python3
"""v48-policy — vague 4.8, chantier 3 complet : qui atteint le SET bit 8
(0x1635656), qui écrit l'ID de séquence [obj+0x180], qui pose [s2+0x2f8],
et remontée du flux du bloc politique 0x16355a0-0x16358f6.

Sortie : stdout + v48_policy.json (cibles entrantes + candidats écrivains).
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
idx = {a: i for i, (a, s, m, o) in enumerate(rows)}


def parse(o):
    return [x.strip() for x in o.split(",")]


BRANCH_MNEMS = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
                "bgez", "blez", "bltz", "bgtz", "j", "jal", "c.j", "c.jal",
                "c.bnez", "c.beqz", "c.jr", "c.jalr"}


def branch_target(m, o, a):
    if m not in BRANCH_MNEMS:
        return None
    parts = parse(o)
    last = parts[-1]
    try:
        val = int(last, 16) if last.startswith("0x") else int(last)
    except ValueError:
        return None
    if -0x100000 < val < 0x100000:
        return a + val
    return None


# ------------------------------------------------ 1 : qui atteint 0x1635656 ?
print("=== 1. branches GLOBALES visant 0x1635656 (SET bit 8) ===")
target = 0x1635656
incoming = []
for a, s, m, o in rows:
    t = branch_target(m, o, a)
    if t == target:
        incoming.append((hex(a), m, o))
for x in incoming:
    print(f"  {x[0]}  {x[1]} {x[2]}")
if not incoming:
    print("  AUCUNE — site atteint par chute ou par pointeur")

# ------------------------------------------------ 2 : contexte amont (0x16354e0-0x16355a8)
print("\n=== 2. fenêtre amont 0x16354e0-0x16355a8 ===")
i0 = bisect.bisect_left(addrs, 0x16354E0)
lines = []
while i0 < len(rows) and rows[i0][0] <= 0x16355A8:
    a, s, m, o = rows[i0]
    t = branch_target(m, o, a)
    lines.append(f"  {a:#08x}  {m:10} {o}" + (f"   → {t:#x}" if t else ""))
    i0 += 1
print("\n".join(lines))
(OUT / "v48_upstream.dump").write_text("\n".join(lines) + "\n")

# ------------------------------------------------ 3 : écrivains de [x+0x180] avec
#      constantes de séquence 0x20/0x30/0x35/0x40 dans la région perf
print("\n=== 3. stores à +0x180 avec li de 0x20/0x30/0x35/0x40 à ≤8 insns (région 0x1620000-0x16a0000) ===")
seq_consts = {0x20, 0x30, 0x35, 0x40, 0x50, 0xff}
cands = []
for i, (a, s, m, o) in enumerate(rows):
    if not (0x1620000 <= a <= 0x16A0000):
        continue
    if m not in ("sb", "sh", "sw", "sd"):
        continue
    p = parse(o)
    if len(p) != 2 or not p[1].endswith("0x180("):
        continue
    val_reg = p[0]
    for j in range(i - 1, max(0, i - 8) - 1, -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm in ("li", "c.li") and len(pp) == 2 and pp[0] == val_reg:
            try:
                v = int(pp[1], 0)
            except ValueError:
                break
            if v in seq_consts:
                cands.append({"store": hex(a), "li": hex(aa), "val": hex(v),
                              "insn": f"{mm} {oo}"})
            break
        if mm in ("auipc", "lui", "mv", "c.mv", "ld", "lw", "lbu"):
            break
for c in cands:
    print(f"  store {c['store']} ← {c['li']} ({c['val']})  [{c['insn']}]")
print(f"  {len(cands)} candidat(s)")

# ------------------------------------------------ 4 : écrivains de [x+0x2f8]
print("\n=== 4. stores à +0x2f8 (région perf) — l'objet séquence ===")
writes = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("sd", "sw"):
        continue
    p = parse(o)
    if len(p) == 2 and p[1].endswith("0x2f8("):
        writes.append((a, m, o))
print(f"  {len(writes)} store(s) globaux à +0x2f8 ; détail région perf :")
for a, m, o in writes:
    if 0x1620000 <= a <= 0x16A0000:
        print(f"    {a:#08x}  {m} {o}")

json.dump({"incoming_to_set8": incoming, "seq_id_candidates": cands,
           "writes_2f8_perf": [[hex(a), m, o] for a, m, o in writes
                                if 0x1620000 <= a <= 0x16A0000]},
          (OUT / "v48_policy.json").open("w"), indent=1)
print("\nv48-policy terminé.")
