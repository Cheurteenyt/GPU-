#!/usr/bin/env python3
"""v47-hunt — vague 4.7, chasse 3 :

1. Census GLOBAL des appelants (auipc+jalr) de la passe P-states 0x1b3c4f0
   → branches d'entrée de la boucle (chantier C).
2. Résolution des handlers ENREGISTRÉS à [obj+0x288] (callback PerfPmaControlReg) :
   pattern auipc rd / addi rd, rd, lo → sd rd, 0x288(base) ; cible résolue par script.
3. Fenêtres détail : bit 8 par le moteur (0x1635560..0x1635680),
   bit 11 (0x1635490..0x16354d0), appels 0x1630b60 (0x1635100..0x1635230).
"""
import json
import re
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v47")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
idx = {a: i for i, (a, s, m, o) in enumerate(rows)}
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def resolve_callers(target):
    sites = []
    for i, (a, s, m, o) in enumerate(rows):
        if m != "auipc":
            continue
        p = parse(o)
        if len(p) != 2:
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
                p2 = parse(o2)
                if len(p2) == 3 and p2[0] == p2[1]:
                    try:
                        lo = int(p2[2], 0)
                    except ValueError:
                        break
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    if base + lo == target:
                        sites.append((i, a, p2[0]))
                    break
            if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == p[0]:
                break
    return sites


# ------------------------------------------------ 1 : appelants de la passe
print("=== 1. appelants globaux de 0x1b3c4f0 (passe P-states) ===")
sites = resolve_callers(0x1B3C4F0)
print(f"  {len(sites)} appelant(s) auipc+jalr :")
for i, a, reg in sites:
    print(f"    {a:#08x} (reg {reg})")

# ------------------------------------------------ 2 : handlers stockés à +0x288
print("\n=== 2. handlers enregistrés à [obj+0x288] ===")
pat_sd = re.compile(r",\s*0x288\(")
handlers = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("sd", "sw"):
        continue
    p = parse(o)
    if len(p) != 2 or not pat_sd.search(o):
        continue
    reg = p[0]
    # en arrière ≤ 10 insns : reg écrit par addi auipc-reg ? (auipc + addi/add)
    for j in range(i - 1, max(0, i - 10) - 1, -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm == "addi" and len(pp) == 3 and pp[0] == reg:
            src = pp[1]
            # chercher l'auipc de src (≤3 insns avant)
            for k in range(j - 1, max(0, j - 3) - 1, -1):
                ka, ks, km, ko = rows[k]
                kp = parse(ko)
                if km == "auipc" and len(kp) == 2 and kp[0] == src:
                    try:
                        hi12 = int(kp[1], 0) << 12
                        lo12 = int(pp[2], 0)
                    except ValueError:
                        break
                    base = ka + hi12
                    if base >= 0x80000000:
                        base -= 0x100000000
                    tgt = base + lo12
                    handlers.append({"site": hex(aa), "store": hex(a), "target": hex(tgt)})
                    break
            break
        if mm in ("auipc",) and len(pp) == 2 and pp[0] == reg:
            break  # reg réécrit sans addi → pas une fonction liée
from collections import Counter
cnt = Counter(h["target"] for h in handlers)
print(f"  {len(handlers)} enregistrement(s) résolus ; cibles distinctes : {len(cnt)}")
for tgt, c in cnt.most_common():
    print(f"    {tgt} ×{c}")
(OUT / "v47_288_handlers.json").open("w").write(json.dumps(handlers, indent=1))

# ------------------------------------------------ 3 : fenêtres détail
import bisect
addrs_all = [r[0] for r in rows]


def dump(name, lo, hi):
    i0 = bisect.bisect_left(addrs_all, lo)
    lines = []
    while i0 < len(rows) and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        lines.append(f"  {a:#08x}  {m:10} {o}")
        i0 += 1
    (OUT / f"v47_{name}.dump").write_text("\n".join(lines) + "\n")
    print(f"\n=== fenêtre {name} : {len(lines)} instr → v47_{name}.dump ===")

dump("bit8_engine", 0x1635540, 0x1635690)
dump("bit11_engine", 0x1635490, 0x16354E0)
dump("call_0x1630b60", 0x1635100, 0x1635230)
print("\nv47-hunt terminé.")
