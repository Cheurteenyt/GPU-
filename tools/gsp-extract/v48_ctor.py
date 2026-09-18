#!/usr/bin/env python3
"""v48-ctor — vague 4.8, chantier 1 suite : le constructeur de l'état RM.

L'état RM du grand parseur est l'objet qui porte [state+0x88130] = l'objet
capacité (lui 0x88 ; add ; ld/sd 0x130). Son constructeur doit exister.
1. scan global du pattern : lui Rx, 0x88 ; (add/addi) Rx, Rx, base ; sd Y, 0x130(Rx)
   → les ÉCRIVAINS de [state+0x88130].
2. pour chaque écrivain : fenêtre ±0x80 et recherche d'un store à 0x288
   sur la même base (LE callback PMA nominatif).
3. déroulé du prologue de la fonction englobante + appelants.
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
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


# ------------------------------------------------ 1 : écrivains de 0x88130
print("=== 1. écrivains de [state+0x88130] (lui 0x88 ; add ; sd 0x130) ===")
writers = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("sd", "sw"):
        continue
    p = parse(o)
    if len(p) != 2 or not p[1].endswith("0x130("):
        continue
    basereg = p[1].split("(")[1].rstrip(")")
    # en arrière ≤ 8 : basereg ← add basereg, Rx, Ry (ou addi) issu de lui Rx, 0x88
    for j in range(i - 1, max(0, i - 8) - 1, -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm in ("add", "c.add", "addi", "c.addi") and pp and pp[0] == basereg:
            # remonte chercher le lui 0x88 sur l'une des sources
            for src in pp[1:3]:
                if src in ("sp", "zero"):
                    continue
                for k in range(j - 1, max(0, j - 8) - 1, -1):
                    ka, ks, km, ko = rows[k]
                    kp = parse(ko)
                    if km == "lui" and len(kp) == 2 and kp[0] == src and kp[1] == "0x88":
                        writers.append({"store": hex(a), "lui": hex(ka),
                                        "kind": m, "insn": f"{m} {o}"})
                        break
                else:
                    continue
                break
            break
        if mm in ("auipc",) and pp and pp[0] == basereg:
            break
print(f"  {len(writers)} écriture(s) :")
for w in writers:
    print(f"    store {w['store']} (lui {w['lui']})  [{w['insn']}]")
(OUT / "v48_88130_writers.json").open("w").write(json.dumps(writers, indent=1))

# ------------------------------------------------ 2 : fenêtres et stores 0x288
print("\n=== 2. pour chaque région d'écriture : stores à 0x288 à ±0x100 ==="
      )
sites = sorted({int(w["store"], 16) for w in writers})
hits = []
for st in sites:
    i = bisect.bisect_left(addrs, st)
    lo, hi = max(0, i - 60), min(n, i + 60)
    lines = []
    for j in range(lo, hi):
        a, s, m, o = rows[j]
        lines.append(f"  {a:#08x}  {m:10} {o}")
        if m in ("sd", "sw") and parse(o)[-1].endswith("0x288("):
            hits.append({"near": hex(st), "store": hex(a), "insn": f"{m} {o}"})
    (OUT / f"v48_w88130_{st:x}.dump").write_text("\n".join(lines) + "\n")
print(f"  stores 0x288 trouvés près des écrivains : {len(hits)}")
for h in hits:
    print(f"    {h['store']}  [{h['insn']}]  (près {h['near']})")

# ------------------------------------------------ 3 : la valeur du store 0x288
print("\n=== 3. résolution de la VALEUR stockée à +0x288 ===")


def resolve_auipc_jalr(i):
    a, s, m, o = rows[i]
    p = parse(o)
    if m == "jalr" and len(p) == 3 and p[0] == p[1]:
        for k in (i - 1, i - 2):
            ka, ks, km, ko = rows[k]
            kp = parse(ko)
            if km == "auipc" and len(kp) == 2 and kp[0] == p[1]:
                base = ka + (int(kp[1], 0) << 12)
                if base >= 0x80000000:
                    base -= 0x100000000
                return base + int(p[2], 0)
    return None


for h in hits:
    i = bisect.bisect_left(addrs, int(h["store"], 16))
    valreg = parse(rows[i][3])[0]
    val = None
    for j in range(i - 1, max(0, i - 14) - 1, -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm in ("auipc",) and pp and pp[0] == valreg:
            # auipc (+addi éventuel) → constante
            base = aa + (int(pp[1], 0) << 12)
            if base >= 0x80000000:
                base -= 0x100000000
            val = hex(base)
            for k in range(j + 1, i):
                ka, ks, km, ko = rows[k]
                kp = parse(ko)
                if km == "addi" and len(kp) == 3 and kp[0] == valreg and kp[1] == valreg:
                    val = hex(base + int(kp[2], 0))
                    break
            break
        if mm == "addi" and len(pp) == 3 and pp[0] == valreg and pp[1] in ("a2", "s1", "s2", "a0", "a1", "s6"):
            val = f"{pp[1]}+{pp[2]} (auto-pointeur)"
            break
    print(f"  store {h['store']} ← {valreg} : {val}")

print("\nv48-ctor terminé.")
