#!/usr/bin/env python3
"""v49-lists — vague 4.9, chantier 2 : catalogue des listes BOARDOBJ.

1. Prologue du chercheur 0x1b3c4f0 : convention d'args (quel arg = root,
   où on lit +0x1100, +0x170, +0x38, +0x28).
2. Appelants (auipc+addi/jal résolus → 0x1b3c4f0).
3. Pour chaque appelant : dérivation de l'arg-root (fenêtre arrière 16),
   classée (global-résolu, ld-global, frame, passthrough, mv-chain).
Sortie : stdout + v49_lists.json.
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


FINDER = 0x1B3C4F0

# ---------------- 1 : prologue du chercheur
print("=== chercheur 0x1b3c4f0 : 44 premières instructions ===")
fi = bisect.bisect_left(addrs, FINDER)
for i in range(fi, min(fi + 44, n)):
    a, s, m, o = rows[i]
    print(f"  {a:#08x}  {m:10} {o}")

# ---------------- 2 : appelants
callers = []
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
    elif m in ("auipc",):
        # auipc+addi non-jal (adresse prise) aussi utile — mais ici on veut
        # les appels : auipc ra/jalr gérés plus bas
        pass
    if t == FINDER:
        callers.append((i, a, m, o))
# auipc ra, hi ; jalr ra, ra, lo
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m != "auipc" or len(p) != 2 or p[0] != "ra":
        continue
    hi20 = int(p[1], 0)
    for j in range(i + 1, min(i + 3, n)):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm == "jalr" and len(pp) == 3 and pp[0] == "ra" and pp[1] == "ra":
            try:
                t = (a + (hi20 << 12) + int(pp[2], 0)) & 0xFFFFFFFF
            except ValueError:
                break
            if t == FINDER:
                callers.append((i, a, "auipc+jalr", f"{o} / {oo}"))
            break
        if is_reg(pp[0]) and pp[0] == "ra" and pp[0] == pp[1] if len(pp) > 1 else False:
            break
callers = sorted(set(callers), key=lambda x: x[1])
print(f"\n=== {len(callers)} appelant(s) du chercheur ===")

# ---------------- 3 : convention d'arg du chercheur — quel registre porte
# le root ? On regarde comment a0/a1/a2 sont consommés dans les 20 premières
# insns (déjà affiché) : on détecte le premier `ld x, 0x1100(r)` et le r.
root_reg = "a0"  # preuve : 0x1b3c4fe c.lui a5,1 ; 0x1b3c502 add s2,a0,a5 ;
# 0x1b3c506 ld a0,0x100(s2) → list = [a0+0x1000+0x100] = [root+0x1100]
print(f"\nroot arg = {root_reg}  (a0+0x1000 → [s2+0x100] @ 0x1b3c506)")


def reg_origin(i, reg, back=16):
    """classification de la provenance de reg avant l'index i"""
    for j in range(i - 1, max(0, i - back) - 1, -1):
        aa, ss, mm, oo = rows[j]
        p = parse(oo)
        if not p or p[0] != reg:
            continue
        if mm == "auipc" and len(p) == 2:
            hi20 = int(p[1], 0)
            if j + 1 < n:
                a2, s2_, m2, o2 = rows[j + 1]
                p2 = parse(o2)
                if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == reg \
                        and p2[1] == reg:
                    try:
                        return ("global", (aa + (hi20 << 12) + int(p2[2], 0))
                                & 0xFFFFFFFF, hex(aa))
                    except ValueError:
                        pass
            return ("global", (aa + (hi20 << 12)) & 0xFFFFFFFF, hex(aa))
        if mm in ("ld", "lw") and len(p) == 2 and "(" in p[1]:
            base = p[1].split("(")[1].rstrip(")")
            for k in range(j - 1, max(0, j - 6) - 1, -1):
                ak, sk, mk, ok = rows[k]
                pk = parse(ok)
                if mk == "auipc" and len(pk) == 2 and pk[0] == base:
                    disp = int(p[1].split("(")[0] or "0", 16)
                    return ("ld_global",
                            (ak + (int(pk[1], 0) << 12) + disp) & 0xFFFFFFFF,
                            hex(aa))
            return ("ld_frame", f"{mm} {oo}", hex(aa))
        if mm in ("mv", "c.mv") and len(p) == 2:
            return ("chain", p[1], hex(aa))
        if mm in ("li", "c.li") and len(p) == 2:
            return ("li", p[1], hex(aa))
        return ("other", f"{mm} {oo}", hex(aa))
    return ("passthrough", reg, "")


results = []
for i, a, m, o in callers:
    if root_reg is None:
        break
    # root_reg est un registre arg du chercheur (a0/a1/a2?) — à l'appel,
    # la valeur vient du registre de l'appelant du MÊME nom abi
    origin = reg_origin(i, root_reg)
    results.append({"site": hex(a), "insn": f"{m} {o}",
                    "kind": origin[0],
                    "val": hex(origin[1]) if isinstance(origin[1], int)
                    else origin[1],
                    "at": origin[2]})
    print(f"  {a:#08x}  {m:14} {o:28} root={root_reg} → "
          f"{origin[0]:12} {results[-1]['val']}")

json.dump({"root_reg": root_reg,
           "callers": results},
          (OUT / "v49_lists.json").open("w"), indent=1)
print("\n→ v49_lists.json")
