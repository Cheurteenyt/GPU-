#!/usr/bin/env python3
"""v49-ctor5 — vague 4.9 : recensement classé des stores +0x288.

Pour chaque store sd/sw x, 0x288(base) de tout X-R :
  - origine de la valeur (12 insns en arrière) : auipc+addi (résolu),
    ld absolu (auipc+ld résolu), frame, mv-chaîne, autre ;
  - dérivation de la base (3 insns en arrière) : global (auipc+addi),
    frame, registre-arg, autre.
Sortie : census stdout + JSON des sites résolus.
Aussi : références adresse-prises / appels proches de 0x1631010.
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


# -------- valeur : résolution du registre source (retour arrière borné)
def value_origin(i, reg, back=12):
    """→ ('auipc', va) | ('ld_abs', va) | ('frame', insn) | ('chain', insn) | None"""
    for j in range(i - 1, max(0, i - back) - 1, -1):
        aa, ss, mm, oo = rows[j]
        p = parse(oo)
        if not p:
            continue
        if p[0] != reg:
            continue
        if mm == "auipc" and len(p) == 2:
            hi20 = int(p[1], 0)
            # addi suivant ?
            if j + 1 < n:
                a2, s2_, m2, o2 = rows[j + 1]
                p2 = parse(o2)
                if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == reg \
                        and p2[1] == reg:
                    try:
                        return ("auipc",
                                (aa + (hi20 << 12) + int(p2[2], 0)) & 0xFFFFFFFF,
                                hex(aa))
                    except ValueError:
                        pass
            return ("auipc", (aa + (hi20 << 12)) & 0xFFFFFFFF, hex(aa))
        if mm in ("ld", "lw") and len(p) == 2 and "(" in p[1]:
            # auipc+ld (data) : base = registre d'un auipc précédent
            base = p[1].split("(")[1].rstrip(")")
            for k in range(j - 1, max(0, j - 6) - 1, -1):
                ak, sk, mk, ok = rows[k]
                pk = parse(ok)
                if mk == "auipc" and len(pk) == 2 and pk[0] == base:
                    disp = int(p[1].split("(")[0] or "0", 16)
                    va = (ak + (int(pk[1], 0) << 12) + disp) & 0xFFFFFFFF
                    return ("ld_abs", va, hex(ak))
            return ("frame", f"{mm} {oo}", hex(aa))
        if mm in ("c.mv", "mv") and len(p) == 2:
            return ("chain", f"{mm} {oo}", hex(aa))
        if mm in ("li", "c.li") and len(p) == 2:
            return ("li", p[1], hex(aa))
        if mm in ("sd", "sw", "sb", "sh") or m == "c.sdsp":
            return None  # registre écrasé avant d'être défini
        return ("other", f"{mm} {oo}", hex(aa))
    return None


# -------- recensement des stores +0x288
census = {}
resolved = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("sd", "sw"):
        continue
    p = parse(o)
    if len(p) != 2 or not p[1].startswith("0x288("):
        continue
    vr = p[0]
    vo = value_origin(i, vr)
    key = vo[0] if vo else "none"
    census[key] = census.get(key, 0) + 1
    if vo and vo[0] in ("auipc", "ld_abs"):
        resolved.append({"store": hex(a), "insn": f"{m} {o}",
                         "kind": vo[0], "value": hex(vo[1]),
                         "at": vo[2]})

print("=== census stores +0x288 (origine valeur) ===")
for k, v in sorted(census.items(), key=lambda x: -x[1]):
    print(f"  {k:8} {v}")
print(f"\n=== stores +0x288 à valeur résolue ({len(resolved)}) ===")
from collections import Counter
vc = Counter(r["value"] for r in resolved)
for val, cnt in vc.most_common(12):
    sites = [r["store"] for r in resolved if r["value"] == val][:4]
    print(f"  valeur {val}  ×{cnt}   ex: {sites}")

# -------- références au grand parseur 0x1631010
print("\n=== références 0x1631010 (appel/adresse prise) ===")
GP = 0x1631010
refs = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m in ("call", "tail", "jal") and p:
        try:
            t = int(p[-1], 0)
            if m == "jal" and -0x100000 < t < 0x100000:
                t = a + t
            if GP - 0x10 <= t <= GP + 0x8:
                refs.append((hex(a), m, o))
        except ValueError:
            pass
    if m == "auipc" and len(p) == 2:
        hi20 = int(p[1], 0)
        if i + 1 < n:
            a2, s2_, m2, o2 = rows[i + 1]
            p2 = parse(o2)
            if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == p[0] \
                    and p2[1] == p[0]:
                try:
                    t = (a + (hi20 << 12) + int(p2[2], 0)) & 0xFFFFFFFF
                except ValueError:
                    continue
                if GP - 0x10 <= t <= GP + 0x8:
                    refs.append((hex(a), f"auipc+{m2}", o2))
for r in refs:
    print(f"  {r[0]}  {r[1]}  {r[2]}")
print(f"  {len(refs)} référence(s)")

json.dump({"census": census, "resolved": resolved, "gp_refs": refs},
          (OUT / "v49_ctor5.json").open("w"), indent=1)
print("\n→ v49_ctor5.json")
