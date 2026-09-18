#!/usr/bin/env python3
"""v48-ctor4 — vague 4.8 : analyse AVANT corrigée depuis chaque `lui Rx, 0x88`.

Propagaton d'alias propre : la décision d'aliasage utilise l'état AVANT mise
à jour. Rapporte chaque store via base aliasée (offset quelconque).
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
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def is_reg(x):
    return not (x.startswith("0x") or x.startswith("-") or x[:1].isdigit())


ADD_FAM = ("add", "addi", "c.add", "c.addi", "addw", "addiw", "c.addiw")
DEF_MNEMS = ADD_FAM + ("mv", "c.mv", "lui", "c.lui", "ld", "lw", "lbu", "lhu",
                       "auipc", "slli", "c.slli", "li", "c.li", "sd", "sw",
                       "sb", "sh", "sext.w", "srai", "srli", "andi", "sllw")

stores_out = []
for i, (a, s, m, o) in enumerate(rows):
    if m != "lui":
        continue
    p = parse(o)
    if len(p) != 2 or p[1] != "0x88":
        continue
    r0 = p[0]
    alias = {r0}
    j = i + 1
    while j < min(i + 80, n):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if not pp:
            j += 1
            continue
        rd = pp[0]
        if mm in ("sd", "sw", "sb", "sh") and len(pp) == 2 and "(" in pp[1]:
            b = pp[1].split("(")[1].rstrip(")")
            if b in alias:
                stores_out.append({"lui": hex(a), "store": hex(aa),
                                   "off": pp[1].split("(")[0],
                                   "insn": f"{mm} {oo}"})
            j += 1
            continue
        if mm in DEF_MNEMS and rd in ("a0", "a1", "a2", "a3", "a4", "a5",
                                      "a6", "a7", "t0", "t1", "t2", "t3",
                                      "t4", "t5", "t6", "s1", "s2", "s3",
                                      "s4", "s5", "s6", "s7", "s8", "s9",
                                      "s10", "s11"):
            reg_srcs = [x for x in pp[1:] if is_reg(x) and x != "zero"]
            if mm in ADD_FAM:
                keep = rd in alias or any(x in alias for x in reg_srcs)
            elif mm in ("mv", "c.mv"):
                keep = len(pp) >= 2 and pp[1] in alias
            elif mm in ("sext.w", "slli", "c.slli", "srai", "srli", "sllw",
                        "andi"):
                keep = len(pp) >= 2 and pp[1] in alias
            else:
                keep = False  # ld/lui/auipc/li = valeur fraîche
            if keep:
                alias.add(rd)
            else:
                alias.discard(rd)
        j += 1

print(f"stores via base aliasée (lui 0x88) : {len(stores_out)}")
offs = {}
for x in stores_out:
    offs[x["off"]] = offs.get(x["off"], 0) + 1
print("distribution des offsets (top 20) :")
for k, c in sorted(offs.items(), key=lambda kv: -kv[1])[:20]:
    print(f"  {k} : {c}")
sel = [x for x in stores_out if x["off"] in ("0x130", "0x0", "0")]
print(f"\noff 0x130 (écriture de 0x88130) : {len(sel)}")
for x in sel:
    print(f"  lui {x['lui']} → store {x['store']}  [{x['insn']}]")
(OUT / "v48_88130_writers4.json").open("w").write(json.dumps(stores_out, indent=1))
print("\nv48-ctor4 terminé.")
