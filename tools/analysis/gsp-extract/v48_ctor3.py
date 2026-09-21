#!/usr/bin/env python3
"""v48-ctor3 — vague 4.8, chantier 1 ter : analyse AVANT depuis chaque
`lui Rx, 0x88` — qui STORE via une base dérivée de Rx ?

Le champ [state+0x88130] peut être écrit :
  (a) sd X, 0x130(deriv)          — l'état + 0x88000, immédiat 0x130 ;
  (b) addi deriv2, deriv, 0x130 ; sd X, 0(deriv2) — addr fusionnée.
Fenêtre avant 60 insns, ensemble d'alias des registres dérivés de Rx.
Sortie : tous les stores via base aliasée, avec offset et valeur.
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


ALIAS_DEF = ("add", "addi", "c.add", "c.addi", "mv", "c.mv", "addw", "addiw",
             "c.addiw", "lui", "c.lui", "ld", "lw", "lbu", "lhu", "auipc",
             "slli", "c.slli", "sd", "sw", "sb", "sh")

stores_out = []
lui_sites = []
for i, (a, s, m, o) in enumerate(rows):
    if m != "lui":
        continue
    p = parse(o)
    if len(p) != 2 or p[1] != "0x88":
        continue
    lui_sites.append((i, a, p[0]))

print(f"=== {len(lui_sites)} sites `lui X, 0x88` ===")
for i, a, r0 in lui_sites:
    alias = {r0}
    j = i + 1
    while j < min(i + 60, n):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if pp and pp[0] in alias and mm in ALIAS_DEF:
            # la base est redéfinie à partir d'une source aliasée ?
            srcs = set()
            if len(pp) >= 2 and is_reg(pp[1]):
                srcs.add(pp[1])
            if len(pp) >= 3 and is_reg(pp[2]) and pp[2] != "zero":
                srcs.add(pp[2])
            if len(pp) == 2 and mm in ("addi", "addiw", "c.addi", "c.addiw") \
                    and not is_reg(pp[1]):
                srcs.add(pp[0])
            if mm in ("mv", "c.mv", "ld", "lw", "lbu", "lhu", "auipc", "lui",
                      "c.lui"):
                alias.discard(pp[0])  # redéfinition non-aliasée (valeur fraîche)
            else:
                alias.discard(pp[0])
                alias |= (srcs & alias) | ({pp[0]} if (srcs & alias) else set())
                if srcs & alias:
                    alias.add(pp[0])
            if mm in ("add", "c.add", "addi", "c.addi", "addw", "addiw",
                      "c.addiw"):
                # rd = rd(ou rs) + X : si rd était aliasé → reste aliasé
                if pp[0] in alias or (len(pp) >= 2 and is_reg(pp[1]) and pp[1] in alias):
                    alias.add(pp[0])
                    if len(pp) >= 2 and is_reg(pp[1]):
                        alias.add(pp[1])
        if mm in ("sd", "sw", "sb", "sh") and pp and len(pp) == 2 \
                and "(" in pp[1]:
            b = pp[1].split("(")[1].rstrip(")")
            if b in alias:
                off = pp[1].split("(")[0]
                stores_out.append({"lui": hex(a), "store": hex(aa),
                                   "off": off, "insn": f"{mm} {oo}"})
        j += 1

# filtre : les offsets 0x130 (écriture de 0x88130) et 0 (écriture via addr fusionnée)
sel = [x for x in stores_out if x["off"] in ("0x130", "0", "0x0")]
print(f"stores via base aliasée lui-0x88 : {len(stores_out)} ; "
      f"avec off 0x130/0 : {len(sel)}")
for x in sel:
    print(f"  lui {x['lui']} → store {x['store']}  [{x['insn']}]")
(OUT / "v48_88130_writers3.json").open("w").write(json.dumps(
    {"all": stores_out, "sel": sel}, indent=1))

# contexte du premier hit off=0x130 / off=0
import bisect
addrs_all = [r[0] for r in rows]
for x in sel[:4]:
    st = int(x["store"], 16)
    i = bisect.bisect_left(addrs_all, st)
    lo, hi = max(0, i - 30), min(n, i + 30)
    lines = [f"  {rows[j][0]:#08x}  {rows[j][2]:10} {rows[j][3]}"
             for j in range(lo, hi)]
    (OUT / f"v88_{st:x}.dump").write_text("\n".join(lines) + "\n")
print("\nv48-ctor3 terminé.")
