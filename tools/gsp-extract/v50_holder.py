#!/usr/bin/env python3
"""v50-holder — vague 4.10 : l'anatomie du holder [état+0x3AF0].

Le champ holder = [a0+0x3AF0] est unique au consommateur. Son ÉCRIVAIN
donne la création du holder ; l'objet [holder+0x50] est posé par le
constructeur du holder.

Patron d'accès au champ (vu dans le wrapper) : c.lui x, 4 ; c.add x, y
puis ld/sd ..., -0x510(x). Variantes : lui x, 4 ; add x, y.

1. Census de TOUTES les fenêtres formant a0+0x3AF0 (c.lui/lui 4 puis add)
   suivies d'un accès à -0x510 ou +0x3AF0 (≤ 8 insns).
2. Classement ld (lecteurs) / sd (écrivains) / autre.
3. Pour chaque ÉCRIVAIN : fonction porteuse + fenêtre ±30 insns
   (d'où vient la valeur stockée ?).

Sortie : stdout + scratch-gsp/v50/v50_holder.json
"""
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v50")

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)


def parse(o):
    return [x.strip() for x in o.split(",")]


def func_start(idx):
    for i in range(idx, max(-1, idx - 4000), -1):
        m, o = rows[i][2], rows[i][3]
        p = parse(o)
        if (m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
                and p[1] == "sp" and p[2].startswith("-")) or \
           (m == "c.addi16sp" and p and p[-1].startswith("-")):
            return i
    return None


def dump(i0, i1, title):
    print(f"--- {title} ---")
    for j in range(max(0, i0), min(n, i1 + 1)):
        a, s, m, o = rows[j]
        print(f"  {a:#08x}  {m:10} {o}")
    print()


LUI = {"c.lui", "lui"}
ADD = {"c.add", "add"}
acc = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m in LUI and len(p) == 2 and p[1] in ("4", "0x4"):
        reg = p[0]
        for j in range(i + 1, min(i + 3, n)):
            m2, o2 = rows[j][2], rows[j][3]
            p2 = parse(o2)
            if m2 in ADD and len(p2) == 3 and p2[0] == reg and p2[1] == reg:
                # accès ±0x510 dans les 8 insns suivantes
                for k in range(j + 1, min(j + 9, n)):
                    m3, o3 = rows[k][2], rows[k][3]
                    p3 = parse(o3)
                    if "-0x510(" in o3 or "0x3af0(" in o3.lower():
                        fsi = func_start(i)
                        own = rows[fsi][0] if fsi is not None else None
                        kind = "w" if m3 in ("sd", "c.sd") else \
                            ("r" if m3 in ("ld", "c.ld") else "?")
                        acc.append((kind, a, rows[k][0], own, m3, o3))
                    break
                break

reads = [x for x in acc if x[0] == "r"]
writes = [x for x in acc if x[0] == "w"]
other = [x for x in acc if x[0] == "?"]
print(f"accès au champ +0x3AF0 (motif lui-4/add) : {len(acc)}"
      f"  (lectures {len(reads)}, écritures {len(writes)}, autres {len(other)})")
uniq_r = sorted({x[2] for x in reads})
uniq_w = sorted({x[2] for x in writes})
print(f"\nlectures : {[hex(x) for x in uniq_r]}")
print(f"écritures : {[hex(x) for x in uniq_w]}")
if other:
    print(f"autres : {[(hex(x[2]), x[4]) for x in other]}")

for k, a, at, own, m3, o3 in writes:
    print(f"\n=== ÉCRITURE @ {at:#08x} ({m3} {o3}) — fonction {own:#08x} ==="
          if own else f"\n=== ÉCRITURE @ {at:#08x} ({m3} {o3}) ===")
    i = next(idx for idx, r in enumerate(rows) if r[0] == at)
    dump(i - 30, i + 12, "contexte de création")

json.dump({"reads": [hex(x) for x in uniq_r],
           "writes": [hex(x) for x in uniq_w],
           "other": [(hex(x[2]), x[4], x[5]) for x in other]},
          (OUT / "v50_holder.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_holder.json'}")
