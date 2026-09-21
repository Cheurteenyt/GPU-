#!/usr/bin/env python3
"""v49-ctor — vague 4.9, chantier 1 : le constructeur de l'état perf.

Fenêtre 0x164b000-0x164d000 (module du destructeur 0x164b7be).
1. Frontières de fonctions (prologues RV64 : addi sp,sp,-N / sd ra,-N(sp)).
2. Appels ENTRANTS dans la fenêtre depuis tout X-R (cibles = entrées).
3. Stores aux champs-signature : +0x288, +0x324, +0x460, +0x88130,
   +0x8F188, +0x881A0 — dans la fenêtre, avec traçage de la valeur.
Sortie : stdout + v49/v49_ctor.json + dump fenêtre.
"""
import bisect
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v49")
OUT.mkdir(exist_ok=True)

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]

WIN0, WIN1 = 0x164B000, 0x164D000


def parse(o):
    return [x.strip() for x in o.split(",")]


CALL_MNEMS = {"call", "jal", "c.jal", "c.jalr", "jalr", "tail", "c.j"}


def call_target(m, o, a):
    if m in ("call", "tail"):
        # call rd, sym  -> dernier champ = cible absolue (numérotée par objdump)
        p = parse(o)
        try:
            return int(p[-1], 0)
        except ValueError:
            return None
    if m in ("jal",):
        p = parse(o)
        if len(p) == 2:
            try:
                t = int(p[1], 0)
                if -0x100000 < t < 0x100000:
                    return a + t
            except ValueError:
                return None
    if m in ("c.j",):
        p = parse(o)
        try:
            t = int(p[-1], 0)
            if -0x100000 < t < 0x100000:
                return a + t
        except ValueError:
            return None
    return None


def is_reg(x):
    return not (x[:1].isdigit() or x[0] == "-")


# ------------------------------------------------ 1 : prologues dans la fenêtre
print("=== 1. prologues (frontières de fonctions) 0x164b000-0x164d000 ===")
funcs = []
i0 = bisect.bisect_left(addrs, WIN0)
i = i0
while i < n and rows[i][0] < WIN1:
    a, s, m, o = rows[i]
    p = parse(o)
    # addi sp, sp, -N   ou   sd ra, -N(sp)
    if m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp" and p[1] == "sp" \
            and p[2].startswith("-"):
        funcs.append(a)
    if m == "sd" and len(p) == 2 and p[0] == "ra" and "-" in p[1] \
            and "sp" in p[1]:
        funcs.append(a)
    i += 1
funcs = sorted(set(funcs))
for f in funcs:
    print(f"  {f:#08x}")
print(f"  {len(funcs)} prologue(s)")

# ------------------------------------------------ 2 : appels entrants (toute X-R)
print("\n=== 2. appels entrants dans la fenêtre depuis TOUT X-R ===")
lo, hi = bisect.bisect_left(addrs, WIN0), bisect.bisect_left(addrs, WIN1)
win_set = set(addrs[lo:hi])
incoming = []
for i, (a, s, m, o) in enumerate(rows):
    if WIN0 <= a < WIN1:
        continue
    t = call_target(m, o, a)
    if t in win_set:
        incoming.append((a, m, o, t))
for a, m, o, t in incoming:
    print(f"  {a:#08x}  {m} {o}  → {t:#08x}")
print(f"  {len(incoming)} appel(s) entrant(s)")

# ------------------------------------------------ 3 : stores champs-signature
print("\n=== 3. stores aux champs-signature dans la fenêtre ===")
SIG = ("0x288", "0x324", "0x460", "0x88130", "0x8f188", "0x881a0", "0x88130(")
sig_stores = []
for i in range(lo, hi):
    a, s, m, o = rows[i]
    if m not in ("sd", "sw", "sh", "sb"):
        continue
    p = parse(o)
    if len(p) != 2 or "(" not in p[1]:
        continue
    disp = p[1].split("(")[0]
    if disp.lstrip("-") in ("288", "324", "460", "88130", "8f188", "881a0"):
        sig_stores.append((a, m, o))
for a, m, o in sig_stores:
    print(f"  {a:#08x}  {m} {o}")
print(f"  {len(sig_stores)} store(s) signature")

# ------------------------------------------------ 4 : dump fenêtre + json
lines = []
for i in range(lo, hi):
    a, s, m, o = rows[i]
    lines.append(f"{a:#08x}  {m:10} {o}")
(OUT / "v49_ctor_window.dump").write_text("\n".join(lines) + "\n")
json.dump({"funcs": [hex(f) for f in funcs],
           "incoming": [(hex(a), m, o, hex(t)) for a, m, o, t in incoming],
           "sig_stores": [(hex(a), m, o) for a, m, o in sig_stores]},
          (OUT / "v49_ctor.json").open("w"), indent=1)
print("\n→ v49_ctor_window.dump / v49_ctor.json")
