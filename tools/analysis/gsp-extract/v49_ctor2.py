#!/usr/bin/env python3
"""v49-ctor2 — vague 4.9 : anatomie complète de la fonction du destructeur.

1. Début de fonction contenant 0x164b7be (scan arrière de prologue).
2. Fin de fonction (scan avant).
3. Appels SORTANTS résolus (auipc+jalr) depuis toute la fonction.
4. Appels ENTRANTS vers l'entrée de fonction.
5. Stores s2/s3-relative aux champs-signature sur TOUTE la fonction.
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


DESTR = 0x164B7BE

# --- début de fonction : dernier `addi sp, sp, -N` avant DESTR
di = bisect.bisect_left(addrs, DESTR)
fstart = None
for i in range(di, -1, -1):
    a, s, m, o = rows[i]
    p = parse(o)
    if (m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
            and p[1] == "sp" and p[2].startswith("-")):
        fstart = (i, a)
        break
    if m == "c.addi16sp" and p and p[-1].startswith("-"):
        fstart = (i, a)
        break
print(f"début de fonction candidat : {fstart[1]:#08x} (idx {fstart[0]})")

# --- fin de fonction : prochain prologue après DESTR (épilogue-like aussi)
fend = None
for i in range(di, n):
    a, s, m, o = rows[i]
    p = parse(o)
    if (m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
            and p[1] == "sp" and p[2].startswith("-")):
        fend = (i, a)
        break
print(f"prologue suivant : {fend[1]:#08x} (idx {fend[0]})")

fs, fe = fstart[0], fend[0]
print(f"taille : {rows[fe][0]-rows[fs][0]:#x} octets, {fe-fs} instructions")

# --- appels sortants résolus : auipc ra, imm ; jalr ra, ra, imm
print("\n=== appels sortants résolus ===")
calls = []
i = fs
while i < fe:
    a, s, m, o = rows[i]
    p = parse(o)
    if m == "auipc" and len(p) == 2 and is_reg(p[0]):
        rd, imm1 = p[0], int(p[1], 0)
        j = i + 1
        while j < min(i + 6, fe):
            aa, ss, mm, oo = rows[j]
            pp = parse(oo)
            if mm in ("jalr",) and len(pp) == 3 and pp[0] == rd and pp[1] == rd:
                try:
                    imm2 = int(pp[2], 0)
                except ValueError:
                    break
                tgt = (a + (imm1 << 12) + imm2) & 0xFFFFFFFF
                calls.append((a, aa, tgt))
                break
            if mm in ("addi", "c.add", "c.addi") and len(pp) >= 2 and is_reg(pp[0]) \
                    and pp[1] == rd and pp[0] == rd:
                # rd = rd + imm (rare) — continuer à chercher jalr sur rd
                j += 1
                continue
            if mm in ("c.mv", "mv") and len(pp) == 2 and pp[0] == rd:
                break  # rd réassigné — abandon
            j += 1
    i += 1
# dédoublonner par adresse d'appel
seen = set()
uniq = []
for a, aa, t in calls:
    if a not in seen:
        seen.add(a)
        uniq.append((a, aa, t))
for a, aa, t in uniq:
    print(f"  {a:#08x} → {t:#08x}")
print(f"  {len(uniq)} appel(s) sortant(s) résolu(s)")

# --- entrants vers fstart
print("\n=== appels entrants vers l'entrée ===")
inc = []
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m in ("call", "tail") and p:
        try:
            if int(p[-1], 0) == fstart[1]:
                inc.append((a, m, o))
        except ValueError:
            pass
    if m in ("jal",) and len(p) == 2:
        try:
            t = int(p[1], 0)
            if -0x100000 < t < 0x100000 and a + t == fstart[1]:
                inc.append((a, m, o))
        except ValueError:
            pass
    if m in ("c.j",) and p:
        try:
            t = int(p[-1], 0)
            if -0x100000 < t < 0x100000 and a + t == fstart[1]:
                inc.append((a, m, o))
        except ValueError:
            pass
for a, m, o in inc:
    print(f"  {a:#08x}  {m} {o}")
print(f"  {len(inc)} entrant(s)")

# --- stores s2/s3 aux champs-signature sur la fonction
print("\n=== stores s2/s3 +0x288/+0x324/+0x460/+0x88130/+0x8F188 sur la fonction ===")
SIG = {"0x288", "0x324", "0x460", "0x88130", "0x8f188", "0x881a0"}
hits = []
for i in range(fs, fe):
    a, s, m, o = rows[i]
    if m not in ("sd", "sw", "sh", "sb"):
        continue
    p = parse(o)
    if len(p) != 2 or "(" not in p[1]:
        continue
    disp, base = p[1].split("(")
    base = base.rstrip(")")
    if disp.lstrip("-") in {x.lstrip("0x") for x in SIG} and base in ("s2", "s3"):
        hits.append((a, m, o))
for a, m, o in hits:
    print(f"  {a:#08x}  {m} {o}")
print(f"  {len(hits)} store(s)")

json.dump({"fstart": hex(fstart[1]), "fend": hex(fend[1]),
           "out_calls": [(hex(a), hex(t)) for a, aa, t in uniq],
           "incoming": [(hex(a), m, o) for a, m, o in inc],
           "sig_stores": [(hex(a), m, o) for a, m, o in hits]},
          (OUT / "v49_ctor2.json").open("w"), indent=1)

# dump complet de la fonction
lines = []
for i in range(fs, fe):
    a, s, m, o = rows[i]
    lines.append(f"{a:#08x}  {m:10} {o}")
(OUT / "v49_destructor_func.dump").write_text("\n".join(lines) + "\n")
print("\n→ v49_destructor_func.dump / v49_ctor2.json")
