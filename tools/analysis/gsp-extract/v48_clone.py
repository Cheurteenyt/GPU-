#!/usr/bin/env python3
"""v48-clone — vague 4.8, chantier 1 : remonter le clone-source du callback PMA.

La 4.7 a établi : [état RM +0x288] (callback PMA) est rempli PAR CLONE par des
copieurs champ-par-champ (0x1156xxx/0x1159xxx). Ce script :
1. dresse les fenêtres des copieurs (±0x60) autour des stores à 0x288(a2) ;
2. identifie la base SOURCE de chaque copie (ld X, 0x288(src) amont) ;
3. borne la fonction englobante de chaque copieur (prologue le plus proche) ;
4. résout les appelants (auipc+jalr) des fonctions englobantes.
Sortie : stdout + v48_clone.json.
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


def resolve_auipc_jalr(i):
    a, s, m, o = rows[i]
    p = parse(o)
    if m == "jalr" and len(p) == 3 and p[0] == p[1]:
        for k in (i - 1, i - 2):
            if k < 0:
                break
            ka, ks, km, ko = rows[k]
            kp = parse(ko)
            if km == "auipc" and len(kp) == 2 and kp[0] == p[1]:
                base = ka + (int(kp[1], 0) << 12)
                if base >= 0x80000000:
                    base -= 0x100000000
                return base + int(p[2], 0)
    return None


COPIERS = [0x115665e, 0x1156e2a, 0x1157282, 0x1157a9c,
           0x115996c, 0x1159cac, 0x115a108, 0x115a324,
           0x115fa8e, 0x11600d8]
prologue_mnems = {"c.addi16sp", "addi", "addi16sp"}  # addi sp, sp, -N


def find_func_start(i):
    """Marche arrière jusqu'au prologue c.addi16sp/addi sp,-N qui suit un c.jr ra."""
    for j in range(i, max(0, i - 400), -1):
        a, s, m, o = rows[j]
        p = parse(o)
        if m == "c.addi16sp" and p and p[0].startswith("-"):
            return a
        if m == "addi" and len(p) == 3 and p[0] == "sp" and p[1] == "sp" \
                and p[2].startswith("-"):
            return a
    return None


print("=== 1-2. fenêtres des copieurs : base source de chaque +0x288 ===")
report = []
for site in COPIERS:
    i = bisect.bisect_left(addrs, site)
    win_lo, win_hi = max(0, i - 40), min(n, i + 6)
    src = None
    valreg = parse(rows[i][3])[0]
    # en arrière : qui écrit valreg ? ld valreg, 0x288(base) ?
    for j in range(i - 1, max(0, i - 30) - 1, -1):
        a, s, m, o = rows[j]
        p = parse(o)
        if m == "ld" and len(p) == 2 and p[0] == valreg and "(" in p[1]:
            src = {"site": hex(a), "insn": f"ld {o}"}
            break
        if m in ("auipc", "lui") and p and p[0] == valreg:
            src = {"site": hex(a), "insn": f"CONST {m} {o}"}
            break
    fstart = find_func_start(i)
    head = (f"\n--- copieur {site:#x} (val {valreg}) ; "
            f"src = {src} ; fonction ≈ "
            f"{hex(fstart) if fstart else '?'} ---")
    print(head)
    lines = []
    for j in range(win_lo, win_hi):
        a, s, m, o = rows[j]
        lines.append(f"  {a:#08x}  {m:10} {o}")
    fname = OUT / f"v48_cop_{site:x}.dump"
    fname.write_text("\n".join(lines) + "\n")
    print(f"  fenêtre → {fname.name} ({len(lines)} instr)")
    report.append({"site": hex(site), "valreg": valreg, "src": src,
                   "func_start": hex(fstart) if fstart else None})

# ------------------------------------------------ 3 : appelants des fonctions
print("\n=== 3. appelants des fonctions englobantes ===")
starts = sorted({int(r["func_start"], 16) for r in report
                 if r["func_start"] and int(r["func_start"], 16) != 0
                 and int(r["func_start"], 16) != 0})
callers = {}
for st in starts:
    sites = []
    for i, (a, s, m, o) in enumerate(rows):
        if m != "auipc":
            continue
        p = parse(o)
        if len(p) != 2:
            continue
        for j in (i + 1, i + 2):
            if j >= n:
                break
            a2, s2, m2, o2 = rows[j]
            if m2 == "jalr":
                p2 = parse(o2)
                if len(p2) == 3 and p2[0] == p2[1]:
                    hi = int(p[1], 0) << 12
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    if base + int(p2[2], 0) == st:
                        sites.append(hex(a))
                    break
            if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == p[0]:
                break
    callers[hex(st)] = sites
    print(f"  fonction {st:#x} : {len(sites)} appelant(s) : {sites[:10]}")

(OUT / "v48_clone.json").open("w").write(json.dumps(
    {"copiers": report, "callers": callers}, indent=1))
print("\nv48-clone terminé.")
