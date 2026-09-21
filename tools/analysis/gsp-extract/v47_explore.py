#!/usr/bin/env python3
"""v47-explore — vague 4.7 : trois sondes en un chargement du TSV v45.

A : déroulé du dispatcher moteur 0x1634a38 (réconciliation N ctor ↔ type moteur)
B : scan global des écrivains/lecteurs de [obj+0x288] (callback PerfPmaControlReg)
C : census des appels vers la passe P-states 0x1B3C4F4 + jal vers l'entrée de boucle

Sorties : scratch-gsp/v47/*.dump + résumé stdout.
"""
import bisect
import re
import sys
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v47")
OUT.mkdir(parents=True, exist_ok=True)

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]
print(f"TSV chargé : {len(rows)} instructions", file=sys.stderr)


def dump_window(name, lo, hi, out=None):
    """Déroulé brut d'une fenêtre d'adresses → fichier + retourne lignes."""
    i0 = bisect.bisect_left(addrs, lo)
    lines = []
    while i0 < len(rows) and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        lines.append(f"  {a:#08x}  {m:10} {o}")
        i0 += 1
    p = out or (OUT / f"{name}.dump")
    p.write_text("\n".join(lines) + "\n")
    print(f"[window] {name}: {len(lines)} instr → {p}")
    return lines


def scan_mem_offset(off, ops_regex=None):
    """Toutes les instructions accédant [reg+off] (offset décimal dans operands)."""
    pat = re.compile(rf",(?:{off})\(")
    hits = []
    for a, s, m, o in rows:
        if pat.search(o):
            if ops_regex is None or re.search(ops_regex, m + " " + o):
                hits.append((a, m, o))
    return hits


def scan_calls(target):
    """Tous les jal/jalr dont la destination (immédiate) == target."""
    hits = []
    t = f"{target:#x}"
    for a, s, m, o in rows:
        if m in ("jal", "jalr") and o.rstrip().endswith(t):
            hits.append((a, m, o))
    return hits


# ---------------------------------------------------------------- A : dispatcher
DISP_LO, DISP_HI = 0x1634A38, 0x1635700
dump_window("v47_A_dispatcher", DISP_LO, DISP_HI)

# qui appelle le dispatcher ?
calls_disp = scan_calls(DISP_LO)
print(f"[A] jal→dispatcher 0x1634a38 : {len(calls_disp)}")
for a, m, o in calls_disp[:40]:
    print(f"    {a:#08x}  {m} {o}")

# ---------------------------------------------------------------- B : +0x288
hits_288 = scan_mem_offset(648)
print(f"[B] accès [reg+0x288] : {len(hits_288)}")
stores = [(a, m, o) for a, m, o in hits_288 if m.startswith("s")]
loads = [(a, m, o) for a, m, o in hits_288 if m.startswith("l")]
print(f"    stores: {len(stores)}  loads: {len(loads)}")
(OUT / "v47_B_288.txt").write_text(
    "STORES:\n" + "\n".join(f"  {a:#08x}  {m:8} {o}" for a, m, o in stores)
    + "\nLOADS:\n" + "\n".join(f"  {a:#08x}  {m:8} {o}" for a, m, o in loads) + "\n"
)
for a, m, o in stores[:40]:
    print(f"    S {a:#08x}  {m} {o}")

# ---------------------------------------------------------------- C : passe P-states
calls_pass = scan_calls(0x1B3C4F4)
print(f"[C] jal→passe 0x1b3c4f4 : {len(calls_pass)}")
for a, m, o in calls_pass:
    print(f"    {a:#08x}  {m} {o}")
(OUT / "v47_C_pass_calls.txt").write_text(
    "\n".join(f"  {a:#08x}  {m} {o}" for a, m, o in calls_pass) + "\n"
)

# jal sortant de la région boucle (0x1631860..0x1631a80) vers ailleurs → structure
lines_w1 = dump_window("v47_C_loop_entry", 0x1631840, 0x1631A80)
print("vague 4.7 : sondes A/B/C écrites dans", OUT)
