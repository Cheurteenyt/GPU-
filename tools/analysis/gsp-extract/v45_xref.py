#!/usr/bin/env python3
"""v45-xref — index des formations d'adresses RISC-V (auipc+addi, lui+addi)
et xref des 8 strings CheckIgnore + appelants du chercheur BOARDOBJ 0x1457440.

Sorties :
  - sites de formation des 8 adresses de strings (toute la zone texte)
  - carte de la table du parseur 0x1630f00..0x1631500 (strings référencées)
  - appelants jal du chercheur 0x1457440 (enum requêtes)
"""
import json
from collections import defaultdict
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
TARGETS = {
    0x1E086D8: "RMDevidCheckIgnore",
    0x1E714F0: "RMHwSpeedoCheckIgnore",
    0x1DFBB50: "RmClkAdcCalRevCheckIgnore",
    0x1DFBB70: "RmClkAdcTempErrRevCheckIgnore",
    0x1E71568: "RmPmgrIddqCheckIgnore",
    0x1E71648: "RmPmgrIsenseCheckIgnore",
    0x1E71580: "RmSramVminCheckIgnore",
    0x1E71130: "RmVFPointCheckIgnore",
}
PARSER_LO, PARSER_HI = 0x1630F00, 0x1631500
SEARCHER = 0x1457440
LOOKAHEAD = 8

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
print(f"chargé {len(rows)} instructions")

def parse_ops(o):
    return [x.strip() for x in o.split(",")]

# --- 1) formations d'adresses ---
hits = defaultdict(list)          # formed -> [(site, kind)]
parser_strings = defaultdict(list)  # formed -> [site] restreint à la région parseur
searcher_callers = []

n = len(rows)
for i, (a, s, m, o) in enumerate(rows):
    if m in ("auipc", "lui"):
        p = parse_ops(o)
        if len(p) != 2:
            continue
        rd = p[0]
        try:
            hi20 = int(p[1], 0) << 12
        except ValueError:
            continue
        base = a + hi20 if m == "auipc" else hi20  # lui = absolu
        kind = m
        # lookahead: addi rd, rd, imm (ou c.addi) dans les LOOKAHEAD suivantes
        for j in range(i + 1, min(i + 1 + LOOKAHEAD, n)):
            a2, s2, m2, o2 = rows[j]
            if m2 in ("addi", "c.addi"):
                p2 = parse_ops(o2)
                if len(p2) == 3 and p2[0] == rd and p2[1] == rd:
                    try:
                        lo12 = int(p2[2], 0)
                    except ValueError:
                        break
                    formed = base + lo12
                    if formed in TARGETS:
                        hits[formed].append((a, kind + "+addi"))
                    if PARSER_LO <= a <= PARSER_HI:
                        parser_strings[formed].append(a)
                    break
                # rd écrasé par autre chose que lui-même -> fin de chaîne
                if p2[0] == rd:
                    break
            elif m2 in ("mv", "c.mv") and parse_ops(o2) and parse_ops(o2)[0] == rd:
                break
        # formation SANS addi (adresse page) : utile si la cible est page-alignée
        if m == "auipc" and base in TARGETS:
            hits[base].append((a, "auipc(page)"))
        if m == "lui" and base in TARGETS:
            hits[base].append((a, "lui(page)"))
    elif m == "jal":
        p = parse_ops(o)
        if len(p) == 2 and p[1].startswith("0x"):
            try:
                if int(p[1], 16) == SEARCHER:
                    searcher_callers.append(a)
            except ValueError:
                pass

print("\n=== XREF DES 8 STRINGS CHECKIGNORE (formations texte) ===")
for va, name in sorted(TARGETS.items()):
    h = hits.get(va, [])
    print(f"  {name:30} {va:#x} : {len(h)} site(s) -> {[f'{s:#x}({k})' for s, k in h[:6]]}")

print(f"\n=== TABLE DU PARSEUR {PARSER_LO:#x}..{PARSER_HI:#x} : strings formées ===")
for formed, sites in sorted(parser_strings.items()):
    print(f"  {formed:#x} <- sites {[f'{s:#x}' for s in sites]}")

print(f"\n=== APPELANTS jal DU CHERCHEUR {SEARCHER:#x} : {len(searcher_callers)} ===")
for c in searcher_callers[:40]:
    print(f"  {c:#x}")

json.dump({
    "targets": {hex(k): v for k, v in TARGETS.items()},
    "hits": {hex(k): [[hex(s), kind] for s, kind in v] for k, v in hits.items()},
    "parser_strings": {hex(k): [hex(s) for s in v] for k, v in parser_strings.items()},
    "searcher_callers": [hex(c) for c in searcher_callers],
}, (V45 / "xref_checkignore.json").open("w"), indent=1)
print(f"\n-> {V45/'xref_checkignore.json'}")
