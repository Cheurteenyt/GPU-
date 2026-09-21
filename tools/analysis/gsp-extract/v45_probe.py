#!/usr/bin/env python3
"""v45-probe — pour chaque site de référence des dials CheckIgnore :
fenêtre ±W instructions, extraction des `li reg, imm` (imm <= 64 : candidats
bit_index/config) et des jal (cibles). Sortie : tableau + JSON.
"""
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")

SITES = {
    "RmVFPointCheckIgnore(parser)": [0x1631048],
    "RMHwSpeedoCheckIgnore": [0x16AE514, 0x16AEC2A, 0x16AF7AC, 0x17D43EA],
    "RmPmgrIddqCheckIgnore": [0x16AE33E, 0x16AEB46, 0x16AF6C6],
    "RmSramVminCheckIgnore": [0x16AE370, 0x16AEB80, 0x16AF808],
    "RmPmgrIsenseCheckIgnore": [0x16AE428, 0x16AECBA, 0x16AF742],
    "RMDevidCheckIgnore": [0x144DB5E, 0x145DA2E, 0x1B17348],
    "RmClkAdcCalRevCheckIgnore": [0x114D566, 0x116B2C8, 0x116BE16],
    "RmClkAdcTempErrRevCheckIgnore": [0x10DDB70, 0x114D4D6, 0x116B63C],
}

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))

# index par adresse -> rang (le sweep est croissant, addresses uniques)
import bisect
addrs = [r[0] for r in rows]

def idx_of(va):
    i = bisect.bisect_left(addrs, va)
    return i if i < len(rows) and rows[i][0] == va else None

def window(va, before=12, after=28):
    i = idx_of(va)
    if i is None:
        return []
    return rows[max(0, i - before): i + after]

summary = {}
for name, sites in SITES.items():
    for site in sites:
        win = window(site)
        lis, jals, stores = [], [], []
        for a, sz, m, o in win:
            if m in ("li", "c.li"):
                p = [x.strip() for x in o.split(",")]
                if len(p) == 2:
                    try:
                        v = int(p[1], 0)
                        if 0 <= v <= 64:
                            lis.append((hex(a), p[0], v))
                    except ValueError:
                        pass
            elif m == "jal":
                p = [x.strip() for x in o.split(",")]
                if len(p) == 2:
                    jals.append((hex(a), p[1]))
            elif m in ("sd", "sw", "c.sw", "c.sd", "sb", "sh"):
                stores.append((hex(a), m, o))
        rel = [(hex(int(a, 16) - site), *rest) for a, *rest in lis]
        relj = [(hex(int(a, 16) - site), t) for a, t in jals]
        summary[f"{name}@{site:#x}"] = {"li": rel, "jal": relj, "n_stores": len(stores)}

for k, v in summary.items():
    print(f"\n### {k}")
    print(f"  li<=64 : {v['li']}")
    print(f"  jal    : {v['jal']}")

json.dump(summary, (V45 / "probe_checkignore.json").open("w"), indent=1)
print(f"\n-> {V45/'probe_checkignore.json'}")
