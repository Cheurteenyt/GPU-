#!/usr/bin/env python3
"""v45-bits — census des bits lus/écrits dans le mot de capacité (+0x324/+0x328).

Pour chacun des 509 sites v44 : fenêtre ±40 instructions, extraction des
tests de bits (andi/c.andi imm, srli/srai/sraiw/srliw shamt) et des
immédiats li<=31 feedant un and/or. Agrégat : immédiat -> sites.

Sortie : scratch-gsp/v45/cap_bits.json + tableau stdout.
"""
import json
import bisect
from collections import defaultdict
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
CAP_IMMS = (0x324, 0x328)

sites = json.load((Path("/home/z/my-project/scratch-gsp/v44") / "sites.json").read_text() and open("/home/z/my-project/scratch-gsp/v44/sites.json"))

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]

def idx_of(va):
    i = bisect.bisect_left(addrs, va)
    return i if i < len(rows) and rows[i][0] == va else None

SHIFT_OPS = {"srli", "srai", "srliw", "sraiw", "c.srli", "c.srai", "c.srliw", "c.srli64", "srli64", "srai64"}
AND_OPS = {"andi", "c.andi"}

bit_tests = defaultdict(set)     # imm -> {site}
shamt_tests = defaultdict(set)   # shamt -> {site}
li_small_near = defaultdict(set) # v -> {site}

for st in sites:
    va = st["addr"]
    i = idx_of(va)
    if i is None:
        continue
    lo, hi = max(0, i - 40), min(len(rows), i + 40)
    for j in range(lo, hi):
        a, s, m, o = rows[j]
        p = [x.strip() for x in o.split(",")]
        if m in AND_OPS and len(p) == 3:
            try:
                imm = int(p[2], 0)
                if 0 <= imm <= 0xFFFF:
                    bit_tests[imm].add(va)
            except ValueError:
                pass
        elif m in SHIFT_OPS and len(p) == 3:
            try:
                sh = int(p[2], 0)
                if 0 <= sh <= 31:
                    shamt_tests[sh].add(va)
            except ValueError:
                pass
        elif m in ("li", "c.li") and len(p) == 2:
            try:
                v = int(p[1], 0)
                if 0 <= v <= 31:
                    li_small_near[v].add(va)
            except ValueError:
                pass

print("=== ANDI imm près des accès +0x324/+0x328 (bits testés en place) ===")
for imm, ss in sorted(bit_tests.items()):
    print(f"  andi {imm:#06x} (bit {imm.bit_length()-1 if imm and not (imm & (imm-1)) else 'multi'}): {len(ss)} site(s) {sorted(hex(x) for x in list(ss)[:8])}")

print("\n=== SRLI/SRAIW shamt près des accès (extraction bit -> bit 0) ===")
for sh, ss in sorted(shamt_tests.items()):
    print(f"  shift {sh}: {len(ss)} site(s) {sorted(hex(x) for x in list(ss)[:8])}")

out = {
    "andi": {str(k): sorted(hex(x) for x in v) for k, v in sorted(bit_tests.items())},
    "shift": {str(k): sorted(hex(x) for x in v) for k, v in sorted(shamt_tests.items())},
}
json.dump(out, (V45 / "cap_bits.json").open("w"), indent=1)
print(f"\n-> {V45/'cap_bits.json'}")
