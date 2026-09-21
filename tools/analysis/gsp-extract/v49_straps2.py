#!/usr/bin/env python3
"""v49-straps2 — vague 4.9 : tables au fichier + appelants des mappers.

1. Lecture des 27 + 8 entrées 32 bits à 0x1DEB210/0x1DEB280 (rm.elf,
   LOAD1 : off = VA-0x1000000), décodage des cibles (base + offset).
2. Appelants des mappers 0x1b3c5ec (JT1, borne 27) et 0x1b3c708 (JT2,
   borne 8) : auipc+jalr résolus + call/jal.
3. Pour chaque appelant : contexte -14 → l'origine de a0 (le champ 5 bits).
"""
import bisect
import json
import struct
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v49")
ELF = Path("/home/z/my-project/scratch-gsp/rm.elf")
data = ELF.read_bytes()


def va2off(va):
    if 0x1000000 <= va < 0x1000000 + 0xE85000:
        return va - 0x1000000
    if 0x4000000 <= va < 0x4000000 + 0x19C000:
        return 0xE85000 + (va - 0x4000000)
    return None


def read_va(va, n):
    o = va2off(va)
    return data[o:o + n] if o is not None else None


print("=== JT1 @ 0x1DEB210 (27 entrées, base relative) ===")
base = 0x1DEB210
b = read_va(base, 27 * 4)
for k in range(27):
    off = struct.unpack_from("<i", b, k * 4)[0]
    print(f"  [{k:2d}] off {off:+#08x} → {base + off:#08x}")

print("\n=== JT2 @ 0x1DEB280 (8 entrées) ===")
base2 = 0x1DEB280
b2 = read_va(base2, 8 * 4)
for k in range(8):
    off = struct.unpack_from("<i", b2, k * 4)[0]
    print(f"  [{k}] off {off:+#08x} → {base2 + off:#08x}")

# ---- appelants des mappers
rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]
addrs_set = set(addrs)


def parse(o):
    return [x.strip() for x in o.split(",")]


MAPS = {0x1B3C5EC: "JT1_user(27)", 0x1B3C708: "JT2_user(8)"}
callers = {t: [] for t in MAPS}
for i, (a, s, m, o) in enumerate(rows):
    p = parse(o)
    if m == "auipc" and len(p) == 2 and p[0] == "ra":
        hi20 = int(p[1], 0)
        if i + 1 < n:
            aa, ss, mm, oo = rows[i + 1]
            pp = parse(oo)
            if mm == "jalr" and len(pp) == 3 and pp[0] == "ra" and pp[1] == "ra":
                try:
                    t = (a + (hi20 << 12) + int(pp[2], 0)) & 0xFFFFFFFF
                except ValueError:
                    continue
                if t in MAPS:
                    callers[t].append(a)
    elif m in ("call", "tail", "jal") and p:
        try:
            t = int(p[-1], 0)
            if m == "jal" and -0x100000 < t < 0x100000:
                t = a + t
            if t in MAPS:
                callers[t].append(a)
        except ValueError:
            pass

for t, name in MAPS.items():
    print(f"\n=== appelants {name} {t:#08x} : {len(callers[t])} ===")
    for ca in callers[t]:
        print(f"  {ca:#08x}")


def dump(lo, hi, title):
    print(f"--- {title} ---")
    i0 = bisect.bisect_left(addrs, lo)
    while i0 < n and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        print(f"  {a:#08x}  {m:10} {o}")
        i0 += 1


for t in MAPS:
    for ca in callers[t]:
        dump(ca - 0x40, ca + 4, f"contexte appel {MAPS[t]} @ {ca:#08x}")

json.dump({"jt1": [base + struct.unpack_from('<i', b, k * 4)[0]
                   for k in range(27)],
           "jt2": [base2 + struct.unpack_from('<i', b2, k * 4)[0]
                   for k in range(8)],
           "callers": {MAPS[t]: [hex(c) for c in callers[t]] for t in MAPS}},
          (OUT / "v49_straps2.json").open("w"), indent=1)
