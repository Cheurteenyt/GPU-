#!/usr/bin/env python3
"""v46-enum — l'enum des requêtes construites par 0x1456c7c.

Pour chacun des 52 appelants : backward ≤ 10 insns pour capturer
  - le N du prep 0x18E11F8 (li/c.li a2, imm) — candidat « type/format »
  - la TABLE (formation auipc+addi vers a1)
  - l'offset a3 (addi aX, sY, imm / lui+addi)
+ scan global des formations de 0x1E71260 ('PerfPmaControlReg')
  pour trouver son vrai site de consommation.
+ N du site post-grand-parseur (fenêtre avant 0x1632816).

Sortie : scratch-gsp/v45/v46_enum.json
"""
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
CTOR = 0x1456C7C
PREP = 0x18E11F8
TARGET_PERF_PMA = 0x1E71260

rm = RM.read_bytes()

def cstr(va, maxlen=72):
    off = va - 0x1000000
    if off < 0 or off >= len(rm):
        return None
    end = rm.find(b"\x00", off, off + maxlen)
    if end < 0:
        end = off + maxlen
    try:
        s = rm[off:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if len(s) >= 3 and all(32 <= ord(c) < 127 for c in s) else None

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))

def parse(o):
    return [x.strip() for x in o.split(",")]

n = len(rows)

# appelants du ctor (même mécanique que v46_ctor)
sites = []
for i, (a, s, m, o) in enumerate(rows):
    if m == "jal":
        p = parse(o)
        if len(p) == 2 and p[1].startswith("0x") and int(p[1], 16) == CTOR:
            sites.append((i, a))
    elif m == "auipc" and parse(o) and parse(o)[0] == "ra":
        p = parse(o)
        try:
            hi = int(p[1], 0) << 12
        except ValueError:
            continue
        for j in (i + 1, i + 2):
            if j >= n:
                break
            m2, o2 = rows[j][2], rows[j][3]
            if m2 == "jalr":
                p2 = parse(o2)
                if len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    if base + int(p2[2], 0) == CTOR:
                        sites.append((i, a))
                    break
            if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == "ra":
                break

print(f"{len(sites)} appelants du ctor")

enum = []
for i, a in sites:
    li_a2, table, a3_off = None, None, None
    for j in range(i - 1, max(-1, i - 11), -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm in ("li", "c.li") and len(pp) == 2 and pp[0] == "a2":
            try:
                v = int(pp[1], 0)
                if 0 <= v <= 0x80:
                    li_a2 = v
            except ValueError:
                pass
        if mm in ("auipc", "lui") and len(pp) == 2 and pp[0] == "a1":
            try:
                hi = int(pp[1], 0) << 12
            except ValueError:
                continue
            base = aa + hi if mm == "auipc" else hi
            if base >= 0x80000000:
                base -= 0x100000000
            for u in (j + 1, j + 2, j + 3):
                if u >= n:
                    break
                m2, o2 = rows[u][2], rows[u][3]
                p2 = parse(o2)
                if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == "a1" and p2[1] == "a1":
                    try:
                        table = base + int(p2[2], 0)
                    except ValueError:
                        pass
                    break
                if p2 and p2[0] == "a1":
                    break
        if mm == "addi" and len(pp) == 3 and pp[0] == "a3":
            try:
                a3_off = int(pp[2], 0)
            except ValueError:
                pass
    entry = {"site": hex(a), "N": li_a2, "table": hex(table) if table else None,
             "a3_off": hex(a3_off) if a3_off is not None else None}
    enum.append(entry)
    print(f"  {a:#08x}  N={li_a2}  table={entry['table']}  a3off={entry['a3_off']}")

from collections import Counter
census_n = Counter(e["N"] for e in enum)
census_t = Counter(e["table"] for e in enum)
print("\ncensus N  :", dict(sorted(census_n.items(), key=lambda kv: (kv[0] is None, kv[0]))))
print("census tbl:", dict(census_t))

# formations globales de PerfPmaControlReg (0x1E71260)
print(f"\n=== formations globales de {TARGET_PERF_PMA:#x} ('PerfPmaControlReg') ===")
perf_sites = []
for i, (a, s, m, o) in enumerate(rows):
    if m not in ("auipc", "lui"):
        continue
    p = parse(o)
    if len(p) != 2:
        continue
    try:
        hi = int(p[1], 0) << 12
    except ValueError:
        continue
    rd = p[0]
    base = a + hi if m == "auipc" else hi
    if base >= 0x80000000:
        base -= 0x100000000
    if abs(base - TARGET_PERF_PMA) > 0x8000:
        continue
    for u in range(i + 1, min(i + 9, n)):
        m2, o2 = rows[u][2], rows[u][3]
        p2 = parse(o2)
        if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == rd and p2[1] == rd:
            try:
                formed = base + int(p2[2], 0)
            except ValueError:
                break
            if formed == TARGET_PERF_PMA:
                perf_sites.append(hex(a))
                print(f"  formé au site {a:#x}")
            break
        if p2 and p2[0] == rd:
            break
if not perf_sites:
    print("  AUCUNE formation auipc+addi — string consommée autrement (lui nu / data relative)")

# N du site post-grand-parseur : fenêtre avant 0x1632816
print("\n=== fenêtre avant le 3e site (0x1632816) ===")
import bisect
addrs = [r[0] for r in rows]
i0 = bisect.bisect_left(addrs, 0x16327D0)
while i0 < len(rows) and rows[i0][0] <= 0x1632816:
    a, s, m, o = rows[i0]
    print(f"  {a:#08x}  {m:10} {o}")
    i0 += 1

json.dump({"enum": enum, "census_N": {str(k): v for k, v in census_n.items()},
           "census_tables": {str(k): v for k, v in census_t.items()},
           "perf_pma_formed_at": perf_sites},
          (V45 / "v46_enum.json").open("w"), indent=1)
print(f"\n-> {V45/'v46_enum.json'}")
