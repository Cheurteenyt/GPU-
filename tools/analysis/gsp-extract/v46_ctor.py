#!/usr/bin/env python3
"""v46-ctor — vague 4.6 : le constructeur de requêtes 0x1456c7c et l'enum des types.

A. Appelants COMPLETS de 0x1456c7c (jal + paires auipc+jalr) avec
   backward-resolve a0-a3 (WIN 80) — l'enum des types demandés.
B. Déroulé de la fenêtre du constructeur lui-même (les premiers 0x60 mots).
C. Lecture de la table 0x16346c8 (a1 du constructeur au site VF) : octets +
   strings pointées (mapping VA = off + 0x1000000).
D. Vérification ponctuelle : cstr(0x1E76C60) vs cstr(0x1E71260) (W4 addi).

Sortie : scratch-gsp/v45/v46_ctor.json
"""
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
CTOR = 0x1456C7C
WIN = 80

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
print(f"chargé {len(rows)} instructions")

def parse(o):
    return [x.strip() for x in o.split(",")]

n = len(rows)

# --- A. appelants du constructeur ---
sites = []
for i, (a, s, m, o) in enumerate(rows):
    if m == "jal":
        p = parse(o)
        if len(p) == 2 and p[1].startswith("0x"):
            try:
                if int(p[1], 16) == CTOR:
                    sites.append((i, a, "jal"))
            except ValueError:
                pass
    elif m == "auipc":
        p = parse(o)
        if len(p) != 2 or p[0] != "ra":
            continue
        try:
            hi = int(p[1], 0) << 12
        except ValueError:
            continue
        for j in (i + 1, i + 2):
            if j >= n:
                break
            a2, s2, m2, o2 = rows[j]
            if m2 == "jalr":
                p2 = parse(o2)
                if len(p2) == 3 and p2[0] == "ra" and p2[1] == "ra":
                    try:
                        lo = int(p2[2], 0)
                    except ValueError:
                        break
                    base = a + hi
                    if base >= 0x80000000:
                        base -= 0x100000000
                    if base + lo == CTOR:
                        sites.append((i, a, "a+j"))
                    break
            if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == "ra":
                break

print(f"\n=== A. APPELANTS DU CONSTRUCTEUR {CTOR:#x} : {len(sites)} ===")
KIND_LI = {"li", "c.li"}
KIND_ADDI = {"addi", "c.addi"}
KIND_MV = {"mv", "c.mv"}
out_sites = []
for i, a, kind in sites:
    regs, found = {}, {}
    for j in range(i - 1, max(-1, i - 1 - WIN), -1):
        aa, ss, mm, oo = rows[j]
        pp = parse(oo)
        if mm in KIND_LI and len(pp) == 2:
            d = pp[0]
            if d not in found:
                try:
                    regs[d] = int(pp[1], 0)
                except ValueError:
                    regs[d] = None
        elif mm in KIND_ADDI and len(pp) == 3:
            d, src = pp[0], pp[1]
            if d not in found:
                try:
                    imm = int(pp[2], 0)
                except ValueError:
                    regs[d] = None
                    continue
                if src in ("zero", "x0"):
                    regs[d] = imm
                elif src == d and regs.get(d) is not None:
                    regs[d] = regs[d] + imm
                else:
                    regs[d] = None
        elif mm in KIND_MV and len(pp) == 2:
            d, src = pp[0], pp[1]
            if d not in found:
                regs[d] = regs.get(src)
        for r in ("a0", "a1", "a2", "a3"):
            if r not in found and r in regs:
                found[r] = (regs[r], i - j)
        if len(found) == 4:
            break
    st = {
        "site": hex(a), "kind": kind,
        "a0": found.get("a0", (None, None))[0],
        "a1": found.get("a1", (None, None))[0],
        "a2": found.get("a2", (None, None))[0],
        "a3": found.get("a3", (None, None))[0],
    }
    out_sites.append(st)
    print(f"  {a:#08x} ({kind})  a0={st['a0']} a1={st['a1']} a2={st['a2']} a3={st['a3']}")

# --- B. fenêtre du constructeur ---
print(f"\n=== B. CONSTRUCTEUR {CTOR:#x} : premiers 90 mots ===")
import bisect
addrs = [r[0] for r in rows]
i0 = bisect.bisect_left(addrs, CTOR)
for k in range(i0, min(i0 + 90, n)):
    a, s, m, o = rows[k]
    print(f"  {a:#08x}  {m:10} {o}")
    if m in ("c.jr", "ret", "jr") and k > i0 + 4:
        break

# --- C. table 0x16346c8 ---
print(f"\n=== C. TABLE 0x16346C8 : 20 entrées de 8 octets (motifs) ===")
off = 0x16346C8 - 0x1000000
tbl = []
for e in range(20):
    b = rm[off + 8 * e: off + 8 * e + 8]
    q = int.from_bytes(b, "little")
    entry = {"idx": e, "raw": b.hex(), "qw": hex(q)}
    if 0x1000000 <= q < 0x1E85000:
        entry["as_va"] = hex(q)
        entry["string"] = cstr(q)
    tbl.append(entry)
    print(f"  [{e:2}] {b.hex()}  qw={q:#x}" + (f"  -> {entry['string']!r}" if entry.get("string") else ""))

# --- D. vérification strings W4 ---
print("\n=== D. VÉRIF STRINGS W4 ===")
for va in (0x1E71260, 0x1E76C60, 0x1E76B00, 0x1E71170, 0x169819C):
    print(f"  cstr({va:#x}) = {cstr(va)!r}")

json.dump({"ctor_callers": out_sites, "table_16346c8": tbl},
          (V45 / "v46_ctor.json").open("w"), indent=1)
print(f"\n-> {V45/'v46_ctor.json'}")
