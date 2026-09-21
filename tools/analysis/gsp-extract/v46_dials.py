#!/usr/bin/env python3
"""v46-dials — vague 4.6 : le grand parseur perf 0x1631300-0x16327A0.

Partie A : appariement dial <-> site de lookup. Dans la région, on identifie
toutes les formations de strings (auipc+addi, lui+addi -> rodata) et tous les
appels (jal + auipc+jalr) au lookup générique 0x10432d4. Chaque site d'appel
est associé à la string formée dans les LOOKBACK instructions précédentes.
Les strings sont lues dans rm.elf (mapping VA = off + 0x1000000).

Partie B : appels au setter 0x1630c48 dans la même région (backward-resolve
a0-a3, WIN 80) pour l'attribution bits 9/11 par dial.

Sortie : scratch-gsp/v45/v46_dials.json
"""
import json
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
RM = Path("/home/z/my-project/scratch-gsp/rm.elf")

REGION_LO, REGION_HI = 0x1631300, 0x16327A0
LOOKUP = 0x10432D4
SETTER = 0x1630C48
STR_LO, STR_HI = 0x1D00000, 0x1E9F000
LOOKBACK = 24
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

# rang du premier mot >= REGION_LO, dernier <= REGION_HI
import bisect
addrs_all = [r[0] for r in rows]
i_lo = bisect.bisect_left(addrs_all, REGION_LO)
i_hi = bisect.bisect_right(addrs_all, REGION_HI)
region = rows[i_lo:i_hi]
print(f"région parseur perf : {len(region)} instructions ({REGION_LO:#x}..{REGION_HI:#x})")

# formations d'adresses -> string, avec index régional
str_formed = {}   # site_idx -> (va, string)
for k, (a, s, m, o) in enumerate(region):
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
    for u in range(k + 1, min(k + 9, len(region))):
        a2, s2, m2, o2 = region[u]
        p2 = parse(o2)
        if m2 in ("addi", "c.addi") and len(p2) == 3 and p2[0] == rd and p2[1] == rd:
            try:
                formed = base + int(p2[2], 0)
            except ValueError:
                break
            if STR_LO <= formed <= STR_HI:
                txt = cstr(formed)
                if txt:
                    str_formed[k] = (formed, txt)
            break
        if p2 and p2[0] == rd:
            break

print(f"strings formées dans la région : {len(str_formed)}")

# appels au lookup et au setter (jal direct + paire auipc+jalr)
lookup_sites, setter_sites = [], []
for k, (a, s, m, o) in enumerate(region):
    if m == "jal":
        p = parse(o)
        if len(p) == 2 and p[1].startswith("0x"):
            try:
                t = int(p[1], 16)
            except ValueError:
                continue
            if t == LOOKUP:
                lookup_sites.append((k, a, "jal"))
            elif t == SETTER:
                setter_sites.append((k, a, "jal"))
    elif m == "auipc":
        p = parse(o)
        if len(p) != 2 or p[0] != "ra":
            continue
        try:
            hi = int(p[1], 0) << 12
        except ValueError:
            continue
        for j in (k + 1, k + 2):
            if j >= len(region):
                break
            a2, s2, m2, o2 = region[j]
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
                    t = base + lo
                    if t == LOOKUP:
                        lookup_sites.append((k, a, "a+j"))
                    elif t == SETTER:
                        setter_sites.append((k, a, "a+j"))
                    break
            if m2 in ("mv", "c.mv") and parse(o2) and parse(o2)[0] == "ra":
                break

def dial_for(k):
    """string formée dans les LOOKBACK insns avant l'appel d'indice k"""
    cands = [(kk, va, txt) for kk, (va, txt) in str_formed.items()
             if 0 < k - kk <= LOOKBACK]
    return sorted(cands)[-1] if cands else None

def resolve_args(k, site_kind):
    """backward-resolve a0-a3 avant l'appel d'indice k (paires a+j : cible=auipc)."""
    regs, found = {}, {}
    for j in range(k - 1, max(-1, k - 1 - WIN), -1):
        aa, ss, mm, oo = region[j]
        pp = parse(oo)
        if mm in ("li", "c.li") and len(pp) == 2:
            d = pp[0]
            if d not in found:
                try:
                    regs[d] = int(pp[1], 0)
                except ValueError:
                    regs[d] = None
        elif mm in ("addi", "c.addi") and len(pp) == 3:
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
        elif mm in ("mv", "c.mv") and len(pp) == 2:
            d, src = pp[0], pp[1]
            if d not in found:
                regs[d] = regs.get(src)
        for r in ("a0", "a1", "a2", "a3"):
            if r not in found and r in regs:
                found[r] = (regs[r], k - j)
        if len(found) == 4:
            break
    return found

print("\n=== A. APPELS AU LOOKUP 0x10432d4 DANS LE GRAND PARSEUR ===")
lookup_report = []
for k, a, kind in lookup_sites:
    d = dial_for(k)
    args = resolve_args(k, kind)
    entry = {
        "site": hex(a), "kind": kind,
        "dial_va": hex(d[1]) if d else None,
        "dial": d[2] if d else None,
        "a0": args.get("a0", (None, None))[0],
        "a1": args.get("a1", (None, None))[0],
        "a2": args.get("a2", (None, None))[0],
        "a3": args.get("a3", (None, None))[0],
    }
    lookup_report.append(entry)
    print(f"  {a:#08x} ({kind})  dial={entry['dial']!r}  a0={entry['a0']} a1={entry['a1']} a2={entry['a2']} a3={entry['a3']}")

print("\n=== B. APPELS AU SETTER 0x1630c48 DANS LE GRAND PARSEUR ===")
setter_report = []
for k, a, kind in setter_sites:
    args = resolve_args(k, kind)
    d = dial_for(k)
    entry = {
        "site": hex(a), "kind": kind,
        "near_dial": d[2] if d else None,
        "a0": args.get("a0", (None, None))[0],
        "a1": args.get("a1", (None, None))[0],
        "a2": args.get("a2", (None, None))[0],
        "a3": args.get("a3", (None, None))[0],
    }
    setter_report.append(entry)
    print(f"  {a:#08x} ({kind})  bit={entry['a2']} dir={entry['a3']} a0={entry['a0']} a1={entry['a1']}  dial_proche={entry['near_dial']!r}")

print("\n=== C. STRINGS FORMÉES DE LA RÉGION (inventaire complet) ===")
inv = []
for k in sorted(str_formed):
    va, txt = str_formed[k]
    inv.append({"site": hex(region[k][0]), "va": hex(va), "string": txt})
    print(f"  {region[k][0]:#08x} -> {va:#x} {txt!r}")

json.dump({
    "region": [hex(REGION_LO), hex(REGION_HI)],
    "lookup_sites": lookup_report,
    "setter_sites": setter_report,
    "strings_inventory": inv,
}, (V45 / "v46_dials.json").open("w"), indent=1)
print(f"\n-> {V45/'v46_dials.json'}")
