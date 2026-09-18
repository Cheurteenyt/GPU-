#!/usr/bin/env python3
"""v42-tables — énumère les tables de descripteurs de paramètres du rm.elf.

Ligne (32 o) : {ptr_nom(8), u16 type, u16 accès, u32 idx_a, u32 idx_b, u32 groupe, u32 pad}
Graine : pointeurs absolus connus vers des noms (CUSTOMER_BOOST_MAX @0x1dee560…,
CLIENT_LOW_INTERSECT @0x1deda00…). Marche avant/arrière tant que les lignes sont valides.
Sortie : scratch-gsp/v42/tables.json + résumé console + croisement wave2_dial_names.txt
"""
import json
import struct
from pathlib import Path

RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
OUT = Path("/home/z/my-project/scratch-gsp/v42")
TEXT_VA, TEXT_SZ = 0x1000000, 0xE85000
DATA_VA, DATA_OFF, DATA_SZ = 0x4000000, 0xE85000, 0x19C000

rm = RM.read_bytes()
strings = json.loads((OUT / "strings.json").read_text())
STR_VAS = {int(k, 16) for k in strings}


def cstr(va):
    off = va - TEXT_VA if va < TEXT_VA + TEXT_SZ else DATA_OFF + (va - DATA_VA)
    if not (0 <= off < len(rm)):
        return None
    end = rm.find(b"\x00", off)
    if end < 0 or end - off > 96:
        return None
    try:
        return rm[off:end].decode()
    except UnicodeDecodeError:
        return None


def row_at(va):
    """lit une ligneCandidate @va (VA), retourne dict ou None si invalide."""
    off = va - TEXT_VA
    if not (0 <= off <= len(rm) - 32):
        return None
    ptr, tacc, zero, ia, ib, grp, pad = struct.unpack_from("<QIIIIII", rm, off)
    typ = tacc & 0xFF        # u8 type de valeur (0x01,0x02,0x03,0x05,0x06,0x07)
    acc = (tacc >> 8) & 0xFF  # u8 accès (0xff rw, 0x01 ro?)
    name = cstr(ptr) if ptr in STR_VAS else None
    if name is None:
        return None
    if typ > 0x20 or pad != 0 or zero != 0:
        return None
    return {"va": hex(va), "name": name, "type": typ, "access": acc,
            "idx_a": ia, "idx_b": ib, "group": grp}


def walk(seed_va):
    """étend la table depuis une graine (VA de ligne)."""
    rows = [row_at(seed_va)]
    lo = seed_va - 32
    while True:
        r = row_at(lo)
        if r is None:
            break
        rows.insert(0, r)
        lo -= 32
    hi = seed_va + 32
    while True:
        r = row_at(hi)
        if r is None:
            break
        rows.append(r)
        hi += 32
    return rows, lo + 32, hi


SEEDS = [0x1dee560, 0x1defd00, 0x1df1580, 0x1df2ee0, 0x1df4b80, 0x1df6960, 0x1deda00]
tables = []
seen_ranges = []
for seed in SEEDS:
    if any(a <= seed < b for a, b in seen_ranges):
        continue
    rows, lo, hi = walk(seed)
    if len(rows) < 8:
        continue
    tables.append({"lo": hex(lo), "hi": hex(hi), "rows": len(rows), "entries": rows})
    seen_ranges.append((lo, hi))
    names = [r["name"] for r in rows]
    print(f"table @{lo:#x}..{hi:#x} — {len(rows)} lignes")
    print(f"   premières: {names[:6]}")
    print(f"   groupes: {sorted(set(r['group'] for r in rows))[:20]}")
    print(f"   types: {sorted(set(r['type'] for r in rows))}  accès: {sorted(set(r['access'] for r in rows))}")

# fusion + dédoublonnage par nom (6 tables ≈ variantes)
allrows = {}
for t in tables:
    for r in t["entries"]:
        allrows.setdefault(r["name"], []).append(r)
print(f"\nTOTAL: {len(tables)} tables, {sum(t['rows'] for t in tables)} lignes, {len(allrows)} noms uniques")

(OUT / "tables.json").write_text(json.dumps({"tables": tables}, indent=1))

# croisement avec les 881 dials du ROM
w2 = Path("/home/z/my-project/scripts/wave2_dial_names.txt")
if w2.exists():
    rom = set(w2.read_text().split())
    drv = set(allrows)
    print(f"\nROM 881 vs tables rm.elf: communs={len(rom & drv)} rom-seuls={len(rom - drv)} rm-seuls={len(drv - rom)}")
    inter = sorted(rom & drv)
    print("échantillon communs:", inter[:12])
    print("rm-seuls (nouveautés driver):", sorted(drv - rom)[:25])
