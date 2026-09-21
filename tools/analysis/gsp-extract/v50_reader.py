#!/usr/bin/env python3
"""v50-reader — vague 4.10 : les références indirectes et la vtable porteuse.

Le pré-wrapper 0x12c7a1e a ZÉRO appelant direct : il est porté par une
structure (vtable ?). Le consommateur appelle [vtbl(obj)+0x28] — le lecteur
matériel n'est pas identifié.

1. Scan du FICHIER binaire (rm.elf) : qwords dont la valeur est une VA texte
   ∈ [0x1000000, 0x1E85000) — on cherche les pointeurs de fonction vers
   0x12c7a1e, 0x12b5c88, 0x1bd979c → structures porteuses.
2. Pour chaque hit : contexte ±6 qwords (lecture de la vtable candidate :
   le slot +0x28 relatif au début supposé).
3. Toute vtable candidate trouvée → slot +0x28 extrait → LE LECTEUR →
   déroulé court (prologue + 40 insns).

Sortie : stdout + scratch-gsp/v50/v50_reader.json
"""
import bisect
import json
import struct
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v50")
ELF = Path("/home/z/my-project/scratch-gsp/rm.elf")
data = ELF.read_bytes()
TEXT_LO, TEXT_HI = 0x1000000, 0x1E85000

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
n = len(rows)
addrs = [r[0] for r in rows]


def parse(o):
    return [x.strip() for x in o.split(",")]


def dump(i0, i1, title):
    print(f"--- {title} ---")
    for j in range(max(0, i0), min(n, i1 + 1)):
        a, s, m, o = rows[j]
        print(f"  {a:#08x}  {m:10} {o}")
    print()


TARGETS = {0x12C7A1E: "pré-wrapper", 0x12B5C88: "wrapper", 0x1BD979C: "consommateur"}

# ---- 1. scan qwords du fichier
hits = {}
for tgt, name in TARGETS.items():
    pat = struct.pack("<Q", tgt)
    lst = []
    off = data.find(pat)
    while off != -1:
        if off % 8 == 0:  # aligné qword
            lst.append(off)
        off = data.find(pat, off + 1)
    hits[name] = lst
    print(f"=== pointeurs vers {name} ({tgt:#08x}) : {len(lst)} (alignés qword) ===")

# conversion off → VA (LOAD1 : VA = off + 0x1000000 ; zone2 : VA = off - 0xE85000 + 0x4000000)
def off2va(off):
    if off < 0xE85000:
        return off + 0x1000000
    if 0xE85000 <= off < 0xE85000 + 0x19C000:
        return off - 0xE85000 + 0x4000000
    return None


# ---- 2. contexte de chaque hit + extraction vtable candidate
vtables = []
for name, lst in hits.items():
    for off in lst:
        va = off2va(off)
        lo, hi = max(0, off - 48), min(len(data), off + 56)
        print(f"\n--- hit {name} @ fichier {off:#x} (VA {va:#x} si LOAD1) ---")
        ctx = []
        for q in range(lo, hi, 8):
            v = struct.unpack_from("<Q", data, q)[0]
            tag = ""
            if TEXT_LO <= v < TEXT_HI:
                tag = " ← CODE"
            elif v:
                tag = ""
            ctx.append((q, v, tag))
            print(f"  +{q - lo:02x}  {v:#018x}{tag}")
        # slot +0x28 du début supposé (si le hit EST le slot +0x28, le début
        # supposé = off - 0x28) : on explore les deux hypothèses
        for delta in (0x28, -0x28, 0x0):
            base = off - delta
            if base < 0:
                continue
            v28 = struct.unpack_from("<Q", data, base + 0x28)[0]
            if TEXT_LO <= v28 < TEXT_HI and v28 not in TARGETS:
                vtables.append({"holder": name, "vtable_va_load1":
                                off2va(base) if base < 0xE85000 else None,
                                "file_off": base, "slot28": v28})
                print(f"  ⇒ vtable candidate @ fichier {base:#x} : slot +0x28 = {v28:#08x}")

# ---- 3. déroulé court du lecteur
readers = sorted({v["slot28"] for v in vtables})
print(f"\n=== lecteurs candidats (slot +0x28) : {[hex(r) for r in readers]} ===")
for r in readers:
    di = bisect.bisect_left(addrs, r)
    if di >= n or addrs[di] != r:
        print(f"  {r:#08x} : PAS une adresse d'instruction (donnée ?)")
        continue
    dump(di, min(di + 40, n), f"lecteur {r:#08x}")

json.dump({"hits": {k: [hex(off2va(o) or o) for o in v] for k, v in hits.items()},
           "vtables": vtables,
           "readers": [hex(r) for r in readers]},
          (OUT / "v50_reader.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_reader.json'}")
