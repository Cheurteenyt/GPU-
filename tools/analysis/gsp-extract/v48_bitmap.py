#!/usr/bin/env python3
"""v48-bitmap — vague 4.8, chantier 3 : la liste blanche 0x20-0x4F.

La vague 4.7 a localisé la politique (0x16355e2-0x1635618) :
  lbu a5, 0x19(s3)          ; flag +0x19 de la requête
  ld  a5, 0x2f8(s2)         ; objet à [s2+0x2f8]
  lbu a5, 0x180(a5)         ; l'ID de séquence = octet à [obj+0x180]
  (0xff = pas de séquence → skip)
  addiw -0x20 ; andi 0xff   ; normalisation
  bltu 0x30                 ; espace 0x20-0x4F (48 valeurs)
  auipc a4, 0x84e ; ld a4, 0x72e(a4)  ; LA BITMAP (64 bits)
  srl a5, a4, a5 ; andi 1   ; test du bit de l'ID
  bnez → bit posé ; chute → bit clair

Ce script :
  1. résout l'adresse du `auipc+ld` PAR SCRIPT (leçon Task 70) ;
  2. mappe la VA → offset fichier via les program headers de rm.elf ;
  3. lit les 8 octets bruts et les interprète (petit-boutiste) ;
  4. énumère les IDs posés (id = bit + 0x20) ;
  5. dresse les deux fenêtres de branches (bit posé / bit clair).
"""
import struct
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v48")
OUT.mkdir(parents=True, exist_ok=True)

rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
idx = {a: i for i, (a, s, m, o) in enumerate(rows)}


def parse(o):
    return [x.strip() for x in o.split(",")]


import bisect
addrs_all = [r[0] for r in rows]

# ---------------------------------------------------- 1 : résolution par script
print("=== 1. résolution de la charge de bitmap (fenêtre 0x1635600-0x1635620) ===")
loads = []
i0 = bisect.bisect_left(addrs_all, 0x1635600)
while i0 < len(rows) and rows[i0][0] <= 0x1635620:
    i = i0
    a, s, m, o = rows[i]
    i0 += 1
    if m != "auipc":
        continue
    p = parse(o)
    if len(p) != 2:
        continue
    # cherche le ld immédiatement après (≤2 insns) — base = registre de l'auipc
    for j in (i + 1, i + 2):
        if j >= len(rows):
            break
        a2, s2, m2, o2 = rows[j]
        if m2 == "ld":
            p2 = parse(o2)
            if len(p2) == 2 and "(" in p2[1]:
                base_reg = p2[1].split("(")[1].rstrip(")")
                if base_reg == p[0]:
                    hi12 = int(p[1], 0) << 12
                    base = a + hi12
                    off = int(p2[1].split("(")[0], 0)
                    va = base + off
                    loads.append({"auipc": hex(a), "ld": hex(a2), "base": hex(base),
                                  "off": hex(off), "va": hex(va)})
    # auipc suivi d'un addi → adresse de rodata (formats/log) : résolu aussi
    for j in (i + 1, i + 2):
        if j >= len(rows):
            break
        a2, s2, m2, o2 = rows[j]
        if m2 == "addi":
            p2 = parse(o2)
            if len(p2) == 3 and p2[1] == p[0]:
                hi12 = int(p[1], 0) << 12
                base = a + hi12
                va = base + int(p2[2], 0)
                loads.append({"auipc": hex(a), "addi": hex(a2), "va": hex(va),
                              "reg": p2[0], "kind": "address"})
assert loads, "charge de bitmap non trouvée dans la fenêtre"
for l in loads:
    print(f"  {l}")

bitmap_va = [l for l in loads if "ld" in l][0]["va"]
bitmap_va = int(bitmap_va, 16)
print(f"  BITMAP VA = {bitmap_va:#x}")

# ---------------------------------------------------- 2 : VA → offset fichier
print("\n=== 2. mapping VA → offset fichier (program headers rm.elf) ==="
      )
d = Path("/home/z/my-project/scratch-gsp/rm.elf").read_bytes()
e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    ptype, flags = struct.unpack_from("<II", d, o)
    off, va, pa, fsz, msz, algn = struct.unpack_from("<QQQQQQ", d, o + 8)
    if ptype == 1:
        segs.append((va, fsz, msz, off, flags))
        fl = ("X" if flags & 1 else "-") + ("W" if flags & 2 else "-") + ("R" if flags & 4 else "-")
        cov = "COUVRE" if va <= bitmap_va < va + msz else ""
        print(f"  LOAD {fl} va {va:#012x} fsz {fsz:#010x} off {off:#011x} {cov}")
file_off = None
for va, fsz, msz, off, flags in segs:
    if va <= bitmap_va < va + fsz:
        file_off = off + bitmap_va - va
        print(f"  >>> bitmap @ fichier {file_off:#x} (dans la partie FILE sz)")
        break
    if va <= bitmap_va < va + msz:
        print(f"  >>> bitmap dans la partie BSS (msz>fsz) — pas de fichier")
if file_off is None:
    print("  PAS DE COUVERTURE FICHIER — bit chiffré/absent")
    raw = None
else:
    raw = d[file_off:file_off + 16]
    print(f"  16 octets bruts @ {file_off:#x} : {raw.hex(' ')}")

# ---------------------------------------------------- 3-4 : interprétation
print("\n=== 3-4. interprétation de la bitmap ===")
if raw is not None:
    val = struct.unpack_from("<Q", raw, 0)[0]
    print(f"  valeur 64 bits (LE) : {val:#018x}")
    print(f"  binaire : {val:064b}")
    ids = [bit + 0x20 for bit in range(64) if (val >> bit) & 1]
    print(f"  IDs posés (bit+0x20) : {[hex(x) for x in ids]}")
    print(f"  décompte : {len(ids)}/64 bits posés ; espace utile 0x20-0x4F = bits 0-47")
    # détection chiffrement : motif ffffe780 récurrent signalé en 4.6
    enc_marks = sum(1 for w in (raw[:8],) if (struct.unpack('<Q', w)[0] & 0xFFFFFFFF) == 0xFFFFE780)
    print(f"  motif ffffe780 (marqueur chiffrement) : {'PRÉSENT' if enc_marks else 'absent'}")
    (OUT / "v48_bitmap.json").open("w").write(
        f'{{"va": "{bitmap_va:#x}", "file_off": "{file_off:#x}", '
        f'"raw": "{raw.hex()}", "value": "{val:#x}", "ids": {[hex(i) for i in ids]}}}\n')
else:
    print("  lecture impossible statiquement")

# ---------------------------------------------------- 5 : les deux branches
import bisect
addrs_all = [r[0] for r in rows]


def dump(name, lo, hi):
    i0 = bisect.bisect_left(addrs_all, lo)
    lines = []
    while i0 < len(rows) and rows[i0][0] <= hi:
        a, s, m, o = rows[i0]
        lines.append(f"  {a:#08x}  {m:10} {o}")
        i0 += 1
    (OUT / f"v48_{name}.dump").write_text("\n".join(lines) + "\n")
    print(f"\n=== fenêtre {name} : {len(lines)} instr → v48_{name}.dump ===")


# bit posé → bnez +0x216 depuis 0x1635618 → 0x163582e ; bit clair → chute 0x163561c
dump("bitmap_set_branch", 0x1635820, 0x1635900)
dump("bitmap_clear_branch", 0x1635618, 0x1635680)
dump("bitmap_policy", 0x16355d8, 0x1635620)
print("\nv48-bitmap terminé.")
