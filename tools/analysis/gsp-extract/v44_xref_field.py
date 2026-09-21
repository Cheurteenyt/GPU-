#!/usr/bin/env python3
"""v44 — xref complète d'un champ d'objet (offsets +0x324/+0x328 de l'état
RmVFPointCheckIgnore, jalon vague 4.4).

Méthode : scan binaire exact des encodages load/store I-type/S-type à immédiat
cible. Toute instruction 32 bits RISC-V (RVC actif) est à adresse PAIRE, donc un
pas de 2 voit chaque instruction 32 bits exactement une fois. Les load/store
compressés ne peuvent pas encoder 0x324/0x328 (max 192) -> aucun faux négatif.
Fenêtres capstone courtes pour le contexte autour de chaque hit.

Sortie :
  scratch-gsp/v44/sites.json, fonctions groupées, win-*.txt (contexte ±0x250)
"""
import json
import re
import struct
import sys
from pathlib import Path

import capstone

RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
V42 = Path("/home/z/my-project/scratch-gsp/v42")
OUT = Path("/home/z/my-project/scratch-gsp/v44")
OUT.mkdir(exist_ok=True)

TEXT_VA, TEXT_SZ = 0x1000000, 0xE85000

md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)

rm = RM.read_bytes()


def decode_loads_stores(text):
    """rend [(off, kind, op, imm, bits)] pour lw/lwu/ld/sw/sd à immédiat cible."""
    hits = []
    n = len(text)
    for p in range(0, n - 4, 2):
        w = struct.unpack_from("<I", text, p)[0]
        op = w & 0x7F
        if op == 0x03:  # LOAD I-type
            f3 = (w >> 12) & 7
            imm = w >> 20  # bits [31:20]
            if imm in (0x324, 0x328):
                name = {2: "lw", 3: "ld", 6: "lwu"}.get(f3)
                if name:
                    hits.append((p, "L", name, imm, w))
        elif op == 0x23:  # STORE S-type
            f3 = (w >> 12) & 7
            imm = ((w >> 25) << 5) | ((w >> 7) & 0x1F)
            if imm in (0x324, 0x328):
                name = {2: "sw", 3: "sd"}.get(f3)
                if name:
                    hits.append((p, "S", name, imm, w))
    return hits


def main():
    imm_filter = [int(a, 0) for a in sys.argv[1:]] or [0x324, 0x328]
    print(f"scan load/store imm {[hex(i) for i in imm_filter]} sur {TEXT_SZ:#x} o ...")

    hits = decode_loads_stores(rm[:TEXT_SZ])
    print(f"hits bruts : {len(hits)}")

    sites = []
    for off, kind, op, imm, w in hits:
        sites.append({
            "addr": TEXT_VA + off,
            "kind": kind,
            "op": op,
            "imm": imm,
        })

    # bruit : distinguer vrai code (précédés de jal/jalr ra prologue typique) plus tard.
    (OUT / "sites.json").write_text(json.dumps(sites, indent=1))

    for s in sites:
        print(f"{s['addr']:#x}:  {s['op']:<4} imm {s['imm']:#x} ({s['kind']})")

    # fenêtres capstone
    for s in sites:
        off = s["addr"] - TEXT_VA
        start = max(0, off - 0x250)
        end = min(TEXT_SZ, off + 0x250)
        fname = OUT / f"win-{s['kind']}-{s['addr']:x}.txt"
        with open(fname, "w") as fh:
            fh.write(f"=== {s['op']} imm {s['imm']:#x} @ {s['addr']:#x} ===\n")
            for ins in md.disasm(rm[start:end], TEXT_VA + start):
                fh.write(f"{ins.address:#x}:  {ins.mnemonic:<9} {ins.op_str}\n")
        print(f"-> {fname.name}")


if __name__ == "__main__":
    main()
