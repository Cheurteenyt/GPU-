#!/usr/bin/env python3
"""v42-query — pour chaque string cible: VA + xrefs + fenêtres disasm auto.

Usage:
  python3 v42_query.py "<regex>" ...        # cibles par regex sur strings.json
  python3 v42_query.py --va 0x1633636 0x600 # fenêtre brute autour d'une VA (code)
Les fenêtres vont dans scratch-gsp/v42/win-<slug>.txt
Pattern de secours: si un string n'a AUCUNE paire auipc/addi, on liste tous les
auipc dont la page hi20 matche (xref indirect: table/GOT/pointeur).
"""
import json
import re
import struct
import sys
from pathlib import Path

import capstone

RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
OUT = Path("/home/z/my-project/scratch-gsp/v42")
TEXT_VA, TEXT_SZ = 0x1000000, 0xE85000
DATA_VA, DATA_OFF, DATA_SZ = 0x4000000, 0xE85000, 0x19C000

md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)

rm = RM.read_bytes()
strings = json.loads((OUT / "strings.json").read_text())
xrefs = {int(k, 16): [int(s, 16) for s in v] for k, v in
         json.loads((OUT / "xrefs.json").read_text()).items()}


def va_to_off(va):
    if TEXT_VA <= va < TEXT_VA + TEXT_SZ:
        return va - TEXT_VA
    if DATA_VA <= va < DATA_VA + DATA_SZ:
        return DATA_OFF + (va - DATA_VA)
    return None


def disasm_window(fh, va, before=0x300, after=0x500, title=""):
    off = va_to_off(va)
    if off is None:
        fh.write(f"!! VA {va:#x} hors segments\n")
        return
    start = max(0, off - before)
    end = min(len(rm), off + after)
    fh.write(f"=== {title} — {TEXT_VA + start:#x} .. {TEXT_VA + end:#x} ===\n")
    for ins in md.disasm(rm[start:end], TEXT_VA + start):
        fh.write(f"{ins.address:#x}:  {ins.mnemonic:<9} {ins.op_str}\n")
    fh.write("\n")


def find_indirect(str_va):
    """tous les auipc dont la page hi20 == page du string (candidats xref indirects)."""
    page = str_va & ~0xFFF
    hits = []
    for off in range(0, TEXT_SZ - 4, 2):
        w = struct.unpack_from("<I", rm, off)[0]
        if (w & 0x7F) == 0x17:
            imm20 = (w >> 12) & 0xFFFFF
            if imm20 & 0x80000:
                imm20 -= 1 << 20
            if off + TEXT_VA + (imm20 << 12) == page:
                hits.append(off + TEXT_VA)
        if len(hits) > 40:
            break
    return hits


def slug(s):
    return re.sub(r"[^A-Za-z0-9_-]", "_", s)[:48]


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    if args[0] == "--va":
        va = int(args[1], 0)
        before = int(args[2], 0) if len(args) > 2 else 0x300
        after = int(args[3], 0) if len(args) > 3 else 0x500
        with open(OUT / f"win-raw-{va:x}.txt", "w") as fh:
            disasm_window(fh, va, before, after, f"raw {va:#x}")
        print(f"win-raw-{va:x}.txt")
        return

    targets = {}
    for pat in args:
        rx = re.compile(pat)
        for va_s, s in strings.items():
            if rx.fullmatch(s) or (rx.search(s) and len(s) < 64):
                targets[s] = int(va_s, 16)

    print(f"{len(targets)} cibles")
    for s, va in sorted(targets.items(), key=lambda kv: kv[1]):
        sites = xrefs.get(va, [])
        print(f"\n### {s}")
        print(f"    VA {va:#x} — paires auipc/addi: {len(sites)}")
        fname = OUT / f"win-{slug(s)}.txt"
        with open(fname, "w") as fh:
            for i, site in enumerate(sites[:8]):
                disasm_window(fh, site, 0x300, 0x600, f"{s} — site {i+1} @{site:#x}")
            if not sites:
                ind = find_indirect(va)
                print(f"    !! pas de paire directe — {len(ind)} auipc de page matchée: "
                      + " ".join(f"{h:#x}" for h in ind[:12]))
                for i, h in enumerate(ind[:6]):
                    disasm_window(fh, h, 0x100, 0x300, f"{s} — indirect {i+1} @{h:#x}")
        print(f"    -> {fname.name}")


if __name__ == "__main__":
    main()
