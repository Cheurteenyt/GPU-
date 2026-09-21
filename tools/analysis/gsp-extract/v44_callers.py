#!/usr/bin/env python3
"""v44-callers — trouve tous les jal (et jalr via registre pré-chargé auipc+addi au
reg}) vers une cible. Pour jal c'est exact ; on liste aussi les jalr pour contexte.

Usage: python3 v44_callers.py <target_va> [target2 ...]
"""
import struct
import sys
from pathlib import Path

RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
TEXT_VA, TEXT_SZ = 0x1000000, 0xE85000
rm = RM.read_bytes()


def jal_target(w, pc):
    if (w & 0x7F) != 0x6F:
        return None
    imm = ((w >> 31) & 1) << 20
    imm |= ((w >> 12) & 0xFF) << 12
    imm |= ((w >> 20) & 1) << 11
    imm |= ((w >> 21) & 0x3FF) << 1
    if imm & (1 << 20):
        imm -= 1 << 21
    return pc + imm


def main():
    targets = [int(a, 0) for a in sys.argv[1:]]
    tset = set(targets)
    callers = {t: [] for t in targets}
    for p in range(0, TEXT_SZ - 4, 2):
        w = struct.unpack_from("<I", rm, p)[0]
        if (w & 0x7F) == 0x6F:
            pc = TEXT_VA + p
            t = jal_target(w, pc)
            if t in tset:
                callers[t].append(pc)
    for t in targets:
        cl = callers[t]
        print(f"jal -> {t:#x} : {len(cl)} appel(s)")
        for c in cl:
            print(f"  {c:#x}")


if __name__ == "__main__":
    main()
