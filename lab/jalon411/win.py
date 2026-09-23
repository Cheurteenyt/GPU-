#!/usr/bin/env python3
"""4.44 helper — decode a window of rm-full.elf by VA. ad-hoc, committed
as the pass's interactive lens (the v443b decode_window method)."""
import sys
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

img = A.read_bytes()[0x40:0x40 + 0xE9B000]

va = int(sys.argv[1], 0)
n = int(sys.argv[2], 0) if len(sys.argv) > 2 else 24
back = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
o = va - IMG_LO - back
for _ in range(n):
    try:
        ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
    except StopIteration:
        print(f"0x{IMG_LO + o:x}: <undecodable>")
        o += 2
        continue
    print(f"0x{IMG_LO + o:x}: {ins.mnemonic:<9} {ins.op_str}")
    o += ins.size
