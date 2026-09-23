#!/usr/bin/env python3
"""4.38 TASK A, instrument 4 — WHO writes the 4x8-B table at
B+0x8D9CC/B+0x8D9DC that the 0x2080A080 internal-event getter reads?

The getter (0x16502d0, cited in v438a3) reads:
  flags byte  = *(B + 0x8D9CC)      via lui 0x8e + addi -0x634
  pair[index] = *(B + 0x8D9DC + i*8) via lui 0x8e + addi -0x624/-0x620
where B = *(*( *(a0+0x158) + 0x2000 ) + 0xe0 ) + 0x2000 ) - 0x68.

This instrument walks the WHOLE image on the seen bitmap and collects
every accessor (load AND store) whose mem offset lies in the window
[0x8D9C0, 0x8D9F0) formed through the lui-0x8e idiom (the base register
is formed by lui reg,0x8e + addi negative within 8 insns). Stores = the
writers; loads = the other readers.

Output: lab/jalon411/v438a4_table_writers.json
"""
import json
import re
import zlib
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw"}
LOADS = {"ld", "lw", "lbu", "lhu", "c.ld", "c.lw"}
WINDOW_LO, WINDOW_HI = 0x8D9C0, 0x8D9F0


def main():
    da = A.read_bytes()
    img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]

    hits = []
    recent_lui = []          # (va, reg) of lui 0x8e
    window = []              # last 8 decoded insns (va, m, op)
    o = 0
    n = len(img)
    import time
    t0 = time.time()
    while o < n:
        if not seen[o]:
            o += 1
            continue
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except Exception:
            o += 2
            continue
        m, ops = ins.mnemonic, ins.op_str

        if m == "lui" and re.match(r"^\w+, 0x8e$", ops):
            recent_lui.append((IMG_LO + o, ops.split(",")[0]))
            recent_lui = recent_lui[-8:]
        elif m in (STORES | LOADS) and "(" in ops:
            mm = re.search(r"(-?0x[0-9a-f]+|-?\d+)\(", ops)
            base = ops.split("(")[1].rstrip(")")
            if mm:
                imm = int(mm.group(1), 0) & 0xFFFFFFFF
                # offset formed as lui(0x8e<<12) + sign-extended imm
                # the accessor addr = 0x8e000 + imm (imm negative-ish)
                if 0x8e000 + (int(mm.group(1), 0) if int(mm.group(1), 0) < 0x800
                              else int(mm.group(1), 0)) or True:
                    val = (0x8E000 + int(mm.group(1), 0)) & 0xFFFFFFFF
                    if WINDOW_LO <= val <= WINDOW_HI:
                        # find the lui 0x8e for this base reg
                        lui = next((l for l in reversed(recent_lui)
                                    if l[1] == base), None)
                        hits.append({
                            "va": hex(IMG_LO + o), "m": m, "o": ops,
                            "off_raw": mm.group(1), "abs_off": hex(val),
                            "lui0x8e": hex(lui[0]) if lui else None,
                            "kind": "STORE" if m in STORES else "LOAD",
                        })
        window.append((IMG_LO + o, m, ops))
        window = window[-8:]
        o += ins.size
    print(f"walk done in {time.time()-t0:.0f}s, hits={len(hits)}")
    for h in hits:
        print("  ", h["kind"], h["va"], h["m"], h["o"],
              "abs", h["abs_off"], "lui", h["lui0x8e"])

    OUT.write_text(json.dumps({
        "window": [hex(WINDOW_LO), hex(WINDOW_HI)],
        "hits": hits}, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
