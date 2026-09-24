#!/usr/bin/env python3
"""4.46 pass, TÂCHE D — the BOOTER optimization surface (first ever):
the booter's own knob census, the SBI service decode, and the
desc-cell writer hunt.

The booter image = bootloader.bin (446,464 B, sha ab90560bad520e65...),
1 LOAD @VA 0x100000 filesz 0x6d000 — the code AND the static DMEM image
(the ctx cell @0x124000, the desc cell @0x16C088, the boot params
@0x16D000) live IN the file.

  1. self-checks: the booter banked counts (84 c.ret = the 0x8082
     halfword census; 515 auipc), the image size;
  2. the KNOB census (first ever for this image): lui+addi /
     c.lui+c.addi pairs materializing |v| >= 1000, v % 1000 == 0 —
     the booter's round-constant table with first-consumer classes;
  3. the SBI SERVICE decode: the wrapper @0x10045e callers (banked:
     10 sites, fns {0x20,0x21,0x22,0x23,0x25,0x2a,0x2b,0x2d,0x2e} +
     the direct stubs a6 in {7,8,9,A}) — per site: the fn, the arg
     registers' provenance (literal/load/boot-block), the result
     handling (branch? store? ignore?);
  4. the DESC-CELL writer hunt: every lui/auipc composition into
     [0x16C000, 0x16D000) (the logger ring space) — classify the
     consuming instruction (load vs store) — WHO arms the ring?

Output: lab/jalon411/v446d_booter_surface.json
"""
import json
import re
import struct
from pathlib import Path

import capstone
import numpy as np
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
B = ROOT / "tools/analysis/gsp-extract/binaries/bootloader.bin"
OUT = Path(__file__).with_suffix(".json")

VA_LO = 0x100000
FILE_OFF = 0x78  # VA = file_off - 0x78 + 0x100000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

img = B.read_bytes()


def va2off(va):
    return va - VA_LO + FILE_OFF


def off2va(off):
    return off + VA_LO - FILE_OFF


def dec(va, n, back=0):
    o = va2off(va) - back
    out = []
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], VA_LO + o - FILE_OFF))
        except StopIteration:
            break
        out.append((ins.address, ins.mnemonic, ins.op_str))
        o += ins.size
    return out


def main():
    out = {}

    # -- 1. self-checks ---------------------------------------------------
    assert len(img) == 446464, len(img)
    import hashlib
    sha = hashlib.sha256(img).hexdigest()
    out["image"] = {"size": len(img), "sha256": sha[:16] + "..."}
    # auipc census (banked 515): opcode 0x17, both parities, code area
    auipc = 0
    code_end = va2off(0x16D000)
    for off in range(0, code_end - 2, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        if (w & 0x7F) == 0x17:
            auipc += 1
    out["selfchecks"] = {"auipc": auipc, "banked_auipc": 515}
    # c.ret census (banked 84): the c.ret encoding = 0x8082 halfword
    cret = 0
    for off in range(0, code_end - 2, 2):
        if img[off:off + 2] == b"\x82\x80":
            cret += 1
    out["selfchecks"]["cret"] = cret
    out["selfchecks"]["banked_cret"] = 84

    # -- 2. the booter knob census -----------------------------------------
    knobs = {}
    code_lo, code_hi = FILE_OFF, code_end
    for off in range(code_lo, code_hi - 8, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        op = w & 0x7F
        if op not in (0x37, 0x17):  # lui / auipc
            continue
        rd = (w >> 7) & 0x1F
        up = (w >> 12) & 0xFFFFF
        base = (up << 12) if op == 0x37 else (off2va(off) + (up << 12))
        for da in (2, 4):
            w2 = int.from_bytes(img[off + da:off + da + 4], "little")
            val = None
            if (w2 & 0x7F) == 0x13 and ((w2 >> 12) & 7) == 0 and \
               ((w2 >> 15) & 0x1F) == rd and ((w2 >> 7) & 0x1F) == rd:
                imm = (w2 >> 20) & 0xFFF
                if imm >= 0x800:
                    imm -= 0x1000
                val = base + imm
            elif op == 0x37 and (w2 & 3) == 1 and ((w2 >> 13) & 7) == 0:
                crd = ((w2 >> 7) & 7) + (8 if rd >= 8 else 0)
                if crd == rd:
                    nz = ((w2 >> 12) & 1) << 5 | (w2 >> 2) & 0x1F
                    if nz >= 0x20:
                        nz -= 0x40
                    val = base + nz
            if val is not None and abs(val) >= 1000 and val % 1000 == 0:
                knobs.setdefault(val, []).append(
                    {"va": f"0x{off2va(off):X}", "gap": da,
                     "op": "lui" if op == 0x37 else "auipc"})
    out["knob_census"] = {
        "rule": "|v| >= 1000 and v % 1000 == 0 (the 4.33 lane-A rule)",
        "distinct_values": len(knobs),
        "table": {str(k): v for k, v in sorted(
            knobs.items(), key=lambda kv: -abs(int(kv[0])))[:40]},
    }

    # -- 3. the SBI service decode ------------------------------------------
    # find callers of the wrapper 0x10045e: auipc+jalr pairs targeting it
    # plus the direct SBI stubs (a6/a7 = {7,8,9,A} with ecall)
    WRAP = 0x10045E
    callers = []
    for off in range(code_lo, code_hi - 8, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        if (w & 0x7F) != 0x17:
            continue
        rd = (w >> 7) & 0x1F
        up = (w >> 12) & 0xFFFFF
        pc = off2va(off)
        for da in (2, 4):
            w2 = int.from_bytes(img[off + da:off + da + 4], "little")
            if (w2 & 0x7F) == 0x67 and ((w2 >> 12) & 7) == 0:
                # jalr (J-type): target = pc + imm
                imm = (w2 >> 20) & 0xFFF
                imm |= ((w2 >> 21) & 0x3FF) << 0
                imm |= ((w2 >> 20) & 1) << 11
                # J-type reassembly: imm[20|10:1|11|19:12]
                w2v = w2
                imm20 = ((w2v >> 31) << 20) | (((w2v >> 21) & 0x3FF) << 1) \
                    | (((w2v >> 20) & 1) << 11) | ((w2v >> 12) & 0xFF)
                if imm20 >= 0x100000:
                    imm20 -= 0x200000
                tgt = pc + imm20
                rs1 = (w2 >> 15) & 0x1F
                if rs1 == rd and tgt == WRAP:
                    callers.append({"site": f"0x{pc:X}"})
    out["sbi_wrapper_callers"] = {"count": len(callers),
                                  "sites": callers}

    # decode windows around each caller: fn + args
    win = []
    for c in callers:
        pc = int(c["site"], 16)
        lines = [f"0x{a:X}  {m} {o}" for a, m, o in dec(pc - 0x40, 36)]
        win.append({"site": c["site"], "window": lines})
    out["sbi_caller_windows"] = win

    # the direct stubs: a7 = 0x900001EB, a6 in {7,8,9,A} then ecall
    stubs = []
    for off in range(code_lo, code_hi - 2, 2):
        if img[off:off + 4] == b"\x73\x00\x00\x00":  # ecall
            # walk back for the a6 materialization
            back = dec(off2va(off) - 0x20, 16)
            for i, (a, m, o) in enumerate(back):
                if m == "addi" and re.search(r"a6, a6, (-?\d+|0x[0-9a-f]+)$",
                                             o):
                    stubs.append({"va": f"0x{a:X}", "ecall_va":
                                  f"0x{off2va(off):X}"})
    out["sbi_stubs"] = stubs

    # -- 4. the desc-cell writer hunt ---------------------------------------
    # compositions into [0x16C000, 0x16D000) — the logger ring space
    comp = []
    for off in range(code_lo, code_hi - 8, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        op = w & 0x7F
        if op not in (0x37, 0x17):
            continue
        rd = (w >> 7) & 0x1F
        up = (w >> 12) & 0xFFFFF
        base = (up << 12) if op == 0x37 else (off2va(off) + (up << 12))
        for da in (2, 4):
            w2 = int.from_bytes(img[off + da:off + da + 4], "little")
            val = None
            if (w2 & 0x7F) == 0x13 and ((w2 >> 12) & 7) == 0 and \
               ((w2 >> 15) & 0x1F) == rd:
                imm = (w2 >> 20) & 0xFFF
                if imm >= 0x800:
                    imm -= 0x1000
                val = base + imm
            elif op == 0x37 and (w2 & 3) == 1 and ((w2 >> 13) & 7) == 0:
                crd = ((w2 >> 7) & 7) + (8 if rd >= 8 else 0)
                if crd == rd:
                    nz = ((w2 >> 12) & 1) << 5 | (w2 >> 2) & 0x1F
                    if nz >= 0x20:
                        nz -= 0x40
                    val = base + nz
            if val is not None and 0x16C000 <= val < 0x16D000:
                comp.append({"va": f"0x{off2va(off):X}",
                             "val": f"0x{val:X}",
                             "op": "lui" if op == 0x37 else "auipc"})
    # classify the consumer instruction after each composition
    for c in comp:
        va = int(c["va"], 16)
        nxt = dec(va, 4)
        c["next"] = [f"{m} {o}" for _, m, o in nxt[1:3]]
    out["dmem_0x16C_compositions"] = comp

    OUT.write_text(json.dumps(out, indent=1))
    print(f"booter image: {len(img)} B sha {sha[:12]}...")
    print(f"auipc: {auipc} (banked 515)  c.ret: {cret} (banked 84)")
    print(f"knob values: {len(knobs)}")
    print(f"SBI wrapper callers: {len(callers)}  stubs: {len(stubs)}")
    print(f"0x16C compositions: {len(comp)}")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
