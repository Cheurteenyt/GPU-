#!/usr/bin/env python3
"""4.48 TASK B — the trace API's world: the partner function, the
MclkProg caller, the L2 switch caller.

v448a proved the most-called function in the image (0x1a9e624, 61,339
sites) = the RM's per-task debug/trace push (rdtime-stamped ring, the
packed format-id referencing the 4.46 opaque rodata). This instrument
closes the loop on the three objects the 4.47 knob cards stood on:

  1. the partner function @0x1b4da4c (35,225 direct calls — the #2
     target, called in sequence with the push at the dense sites):
     bounds + body decode + classification;
  2. the RmClkMprog caller function (contains the banked window
     0x10e8f7e: name->a1, value byte lbu 0x34(s8)->a2, tag 3): full
     bounds, and EVERY access to the 0x34(s8) slot inside it — where
     the value is WRITTEN (the real parse/consumption) vs READ (the
     trace);
  3. the RML2MaxWaysSysmem caller (the 4.47 "pointer-range switch"
     0x130697e..0x1306b04): bounds, the switch structure (the
     consecutive interned-name VA compares), the incoming-name
     provenance (s5), the opaque a1 descriptor 0x202b42f0.

Selftests: the auipc census; the v448a JSON semantics present.

Output: lab/jalon411/v448b_trace_world.json
"""
import json
import re
import struct
import zlib
from pathlib import Path

import numpy as np
import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
IN = Path(__file__).with_name("v448a_trace_api.json")
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_LEN = 0xE9B000
PARTNER_VA = 0x1B4DA4C
MCLK_SITE = 0x10E8F7E          # the auipc a1 (name) in the MclkProg window
L2_FIRST = 0x130697E           # the first banked L2 xref site
L2_LAST = 0x1306AEC            # the last banked L2 xref site

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True


def dec_at(img, off, va=None):
    va = (va if va is not None else IMG_LO + off)
    if img[off] & 3 == 3:
        ins = next(md.disasm(img[off:off + 4], va), None)
        return (ins, 4) if ins else (None, 0)
    ins = next(md.disasm(img[off:off + 2], va), None)
    return (ins, 2) if ins else (None, 0)


def render(ins):
    if ins is None:
        return "<invalid>"
    extra = ""
    for op in ins.operands:
        if op.type == 2:  # IMM: capstone gives it relative for branches
            extra = f"   -> {ins.address + op.imm:#x}"
    return f"{ins.mnemonic:<8} {ins.op_str}{extra}"


def find_start(img, off):
    """Walk back to the nearest function prologue (a sp-negative setup)."""
    o = off
    for _ in range(1200):
        if o <= 0:
            break
        ins, sz = dec_at(img, o)
        if ins is not None:
            m, op = ins.mnemonic, ins.op_str or ""
            if m in ("c.addi16sp", "addi16sp") or \
               (m == "addi" and op.startswith("sp,") and "-" in op) or \
               (m == "c.addi" and op.startswith("sp, -")):
                return o
        o -= 2 if img[o] & 3 != 3 else 4
    return None


def find_end(img, start):
    """Scan forward: the function ends at the LAST ret before a new
    prologue (the ret c.jr ra / ret), capped at 4000 bytes."""
    o = start
    last_ret = None
    while o < min(start + 4000, len(img) - 4):
        ins, sz = dec_at(img, o)
        if ins is None:
            break
        if ins.mnemonic in ("c.jr",) and ins.op_str == "ra":
            last_ret = o
        if ins.mnemonic == "ret":
            last_ret = o
        if o > start + 8 and ins.mnemonic in ("c.addi16sp", "addi16sp") and \
                last_ret is not None:
            return last_ret + 2
        if ins.mnemonic == "addi" and (ins.op_str or "").startswith("sp,") \
                and "-" in ins.op_str and last_ret is not None and o > start + 8:
            return last_ret + 4
        o += sz
    return (last_ret + 4) if last_ret is not None else o


def decode_range(img, a, b):
    lines = []
    o = a
    while o < b:
        ins, sz = dec_at(img, o)
        lines.append(f"0x{IMG_LO + o:x}: {render(ins)}")
        o += sz
    return lines


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    img = da[0x40:0x40 + IMG_LEN]
    blob = zlib.decompress(MAP.read_bytes())
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        assert img[o:o + 16] == db[o - 0x38:o - 0x38 + 16]
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        cnt += int((uarr & 0x7F == 0x17).sum())
    assert cnt == 416206

    a448 = json.loads(IN.read_text())
    assert a448["api"]["semantics"]["kind"].startswith("per-task event")

    out = {"pass": "4.48", "task": "B", "instrument": "v448b_trace_world",
           "baseline": {"auipc": cnt}}

    # -- 1. the partner function @0x1b4da4c --------------------------------
    p_off = PARTNER_VA - IMG_LO
    p_start = find_start(img, p_off)
    p_end = find_end(img, p_start)
    out["partner"] = {
        "va": hex(PARTNER_VA), "start": hex(IMG_LO + p_start),
        "end": hex(IMG_LO + p_end), "bytes": p_end - p_start,
        "body": decode_range(img, p_start, min(p_end, p_start + 0x140)),
    }
    print(f"[partner] {hex(PARTNER_VA)}: [{hex(IMG_LO+p_start)}, "
          f"{hex(IMG_LO+p_end)}) = {p_end-p_start} B")

    # -- 2. the RmClkMprog caller: the 0x34(s8) slot story -----------------
    m_off = MCLK_SITE - IMG_LO
    m_start = find_start(img, m_off)
    m_end = find_end(img, m_start)
    mclk = {"site": hex(MCLK_SITE), "start": hex(IMG_LO + m_start),
            "end": hex(IMG_LO + m_end), "bytes": m_end - m_start,
            "slot_0x34_accesses": [], "calls": []}
    o = m_start
    while o < m_end:
        ins, sz = dec_at(img, o)
        if ins is None:
            break
        op = ins.op_str or ""
        if "0x34(s8)" in op or "0x34(s0)" in op:
            mclk["slot_0x34_accesses"].append(
                {"va": hex(IMG_LO + o), "insn": f"{ins.mnemonic} {op}"})
        if ins.mnemonic == "jalr" and "ra, ra" in op:
            mclk["calls"].append({"va": hex(IMG_LO + o), "insn": f"{ins.mnemonic} {op}"})
        o += sz
    mclk["n_slot_accesses"] = len(mclk["slot_0x34_accesses"])
    out["mclk_caller"] = mclk
    print(f"[mclk] fn [{mclk['start']}, {mclk['end']}) = {mclk['bytes']} B; "
          f"0x34(s8) accesses = {mclk['n_slot_accesses']}")

    # -- 3. the L2 switch caller: a GENEROUS window (the prologue/ret
    # scan breaks on cold sections — the trace API itself proved that)
    l_lo = max(0, (L2_FIRST - IMG_LO) - 0x40)
    l_hi = min(len(img), (L2_LAST - IMG_LO) + 0x80)
    l2 = {"first_site": hex(L2_FIRST), "last_site": hex(L2_LAST),
          "window": [hex(IMG_LO + l_lo), hex(IMG_LO + l_hi)],
          "body": decode_range(img, l_lo, l_hi),
          "interned_compares": []}
    # the interned-name compares: the bgeu/bltu sites against s5 (the
    # incoming name cursor) — the 4.47 "pointer-range switch"
    o = l_lo
    while o < l_hi:
        ins, sz = dec_at(img, o)
        if ins is None:
            break
        op = ins.op_str or ""
        if ins.mnemonic in ("bgeu", "bltu") and "s5" in op:
            l2["interned_compares"].append(
                {"va": hex(IMG_LO + o), "insn": f"{ins.mnemonic} {op}"})
        o += sz
    l2["n_compares"] = len(l2["interned_compares"])
    out["l2_caller"] = l2
    print(f"[l2] window [{l2['window'][0]}, {l2['window'][1]}) "
          f"s5-compares = {l2['n_compares']}")

    # -- 2b. the MclkProg caller: widen +-0x400 for the 0x34(s8) writes --
    w_lo = max(0, m_off - 0x400)
    w_hi = min(len(img), m_off + 0x400)
    wide = []
    o = w_lo
    while o < w_hi:
        ins, sz = dec_at(img, o)
        if ins is None:
            break
        op = ins.op_str or ""
        if "0x34(s8)" in op or "0x34(s0)" in op:
            wide.append({"va": hex(IMG_LO + o),
                         "insn": f"{ins.mnemonic} {op}"})
        o += sz
    out["mclk_caller"]["slot_0x34_wide_window"] = {
        "window": [hex(IMG_LO + w_lo), hex(IMG_LO + w_hi)],
        "accesses": wide}
    print(f"[mclk] wide +-0x400: 0x34(s8) accesses = {len(wide)}")

    out["selftests"] = {"auipc_416206": True, "v448a_semantics": True}
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
