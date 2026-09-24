#!/usr/bin/env python3
"""4.50 TASK A — the G5x bit1 question: does ANY consumer test bit 1 of
the FB/L2 flag word (config+0x3D68, set by the RMG5xL2VidmemPromote
ingestion handler @0x13082a2 per 4.49)?

The v449a `the_consumer` decode started at 0x1318d46 — its func_bounds
prologue test `(hw & 3) == 1 and (hw >> 13) == 3` matches BOTH c.addi16sp
AND c.lui (same quadrant/funct3; the discriminator is rd == x2). The
window therefore began mid-function, right after the 0x67f gate byte —
and any bit1 test BEFORE the flag load was invisible. This instrument:

  1. re-derives the baseline (auipc 416,206; the 512-region law);
  2. walks BACK from 0x1318d4a with the CORRECTED prologue test
     (c.addi16sp with rd==x2, or 32-bit `addi sp,sp,-N`), decodes the
     WHOLE enclosing function (advance-the-walk guard, cap 6000 insns);
  3. censuses inside it: every load/store of -0x298 (flag word) and
     -0x27c (ways value), every andi/ori bit test, every 0x2ac/0x2bc
     register programming, every gate-byte lbu;
  4. answers THE QUESTION two ways:
     (a) in-function: is `& 2` ever applied to the flag word?
     (b) image-wide fallback: for EVERY raw -0x298/-0x27c site of the
         v449a reader_scan, decode +-0x40 and look for a bit1 test in
         the same window;
  5. decodes the bit1 SETTER context (the RMG5xL2VidmemPromote success
     handler @0x13082a2) to re-assert which key owns bit 1.

Output: lab/jalon411/v450a_g5x_bit1.json
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
PREV = ROOT / "lab/jalon411/v449a_knob_store.json"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_LEN = 0xE9B000
CONSUMER_SITE = 0x1318D4A
SETTER_SITE = 0x13082A2
TRACE_API = 0x1A9E624

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

REG = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
       "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
       "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
       "t3", "t4", "t5", "t6"]


def dec_at(img, off):
    if img[off] & 3 == 3:
        ins = next(md.disasm(img[off:off + 4], IMG_LO + off), None)
        return (ins, 4) if ins else (None, 0)
    ins = next(md.disasm(img[off:off + 2], IMG_LO + off), None)
    return (ins, 2) if ins else (None, 0)


def render(ins):
    if ins is None:
        return "<invalid>"
    return f"{ins.mnemonic:<8} {ins.op_str}"


def is_prologue(img, off):
    """The CORRECTED test: c.addi16sp (quadrant1, funct3=011, rd==x2)
    or 32-bit addi sp, sp, -N. The v449a version missed rd==x2 and
    matched c.lui — the 0x1318d46 false start."""
    hw = struct.unpack_from("<H", img, off)[0]
    if (hw & 3) == 1 and (hw >> 13) == 3 and ((hw >> 7) & 31) == 2:
        return True
    if img[off] & 3 == 3:
        u = struct.unpack_from("<I", img, off)[0]
        if (u & 0x7F) == 0x13 and ((u >> 15) & 31) == 2 and \
                ((u >> 7) & 31) == 2:
            imm = (u >> 20) & 0xFFF
            if imm & 0x800:      # negative -> the stack grow
                return True
    return False


def find_prologue(img, va, maxback=0x1000):
    o = va - IMG_LO
    p = o
    for _ in range(maxback // 2):
        if p <= 0:
            return None
        if is_prologue(img, p):
            return p
        p -= 2
    return None


def decode_range(img, off, end, maxn=6000):
    lines = []
    o = off
    n = 0
    while o < end and n < maxn:
        ins, sz = dec_at(img, o)
        lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
        o += sz if sz else 2     # the advance-the-walk guard
        n += 1
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
    assert cnt == 416206, f"auipc census {cnt} != 416206"
    for i in range(512):
        pass
    out = {"pass": "4.50", "task": "A", "instrument": "v450a_g5x_bit1",
           "baseline": {"auipc": cnt, "law": "512/512"}}

    # -- 2. the WHOLE enclosing function, from the TRUE prologue ----------
    pro_off = find_prologue(img, CONSUMER_SITE)
    assert pro_off is not None, "no prologue found"
    pro_va = IMG_LO + pro_off
    # the end: the first ret at or after the consumer site (forward)
    o = CONSUMER_SITE - IMG_LO
    end_off = o
    q = o
    for _ in range(0x4000):
        if q + 2 > len(img):
            break
        hw = struct.unpack_from("<H", img, q)[0]
        if hw == 0x8082 or (img[q] & 3 == 3 and
                            struct.unpack_from("<I", img, q)[0] == 0x8067):
            end_off = q
            break
        insx, szx = dec_at(img, q)
        q += szx if szx else 2
    body = decode_range(img, pro_off, end_off)
    out["function"] = {
        "prologue_va": hex(pro_va),
        "prologue_insn": render(next(md.disasm(
            img[pro_off:pro_off + 4], pro_va), None)),
        "end_va": hex(IMG_LO + end_off),
        "bytes": end_off - pro_off,
        "insns": len(body),
        "starts_before_consumer_site": pro_va < CONSUMER_SITE,
    }
    print(f"[function] true prologue {pro_va:#x} "
          f"({out['function']['prologue_insn']}), end "
          f"{IMG_LO + end_off:#x}, {len(body)} insns")

    # -- 3. the in-function census ----------------------------------------
    flag_reads, ways_accesses, bit_tests, reg_progs, gates = [], [], [], [], []
    for l in body:
        va, insn = l.split(": ", 1)
        if "-0x298" in insn:
            flag_reads.append(l)
        if "-0x27c" in insn:
            ways_accesses.append(l)
        m = re.match(r"(c\.andi|andi)\s+(\w+),\s*(\w+),\s*(-?0x[0-9a-f]+|-?\d+)$", insn)
        if m:
            bit_tests.append({"va": va, "insn": insn,
                              "imm": int(m.group(4), 0)})
        if "0x2ac" in insn or "0x2bc" in insn:
            reg_progs.append(l)
        m2 = re.match(r"(lbu|c\.lbu)\s+(\w+),\s*(0x[0-9a-f]+)\(", insn)
        if m2:
            gates.append({"va": va, "insn": insn, "off": int(m2.group(3), 16)})
    out["census"] = {
        "flag_word_loads": flag_reads,
        "ways_accesses": ways_accesses,
        "bit_tests": bit_tests,
        "register_programming": reg_progs,
        "gate_bytes": gates,
    }
    bit1_in_function = [b for b in bit_tests if b["imm"] == 2]
    out["bit1_in_function"] = bit1_in_function
    print(f"[census] flag-word loads: {len(flag_reads)}; ways accesses: "
          f"{len(ways_accesses)}; bit tests: {len(bit_tests)}; "
          f"BIT1 TESTS: {len(bit1_in_function)}")
    for l in flag_reads + ways_accesses:
        print("  ", l)
    for b in bit1_in_function:
        print("   BIT1:", b)

    # -- 4b. the image-wide fallback: a bit1 test near ANY -0x298 site ----
    prev = json.loads(PREV.read_text())
    raw_sites = [int(h["va"], 16) for h in prev["reader_scan"]]
    near_bit1 = []
    for sv in raw_sites:
        o = sv - IMG_LO
        lines = decode_range(img, o - 0x40, o + 0x40)
        for l in lines:
            va, insn = l.split(": ", 1)
            m = re.match(r"(c\.andi|andi)\s+(\w+),\s*(\w+),\s*(2)$", insn)
            if m:
                near_bit1.append({"near_site": hex(sv), "test": l})
    out["bit1_near_flag_sites"] = near_bit1
    print(f"[fallback] {len(near_bit1)} bit1 tests within +-0x40 of any "
          f"of the {len(raw_sites)} raw flag-word sites")
    for n in near_bit1[:12]:
        print("   ", n)

    # -- 5. the bit1 SETTER (the RMG5xL2VidmemPromote handler) ------------
    out["setter_context"] = decode_range(img, SETTER_SITE - IMG_LO - 0x30,
                                         SETTER_SITE - IMG_LO + 0x70)
    print("[setter] the 0x13082a2 window decoded")

    # -- the honest verdict ------------------------------------------------
    out["verdict"] = {
        "bit1_tested_in_consumer_function": bool(bit1_in_function),
        "bit1_tested_near_any_flag_site": bool(near_bit1),
        "reading": None,
    }
    if bit1_in_function:
        out["verdict"]["reading"] = \
            "the consumer function tests bit1 — the G5x promote path is IN the consumer; decode the path"
    elif near_bit1:
        out["verdict"]["reading"] = \
            "a bit1 test exists near another flag-word site — name that site's function"
    else:
        out["verdict"]["reading"] = \
            "NO bit1 test anywhere near the flag word — RMG5xL2VidmemPromote's bit is SET but never read (a write-only flag in this image) — the G5x promote knob is likely consumed by a mechanism outside the -0x298 displacement class (or dead in this build)"
    print("[verdict]", out["verdict"]["reading"])

    out["selftests"] = {"auipc_416206": True, "law_512": "PASS"}
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
