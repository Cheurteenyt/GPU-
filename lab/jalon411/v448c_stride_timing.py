#!/usr/bin/env python3
"""4.48 TASK C — the timing-parse hunt: who walks a 76-byte-record table
inside GSP-RM, and the DMEM-dump fingerprints for the machine day.

The 4.47 grosse tâche TÂCHE B asks: WHERE do the parsed VBIOS DRAM
timing records live at runtime (DMEM state -> the f18-analog payload;
FB-Falcon/MC-direct -> the lane honestly dies)? The static half:

  1. the stride-0x4C census: the gx5 timing table = 65 records x 76 B;
     any RM-side walker must advance by 76 — the image-wide census of
     `addi rX, rY, 0x4c` (the loop-advance), the li-76 constant (addi
     rT, zero, 0x4c — c.li CANNOT carry 76, the 4.46 lesson) and the
     mul consuming it, and the shift-add compositions;
  2. for each hit: the +-6-insn neighborhood decode + a coarse
     classification (loads from one base + stores to another = a
     copy/parse walker; pure arithmetic = noise);
  3. the DMEM-dump fingerprint builder: the gx5-banked top-bin field
     vectors (launch id 6 {rc=78, rfc=210, ras=52, rp=26, cl=24}; the
     LHR deltas {70, 175, 44, 20, 5} for rc/rfc/ras/faw/rrd) rendered
     as u8/u16/u32-LE contiguous byte patterns — the searcher the
     machine-day runbook runs over the post-boot dump.

Selftests: the auipc census; the gx5 vector round-trip (the u8 pattern
re-parses to the vector).

Output: lab/jalon411/v448c_stride_timing.json
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
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_LEN = 0xE9B000

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

REG = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
       "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
       "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
       "t3", "t4", "t5", "t6"]


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
        if op.type == 2:
            extra = f"   -> {ins.address + op.imm:#x}"
    return f"{ins.mnemonic:<8} {ins.op_str}{extra}"


# the gx5-banked vectors (findings-gx5.md, banked 2026-09)
G6_LAUNCH = {"id": 6, "fields": {"rc": 78, "rfc": 210, "ras": 52,
                                 "rp": 26, "cl": 24}}
G26_LHR = {"id": 26, "fields": {"rc": 70, "rfc": 175, "ras": 44,
                                "faw": 20, "rrd": 5}}


def fingerprints(vec):
    """Render the field vector as u8/u16/u32-LE contiguous patterns."""
    vals = list(vec)
    out = {}
    out["u8"] = bytes(vals).hex()
    out["u16le"] = b"".join(struct.pack("<H", v) for v in vals).hex()
    out["u32le"] = b"".join(struct.pack("<I", v) for v in vals).hex()
    # the distinctive pair (rfc, ras) — the strongest 2-field fingerprint
    out["pair_u8_rc_rfc"] = bytes(vals[0:2]).hex()
    return out


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

    out = {"pass": "4.48", "task": "C", "instrument": "v448c_stride_timing",
           "baseline": {"auipc": cnt}}

    # -- 1. the stride-0x4C census -----------------------------------------
    # (a) addi rX, rY, 0x4c  (I-type, opcode 0x13, funct3 0)
    addi_hits = []
    for off in range(0, len(img) - 4, 2):
        if img[off] & 3 != 3:
            continue
        u = struct.unpack_from("<I", img, off)[0]
        if (u & 0x7F) != 0x13 or ((u >> 12) & 7) != 0:
            continue
        imm = (u >> 20) & 0xFFF
        if imm != 0x04C:
            continue
        rd = REG[(u >> 7) & 31]
        rs1 = REG[(u >> 15) & 31]
        addi_hits.append({"va": hex(IMG_LO + off), "insn":
                          f"addi {rd}, {rs1}, 0x4c", "rd": rd, "rs1": rs1})
    # (b) the li-76 constant (addi rT, zero, 0x4c) + the mul that consumes rT
    li76 = []
    for off in range(0, len(img) - 4, 2):
        if img[off] & 3 != 3:
            continue
        u = struct.unpack_from("<I", img, off)[0]
        if (u & 0x7F) != 0x13 or ((u >> 12) & 7) != 0:
            continue
        if ((u >> 20) & 0xFFF) != 0x04C:
            continue
        if ((u >> 15) & 31) != 0:
            continue  # rs1 must be zero -> li
        li76.append((off, REG[(u >> 7) & 31]))
    mul_hits = []
    for (off, rt) in li76:
        o = off
        for _ in range(8):
            if img[o] & 3 == 3:
                u = struct.unpack_from("<I", img, o)[0]
                if (u & 0x7F) == 0x33 and ((u >> 25) & 0x7F) == 1 and \
                        ((u >> 12) & 7) == 0:
                    rs2 = REG[(u >> 20) & 31]
                    rs1 = REG[(u >> 15) & 31]
                    if rt in (rs1, rs2):
                        mul_hits.append({"li": hex(IMG_LO + off),
                                         "mul": hex(IMG_LO + o),
                                         "insn": f"mul with {rt}"})
                        break
                o += 4
            else:
                o += 2
    out["stride76"] = {
        "addi_0x4c_total": len(addi_hits),
        "addi_0x4c_list": addi_hits[:60],
        "li76_constants": len(li76),
        "mul_by_76": mul_hits,
    }
    print(f"[stride76] addi x,x,0x4c = {len(addi_hits)}; li76 = {len(li76)}; "
          f"mul-by-76 = {len(mul_hits)}")

    # -- 2. the neighborhoods of the addi hits (coarse classification) -----
    ne = []
    for h in addi_hits[:40]:
        off = int(h["va"], 16) - IMG_LO
        lines = []
        o = max(0, off - 12)
        while o < off + 4 + 12:
            ins, sz = dec_at(img, o)
            if ins is None:
                o += 2
                continue
            lines.append(render(ins))
            o += sz
        ne.append({"va": h["va"], "ctx": lines})
    out["stride76_neighborhoods"] = ne

    # -- 3. the DMEM-dump fingerprints --------------------------------------
    out["dmem_fingerprints"] = {
        "note": "the post-boot GSP DMEM dump is searched for these byte "
                "patterns (all representations, both LHR-era and "
                "launch-era top-bin records); a hit = the parsed record "
                "lives in RM-reachable state (the f18-analog lane opens); "
                "no hit anywhere in DMEM + no FB-Falcon consumer found = "
                "the lane closes honestly",
        "record_id6_launch": {"vector": G6_LAUNCH,
                              "patterns": fingerprints(
                                  [78, 210, 52, 26, 24])},
        "record_id26_lhr": {"vector": G26_LHR,
                            "patterns": fingerprints([70, 175, 44, 20, 5])},
        "caveat": "the gx5 grammar (six u32 -> 18 fields) is NOT in the "
                  "repo (the instrument ran pre-repo on the founder's "
                  "machine) — the fingerprints use the five banked field "
                  "values in record order; a bit-packed layout needs the "
                  "u8 pattern or a fieldwise search, both listed",
    }
    # selftest: the u8 pattern round-trips
    assert list(bytes.fromhex(out["dmem_fingerprints"]
                              ["record_id6_launch"]["patterns"]["u8"])) == \
        [78, 210, 52, 26, 24]

    out["selftests"] = {"auipc_416206": True, "fingerprint_roundtrip": True}
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
