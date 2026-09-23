#!/usr/bin/env python3
"""4.34 PART B — the semantics of the 34 c.lui-100000 bodies.

The 4.33 queue: "the semantics of the 34 ret-bounded bodies that carry
the 36 c.lui-100000 sites (2 bodies carry 2 sites; 3 sites sit inside
the s2/s3 regions)". The constant 100000 is c.lui-encodable (the 4.32e
theorem) and appears ONLY in compressed form — 36 real sites, all
seen-validated (v432e C1 / v433c census).

Method (per body, all byte-derived):
  1. load the 36 sites + body bounds from the banked v433c attribution
     (VA coords; B_file = VA - 0x1000000 + 0x38 under the proven law);
  2. disassemble the site window AND the whole body (site -> body end,
     the ret-bounded tail; the c.lui+addi may sit BEFORE more body);
  3. forward-slice the materializing register: the FIRST consumer of rd
     after the pair decides the class —
       STORE-DATA  sd/sw/c.sd/c.sw rd, off(base)   (the offset recorded)
       COMPARE     bltu/beq/bne... rd
       ARITH       add/addw/mul/divu/rem rd, rd, x
       CALL-ARG    the rd moved into an a-register before a call, or
                   the call's register window overlaps
       LOAD-BASE   lw/ld rd2, off(rd)  (the value used as an ADDRESS)
       DEAD        no consumer before ret (a sunk store, a debug knob)
  4. the time-domain probe: for each body, the OTHER time constants in
     the same body window (full-form knobs 1e6/5e5/2.5e5/1e7... and the
     c.lui family) — is 100000 co-tabulated with the us ladder?
  5. per-body verdict: PROVEN (the consumer class is unambiguous),
     HYPOTHESIS (ambiguous/arg flow), with the cited disassembly of
     every distinct consumer pattern.

Output: lab/jalon411/v434b_cl100_bodies.json (+ the printed table).
"""
import json
import struct
import zlib
from collections import Counter, defaultdict
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
KNOBS = ROOT / "lab/jalon411/v433c_knobs.json"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38                 # B_file = A_img - 0x38
IMG_LO = 0x1000000           # VA = A_img + 0x1000000

db = B.read_bytes()
blob = zlib.decompress(MAP.read_bytes())   # the v416 map is zlib-packed
half = len(blob) // 2
seen, covered = blob[:half], blob[half:]
assert seen[0x1A02A] == 1 and seen[0x1A02C] == 0   # the s1 proof re-asserted

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True


def dis1(off, va=None):
    if off + 2 > len(db):
        return None
    if db[off] & 3 == 3:
        if off + 4 > len(db):
            return None
        ins = next(md.disasm(db[off:off + 4], (va if va is not None else off)), None)
    else:
        ins = next(md.disasm(db[off:off + 2], (va if va is not None else off)), None)
    return ins


def rn(ins, k):
    try:
        return ins.reg_name(ins.operands[k].reg)
    except Exception:
        try:
            return ins.op_str.split(",")[k].strip()
        except Exception:
            return "?"


def dis_lines(off, n, end=None):
    lines = []
    cur = off
    while len(lines) < n:
        if end is not None and cur >= end:
            break
        ins = dis1(cur)
        if ins is None:
            lines.append((cur, None))
            break
        lines.append((cur, ins))
        cur += ins.size
    return lines


ATTR = json.load(open(KNOBS))["clui_100000_attribution"]
sites = ATTR["sites"]
assert len(sites) == 36

print(f"[1] 36 sites / {ATTR['distinct_bodies']} bodies banked (v433c)")

# group sites by body
bodies = defaultdict(list)
for s in sites:
    bodies[tuple(s["body"])].append(s)
print(f"[2] {len(bodies)} distinct bodies reconstructed")


LOADS = {"lw", "ld", "lh", "lb", "lhu", "lbu", "lwu", "c.lw", "c.ld",
         "c.lwsp", "c.ldsp"}
STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp"}
BRANCHES = {"bltu", "bgeu", "beq", "bne", "blt", "bge", "beqz", "bnez",
            "c.beqz", "c.bnez", "bltz", "bgez", "blez", "bgtz"}
DIVMUL = {"divu": "DIVIDE", "div": "DIVIDE", "remu": "DIVIDE",
          "rem": "DIVIDE", "mul": "MUL", "mulhu": "MUL"}


def reg_roles(ins, rd_num):
    """(reads, writes) of register NUMBER rd_num by ins — by capstone
    operand positions, the 4.31 lesson (capstone decodes everything)."""
    m = ins.mnemonic
    reads = writes = False
    try:
        ops = ins.operands
        if m in LOADS:
            if len(ops) > 1 and ops[1].type == capstone.CS_OP_MEM:
                reads = (ops[1].mem.base == rd_num)
            writes = bool(ops) and ops[0].type == capstone.CS_OP_REG \
                and ops[0].reg == rd_num
        elif m in STORES:
            for o in ops:
                if o.type == capstone.CS_OP_REG and o.reg == rd_num:
                    reads = True
                elif o.type == capstone.CS_OP_MEM and \
                        (o.mem.base == rd_num or o.mem.index == rd_num):
                    reads = True
        elif m in BRANCHES or m in ("j", "c.j", "ret", "c.ret", "ecall",
                                    "ebreak", "fence", "fence.i", "nop",
                                    "c.nop", "wfi", "mret", "sret"):
            for o in ops:
                if o.type == capstone.CS_OP_REG and o.reg == rd_num:
                    reads = True
                elif o.type == capstone.CS_OP_MEM and o.mem.base == rd_num:
                    reads = True
        elif m == "jal":
            writes = rd_num == 1
        elif m in ("jalr", "c.jalr"):
            if m == "jalr":
                reads = len(ops) > 1 and ops[1].type == capstone.CS_OP_REG \
                    and ops[1].reg == rd_num or \
                    (len(ops) > 1 and ops[1].type == capstone.CS_OP_MEM
                     and ops[1].mem.base == rd_num)
                writes = ops[0].type == capstone.CS_OP_REG and \
                    ops[0].reg == rd_num
            else:
                reads = True          # c.jalr reads rs1
                writes = rd_num == 1
        else:
            # compute class: ops[0] = dest, ops[1:] = sources (except the
            # RMW compressed forms where ops[0] reads too)
            rmw = m in ("c.add", "c.addi", "c.addiw", "c.addi16sp",
                        "c.slli", "c.and", "c.or", "c.xor", "c.sub",
                        "c.andi", "c.ori", "c.xori", "c.addi4spn")
            if ops:
                if ops[0].type == capstone.CS_OP_REG:
                    writes = ops[0].reg == rd_num
                    if rmw:
                        reads = writes
            for o in ops[1:]:
                if o.type == capstone.CS_OP_REG and o.reg == rd_num:
                    reads = True
                elif o.type == capstone.CS_OP_MEM and o.mem.base == rd_num:
                    reads = True
    except Exception:
        pass
    return reads, writes


def first_consumer(start_off, rd_num, end_b):
    """the first consumer of register NUMBER rd_num after the pair."""
    cur = start_off
    depth = 0
    misses = 0
    while cur < end_b and depth < 300:
        ins = dis1(cur)
        if ins is None:
            misses += 1
            if misses > 3:
                return ("STOP-DECODE", None, None, cur)
            cur += 2
            continue
        m = ins.mnemonic
        reads, writes = reg_roles(ins, rd_num)
        if reads:
            if m in STORES:
                try:
                    disp = ins.operands[-1].mem.disp
                except Exception:
                    disp = None
                return ("STORE-DATA", disp, ins, cur)
            if m in BRANCHES:
                return ("COMPARE", None, ins, cur)
            if m in DIVMUL:
                return (DIVMUL[m], None, ins, cur)
            if m in LOADS:
                return ("LOAD-BASE", None, ins, cur)
            return ("USE:" + m, None, ins, cur)
        if writes:
            return ("CLOBBERED", None, ins, cur)
        cur += ins.size
        depth += 1
    return ("DEAD-AT-RET", None, None, cur)


def body_time_constants(start, end_b):
    """other time-domain constants inside the body window (full-form
    lui+addi pairs and c.lui pairs, all even offsets)."""
    vals = []
    off = start & ~1
    while off + 8 <= end_b:
        w = struct.unpack_from("<I", db, off)[0]
        if (w & 0x7F) == 0x37 and ((w >> 7) & 0x1F) != 0:
            rd = (w >> 7) & 0x1F
            w2 = struct.unpack_from("<I", db, off + 4)[0]
            if (w2 & 0x7F) in (0x13, 0x1B) and ((w2 >> 12) & 7) == 0 \
                    and ((w2 >> 15) & 0x1F) == rd and ((w2 >> 7) & 0x1F) == rd:
                hi = w >> 12
                lo = (w2 >> 20) & 0xFFF
                v = (hi << 12) + (lo - 0x1000 if lo >= 0x800 else lo)
                if abs(v) >= 1000:
                    vals.append((hex(off), v))
                off += 8
                continue
        off += 2
    return vals


print("[3] per-body analysis")
out_bodies = []
cls_hist = Counter()
for body_key, b_sites in sorted(bodies.items(), key=lambda kv: kv[0][1] or "0"):
    body_start_va, body_end_va = body_key
    # B_file bounds: the body END is hard (ret-bounded); the start may be
    # None (unresolved prologue) — scan from the FIRST site.
    end_b = int(body_end_va, 16) - IMG_LO + SHIFT if body_end_va else None
    recs = []
    for s in b_sites:
        a_b = int(s["B_file"], 16) if isinstance(s.get("B_file"), str) \
            else int(s["A_img"], 16) - SHIFT
        # decode the pair with capstone (the 4.31 lesson: capstone decodes
        # everything — the raw rd field of a COMPRESSED c.lui is NOT at
        # bits [11:7] of the padded word)
        ins1 = dis1(a_b)
        rd_num = None
        try:
            if ins1 and ins1.operands and \
                    ins1.operands[0].type == capstone.CS_OP_REG:
                rd_num = ins1.operands[0].reg
        except Exception:
            rd_num = None
        if rd_num is None:
            rd_num = int(s["rd"].lstrip("x"), 0) if isinstance(s["rd"], str) \
                and s["rd"].lstrip("x").isdigit() else \
                {"zero": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4, "t0": 5,
                 "t1": 6, "t2": 7, "s0": 8, "fp": 8, "s1": 9, "a0": 10,
                 "a1": 11, "a2": 12, "a3": 13, "a4": 14, "a5": 15,
                 "a6": 16, "a7": 17, "s2": 18, "s3": 19, "s4": 20,
                 "s5": 21, "s6": 22, "s7": 23, "s8": 24, "s9": 25,
                 "s10": 26, "s11": 27, "t3": 28, "t4": 29, "t5": 30,
                 "t6": 31}.get(s.get("rd"), 0)
        gap = s["gap"]
        pair = []
        cur = a_b
        for _ in range(2):
            ins = dis1(cur)
            pair.append(f"{ins.mnemonic:<7} {ins.op_str}" if ins else "<bad>")
            cur += ins.size if ins else 2
        # scan starts AFTER the addi insn (decode its size)
        addi_ins = dis1(a_b + gap)
        scan0 = a_b + gap + (addi_ins.size if addi_ins else 4)
        cls, disp, cins, cpos = first_consumer(scan0, rd_num, end_b or len(db))
        cls_hist[cls] += 1
        win = [f"0x{IMG_LO + o - SHIFT + SHIFT:x}: {i.mnemonic:<8} {i.op_str}"
               for o, i in dis_lines(a_b - 6 if a_b >= 6 else a_b, 10,
                                     end=(end_b or len(db)))
               for i in [i]] if False else None
        # build a cited window around the pair
        lines = []
        st = a_b
        # rewind a few instructions
        for back_off in (6, 4, 2):
            if a_b - back_off >= 0 and seen[a_b - back_off + SHIFT] == 1 \
                    if a_b - back_off + SHIFT < len(seen) else False:
                st = a_b - back_off
                break
        for o, i in dis_lines(st, 9, end=end_b):
            if i is not None:
                lines.append(f"0x{IMG_LO + o + SHIFT:x}: {i.mnemonic:<8} {i.op_str}")
            else:
                lines.append(f"0x{IMG_LO + o + SHIFT:x}: <invalid>")
        recs.append(dict(
            A_img=s["A_img"], B_file=(s.get("B_file") or
                                      hex(int(s["A_img"], 16) - SHIFT)),
            VA=s["VA"], gap=s["gap"],
            rd=f"x{rd_num}", pair=pair, first_consumer=cls,
            store_disp=(hex(disp) if disp is not None else None),
            consumer_line=(f"0x{IMG_LO + cpos + SHIFT:x}: {cins.mnemonic} {cins.op_str}"
                           if cins else None),
            window=lines,
            in_s2_or_s3=s["in_s2_or_s3_region"],
            region=s["region"]))
    # the body's other time constants
    scan_start = int(b_sites[0]["A_img"], 16) - SHIFT
    consts = body_time_constants(scan_start, end_b or scan_start + 0x200)
    out_bodies.append(dict(
        body=[body_key[0], body_key[1]],
        n_sites=len(b_sites),
        sites=recs,
        other_time_constants=consts[:12]))
    print(f"  body end {body_key[1]}: {len(b_sites)} site(s), "
          f"first consumers: {[r['first_consumer'] for r in recs]}, "
          f"other consts: {[v for _, v in consts][:6]}")

print("[4] classification histogram:", dict(cls_hist))

# the s2/s3 detail (the 4.33 queue item)
s23 = [r for b in out_bodies for r in b["sites"] if r["in_s2_or_s3"]]
print(f"[5] s2/s3 sites detail: {len(s23)}")
for r in s23:
    print(f"  {r['VA']} rd={r['rd']} -> {r['first_consumer']} "
          f"({r['consumer_line']})")

# verdict rollup
prov = sum(1 for b in out_bodies for r in b["sites"]
           if r["first_consumer"] in ("STORE-DATA", "COMPARE", "ARITH",
                                      "LOAD-BASE", "DIVIDE", "MUL"))
hyp = 36 - prov
json.dump(dict(
    law="B_file = A_img - 0x38; VA = A_img + 0x1000000",
    source="v433c_knobs.json clui_100000_attribution (36 sites, 34 bodies)",
    classification_histogram=dict(cls_hist),
    proven_bodies=prov, hypothesis_bodies=hyp,
    s2s3_sites=[dict(A_img=r["A_img"], VA=r["VA"], rd=r["rd"],
                     first_consumer=r["first_consumer"],
                     consumer_line=r["consumer_line"]) for r in s23],
    bodies=out_bodies,
), open(OUT, "w"), indent=1)
print(f"[6] {OUT}")
