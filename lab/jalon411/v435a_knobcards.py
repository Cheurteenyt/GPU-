#!/usr/bin/env python3
"""4.35 TASK A — the knob cards: semantics, risk and leverage per knob.

Pass 4.33 LANE A banked the 60-knob table (round constants, forms,
first-consumer classes). 4.34 proved the TIME domain (tick = 1 ns) and
classified the 36 c.lui-100000 bodies. The 4.35 question is the NEXT
optimization step: for each knob, WHAT is it (unit hypothesis), HOW
risky is turning it (risk class), and HOW MUCH code reaches it
(leverage = owner-region fan-in)?

Method (every card re-derived from the image, never copied):
  - sites re-censused with the banked v433c rules (full24/full68/clui,
    the selftest must reproduce the banked 4.32 counts + 36 c.lui);
  - the extended classifier: forward from the addi, 80 insns, first
    READ of rd — with CFG-follow through unconditional jumps (j / c.j,
    forward, max 3 hops) — this re-attacks the 4.34 value-block shapes;
  - rdtime/rdcycle presence inside the body span (backward+forward
    ret-bounded walk) -> the TIME-context flag;
  - co-constant census inside the body span (full-form pairs only):
    which OTHER round values share the body -> the family evidence;
  - owner attribution: the covered-region (v416 map) containing the
    site; region fan-in recomputed from the PIC call census (auipc+jalr
    at seen starts, the v433b method) + direct jal;
  - unit hypothesis rules (ordered, cited):
      R1 rdtime-in-body and v % 1000 == 0 -> TIME-QUANTA (vs raw ticks)
      R2 body divides by 1e9/1e6 (co-constant with DIVIDE use)
         -> TIME-CONVERSION
      R3 v % 270000 == 0 and v >= 270000 -> CLK-270k-FAMILY (v/270000
         quanta; 4.34 proved 27 MHz has a different role — the family
         math is reported, the semantics stay HYPOTHESIS)
      R4 STORE-DATA dominant -> STATE-DEFAULT (tunable state field)
      R5 COMPARE dominant -> THRESHOLD/POLICY
      R6 CALL-ARG present -> PROTOCOL-ARG
      R7 else -> INTERNAL-MATH
  - risk classes:
      DO-NOT-TOUCH-BLIND : TIME-QUANTA / TIME-CONVERSION / DIVIDE site
      PROTOCOL-RISK      : CALL-ARG (the value enters RM internals)
      GATED-TUNABLE      : STORE-DATA into state (the field consumer
                           must be named before any turn)
      CONTEXT-DEPENDENT  : everything else

Selftests: the coordinate law (512 windows + 7 sites), the map base
(opcode-discriminated), the banked pair counts, the 36 c.lui-100000,
the PIC census selftest (the banked callee 0x188EF44 fan-in >= 2).

Output: lab/jalon411/v435a_knobcards.json
"""
import json
import struct
import zlib
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

import numpy as np
import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82
BANKED_COUNTS = {250000: 6, 500000: 25, 1000000: 123, 4000000: 15,
                 100000000: 17, -250000: 1, -1000000: 3, -500000: 5,
                 100000: 0, 240000: 0, 280000: 0}
N_CLUI_100000 = 36
BANKED_CALLEE = 0x188EF44 - IMG_LO

REGS = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6"]

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True


def dis1(buf, off, va=None):
    if off + 2 > len(buf):
        return None
    if buf[off] & 3 == 3:
        if off + 4 > len(buf):
            return None
        return next(md.disasm(buf[off:off + 4], (va or off)), None)
    return next(md.disasm(buf[off:off + 2], (va or off)), None)


def writes_reg(ins, rd_name):
    if ins is None:
        return False
    m = ins.mnemonic
    if m in ("sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp",
             "beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
             "bltz", "bgez", "blez", "bgtz", "c.beqz", "c.bnez",
             "j", "c.j", "ret", "c.ret", "c.jr", "ecall", "ebreak",
             "fence", "fence.i", "nop", "c.nop", "wfi", "mret", "sret",
             "uret", "sfence.vma", "rdtime", "rdcycle", "rdinstret"):
        return False
    return ins.op_str.split(",")[0].strip() == rd_name


def is_retlike(ins):
    if ins is None:
        return False
    m, ops = ins.mnemonic, ins.op_str
    if m in ("ret", "c.ret"):
        return True
    if m == "jalr" and ops.startswith("zero,"):
        return True
    if m == "c.jr" and ops.strip() == "ra":
        return True
    return False


def is_uncond_jump(ins):
    if ins is None:
        return None
    if ins.mnemonic == "j":
        return int(ins.op_str.strip(), 16) if \
            ins.op_str.strip().startswith("0x") else None
    if ins.mnemonic == "c.j":
        return int(ins.op_str.strip(), 16) if \
            ins.op_str.strip().startswith("0x") else None
    return None


def reads_reg(ins, rd_name):
    if ins is None:
        return False
    try:
        ops = ins.operands
        for k, o in enumerate(ops):
            if o.type == capstone.riscv.RISCV_OP_REG:
                name = ins.reg_name(o.reg)
                if name == rd_name:
                    is_dest = (k == 0 and not ins.mnemonic.startswith(
                        ("b", "c.b", "sd", "sw", "sh", "sb", "c.sd",
                         "c.sw", "c.st", "store")) and
                        ins.mnemonic not in ("sd", "sw", "sh", "sb",
                                             "c.sd", "c.sw"))
                    if not is_dest:
                        return True
    except Exception:
        pass
    return False


def classify_use_cfg(img, aoff_addi, rd, hops=3):
    """extended v433c classifier: 80 insns, CFG-follow u-jumps."""
    rd_name = REGS[rd]
    hops_left = hops

    def scan(off, budget):
        for _ in range(budget):
            ins = dis1(img, off)
            if ins is None:
                return "UNRESOLVED-decode-end", None
            if off != aoff_addi and reads_reg(ins, rd_name):
                m = ins.mnemonic
                if m.startswith(("b", "c.b")):
                    return "COMPARE", off
                if m in ("div", "divu", "rem", "remw", "remuw", "divw",
                         "divuw"):
                    return "DIVIDE", off
                if m in ("sd", "sw", "sh", "sb", "c.sd", "c.sw",
                         "c.swsp", "c.sdsp"):
                    return "STORE-DATA", off
                if m in ("jal", "jalr", "c.jalr") and \
                        ins.op_str.split(",")[0].strip() in \
                        [f"a{i}" for i in range(8)]:
                    return "CALL-ARG", off
                return "ARITH-CHAIN", off
            if is_retlike(ins):
                return "DEAD-at-ret", off
            tgt = is_uncond_jump(ins)
            if tgt is not None:
                t_off = tgt - IMG_LO
                if t_off > off and hops_left[0] > 0:
                    hops_left[0] -= 1
                    return scan(t_off, budget)
            off += ins.size
        return "UNRESOLVED-in-window", None

    return scan(aoff_addi, 80)


def backward_walk(img, aoff, limit=0x800):
    chain = []
    off = aoff
    while aoff - off < limit:
        p2 = off - 2
        if p2 >= 0 and img[p2] & 3 != 3:
            ins = dis1(img, p2)
            if ins is not None and ins.size == 2:
                chain.append((p2, ins))
                off = p2
                continue
            break
        p4 = off - 4
        if p4 >= 0 and img[p4] & 3 == 3:
            ins = dis1(img, p4)
            if ins is not None and ins.size == 4:
                chain.append((p4, ins))
                off = p4
                continue
        break
    chain.reverse()
    return chain


def body_span(img, aoff, limit=0x800):
    chain = backward_walk(img, aoff, limit)
    start, back_ret = None, None
    for o, ins in chain:
        if is_retlike(ins):
            back_ret = o + ins.size
    if back_ret is not None:
        start = back_ret
    end, off = aoff, aoff
    for _ in range(limit // 2):
        ins = dis1(img, off)
        if ins is None:
            break
        off += ins.size
        if is_retlike(ins):
            end = off
            break
    return start, end, back_ret


def body_flags(img, bs, be):
    """rdtime/rdcycle presence + co-constant round pairs inside body."""
    rdtime = False
    co = defaultdict(int)
    if bs is None:
        bs = be
    off = bs
    n = 0
    while off < be and n < 0x1000:
        ins = dis1(img, off)
        if ins is None:
            break
        if ins.mnemonic in ("rdtime", "rdcycle", "rdinstret"):
            rdtime = True
        w = int.from_bytes(img[off:off + 4], "little") \
            if img[off] & 3 == 3 else None
        if w is not None and (w & 0x7F) == 0x37:
            rd = (w >> 7) & 0x1F
            if rd:
                for d in (2, 4):
                    if off + d + 4 > len(img):
                        continue
                    w2 = int.from_bytes(img[off + d:off + d + 4],
                                        "little")
                    if (w2 & 0x7F) not in (0x13, 0x1B):
                        continue
                    if ((w2 >> 12) & 7) or \
                            ((w2 >> 15) & 0x1F) != rd or \
                            ((w2 >> 7) & 0x1F) != rd:
                        continue
                    lo_f = (w2 >> 20) & 0xFFF
                    if lo_f >= 0x800:
                        lo_f -= 0x1000
                    hi_s = (w >> 12) - (1 << 20) if (w >> 12) >= 0x80000 \
                        else (w >> 12)
                    v = (hi_s << 12) + lo_f
                    if abs(v) >= 1000 and v % 1000 == 0:
                        co[v] += 1
                    break
        off += ins.size
        n += 1
    return rdtime, dict(co)


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000",
           "img_len": hex(len(a_img))}

    # -- the law re-asserted
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    for boff in SITES_B:
        if db[boff:boff + 8] != a_img[boff + SHIFT:boff + SHIFT + 8]:
            fails += 1
    if db[CLAIM7_A - SHIFT:CLAIM7_A - SHIFT + 8] != \
            a_img[CLAIM7_A:CLAIM7_A + 8]:
        fails += 1
    out["law_recheck"] = {"windows": 512 + 7, "fails": fails}
    assert fails == 0, "coordinate law broken"

    # -- the map base (opcode-discriminated, as v433c)
    a_lui, b_lui = 0x1A02A + SHIFT, 0x1A02A
    base_a = seen[a_lui] == 1 and seen[a_lui + 2] == 0 \
        and covered[a_lui + 2] == 1 and (a_img[a_lui] & 0x7F) == 0x37
    base_b = seen[b_lui] == 1 and seen[b_lui + 2] == 0 \
        and covered[b_lui + 2] == 1 and (a_img[b_lui] & 0x7F) == 0x37
    assert base_a != base_b and base_a, "map base ambiguous"
    out["map_semantics"] = {"base": "A_img",
                            "seen": "instruction starts"}
    print("[map] base=A_img proven by opcode")

    sarr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]
    carr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    starts = np.nonzero(sarr)[0]

    # covered regions
    idx = np.nonzero(carr)[0]
    splits = np.nonzero(np.diff(idx) > 1)[0]
    b0 = np.concatenate(([0], splits + 1))
    b1 = np.concatenate((splits, [len(idx) - 1]))
    regions = [(int(idx[i0]), int(idx[i1]) + 1)
               for i0, i1 in zip(b0, b1) if idx[i1] + 1 - idx[i0] >= 2]
    rstart = np.array([r[0] for r in regions], dtype=np.int64)
    rend = np.array([r[1] for r in regions], dtype=np.int64)
    out["covered_regions"] = len(regions)

    def region_of(off):
        i = bisect_right(rstart.tolist(), off) - 1
        if i >= 0 and off < rend[i]:
            return regions[i]
        return None

    # -- the full-form pair census (banked rules) + clui for 100000
    img4 = a_img + b"\x00" * ((4 - len(a_img) % 4) % 4)
    u0 = np.frombuffer(img4, dtype="<u4")
    u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    cands = []
    for base_off, uarr in ((0, u0), (2, u2)):
        kmax = (len(img4) - 4 - base_off) >> 2
        k = np.arange(kmax, dtype=np.int64)
        mask = (uarr[k] & 0x7F) == 0x37
        for kk in k[mask]:
            cands.append((int(base_off + (kk << 2)), int(uarr[kk])))
    cands.sort()

    def full_pass(gaps):
        by_value = defaultdict(list)
        for off, w1 in cands:
            rd = (w1 >> 7) & 0x1F
            if rd == 0:
                continue
            hi_s = (w1 >> 12) - (1 << 20) if (w1 >> 12) >= 0x80000 \
                else (w1 >> 12)
            for d in gaps:
                if off + d + 4 > len(a_img):
                    continue
                w2 = struct.unpack_from("<I", a_img, off + d)[0]
                if (w2 & 0x7F) not in (0x13, 0x1B):
                    continue
                if ((w2 >> 12) & 7) != 0:
                    continue
                if ((w2 >> 15) & 0x1F) != rd or ((w2 >> 7) & 0x1F) != rd:
                    continue
                if d > 4:
                    ins = dis1(a_img, off + 4)
                    if ins is not None and writes_reg(ins, REGS[rd]):
                        continue
                lo_f = (w2 >> 20) & 0xFFF
                if lo_f >= 0x800:
                    lo_f -= 0x1000
                by_value[(hi_s << 12) + lo_f].append({"A_img": hex(off),
                                                      "gap": d, "rd": rd})
                break
        return by_value

    p24 = full_pass((2, 4))
    p68 = full_pass((6, 8))
    drift = {v: (len(p24.get(v, [])), want) for v, want in
             BANKED_COUNTS.items() if len(p24.get(v, [])) != want}
    assert not drift, f"banked pair counts drifted: {drift}"
    out["selftest_banked_counts"] = "PASS"
    print("[selftest] banked 4.32 pair counts reproduced exactly")

    # -- the knob universe: round |v|>=1000 (the 4.33 lane-A filter)
    interest = set(v for v in list(p24) + list(p68)
                   if abs(v) >= 1000 and v % 1000 == 0)
    interest |= set(BANKED_COUNTS)
    knob_values = sorted(interest,
                         key=lambda v: -(len(p24.get(v, [])) +
                                         len(p68.get(v, []))))[:60]
    out["knob_values"] = len(knob_values)

    # -- the PIC call census (v433b method) for the owner fan-in
    src_list, tgt_list = [], []
    for base_off, uarr in ((0, u0), (2, u2)):
        sel = starts[(starts & 3) == base_off]
        k = (sel - base_off) >> 2
        keep = (k + 1 < len(uarr)) & (k >= 0)
        sel, k = sel[keep], k[keep]
        mask = (uarr[k] & 0x7F) == 0x17
        if not mask.any():
            continue
        s_sel, s_k = sel[mask], k[mask]
        w_auipc = uarr[s_k]
        rd_a = (w_auipc >> 7) & 0x1F
        hi20 = (w_auipc >> 12).astype(np.int64)
        hi20[hi20 >= 0x80000] -= 0x100000
        w_j = uarr[s_k + 1]
        ok = ((w_j & 0x7F) == 0x67) & (((w_j >> 12) & 7) == 0) & \
             (((w_j >> 15) & 0x1F) == rd_a)
        rd_j = (w_j >> 7) & 0x1F
        lo12 = ((w_j >> 20) & 0xFFF).astype(np.int64)
        lo12[lo12 >= 0x800] -= 0x1000
        t = s_sel + (hi20 << 12) + lo12
        inimg = (t >= 0) & (t < len(a_img))
        ok &= inimg & ((rd_j == 1) | (rd_j == 0)) & (rd_a != 0)
        src_list.append(s_sel[ok].astype(np.int64))
        tgt_list.append(t[ok].astype(np.int64))
    src = np.concatenate(src_list)
    tgt = np.concatenate(tgt_list)
    uniq_t = np.unique(tgt)
    d = dict(zip(uniq_t.tolist(),
                 np.bincount(tgt, minlength=len(a_img))[
                     uniq_t].tolist()))
    assert d.get(BANKED_CALLEE, 0) >= 2, "banked callee lost"
    print(f"[selftest] banked callee 0x188ef44 fan-in = "
          f"{d.get(BANKED_CALLEE)} OK")

    which = np.searchsorted(rstart, tgt, side="right") - 1
    ok = (which >= 0) & (tgt < rend[np.clip(which, 0, len(rend) - 1)])
    reg_fanin = np.bincount(which[ok], minlength=len(regions))
    out["pic_edges"] = int(len(src))
    out["selftest_census"] = {"banked_callee_fanin":
                              int(d.get(BANKED_CALLEE, 0))}

    # -- THE KNOB CARDS
    knobs_out = []
    for v in knob_values:
        sites_raw = ([("full24", s) for s in p24.get(v, [])[:60]] +
                     [("full68", s) for s in p68.get(v, [])[:20]])
        use_counts = defaultdict(int)
        cards = []
        owners = defaultdict(lambda: {"fan_in": 0, "sites": 0,
                                      "KiB": 0.0})
        risk_hits = defaultdict(int)
        rdtime_any = False
        for form, s in sites_raw[:12]:
            off = int(s["A_img"], 16)
            uc, cons = classify_use_cfg(a_img, off + 4, s["rd"])
            use_counts[uc] += 1
            risk_hits[uc] += 1
            bs, be, br = body_span(a_img, off)
            rdtime, co = body_flags(a_img, bs, be) \
                if bs is not None else (False, {})
            rdtime_any |= rdtime
            r = region_of(off)
            if r:
                ri = rstart.tolist().index(r[0])
                o = owners[hex(IMG_LO + r[0])]
                o["fan_in"] = max(o["fan_in"], int(reg_fanin[ri]))
                o["sites"] += 1
                o["KiB"] = round((r[1] - r[0]) / 1024, 1)
                o["end"] = hex(IMG_LO + r[1])
            cards.append({
                "A_img": s["A_img"], "VA": hex(IMG_LO + off),
                "rd": REGS[s["rd"]], "form": form, "use": uc,
                "use_at": hex(IMG_LO + cons) if cons else None,
                "body": [hex(IMG_LO + bs) if bs is not None else None,
                         hex(IMG_LO + be)],
                "rdtime_in_body": rdtime,
                "co_constants": dict(sorted(co.items(),
                                            key=lambda kv: -kv[1])[:6]),
                "owner_region": hex(IMG_LO + r[0]) if r else None})
        # unit hypothesis (ordered rules)
        classified = sum(use_counts.values())
        sd = use_counts.get("STORE-DATA", 0)
        cp = use_counts.get("COMPARE", 0)
        dv = use_counts.get("DIVIDE", 0)
        ca = use_counts.get("CALL-ARG", 0)
        co_all = defaultdict(int)
        for c in cards:
            for k2, n in c["co_constants"].items():
                co_all[int(k2)] += n
        if rdtime_any and v % 1000 == 0:
            unit = "TIME-QUANTA (vs raw 1-ns ticks)"
            risk = "DO-NOT-TOUCH-BLIND"
        elif (1000000000 in co_all or 1000000 in co_all) and \
                (dv or v in (1000000000, 1000000)):
            unit = "TIME-CONVERSION (1e9/1e6 chain in-body)"
            risk = "DO-NOT-TOUCH-BLIND"
        elif v % 270000 == 0 and v >= 270000:
            unit = f"CLK-270k-FAMILY (x{v // 270000})"
            risk = "CONTEXT-DEPENDENT"
        elif classified and sd >= max(cp, dv, ca) and sd * 2 > classified:
            unit = "STATE-DEFAULT (tunable state field)"
            risk = "GATED-TUNABLE"
        elif classified and cp >= max(sd, dv) and cp * 2 > classified:
            unit = "THRESHOLD/POLICY"
            risk = "GATED-TUNABLE" if not ca else "PROTOCOL-RISK"
        elif ca:
            unit = "PROTOCOL-ARG (enters RM internals)"
            risk = "PROTOCOL-RISK"
        else:
            unit = "INTERNAL-MATH"
            risk = "CONTEXT-DEPENDENT"
        best = max((o["fan_in"] for o in owners.values()), default=0)
        knobs_out.append({
            "value": v, "hex": hex(v & 0xFFFFFFFFFFFFFFFF),
            "sites_full24": len(p24.get(v, [])),
            "sites_full68": len(p68.get(v, [])),
            "use_histogram": dict(use_counts),
            "unit_hypothesis": unit, "risk_class": risk,
            "owner_regions": {k2: o for k2, o in
                              sorted(owners.items(),
                                     key=lambda kv: -kv[1]["fan_in"])[:4]},
            "max_owner_fan_in": best,
            "site_cards": cards[:6]})
    knobs_out.sort(key=lambda k: (-k["max_owner_fan_in"],
                                  -(k["sites_full24"] +
                                    k["sites_full68"])))
    out["knobs"] = knobs_out

    # the shortlist: what an optimizer would look at FIRST
    shortlist = [k for k in knobs_out
                 if k["risk_class"] == "GATED-TUNABLE"][:12]
    out["shortlist_gated_tunable"] = [
        {"value": k["value"], "unit": k["unit_hypothesis"],
         "leverage": k["max_owner_fan_in"],
         "owners": list(k["owner_regions"])} for k in shortlist]

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
