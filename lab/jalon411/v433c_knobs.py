#!/usr/bin/env python3
"""4.33 LANE A — the firmware's policy-knob table.

The pass-4.33 question: WHERE can the closed GSP-RM firmware be
optimized? Lane A maps every compile-time "knob" — the materialized
round constants that bound runtime behavior (thresholds, timeouts,
quanta, divisors) — because those are the only behavior-relevant bytes
a binary patch can turn (the 4.30/4.32 lesson: know the semantics
BEFORE the boot test).

Method (built on the banked 4.32 census discipline):
  - full-form lui+addi/addiw pairs, two independent passes exactly as
    v432e ran them: pass1 gaps {2,4} (no clobber check), pass2 gaps
    {6,8} (clobber check at +4 only, banked caveat) — break at first
    matching gap, rd==rs1!=0, canonical AND sign-carry splits.
  - compressed c.lui+addi (quadrant 01 funct3 011, hi fit signed 6-bit,
    adjacent gap 2 or gap 4 with the +4 clobber check), every hit
    validated against the v416 map's seen bitmap (instruction starts).
  - USE classification: decode forward from the addi, first READ of rd:
    COMPARE (branch) / STORE-DATA / DIVIDE / CALL-ARG / ARITH-CHAIN,
    UNRESOLVED-in-window when none reads it within 40 insns.
  - body attribution: deterministic backward/forward walk bounded by
    ret-likes (ret, c.ret, jalr x0, c.jr ra) — sites sharing the body
    span = one function body. Linear-walk caveat banked (no CFG).

Selftest anchors (re-derived, exit 2 on drift): the coordinate law
B_file = A_img - 0x38 (sampled windows + the six 4.30 patch sites + the
7th site A 0xB99C82); the map semantics (seen=instruction starts, tried
in both coordinate bases, exactly one must hold); the 4.32 banked pair
counts for the question values (250000=6, 500000=25, 1000000=123,
4000000=15, 100000000=17, -250000=1, -1000000=3, -500000=5,
100000=0, 240000=0, 280000=0); the 36 real c.lui-100000 sites.

Substrates and law: rm-full.elf image (p_offset 0x40) = gsp-rm-17MB.bin
code under B_file = A_img - 0x38 (v432_coord_check 3739/3739); VA_A =
A_img + 0x1000000.
Output: lab/jalon411/v433c_knobs.json
"""
import json
import struct
import zlib
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


def reads_reg(ins, rd_name):
    """does ins READ rd_name (not as its write-back dest)?"""
    if ins is None:
        return False
    try:
        ops = ins.operands
        w = ins.mnemonic in ("jal",)  # jal writes rd(=ra) only
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


def classify_use(img, aoff_addi, rd):
    """first consumer of rd forward from the addi (40 insns)."""
    rd_name = REGS[rd]
    off = aoff_addi
    for _ in range(40):
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
            if m in ("sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp",
                     "c.sdsp"):
                return "STORE-DATA", off
            if m in ("jal", "jalr", "c.jalr") and \
                    ins.op_str.split(",")[0].strip() in \
                    [f"a{i}" for i in range(8)]:
                return "CALL-ARG", off
            return "ARITH-CHAIN", off
        if is_retlike(ins):
            return "DEAD-at-ret", off
        off += ins.size
    return "UNRESOLVED-in-window", None


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
    """(body_start|None, body_end, ret_crossed_back)."""
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


def window_lines(img, aoff, back=6, fwd=10):
    lines = []
    for o, ins in backward_walk(img, aoff, limit=0x40)[-back:]:
        lines.append(f"0x{IMG_LO + o:x}: {ins.mnemonic:<8} {ins.op_str}")
    off = aoff
    for _ in range(fwd):
        ins = dis1(img, off)
        if ins is None:
            lines.append(f"0x{IMG_LO + off:x}: <invalid>")
            break
        lines.append(f"0x{IMG_LO + off:x}: {ins.mnemonic:<8} {ins.op_str}")
        off += ins.size
    return lines


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000",
           "img_len": hex(len(a_img)), "map_cells": half}

    # -- the coordinate law re-asserted (512 sampled windows + 7 sites)
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

    # -- the map base: BOTH s1 probes (A 0x1a062 / B 0x1a02a) are real
    #    instruction starts (a coincidence), so seen bits alone cannot
    #    discriminate — the OPCODE does: s1's insn at its true offset is
    #    the cited lui (byte&0x7F==0x37); the wrong base lands on a
    #    bltu (0x63). Findings-4.32 cite VA 0x101a062 = A 0x1a062.
    a_lui, b_lui = 0x1A02A + SHIFT, 0x1A02A
    bits_a = seen[a_lui] == 1 and seen[a_lui + 2] == 0 \
        and covered[a_lui + 2] == 1
    bits_b = seen[b_lui] == 1 and seen[b_lui + 2] == 0 \
        and covered[b_lui + 2] == 1
    base_a = bits_a and (a_img[a_lui] & 0x7F) == 0x37
    base_b = bits_b and (a_img[b_lui] & 0x7F) == 0x37
    assert base_a != base_b, "map base ambiguous (opcode test)"
    assert base_a, ("map base is NOT A_img — every campaign coordinate "
                    "assumption breaks; STOP and re-derive")
    # the claim7 lui @A 0xB99C82 re-proven at the opcode level
    assert (a_img[CLAIM7_A] & 0x7F) == 0x37 and seen[CLAIM7_A] == 1
    out["map_semantics"] = {
        "base": "A_img", "seen": "instruction starts",
        "covered": "bytes",
        "s1_lui_probe": hex(a_lui),
        "probe_bytes": {"A_0x1a062": hex(a_img[a_lui]),
                        "B_as_A_0x1a02a": hex(a_img[b_lui])},
        "note": ("both probes hold seen bits (two real starts, a "
                 "coincidence); the opcode discriminates: lui 0x37 vs "
                 "bltu 0x63 — base A proven, claim7 lui re-proven"),
        "v432e_line172_note": ("v432e's seen[0x1A02A]==1 smoke assert "
                               "also holds (a real start); "
                               "non-load-bearing either way")}
    print(f"[map] base=A_img proven by opcode (s1 lui @0x{a_lui:x} "
          f"byte=0x37; the B probe lands on a bltu 0x63)")

    sarr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]
    starts = np.nonzero(sarr)[0]
    out["seen_starts"] = int(len(starts))

    # -- vectorized lui-candidate prefilter over ALL even offsets
    #    (exactly v432e's step-2 coverage — the uncovered islands like
    #    s0's carry real pairs; seen is reported per site, NOT a filter)
    def lui_candidates():
        img4 = a_img + b"\x00" * ((4 - len(a_img) % 4) % 4)
        u0 = np.frombuffer(img4, dtype="<u4")
        u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
        res = []
        for base_off, uarr in ((0, u0), (2, u2)):
            kmax = (len(img4) - 4 - base_off) >> 2
            k = np.arange(kmax, dtype=np.int64)
            mask = (uarr[k] & 0x7F) == 0x37
            for kk in k[mask]:
                res.append((int(base_off + (kk << 2)),
                            int(uarr[kk])))
        res.sort()
        return res

    cands = lui_candidates()
    out["lui_candidates_all_offsets"] = len(cands)
    print(f"[scan] lui candidates (all even offsets): {len(cands)}")

    # -- the two full-form passes (exactly v432e's rules)
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
                by_value[(hi_s << 12) + lo_f].append(
                    {"A_img": hex(off), "gap": d, "rd": rd,
                     "seen_start": bool(seen[off]),
                     "form": "addiw" if (w2 & 0x7F) == 0x1B else "addi"})
                break
        return by_value

    p24 = full_pass((2, 4))
    p68 = full_pass((6, 8))
    out["full_pass_24"] = {str(v): len(s) for v, s in sorted(p24.items())}
    out["full_pass_68"] = {str(v): len(s) for v, s in sorted(p68.items())}
    print(f"[scan] full-form values: pass24={len(p24)} pass68={len(p68)}")

    # -- SELFTEST: the banked 4.32 question-value counts
    drift = {}
    for v, want in BANKED_COUNTS.items():
        got = len(p24.get(v, []))
        if got != want:
            drift[v] = (got, want)
    assert not drift, f"banked pair counts drifted: {drift}"
    out["selftest_banked_counts"] = {"status": "PASS", "drift": drift}
    print("[selftest] banked 4.32 pair counts reproduced exactly")

    # -- compressed c.lui+addi census (v432e rules, seen-validated)
    def clui_pass(values=None):
        by_value = defaultdict(list)
        n = len(a_img) - 6
        off = 0
        while off < n:
            w16 = a_img[off] | (a_img[off + 1] << 8)
            if (w16 & 3) == 1 and (w16 >> 13) == 3:
                rd = (w16 >> 7) & 0x1F
                if rd not in (0, 2):
                    imm6 = ((w16 >> 12) & 1) << 5 | ((w16 >> 2) & 0x1F)
                    if imm6 >= 0x20:
                        imm6 -= 0x40
                    if imm6 != 0:
                        v = (imm6 << 12) & 0xFFFFFFFFFFFFFFFF
                        # candidate hi — the value depends on lo (addi);
                        # enumerate via the addi at +2/+4 (both splits)
                        for d in (2, 4):
                            if off + d + 4 > len(a_img):
                                continue
                            w2 = struct.unpack_from("<I", a_img,
                                                    off + d)[0]
                            if (w2 & 0x7F) not in (0x13, 0x1B):
                                continue
                            if ((w2 >> 12) & 7) != 0:
                                continue
                            if ((w2 >> 15) & 0x1F) != rd or \
                                    ((w2 >> 7) & 0x1F) != rd:
                                continue
                            if d == 4:
                                ins = dis1(a_img, off + 2)
                                if ins is not None and \
                                        writes_reg(ins, REGS[rd]):
                                    continue
                            lo_f = (w2 >> 20) & 0xFFF
                            if lo_f >= 0x800:
                                lo_f -= 0x1000
                            v = (imm6 << 12) + lo_f
                            if values is not None and v not in values:
                                continue
                            by_value[v].append(
                                {"A_img": hex(off), "gap": d, "rd": rd,
                                 "seen_start": bool(seen[off])})
                            break
            off += 2
        return by_value

    # full c.lui census is 7.6M iters in python — restrict to knob
    # pre-filter: only run the compressed scan for values the full pass
    # found plus the banked family (the 4.32e discipline)
    interest = set(v for v in list(p24) + list(p68)
                   if abs(v) >= 1000 and v % 1000 == 0)
    interest |= set(BANKED_COUNTS)
    cl = clui_pass(values=interest)
    real_cl = {v: [s for s in sites if s["seen_start"]]
               for v, sites in cl.items()}
    n100 = len(real_cl.get(100000, []))
    assert n100 == N_CLUI_100000, \
        f"c.lui-100000 drifted: {n100} != {N_CLUI_100000}"
    out["clui_100000_reproduced"] = n100
    print(f"[selftest] c.lui-100000 = {n100} (banked 36) OK")

    # -- the knob table: round |v|>=1000, both forms, USE + body
    knob_values = sorted(interest,
                         key=lambda v: -(len(p24.get(v, [])) +
                                         len(p68.get(v, [])) +
                                         len(real_cl.get(v, []))))
    knobs = []
    for v in knob_values:
        sites = []
        for s in p24.get(v, [])[:60]:
            sites.append(("full24", s))
        for s in p68.get(v, [])[:20]:
            sites.append(("full68", s))
        for s in real_cl.get(v, [])[:60]:
            sites.append(("clui", s))
        use_counts = defaultdict(int)
        detailed = []
        for form, s in sites[:90]:
            off = int(s["A_img"], 16)
            uc, cons = classify_use(a_img, off + 4, s["rd"])
            use_counts[uc] += 1
            bs, be, br = body_span(a_img, off)
            detailed.append({
                "A_img": s["A_img"], "VA": hex(IMG_LO + off),
                "B_file": hex(off - SHIFT), "gap": s["gap"],
                "rd": REGS[s["rd"]], "form": form, "use": uc,
                "use_at": hex(IMG_LO + cons) if cons else None,
                "body": [hex(IMG_LO + bs) if bs is not None else None,
                         hex(IMG_LO + be)],
                "window": window_lines(a_img, off + 4, back=4, fwd=8)})
            if len(detailed) >= 12:
                break
        knobs.append({
            "value": v, "hex": hex(v & 0xFFFFFFFFFFFFFFFF),
            "sites_full24": len(p24.get(v, [])),
            "sites_full68": len(p68.get(v, [])),
            "sites_clui_real": len(real_cl.get(v, [])),
            "use_histogram": dict(use_counts),
            "sites": detailed})
        if len(knobs) >= 60:
            break
    out["knobs"] = knobs
    print(f"[knobs] round knob values: {len(knobs)} "
          f"(top: {[(k['value'], k['sites_full24']) for k in knobs[:8]]})")

    # -- the 4.32e queue item: function-level attribution of the 36
    #    c.lui-100000 sites (bodies + the s2/s3-region overlap)
    regions = []
    carr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    idx = np.nonzero(carr)[0]
    if len(idx):
        splits = np.nonzero(np.diff(idx) > 1)[0]
        b0 = np.concatenate(([0], splits + 1))
        b1 = np.concatenate((splits, [len(idx) - 1]))
        regions = [(int(idx[i0]), int(idx[i1]) + 1)
                   for i0, i1 in zip(b0, b1) if idx[i1] + 1 - idx[i0] >= 2]
    out["covered_regions"] = len(regions)

    def region_of(off):
        import bisect
        i = bisect.bisect_right([r[0] for r in regions], off) - 1
        if i >= 0 and off < regions[i][1]:
            return regions[i]
        return None

    s2r = region_of(0x1F09A8 + SHIFT)   # s2's enclosing region
    s3r = region_of(0x7C467C + SHIFT)
    att = []
    bodies = defaultdict(list)
    for s in real_cl.get(100000, []):
        off = int(s["A_img"], 16)
        bs, be, br = body_span(a_img, off)
        bodies[(bs, be)].append(off)
        r = region_of(off)
        in_s2s3 = (s2r and r and s2r[0] <= r[0] < s2r[1]) or \
                  (s3r and r and s3r[0] <= r[0] < s3r[1])
        att.append({"A_img": s["A_img"], "VA": hex(IMG_LO + off),
                    "gap": s["gap"], "rd": REGS[s["rd"]],
                    "region": [hex(IMG_LO + r[0]), hex(IMG_LO + r[1])]
                    if r else None,
                    "in_s2_or_s3_region": bool(in_s2s3),
                    "body": [hex(IMG_LO + bs) if bs is not None else None,
                             hex(IMG_LO + be)]})
    out["clui_100000_attribution"] = {
        "sites": att,
        "distinct_bodies": len(bodies),
        "multi_site_bodies": {
            str([hex(IMG_LO + b[0]) if b[0] is not None else None,
                 hex(IMG_LO + b[1])]): [hex(IMG_LO + o) for o in offs]
            for b, offs in bodies.items() if len(offs) > 1},
        "in_s2_or_s3": sum(1 for a in att if a["in_s2_or_s3_region"])}

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
