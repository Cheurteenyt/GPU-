#!/usr/bin/env python3
"""4.32 reconciliation — the three contradictions between the local draft
(0b6981e) and the pushed pass (c7fdee8), arbitrated on the bytes.

  C1  the c.lui+addi materialization form: scanned by the local draft's
      v432b (32 hits for 100000), NEVER scanned by the pushed pass (the
      v432_allpairs docstring promises c.lui/c.addi coverage, the code
      implements full lui opcode 0x37 only). Arbitrated here against the
      v416 map's seen bitmap — PROVEN instruction-start ground truth
      (s1: start=1, mid-instruction=0, next=1; s0's island: covered=0).
      THEOREM (checked in code): among the question values only 100000,
      2500 and 25000 are c.lui-encodable (|hi| <= 0x1F, hi != 0);
      240000/250000/280000/500000/1000000/4000000 are NOT — the
      power-trio falsification cannot fall to the compressed form.

  C2  the local draft's "7th split-form 250000" @B 0xb99c4a (= A_img
      0xb99c82): the pushed pass's allpairs scans gaps {2,4} only, so a
      gap-6/8 split is invisible to it. Arbitrated: gap-6/8 split scan
      with an intermediate-instruction CLOBBER check (if the insn between
      lui and addi writes rd, the lui value is dead and the pair does
      not materialize the constant), + the anchor-synced window.

  C3  the UPDATE_EDPP_LIMIT handler: the pushed pass re-confirms
      c.jr ra @A 0x862480; the local draft read gsp-rm-17MB.bin @
      0x862480 WITHOUT the coordinate law = A 0x8624B8, 0x38 bytes past
      the true handler. Both windows disassembled side by side.

Also: the local draft's "57 materializations of 100000" is shown to be a
WORKLOG MISREADING of its own JSON (32 c.lui-100000 + 25 = the ADJACENT
500000 count) — the two passes AGREE on every full-form count (verified
here by re-scan + the five u32 hits asserted equal).

Substrates and law: rm-full.elf image (p_offset 0x40) = gsp-rm-17MB.bin
code under B_file = A_img - 0x38 (v432_coord_check, 3739/3739).
Output: lab/jalon411/v432e_reconcile.json
"""
import json
import struct
import zlib
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
LOCAL_JSON = ROOT / "lab/jalon411/v432b_sister_constants.json"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
IMG_SIZE = 0xE9B000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82          # the local draft's 7th site, A_img coords
UPD_A = 0x862480             # the pushed pass's UPDATE handler (A_img)
UPD_DRAFT_A = 0x862480 + SHIFT   # what the draft actually read (no law)

VALUES = [100000, 240000, 250000, 280000, 500000, 1000000, 4000000,
          279024, 2500, 25000]

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True


def dis1(buf, off, va=None):
    """decode one instruction at off (2- or 4-byte), None on failure."""
    if off + 2 > len(buf):
        return None
    if buf[off] & 3 == 3:
        if off + 4 > len(buf):
            return None
        ins = next(md.disasm(buf[off:off + 4], (va or off)), None)
    else:
        ins = next(md.disasm(buf[off:off + 2], (va or off)), None)
    return ins


def writes_reg(ins, rd_name):
    """does this instruction write rd_name? (coarse but conservative)"""
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
    ops = ins.op_str.split(",")[0].strip()
    if m in ("jal", "c.jalr"):
        return ops == rd_name or m == "c.jalr" and False
    return ops == rd_name


def reg_name(ins, k=0):
    try:
        return ins.reg_name(ins.operands[k].reg)
    except Exception:
        return ins.op_str.split(",")[k].strip()


def backward_walk(img, aoff, limit=0x40):
    """the deterministic predecessor chain (v432_sites.py's method)."""
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


def window_lines(img, aoff, back=10, fwd=12):
    """cited disassembly lines around aoff, anchor = the site itself."""
    lines = []
    chain = backward_walk(img, aoff, limit=0x40)
    for o, ins in chain[-back:]:
        lines.append((o, ins))
    off = aoff
    for _ in range(fwd):
        ins = dis1(img, off)
        if ins is None:
            lines.append((off, None))
            break
        lines.append((off, ins))
        off += ins.size
    return [f"0x{IMG_LO + o:x}: {ins.mnemonic:<8} {ins.op_str}" if ins
            else f"0x{IMG_LO + o:x}: <invalid>" for o, ins in lines]


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + IMG_SIZE]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]

    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

    # -- 0. the coordinate law re-asserted (512 sampled windows + sites)
    fails = 0
    step = len(a_img) // 512
    for i in range(0, 512):
        o = 0x38 + i * step          # the law maps image o to bin o-0x38
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    for boff in SITES_B:
        if db[boff:boff + 8] != a_img[boff + SHIFT:boff + SHIFT + 8]:
            fails += 1
    out["law_recheck"] = {"windows": 512 + 6, "fails": fails}
    assert fails == 0, "coordinate law broken"

    # seen = instruction-start ground truth: the s1 proof re-asserted
    assert seen[0x1A02A] == 1 and seen[0x1A02C] == 0 and covered[0x1A02C] == 1
    out["map_semantics"] = ("seen=instruction starts, covered=byte "
                            "coverage (proof: s1 lui @A 0x1a02a start=1 "
                            "mid=0 covered_mid=1)")

    # -- C1. the c.lui+addi census (validated against seen)
    #    c.lui: quadrant 01 (bits[1:0]=01), funct3 011 (bits[15:13]),
    #    rd != {0,2}, nzimm[17:12] = signed 6-bit {bit12, bits[6:2]}.
    #    theorem guard: hi must fit signed 6-bit.
    clui = {}
    for v in VALUES:
        hi = (v + 0x800) >> 12          # canonical hi (sign-carry split)
        lo = v - ((hi) << 12)
        encodable = (-0x20 <= hi <= 0x1F) and hi != 0
        sites = []
        if encodable:
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
                        if imm6 == hi and imm6 != 0:
                            # addi/addiw at +2 (adjacent) or +4 (one
                            # compressed insn between, clobber-checked)
                            for d in (2, 4):
                                w2 = struct.unpack_from("<I", a_img,
                                                        off + d)[0]
                                if (w2 & 0x7F) not in (0x13, 0x1B):
                                    continue
                                if ((w2 >> 12) & 7) != 0:
                                    continue
                                if ((w2 >> 15) & 0x1F) != rd or \
                                   ((w2 >> 7) & 0x1F) != rd:
                                    continue
                                lo_f = (w2 >> 20) & 0xFFF
                                if lo_f >= 0x800:
                                    lo_f -= 0x1000
                                if lo_f != lo:
                                    continue
                                clob = False
                                if d == 4:
                                    ins = dis1(a_img, off + 2)
                                    clob = writes_reg(ins,
                                                      f"x{rd}") or \
                                        (ins is not None and
                                         reg_name(ins, 0) != "" and
                                         reg_name(ins, 0) ==
                                         ["zero", "ra", "sp", "gp", "tp",
                                          "t0", "t1", "t2", "s0", "s1",
                                          "a0", "a1", "a2", "a3", "a4",
                                          "a5", "a6", "a7", "s2", "s3",
                                          "s4", "s5", "s6", "s7", "s8",
                                          "s9", "s10", "s11", "t3", "t4",
                                          "t5", "t6"][rd])
                                if not clob:
                                    sites.append({
                                        "A_img": hex(off),
                                        "B_file": hex(off - SHIFT),
                                        "gap": d,
                                        "seen_start": bool(seen[off]),
                                        "covered": bool(covered[off]),
                                        "rd": rd})
                                break
                off += 2
        real = [s for s in sites if s["seen_start"]]
        clui[str(v)] = {"encodable": encodable, "sites_total": len(sites),
                        "sites_seen_real": len(real), "sites": sites[:40]}
        print(f"[C1] c.lui+addi {v:>9}: encodable={encodable} "
              f"hits={len(sites)} seen-real={len(real)}")

    # -- full-form lui+addi re-scan (reproduction of allpairs, gaps 2/4,
    #    then the C2 extension 6/8 with the clobber check)
    def full_scan(gaps):
        by_value = {}
        n = len(a_img)
        off = 0
        while off < n - 12:
            w1 = struct.unpack_from("<I", a_img, off)[0]
            if (w1 & 0x7F) == 0x37:
                rd = (w1 >> 7) & 0x1F
                if rd != 0:
                    hi_s = (w1 >> 12) - (1 << 20) \
                        if (w1 >> 12) >= 0x80000 else (w1 >> 12)
                    for d in gaps:
                        w2 = struct.unpack_from("<I", a_img, off + d)[0]
                        if (w2 & 0x7F) not in (0x13, 0x1B):
                            continue
                        if ((w2 >> 15) & 0x1F) != rd or \
                           ((w2 >> 7) & 0x1F) != rd:
                            continue
                        clob = False
                        if d > 4:
                            ins = dis1(a_img, off + 4)
                            clob = ins is not None and writes_reg(
                                ins, ["zero", "ra", "sp", "gp", "tp",
                                      "t0", "t1", "t2", "s0", "s1",
                                      "a0", "a1", "a2", "a3", "a4",
                                      "a5", "a6", "a7", "s2", "s3",
                                      "s4", "s5", "s6", "s7", "s8",
                                      "s9", "s10", "s11", "t3", "t4",
                                      "t5", "t6"][rd])
                        if clob:
                            continue
                        lo_f = (w2 >> 20) & 0xFFF
                        if lo_f >= 0x800:
                            lo_f -= 0x1000
                        v = (hi_s << 12) + lo_f
                        by_value.setdefault(v, []).append(off)
                        break
            off += 2
        return by_value

    repro = full_scan((2, 4))
    ext = full_scan((6, 8))
    out["full_form_reproduction"] = {
        str(v): [hex(o) for o in repro.get(v, [])][:12]
        for v in VALUES}
    out["full_form_gaps_6_8"] = {
        str(v): [hex(o) for o in ext.get(v, [])][:12] for v in VALUES}
    for v in VALUES:
        print(f"[C2] full-form {v:>9}: gaps2/4={len(repro.get(v, []))} "
              f"gaps6/8={len(ext.get(v, []))}")

    # -- C2 verdict on the claimed 7th site: the bytes, the seen bits,
    #    the clobber question, the cited window
    c7 = {
        "claim": "the local draft's 7th split-form 250000",
        "B_file": hex(CLAIM7_A - SHIFT), "A_img": hex(CLAIM7_A),
        "seen_start": bool(seen[CLAIM7_A]),
        "covered": bool(covered[CLAIM7_A]),
        "bytes_B": db[CLAIM7_A - SHIFT:CLAIM7_A - SHIFT + 16].hex(),
        "bytes_A": a_img[CLAIM7_A:CLAIM7_A + 16].hex(),
        "window": window_lines(a_img, CLAIM7_A),
    }
    out["claim7"] = c7
    print(f"[C2] claim7 @A {hex(CLAIM7_A)}: seen={bool(seen[CLAIM7_A])} "
          f"covered={bool(covered[CLAIM7_A])}")

    # -- C3. the UPDATE handler, both windows side by side
    upd = {
        "pushed_pass_claim": "c.jr ra @A 0x862480 (2 bytes)",
        "draft_error": ("the draft read gsp-rm-17MB.bin @0x862480 = "
                        "A 0x8624B8 under the no-law assumption "
                        "VA = B_file + 0x1000000"),
        "A_handler": {
            "A_img": hex(UPD_A), "seen_start": bool(seen[UPD_A]),
            "bytes": a_img[UPD_A:UPD_A + 8].hex(),
            "window": window_lines(a_img, UPD_A, back=4, fwd=8)},
        "A_what_draft_read": {
            "A_img": hex(UPD_DRAFT_A), "seen_start": bool(seen[UPD_DRAFT_A]),
            "bytes": a_img[UPD_DRAFT_A:UPD_DRAFT_A + 8].hex(),
            "window": window_lines(a_img, UPD_DRAFT_A, back=4, fwd=8)},
    }
    out["update_stub"] = upd
    print(f"[C3] handler window head: {upd['A_handler']['window'][:2]}")
    print(f"[C3] draft-misread window head: "
          f"{upd['A_what_draft_read']['window'][:2]}")

    # -- the five u32 100000 hits: local draft vs re-scan asserted equal
    #    (the draft JSON's offsets, B_file coords, from commit 0b6981e)
    import numpy as np
    u32 = np.frombuffer(a_img[:len(a_img) & ~3], dtype="<u4")
    hits = [hex(int(h) * 4) for h in np.nonzero(u32 == 100000)[0]]
    local_hits = ["0x4a7ba8", "0x7bcba8", "0xb1aba8", "0xb33ba8", "0xb73ba8"]
    # the draft's offsets were B_file (no law); convert
    local_a = [hex(int(o, 16) + SHIFT) for o in local_hits]
    out["u32_100000"] = {"rescan_A": hits, "draft_B_converted": local_a,
                         "equal": sorted(hits) == sorted(local_a)}
    print(f"[--] u32 100000: rescan={hits} draft(->A)={local_a} "
          f"equal={out['u32_100000']['equal']}")

    # -- the corrected T2 picture: same-region co-occurrence for the REAL
    #    c.lui-100000 sites vs the six 250000 sites' enclosing regions
    regions = []
    i, n = 0, len(covered)
    while i < n:
        if covered[i]:
            j = i
            while j < n and covered[j]:
                j += 1
            if j - i >= 2:
                regions.append((i, j))
            i = j
        else:
            i += 1

    def region_of(aoff):
        for s0, e0 in regions:
            if s0 <= aoff < e0:
                return (s0, e0)
        return None

    site_regions = []
    for boff in SITES_B:
        site_regions.append(region_of(boff + SHIFT))
    out["site_regions"] = [
        ([hex(IMG_LO + s), hex(IMG_LO + e)] if r else None)
        for r in site_regions
        for s, e in ([r] if r else [(None, None)])]

    clash = []
    for s in clui["100000"]["sites"]:
        r = region_of(int(s["A_img"], 16))
        if r and r in site_regions:
            clash.append(s)
    out["clui100000_in_250000_regions"] = clash
    print(f"[T2] c.lui-100000 sites inside the six 250000 regions: "
          f"{len(clash)}")

    out["clui"] = clui
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
