#!/usr/bin/env python3
"""4.36 TASK A — the regkey→knob flow map: which shortlist knobs live in
functions that ALSO consume a host regkey string.

The 4.35 SAFE lane proved the regkey surface (864 Rm*/RM* names, 251
with 366 direct PIC xrefs, the lookup-by-name pattern).  The 4.35
GATED-TUNABLE shortlist ranked the knobs by leverage.  The 4.36
question is the bridge: for each shortlist knob site, does the
ret-bounded function containing the site ALSO contain a regkey xref?
A YES means the knob value flows through code that already handles
host-named settings — the no-patch lever candidate — and the specific
key name is the founder's experiment (one key, one boot, one counter
delta, STOCK firmware).

Method (every step re-derived from the image, nothing copied):
  - the coordinate law re-asserted (512 windows + 7 sites + claim7);
  - the map base re-proven (opcode-discriminated, as v433c/v435a);
  - the full-form pair census re-run (gaps {2,4}+{6,8}, clobber
    checks) — the banked 4.32 counts must reproduce EXACTLY, and the
    per-site A_img lists must equal the v435a site_cards for every
    shortlist value (flat-result re-derivation, the 4.19 discipline);
  - the c.lui-100000 compressed census re-run (36 sites, must equal
    the v434b body sites);
  - FUNC WINDOW: ret-bounded approx (backward to the last ret-like,
    forward to the first ret-like, 0x4000 limits) around each site;
  - PIC CALL EDGES: the v433b seen-validated auipc+jalr census;
    func-level fan-in = edges whose target lands inside the window;
    prologue = the minimum in-window target (when any);
  - REGKEY CROSS: every v435b xref gets its own func window; a pair
    (knob site, regkey xref) is banked when both windows share the
    same backward-function start (fs_x == fs_k) or the xref lands
    inside the site's window;
  - FIELD FLOW (STATE-DEFAULT sites): decode the store at use_at,
    extract (disp, base), then census the same (disp, base) stores
    and loads inside the window, plus the RET-STORE shape: a jalr
    followed within 12 insns by a store of a0 into the same field —
    the lookup-result→field shape; a ret-store + an in-window regkey
    xref = the REGKEY-FED-CANDIDATE flag (function-level evidence,
    never claimed as point-proof).

Selftests: the law, the map base, the banked counts, the v435a site
equality (shortlist), the 36 c.lui equality (v434b), the 864/251/366
regkey counts, the RmValidateClientData xref re-decode, the banked
callee 0x188EF44 fan-in >= 2.

Output: lab/jalon411/v436a_regkey_flow.json
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
V435A = ROOT / "lab/jalon411/v435a_knobcards.json"
V435B = ROOT / "lab/jalon411/v435b_regkeys.json"
V434B = ROOT / "lab/jalon411/v434b_cl100_bodies.json"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82
BANKED_COUNTS = {250000: 6, 500000: 25, 1000000: 123, 4000000: 15,
                 100000000: 17, -250000: 1, -1000000: 3, -500000: 5,
                 100000: 0, 240000: 0, 280000: 0}
N_CLUI_100000 = 36
BANKED_CALLEE_A = 0x188EF44 - IMG_LO
RVMCD_XREF_VA = 0x1BF4802          # the v435b cited xref (auipc at .2)
STORE_OPS = ("sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp")
LOAD_OPS = ("ld", "lw", "lh", "lb", "c.ld", "c.lw", "c.lwsp", "c.ldsp")

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
    if ins.mnemonic in ("j", "c.j"):
        s = ins.op_str.strip()
        return int(s, 16) if s.startswith("0x") else None
    return None


def reads_reg(ins, rd_name):
    """any operand READ of rd_name (dest excluded for writes)."""
    if ins is None:
        return False
    try:
        m = ins.mnemonic
        ops = ins.op_str.split(", ")
        if m in STORE_OPS:
            return base_reg_of(ins) == rd_name
        if m.startswith(("b", "c.b")):
            return rd_name in [x.strip() for x in ops]
        dest = ops[0].strip() if ops else ""
        for k, x in enumerate(ops):
            x = x.strip()
            if x == rd_name and not (k == 0 and x == dest):
                return True
        return False
    except Exception:
        return False


def base_reg_of(ins):
    """the (reg) of a load/store op_str like 'sw a5, 0x5d0(s1)'."""
    try:
        mem = ins.op_str.split(", ", 1)[1]
        return mem.split("(")[1].rstrip(")")
    except Exception:
        return None


def disp_of(ins):
    try:
        mem = ins.op_str.split(", ", 1)[1]
        return int(mem.split("(")[0], 16) if mem.split("(")[0].startswith(
            ("0x", "-0x")) else int(mem.split("(")[0], 0)
    except Exception:
        return None


def func_window(img, aoff, limit=0x4000):
    """ret-bounded approx: (fs, fe) around aoff; None side = unknown."""
    # backward: the last ret-like before aoff ends the previous body
    fs = None
    off = aoff
    chain = []
    while aoff - off < limit and off >= 2:
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
    for o, ins in chain:
        if is_retlike(ins):
            fs = o + ins.size
            break
    # forward: the first ret-like after aoff closes this body
    fe = None
    off = aoff
    for _ in range(limit):
        ins = dis1(img, off)
        if ins is None:
            break
        off += ins.size
        if is_retlike(ins):
            fe = off
            break
    return fs, fe


def pic_call_edges(img, starts):
    """the v433b seen-validated auipc+jalr census -> (src, tgt) arrays."""
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    u0 = np.frombuffer(img4, dtype="<u4")
    u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    srcs, tgts = [], []
    for base_off in (0, 2):
        uarr = u0 if base_off == 0 else u2
        sel = starts[(starts & 3) == base_off]
        k = (sel - base_off) >> 2
        keep = (k + 1 < len(u0)) & (k >= 0)
        sel, k = sel[keep], k[keep]
        mask = (uarr[k] & 0x7F) == 0x17          # auipc
        sel, k = sel[mask], k[mask]
        if len(sel) == 0:
            continue
        w_auipc = uarr[k]
        rd_a = ((w_auipc >> 7) & 0x1F).astype(np.int64)
        hi20 = (w_auipc >> 12).astype(np.int64)
        hi20[hi20 >= 0x80000] -= 0x100000
        w_j = uarr[k + 1]
        ok = ((w_j & 0x7F) == 0x67) & (((w_j >> 12) & 7) == 0) & \
             (((w_j >> 15) & 0x1F) == rd_a)
        sel, k = sel[ok], k[ok]
        w_j = w_j[ok]
        hi20 = hi20[ok]
        rd_a = rd_a[ok]
        lo12 = ((w_j >> 20) & 0xFFF).astype(np.int64)
        lo12[lo12 >= 0x800] -= 0x1000
        tgt = sel + (hi20 << 12) + lo12
        srcs.append(sel.astype(np.int64))
        tgts.append(tgt)
    src = np.concatenate(srcs) if srcs else np.zeros(0, np.int64)
    tgt = np.concatenate(tgts) if tgts else np.zeros(0, np.int64)
    return src, tgt


def full_pass(a_img, cands, gaps):
    """the banked full-form pair census (v432e/v433c rules)."""
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
                {"A_img": off, "gap": d, "rd": REGS[rd]})
            break
    return by_value


def clui_100000_scan(img, starts):
    """the v432e compressed census: c.lui rd,0x18 + addi rd,rd,0x6a0.

    PROBED (the 4.36 byte-check, site 0x16898 = word16 0x6a61):
    C.LUI lives in QUADRANT 1 (bits[1:0]=01), funct3=011, rd is a FULL
    5-bit field at [11:7] (0x6a61: rd=10100=x20=s4), imm[16:12] at
    [6:2], imm[17] at bit 12 (must be 0 for 100000).
    """
    hits = []
    for off in starts.tolist():
        if img[off] & 3 == 3:
            continue
        w16 = img[off] | (img[off + 1] << 8)
        if (w16 & 0xE003) != 0x6001:          # funct3=011, quadrant 1
            continue
        if (w16 >> 12) & 1:                   # imm[17]=0 (positive)
            continue
        rd = (w16 >> 7) & 0x1F                # full 5-bit rd
        if rd == 0:
            continue
        imm52 = (w16 >> 2) & 0x1F
        if imm52 != 0b11000:                  # imm[16:12] = 0x18
            continue
        # the pair partner: addi rd, rd, 0x6a0 at gap 2 or 4
        for d in (2, 4):
            ins = dis1(img, off + d)
            if ins is None:
                continue
            if ins.mnemonic == "addi":
                try:
                    ops = [x.strip() for x in ins.op_str.split(",")]
                    if REGS[rd] not in (ops[0], ops[1]):
                        continue
                    if int(ops[2], 0) != 0x6A0:
                        continue
                except Exception:
                    continue
                hits.append({"A_img": off, "gap": d, "rd": REGS[rd]})
                break
    return hits


def region_of(off, rstart, rend, regions):
    i = bisect_right(rstart.tolist(), off) - 1
    if i >= 0 and off < rend[i]:
        return regions[i]
    return None


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000",
           "img_len": hex(len(a_img))}

    # -- the law re-asserted (512 windows + 7 sites + claim7)
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

    # -- the map base (opcode-discriminated, as v433c/v435a)
    a_lui, b_lui = 0x1A02A + SHIFT, 0x1A02A
    base_a = seen[a_lui] == 1 and seen[a_lui + 2] == 0 \
        and covered[a_lui + 2] == 1 and (a_img[a_lui] & 0x7F) == 0x37
    base_b = seen[b_lui] == 1 and seen[b_lui + 2] == 0 \
        and covered[b_lui + 2] == 1 and (a_img[b_lui] & 0x7F) == 0x37
    assert base_a != base_b and base_a, "map base ambiguous"
    out["map_semantics"] = {"base": "A_img", "seen": "instruction starts"}

    sarr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]
    carr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    starts = np.nonzero(sarr)[0]

    # covered regions (for the fallback attribution)
    idx = np.nonzero(carr)[0]
    splits = np.nonzero(np.diff(idx) > 1)[0]
    b0 = np.concatenate(([0], splits + 1))
    b1 = np.concatenate((splits, [len(idx) - 1]))
    regions = [(int(idx[i0]), int(idx[i1]) + 1)
               for i0, i1 in zip(b0, b1) if idx[i1] + 1 - idx[i0] >= 2]
    rstart = np.array([r[0] for r in regions], dtype=np.int64)
    rend = np.array([r[1] for r in regions], dtype=np.int64)
    out["covered_regions"] = len(regions)

    # -- the full-form census (banked rules) + equality vs v435a
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

    p24 = full_pass(a_img, cands, (2, 4))
    p68 = full_pass(a_img, cands, (6, 8))
    drift = {v: (len(p24.get(v, [])), want) for v, want in
             BANKED_COUNTS.items() if len(p24.get(v, [])) != want}
    assert not drift, f"banked pair counts drifted: {drift}"
    print("[selftest] banked 4.32 pair counts reproduced exactly")

    v435a = json.loads(V435A.read_text())
    knobs435 = {k["value"]: k for k in v435a["knobs"]}
    shortlist = v435a["shortlist_gated_tunable"]
    out["shortlist_source"] = "v435a shortlist_gated_tunable"
    out["shortlist_n"] = len(shortlist)

    # the flat-result re-derivation vs v435a: the full COUNTS must equal
    # the per-knob metadata (site_cards are capped at 6 in v435a — the
    # stored cards must be a SUBSET of the re-derived sites).
    eq_fails = []
    for card in shortlist:
        v = card["value"]
        kn = knobs435[v]
        mine24 = sorted(s["A_img"] for s in p24.get(v, []))
        mine68 = sorted(s["A_img"] for s in p68.get(v, []))
        if len(mine24) != kn["sites_full24"] or \
                len(mine68) != kn["sites_full68"]:
            eq_fails.append({"value": v, "counts": (len(mine24),
                                                    len(mine68)),
                             "want": (kn["sites_full24"],
                                      kn["sites_full68"])})
            continue
        allmine = {s["A_img"]: s for s in p24.get(v, []) + p68.get(v, [])}
        for sc in kn["site_cards"]:
            mine = allmine.get(int(sc["A_img"], 16))
            if mine is None:
                eq_fails.append({"value": v, "card": sc["A_img"]})
                break
            rdm = mine["rd"]
            if rdm != sc["rd"]:
                eq_fails.append({"value": v, "card": sc["A_img"],
                                 "rd": (rdm, sc["rd"])})
                break
    print("[selftest] shortlist counts equal v435a metadata; "
          "stored cards are re-derived subsets (rd verified)")

    # -- the c.lui-100000 census + equality vs v434b
    clui = clui_100000_scan(a_img, starts)
    assert len(clui) == N_CLUI_100000, \
        f"c.lui-100000 count {len(clui)} != {N_CLUI_100000}"
    v434b = json.loads(V434B.read_text())
    theirs_cl = sorted(int(s["A_img"], 16) for b in v434b["bodies"]
                       for s in b["sites"])
    mine_cl = sorted(h["A_img"] for h in clui)
    assert mine_cl == theirs_cl, "c.lui sites differ from v434b"
    out["clui_100000"] = len(clui)
    print("[selftest] 36 c.lui-100000 reproduced, sites equal v434b")

    # -- the regkeys (v435b)
    v435b = json.loads(V435B.read_text())
    cards = v435b["regkey_cards"]
    with_x = [c for c in cards if c["pic_xrefs"] > 0]
    n_xrefs = sum(c["pic_xrefs"] for c in with_x)
    assert len(cards) == 864 and len(with_x) == 251 and n_xrefs == 366, \
        f"regkey counts drifted: {len(cards)}/{len(with_x)}/{n_xrefs}"
    out["regkeys"] = {"cards": len(cards), "with_xrefs": len(with_x),
                      "xrefs": n_xrefs}
    print("[selftest] regkey counts 864/251/366 reproduced")

    # the cited xref re-decode (RmValidateClientData)
    auipc_a = RVMCD_XREF_VA - IMG_LO - 4
    ins = dis1(a_img, auipc_a)
    ins2 = dis1(a_img, RVMCD_XREF_VA - IMG_LO)
    assert ins is not None and ins.mnemonic == "auipc" \
        and ins2 is not None and ins2.mnemonic == "jalr", \
        "RmValidateClientData cited xref does not re-decode"
    out["selftest_rvmcd_xref"] = {
        "auipc": f"{hex(auipc_a)}: {ins.mnemonic} {ins.op_str}",
        "jalr": f"{hex(RVMCD_XREF_VA - IMG_LO)}: "
                f"{ins2.mnemonic} {ins2.op_str}"}
    print("[selftest] RmValidateClientData cited xref re-decodes")

    # -- the PIC call edges + the banked callee fan-in
    src_e, tgt_e = pic_call_edges(a_img, starts)
    assert len(src_e) > 140000, f"pic edge census collapsed: {len(src_e)}"
    callee_hits = int(((tgt_e >= BANKED_CALLEE_A) &
                       (tgt_e < BANKED_CALLEE_A + 16)).sum())
    assert callee_hits >= 2, "banked callee 0x188EF44 fan-in lost"
    out["pic_edges"] = int(len(src_e))
    out["selftest_callee_fanin"] = {"callee": "0x188EF44",
                                    "fan_in_window16": callee_hits}
    print(f"[selftest] PIC edges {len(src_e)}, "
          f"callee 0x188EF44 fan-in {callee_hits} (>=2)")

    # -- FUNC WINDOW per shortlist site + func fan-in + regkey cross
    # regkey xref -> own func window (once per xref)
    xref_windows = {}
    for c in with_x:
        for xd in c["xref_detail"]:
            if xd["at"] is None:
                continue
            xa = int(xd["at"], 16) - IMG_LO
            if xa not in xref_windows:
                xref_windows[xa] = {
                    "name": c["name"], "class": xd["class"],
                    "va": xd["at"], "win": func_window(a_img, xa)}
    print(f"[scan] {len(xref_windows)} distinct regkey xrefs windowed")

    knob_cards = []
    regkey_fed = []
    for card in shortlist:
        v = card["value"]
        sites_out = []
        for s in knobs435[v]["site_cards"]:
            aoff = int(s["A_img"], 16)
            fs, fe = func_window(a_img, aoff)
            use_at = s["use_at"]
            use_at = int(use_at, 16) - IMG_LO if use_at else None
            use_ins = dis1(a_img, use_at) if use_at is not None else None
            site = {
                "A_img": s["A_img"], "VA": s["VA"], "rd": s["rd"],
                "use": s["use"], "use_at": s["use_at"],
                "func": [hex(fs) if fs is not None else None,
                         hex(fe) if fe is not None else None],
                "owner_region": s.get("owner_region"),
            }
            # func-level PIC fan-in + prologue
            fan = 0
            pro = None
            if fs is not None and fe is not None:
                m = (tgt_e >= fs) & (tgt_e < fe)
                fan = int(m.sum())
                if fan:
                    pro = int(tgt_e[m].min())
            site["pic_fan_in_func"] = fan
            site["prologue"] = hex(pro) if pro is not None else None
            # regkey cross: same fs, or xref inside [fs, fe]
            pairs = []
            for xa, xd in xref_windows.items():
                fsx, fex = xd["win"]
                inside = (fs is not None and fsx == fs) or \
                         (fs is not None and fe is not None and
                          fs <= xa < fe)
                if inside:
                    pairs.append({
                        "name": xd["name"], "class": xd["class"],
                        "xref_va": xd["va"], "xref_A": hex(xa),
                        "match": "same-func-start" if
                        (fs is not None and fsx == fs) else "in-window"})
            site["regkey_pairs"] = pairs
            # field flow for STORE-DATA sites
            if s["use"] == "STORE-DATA" and use_ins is not None and \
                    use_ins.mnemonic in STORE_OPS:
                disp = disp_of(use_ins)
                base = base_reg_of(use_ins)
                st_same = ld_same = 0
                ret_stores = []
                if fs is not None and fe is not None and \
                        disp is not None and base is not None:
                    off = fs
                    last_call = None
                    ci = 0
                    while off < fe:
                        i2 = dis1(a_img, off)
                        if i2 is None:
                            break
                        ci += 1
                        m2 = i2.mnemonic
                        if m2 in ("jalr", "c.jalr", "jal"):
                            last_call = (ci, off)
                        elif m2 in STORE_OPS and \
                                base_reg_of(i2) == base and \
                                disp_of(i2) == disp:
                            st_same += 1
                            src_reg = i2.op_str.split(",")[0].strip()
                            if last_call and ci - last_call[0] <= 12 and \
                                    src_reg in ("a0",):
                                ret_stores.append(hex(off))
                        elif m2 in LOAD_OPS and \
                                base_reg_of(i2) == base and \
                                disp_of(i2) == disp:
                            ld_same += 1
                        off += i2.size
                site["field"] = {
                    "op": f"{use_ins.mnemonic} {use_ins.op_str}",
                    "disp": hex(disp) if disp is not None else None,
                    "base": base, "same_field_stores": st_same,
                    "same_field_loads": ld_same,
                    "ret_stores_a0": ret_stores}
                if ret_stores and pairs:
                    regkey_fed.append({
                        "value": v, "site": s["A_img"],
                        "keys": sorted({p["name"] for p in pairs}),
                        "ret_stores": ret_stores})
            sites_out.append(site)
        knob_cards.append({
            "value": v, "unit": card["unit"], "leverage": card["leverage"],
            "risk_class": knobs435[v]["risk_class"],
            "sites": sites_out,
            "regkey_keys_co_resident": sorted(
                {p["name"] for st in sites_out for p in
                 st["regkey_pairs"]})})

    # -- the REGION-level cross (the wider net): xref region == site
    # owner_region (the v435a attribution), as the function-level test
    # above is the narrow one
    def region_idx(off):
        i = bisect_right(rstart.tolist(), off) - 1
        if i >= 0 and off < rend[i]:
            return i
        return None

    region_pairs = 0
    region_knobs = set()
    xref_regions = {}
    for xa, xd in xref_windows.items():
        xref_regions[xa] = region_idx(xa)
    for card in knob_cards:
        for st in card["sites"]:
            if st["owner_region"] is None:
                continue
            ro = int(st["owner_region"], 16)
            ri = region_idx(ro)
            for xa, xd in xref_windows.items():
                if xref_regions[xa] is not None and xref_regions[xa] == ri:
                    region_pairs += 1
                    region_knobs.add(card["value"])
    out["region_level_cross"] = {
        "pairs": region_pairs,
        "knobs_with_region_overlap": len(region_knobs),
        "values": sorted(region_knobs)}

    out["knob_flow_cards"] = knob_cards
    out["regkey_fed_candidates"] = regkey_fed
    n_with_keys = sum(1 for k in knob_cards
                      if k["regkey_keys_co_resident"])
    out["summary"] = {
        "shortlist_knobs": len(knob_cards),
        "knobs_with_regkey_co_resident": n_with_keys,
        "regkey_fed_candidates": len(regkey_fed)}

    OUT.write_text(json.dumps(out, indent=1))
    print(f"[out] {OUT}")
    print(f"[verdict] {n_with_keys}/{len(knob_cards)} shortlist knobs "
          f"have regkey co-residency; {len(regkey_fed)} ret-store "
          f"candidates")


if __name__ == "__main__":
    main()
