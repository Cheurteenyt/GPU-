#!/usr/bin/env python3
"""4.36 TASK B — the function-level owner map of the 60 knobs.

4.33 lane A banked the 60 knobs; 4.35a carded them with owner
REGIONS (the v416 covered regions, up to ~143 KiB — many functions).
The 4.36 question: WHO OWNS each knob at the FUNCTION level?
  - the ret-bounded func window per site (backward to the last
    ret-like, forward to the first ret-like, 0x4000 limits);
  - the func-level PIC fan-in (the v433b seen-validated edges whose
    target lands inside the window) + the prologue (the min target);
  - the RPC-anchor cross (v420 shapeA key tables): a key-table VA
    landing inside a knob's owner REGION ties the region to the
    dispatch ID (0x2080xxxx) it serves;
  - the name-pointer cross (v435b neighbor_ptrs): Rm*/RM* strings
    pointed at from inside the owner region name the subsystem.

Selftests: the law, the map base, the banked counts, the 36 c.lui,
the PIC edges + the banked callee fan-in 50.

Output: lab/jalon411/v436b_funcowners.json
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
V420 = ROOT / "lab/jalon411/v420_rpcanchor.json"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82
BANKED_COUNTS = {250000: 6, 500000: 25, 1000000: 123, 4000000: 15,
                 100000000: 17, -250000: 1, -1000000: 3, -500000: 5,
                 100000: 0, 240000: 0, 280000: 0}
N_CLUI = 36
BANKED_CALLEE_A = 0x188EF44 - IMG_LO
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


def func_window(img, aoff, limit=0x4000):
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
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    w0 = np.frombuffer(img4, dtype="<u4")
    w2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    srcs, tgts = [], []
    for base_off in (0, 2):
        uvec = w0 if base_off == 0 else w2
        sel = starts[(starts & 3) == base_off]
        k = (sel - base_off) >> 2
        keep = (k + 1 < len(uvec)) & (k >= 0)
        sel = sel[keep]
        k = k[keep]
        okauipc = (uvec[k] & 0x7F) == 0x17
        sel = sel[okauipc]
        k = k[okauipc]
        if len(sel) == 0:
            continue
        w_auipc = uvec[k]
        rd_a = ((w_auipc >> 7) & 0x1F).astype(np.int64)
        hi20 = (w_auipc >> 12).astype(np.int64)
        bigsel = hi20 >= 0x80000
        hi20[bigsel] -= 0x100000
        w_j = uvec[k + 1]
        ok = ((w_j & 0x7F) == 0x67) & (((w_j >> 12) & 7) == 0) & \
             (((w_j >> 15) & 0x1F) == rd_a)
        sel = sel[ok]
        k = k[ok]
        w_j = w_j[ok]
        hi20 = hi20[ok]
        lo12 = ((w_j >> 20) & 0xFFF).astype(np.int64)
        losel = lo12 >= 0x800
        lo12[losel] -= 0x1000
        tgt = sel + (hi20 << 12) + lo12
        srcs.append(sel.astype(np.int64))
        tgts.append(tgt)
    src = np.concatenate(srcs) if srcs else np.zeros(0, np.int64)
    tgt = np.concatenate(tgts) if tgts else np.zeros(0, np.int64)
    return src, tgt


def full_pass(a_img, cands, gaps):
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
    hits = []
    for off in starts.tolist():
        if img[off] & 3 == 3:
            continue
        w16 = img[off] | (img[off + 1] << 8)
        if (w16 & 0xE003) != 0x6001:
            continue
        if (w16 >> 12) & 1:
            continue
        rd = (w16 >> 7) & 0x1F
        if rd == 0:
            continue
        if ((w16 >> 2) & 0x1F) != 0b11000:
            continue
        for d in (2, 4):
            ins = dis1(img, off + d)
            if ins is None:
                continue
            if ins.mnemonic == "addi":
                ops = [x.strip() for x in ins.op_str.split(",")]
                try:
                    if REGS[rd] in (ops[0], ops[1]) and \
                            int(ops[2], 0) == 0x6A0:
                        hits.append({"A_img": off, "gap": d,
                                     "rd": REGS[rd]})
                        break
                except Exception:
                    continue
    return hits


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    cut = len(blob) // 2
    seen, covered = blob[:cut], blob[cut:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

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
    assert fails == 0, "coordinate law broken"
    out["law_recheck"] = {"windows": 512 + 7, "fails": 0}

    a_lui, b_lui = 0x1A02A + SHIFT, 0x1A02A
    base_a = seen[a_lui] == 1 and seen[a_lui + 2] == 0 \
        and covered[a_lui + 2] == 1 and (a_img[a_lui] & 0x7F) == 0x37
    base_b = seen[b_lui] == 1 and seen[b_lui + 2] == 0 \
        and covered[b_lui + 2] == 1 and (a_img[b_lui] & 0x7F) == 0x37
    assert base_a != base_b and base_a, "map base ambiguous"

    sarr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]
    carr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    starts = np.nonzero(sarr)[0]

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

    # the banked censuses (the flat re-derivation)
    img4 = a_img + b"\x00" * ((4 - len(a_img) % 4) % 4)
    w0 = np.frombuffer(img4, dtype="<u4")
    w2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    cands = []
    for base_off, uvec in ((0, w0), (2, w2)):
        kmax = (len(img4) - 4 - base_off) >> 2
        k = np.arange(kmax, dtype=np.int64)
        k37 = (uvec[k] & 0x7F) == 0x37
        for kk in k[k37]:
            cands.append((int(base_off + (kk << 2)), int(uvec[kk])))
    cands.sort()
    p24 = full_pass(a_img, cands, (2, 4))
    p68 = full_pass(a_img, cands, (6, 8))
    drift = {v: (len(p24.get(v, [])), want) for v, want in
             BANKED_COUNTS.items() if len(p24.get(v, [])) != want}
    assert not drift, f"banked pair counts drifted: {drift}"
    print("[selftest] banked pair counts reproduced")

    clui = clui_100000_scan(a_img, starts)
    assert len(clui) == N_CLUI, f"c.lui count {len(clui)} != 36"
    print("[selftest] 36 c.lui-100000 reproduced")

    src_e, tgt_e = pic_call_edges(a_img, starts)
    callee_hits = int(((tgt_e >= BANKED_CALLEE_A) &
                       (tgt_e < BANKED_CALLEE_A + 16)).sum())
    assert callee_hits >= 2
    out["pic_edges"] = int(len(src_e))
    print(f"[selftest] PIC edges {len(src_e)}, callee fan-in {callee_hits}")

    v435a = json.loads(V435A.read_text())
    knobs = v435a["knobs"]
    v435b = json.loads(V435B.read_text())
    v420 = json.loads(V420.read_text())

    # the RPC key tables: ID -> list of table VAs (VA_A space)
    shape_a = v420["shapeA_key_tables"]
    rpc_by_va = {}
    for cid, entries in shape_a.items():
        for e in entries:
            va = e.get("va")
            if va is None:
                continue
            va = int(va) if not isinstance(va, str) else int(va, 16)
            aoff = va - IMG_LO
            if 0 <= aoff < len(a_img):
                rpc_by_va[aoff] = cid
    out["rpc_key_tables"] = len(rpc_by_va)

    # the name-pointer tables from v435b (the strings pointed at)
    ptr_names = {}
    for c in v435b["regkey_cards"]:
        for t in c.get("neighbor_ptrs") or c.get("ptr_table_refs") or []:
            pass
    # neighbor_ptrs live per-card in v435b; collect (ptr_va -> name)
    for c in v435b["regkey_cards"]:
        nm = c["name"]
        for t in c.get("ptr_table_refs") or []:
            at = t.get("at") if isinstance(t, dict) else None
            if at:
                ptr_names[int(at, 16) - IMG_LO] = nm

    cards = []
    n_func = n_rpc = n_names = 0
    for kn in knobs:
        v = kn["value"]
        per_site = []
        for s in kn["site_cards"]:
            aoff = int(s["A_img"], 16)
            fs, fe = func_window(a_img, aoff)
            ent = {"A_img": s["A_img"], "use": s["use"],
                   "owner_region": s.get("owner_region")}
            if fs is not None and fe is not None:
                ent["func"] = [hex(fs), hex(fe)]
                m = (tgt_e >= fs) & (tgt_e < fe)
                fan = int(m.sum())
                ent["pic_fan_in_func"] = fan
                if fan:
                    ent["prologue"] = hex(int(tgt_e[m].min()))
                n_func += 1
            else:
                ent["func"] = None
                ent["pic_fan_in_func"] = None
            # region-level RPC tie: any key-table VA inside the region?
            ro = s.get("owner_region")
            if ro:
                ro0, ro1 = int(ro, 16), None
                reg = region_of(ro0)
                if reg:
                    ro0, ro1 = reg
                    hits_rpc = sorted({cid for va, cid in
                                       rpc_by_va.items()
                                       if ro0 <= va < ro1})
                    if hits_rpc:
                        ent["rpc_ids_in_region"] = hits_rpc[:8]
                        n_rpc += 1
                    # name-pointer tables inside the region
                    nms = sorted({nm for at, nm in ptr_names.items()
                                  if ro0 <= at < ro1})
                    if nms:
                        ent["names_pointed_in_region"] = nms[:8]
                        n_names += 1
            per_site.append(ent)
        cards.append({"value": v, "sites": per_site})

    out["knob_owner_cards"] = cards
    out["summary"] = {
        "sites_total": sum(len(c["sites"]) for c in cards),
        "sites_with_func_window": n_func,
        "sites_with_rpc_tie": n_rpc,
        "sites_with_name_ptrs": n_names}
    OUT.write_text(json.dumps(out, indent=1))
    print(f"[out] {OUT}")
    print("[verdict]", json.dumps(out["summary"]))


if __name__ == "__main__":
    main()
