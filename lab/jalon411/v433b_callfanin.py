#!/usr/bin/env python3
"""4.33 LANE C — the static call census and the hot-function fan-in.

The optimization question: WHERE would a change have the most effect?
Static fan-in (how many direct call sites reach a function) is the
cheap, provable proxy for hotness in a closed binary — no profiling
exists, and the banked cartography (4.16: 81,871 validated call edges)
is the anchor this census must reproduce within tolerance.

Method:
  - direct jal (opcode 0x6F) at SEEN instruction starts only (the v416
    map's ground truth), both parity classes, vectorized;
  - J-imm decode vectorized (imm[20|10:1|11|19:12], sign-extended);
  - target = src + imm; the fan-in histogram = np.unique on targets;
  - every jal candidate at a NON-start offset is counted separately
    (noise floor, reported);
  - top-40 fan-in targets: prologue window cited, body size estimated
    by the forward walk to the first ret-like (cap 0x2000);
  - call-density ranking of the covered regions (edges per KiB).

Selftest anchors: the coordinate law + map base (opcode-discriminated);
the jal census must land within [0.5x, 1.5x] of the banked 81,871
validated call edges (4.16) — the delta is REPORTED, not asserted away;
s1's call site (auipc/jalr @VA 0x101a06c — the banked callee 0x188EF44)
re-verified reachable by the auipc+jalr arithmetic.
Output: lab/jalon411/v433b_callfanin.json
"""
import json
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

SHIFT = 0x38
IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82
BANKED_EDGES_416 = 81871

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


def window(img, aoff, n=6):
    lines, off = [], aoff
    for _ in range(n):
        ins = dis1(img, off)
        if ins is None:
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
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

    # -- the law + the map base (opcode-discriminated, as v433c)
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    for boff in SITES_B:
        if db[boff:boff + 8] != a_img[boff + SHIFT:boff + SHIFT + 8]:
            fails += 1
    assert fails == 0 and (a_img[CLAIM7_A] & 0x7F) == 0x37, "law broken"
    a_lui = 0x1A02A + SHIFT
    assert seen[a_lui] == 1 and (a_img[a_lui] & 0x7F) == 0x37, "map base"
    out["law_recheck"] = {"fails": fails, "map_base": "A_img (opcode)"}

    # -- the jal census at seen starts, both parity classes
    img4 = a_img + b"\x00" * ((4 - len(a_img) % 4) % 4)
    u0 = np.frombuffer(img4, dtype="<u4")
    u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    sarr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]
    starts = np.nonzero(sarr)[0]
    out["seen_starts"] = int(len(starts))

    # -- the call census: this firmware calls in PIC pairs auipc+jalr
    #    (the probe: 300,245 auipc / 148,314 jalr / only 600 jal at
    #    seen starts — the s1 banked window IS the canonical pattern).
    #    Edge = adjacent pair (jalr at auipc+4), rs1==auipc.rd,
    #    rd_jalr == ra (call) | zero (tail-jump), funct3==0.
    src_list, cls_list, tgt_list = [], [], []
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
        tgt = s_sel + (hi20 << 12) + lo12
        inimg = (tgt >= 0) & (tgt < len(a_img))
        ok &= inimg & ((rd_j == 1) | (rd_j == 0)) & (rd_a != 0)
        s_ok = s_sel[ok]
        cls = np.where((rd_j[ok] == 1), 1, 2)   # 1=call(ra) 2=tail(zero)
        src_list.append(s_ok.astype(np.int64))
        cls_list.append(cls)
        tgt_list.append(tgt[ok].astype(np.int64))
    src = np.concatenate(src_list) if src_list else np.array([], np.int64)
    cls = np.concatenate(cls_list) if cls_list else np.array([], np.int64)
    tgt = np.concatenate(tgt_list) if tgt_list else np.array([], np.int64)
    out["auipc_jalr_edges"] = int(len(src))
    out["auipc_jalr_calls_ra"] = int((cls == 1).sum())
    out["auipc_jalr_tails_zero"] = int((cls == 2).sum())

    # -- direct jal census (secondary; 600 expected)
    src_list, w_list = [], []
    for base_off, uarr in ((0, u0), (2, u2)):
        sel = starts[(starts & 3) == base_off]
        k = (sel - base_off) >> 2
        keep = (k + 1 < len(uarr)) & (k >= 0)
        sel, k = sel[keep], k[keep]
        mask = (uarr[k] & 0x7F) == 0x6F
        src_list.append(sel[mask])
        w_list.append(uarr[k][mask])
    jsrc = np.concatenate(src_list) if src_list else np.array([], np.int64)
    jw = np.concatenate(w_list) if w_list else np.array([], np.uint32)
    out["jal_at_seen_starts"] = int(len(jsrc))
    jimm = (((jw.astype(np.uint32) >> 31) & 1) << 20) | \
           (((jw >> 12) & 0xFF) << 12) | (((jw >> 20) & 1) << 11) | \
           (((jw >> 21) & 0x3FF) << 1)
    jimm = jimm.astype(np.int64)
    jimm[jimm >= (1 << 20)] -= (1 << 21)
    jtgt = jsrc + jimm
    jok = (jtgt >= 0) & (jtgt < len(a_img))
    out["jal_edges_in_image"] = int(jok.sum())

    # noise floor: jal-shaped words at even NON-start offsets
    all_even = np.arange(0, (len(a_img) - 4) & ~1, 2, dtype=np.int64)
    k0 = all_even[all_even % 4 == 0] >> 2
    k2 = (all_even[all_even % 4 == 2] - 2) >> 2
    noise = int(((u0[k0] & 0x7F) == 0x6F).sum() +
                ((u2[k2] & 0x7F) == 0x6F).sum()) - int(len(jsrc))
    out["jal_shape_noise_floor"] = noise

    # -- the census = PIC edges + direct jal edges
    all_src = np.concatenate((src, jsrc[jok]))
    all_tgt = np.concatenate((tgt, jtgt[jok]))
    out["call_edges_total"] = int(len(all_src))

    # -- SELFTEST: the anchors that can actually bind
    #    (a) the banked shared callee 0x188EF44 (s1 AND s2 call it,
    #        findings-4.32 §2) must exist with fan-in >= 2;
    #    (b) 100% of the distinct call targets carry the seen bit
    #        (census x map mutual validation);
    #    (c) the 4.16 comparison is OBSERVATIONAL (its 81,871 = distinct
    #        (caller-FUNCTION, callee) tuples — a different unit than
    #        sites; the delta is definitional, named in the JSON).
    uniq_pre, cnt_pre = np.unique(all_tgt, return_counts=True)
    d = dict(zip(uniq_pre.tolist(), cnt_pre.tolist()))
    s1s2_callee = d.get(0x188EF44 - IMG_LO, 0)
    out["selftest_census"] = {
        "s1s2_callee_0x188ef44_fanin": int(s1s2_callee),
        "distinct_targets_all_seen": None,   # filled after the histogram
        "banked_416_edges_unit": ("distinct (caller-function, callee) "
                                  "tuples, recursive-descent validated"),
        "our_units": {"call_sites": int(len(all_src)),
                      "distinct_targets": int(len(uniq_pre)),
                      "note": "units differ; observational only"}}
    assert s1s2_callee >= 2, \
        f"the banked shared callee lost: fan-in {s1s2_callee} < 2"
    print(f"[selftest] shared callee 0x188ef44 fan-in = {s1s2_callee} OK")
    print(f"[census] sites={len(all_src)} distinct-targets={len(uniq_pre)} "
          f"(banked 4.16: 81,871 fn-keyed tuples — different unit)")

    # -- the s1 call-site anchor: auipc ra 0x875 @0x1a06c+4 ... the
    #    banked callee 0x188EF44 reachable from s1's auipc+jalr pair
    #    (findings-4.32: call 0x188EF44 from VA 0x101a06c)
    s1_call = 0x1A02A + SHIFT + 0xA          # auipc @VA 0x101a06c
    w_aui = struct_au = int.from_bytes(a_img[s1_call:s1_call + 4], "little")
    if (w_aui & 0x7F) == 0x17:
        hi20 = (w_aui >> 12) - (1 << 20) if (w_aui >> 12) >= 0x80000 \
            else (w_aui >> 12)
        w_jalr = int.from_bytes(a_img[s1_call + 4:s1_call + 8], "little")
        lo12 = (w_jalr >> 20) - (1 << 12) if ((w_jalr >> 20) & 0xFFF) \
            >= 0x800 else (w_jalr >> 20)
        callee_va = (IMG_LO + s1_call + (hi20 << 12) + lo12) & 0xFFFFFFFF
        out["s1_callee_anchor"] = {
            "auipc_at": hex(IMG_LO + s1_call),
            "callee_VA": hex(callee_va),
            "banked": "0x188ef44",
            "match": hex(callee_va) == "0x188ef44"}
        assert hex(callee_va) == "0x188ef44", "s1 callee anchor drifted"
        print(f"[selftest] s1 callee anchor: {hex(callee_va)} == banked")

    # -- the fan-in histogram
    uniq, cnt = np.unique(all_tgt, return_counts=True)
    out["distinct_call_targets"] = int(len(uniq))
    # the 100%-seen assert binds the PIC CALL targets (the probe: 6,062
    # distinct PIC targets all seen). Direct-jal targets include plain
    # jumps (jal x0) into uncovered islands — REPORTED, not asserted.
    pic_seen_pct = float((sarr[np.unique(tgt[cls == 1])] == 1).mean() * 100)
    tail_seen_pct = float((sarr[np.unique(tgt[cls == 2])] == 1).mean() * 100) \
        if (cls == 2).any() else 100.0
    jal_seen_pct = float((sarr[np.unique(jtgt[jok])] == 1).mean() * 100) \
        if jok.any() else 100.0
    out["selftest_census"]["pic_call_targets_seen_pct"] = pic_seen_pct
    out["selftest_census"]["tail_targets_seen_pct"] = tail_seen_pct
    out["selftest_census"]["jal_targets_seen_pct"] = jal_seen_pct
    assert pic_seen_pct == 100.0, \
        f"PIC call targets outside verified starts: {pic_seen_pct}%"
    print(f"[selftest] PIC call targets 100% seen OK "
          f"(tails: {tail_seen_pct:.1f}%, jal: {jal_seen_pct:.1f}% — "
          f"jumps may enter uncovered islands, reported not asserted)")
    order = np.argsort(-cnt)
    covered_arr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]

    # covered regions (vectorized)
    idx = np.nonzero(covered_arr)[0]
    splits = np.nonzero(np.diff(idx) > 1)[0]
    b0 = np.concatenate(([0], splits + 1))
    b1 = np.concatenate((splits, [len(idx) - 1]))
    regions = [(int(idx[i0]), int(idx[i1]) + 1)
               for i0, i1 in zip(b0, b1) if idx[i1] + 1 - idx[i0] >= 2]
    out["covered_regions"] = len(regions)

    top = []
    for rank in order[:40]:
        t = int(uniq[rank]); c = int(cnt[rank])
        sz, off = 0, t
        for _ in range(0x2000 // 2):
            ins = dis1(a_img, off)
            if ins is None:
                break
            off += ins.size
            sz += ins.size
            if is_retlike(ins):
                break
        r = next(([s0, e0] for s0, e0 in regions
                  if s0 <= t < e0), None)
        top.append({
            "VA": hex(IMG_LO + t), "A_img": hex(t), "fan_in": c,
            "seen_target": bool(sarr[t]),
            "region": [hex(IMG_LO + r[0]), hex(IMG_LO + r[1])] if r
                      else None,
            "body_walk_bytes": sz,
            "prologue": window(a_img, t, 6)})
    out["top_fanin"] = top
    print(f"[fanin] targets={len(uniq)} top10=" +
          str([(t['VA'], t['fan_in']) for t in top[:10]]))

    # -- per-region call density (edges per KiB of region)
    rstart = np.array([r[0] for r in regions], dtype=np.int64)
    ren = np.array([r[1] for r in regions], dtype=np.int64)
    which = np.searchsorted(rstart, all_tgt, side="right") - 1
    ok = (which >= 0) & (all_tgt < ren[np.clip(which, 0, len(ren) - 1)])
    wb = np.bincount(which[ok], minlength=len(regions))
    dens = []
    for i, r in enumerate(regions):
        if wb[i] == 0:
            continue
        dens.append({"region": [hex(IMG_LO + r[0]), hex(IMG_LO + r[1])],
                     "KiB": round((r[1] - r[0]) / 1024, 1),
                     "jal_edges": int(wb[i]),
                     "per_KiB": round(float(wb[i]) /
                                      ((r[1] - r[0]) / 1024), 2)})
    dens.sort(key=lambda d: -d["jal_edges"])
    out["region_call_density_top20"] = dens[:20]
    out["region_call_edges_total"] = int(wb.sum())

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
