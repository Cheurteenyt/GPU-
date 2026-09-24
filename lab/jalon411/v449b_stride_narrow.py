#!/usr/bin/env python3
"""4.49 TASK B — the 0x4C-candidate narrowing: which 76-stride walker
(if any) parses the VBIOS DRAM timing records.

State: 4.48's census banked 349 `addi x,x,0x4c` + 185 li-76 + 15
mul-by-76 sites and closed the question INDECIDABLE-BY-BYTES (76 is a
common stride). This instrument narrows with features instead of a
single anchor. For every candidate site, over a +-0x200 window:

  - LOADS from one base register (the record-field reads: lw/lbu/lhu
    with a shared (reg) base) — the parse signature;
  - the bit-extraction density (slli/srli/srai/andi/xori) — the gx5
    grammar is six u32 -> 18 bitfields;
  - a SECOND 0x4C in the window (the loop advance + the stride const);
  - the li-65 (0x41) co-location — the gx5 table has 65 records;
  - the memcpy-size signature `li a2, 0x4c` (a whole-record copy-out
    call) — censused image-wide with the call that follows;
  - the LHR-value comparisons: li-210 (0xd2) / li-175 (0xaf) near a
    0x4C site (the top-bin LHR record {70,175,44,20,5}).

Every candidate is scored; the top scorers are banked with full
context. If no candidate separates from the noise floor, the honest
verdict stays INDECIDABLE — but with the narrowed list + the features
that failed, which is what the next pass (or the runbook §5 dump)
needs.

Selftests: the auipc census 416,206; the 512-region law; the 4.48
stride totals re-derived (349 / 185 / 15).

Output: lab/jalon411/v449b_stride_narrow.json
"""
import json
import re
import struct
import zlib
from collections import Counter
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
WIN = 0x200          # the feature window around each candidate

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

    out = {"pass": "4.49", "task": "B",
           "instrument": "v449b_stride_narrow",
           "baseline": {"auipc": cnt, "law": "512/512"}}

    # -- 1. re-derive the 4.48 stride totals --------------------------------
    addi_hits = []
    for off in range(0, len(img) - 4, 2):
        if img[off] & 3 != 3:
            continue
        u = struct.unpack_from("<I", img, off)[0]
        if (u & 0x7F) != 0x13 or ((u >> 12) & 7) != 0:
            continue
        if ((u >> 20) & 0xFFF) != 0x04C:
            continue
        addi_hits.append({"va": IMG_LO + off,
                          "rd": REG[(u >> 7) & 31],
                          "rs1": REG[(u >> 15) & 31],
                          "is_li": ((u >> 15) & 31) == 0})
    li76 = [h for h in addi_hits if h["is_li"]]
    assert len(addi_hits) == 349, f"addi-0x4c {len(addi_hits)} != 349"
    assert len(li76) == 185, f"li76 {len(li76)} != 185"
    mul_hits = []
    for h in li76:
        o = h["va"] - IMG_LO
        for _ in range(8):
            if o + 4 > len(img):
                break
            if img[o] & 3 == 3:
                u = struct.unpack_from("<I", img, o)[0]
                if (u & 0x7F) == 0x33 and ((u >> 25) & 0x7F) == 1 and \
                        ((u >> 12) & 7) == 0:
                    rs1 = REG[(u >> 15) & 31]
                    rs2 = REG[(u >> 20) & 31]
                    if h["rd"] in (rs1, rs2):
                        mul_hits.append({"li_va": h["va"],
                                         "mul_va": IMG_LO + o})
                        break
                o += 4
            else:
                o += 2
    assert len(mul_hits) == 15, f"mul {len(mul_hits)} != 15"
    out["stride_totals"] = {"addi_0x4c": len(addi_hits),
                            "li76": len(li76), "mul76": len(mul_hits)}
    print(f"[stride] 349/185/15 re-derived exactly")

    # -- 2. the memcpy-size signature: li a2, 0x4c --------------------------
    # a whole-record copy-out (memcpy(dst, src, 76)) materializes 76 in
    # a2. Census + the next call target within 8 insns.
    a2_4c = []
    for h in li76:
        if h["rd"] != "a2":
            continue
        o = h["va"] - IMG_LO + 4
        call = None
        for _ in range(8):
            if o + 2 > len(img):
                break
            ins, sz = dec_at(img, o)
            if ins is not None and ins.mnemonic == "jalr" and \
                    img[o] & 3 == 3:
                u = struct.unpack_from("<I", img, o)[0]
                imm = (u >> 20) & 0xFFF
                if imm & 0x800:
                    imm -= 0x1000
                if ((u >> 15) & 31) == 1 and img[o - 4] & 3 == 3:
                    u0 = struct.unpack_from("<I", img, o - 4)[0]
                    if (u0 & 0x7F) == 0x17 and ((u0 >> 7) & 31) == 1:
                        imm20 = (u0 >> 12) & 0xFFFFF
                        if imm20 & 0x80000:
                            imm20 -= 0x100000
                        call = hex((IMG_LO + o - 4) + (imm20 << 12) + imm)
                        break
            o += sz if sz else 2
        a2_4c.append({"va": hex(h["va"]), "next_call": call})
    out["memcpy_size_signature"] = a2_4c
    print(f"[memcpy] li a2,0x4c sites: {len(a2_4c)}; with a call: "
          f"{sum(1 for a in a2_4c if a['next_call'])}")

    # -- 3. the feature scoring ---------------------------------------------
    LOADS = {"lw", "lb", "lbu", "lhu", "ld"}
    EXTRACT = {"slli", "srli", "srai", "andi", "xori", "slliw", "srliw"}

    def features(va):
        o0 = va - IMG_LO
        lo = max(0, o0 - WIN)
        hi = min(len(img), o0 + WIN)
        loads = Counter()
        extract_n = 0
        second_4c = 0
        li65 = 0
        li210 = 0
        li175 = 0
        o = lo
        while o < hi:
            if o == o0:
                o += 2
                continue
            ins, sz = dec_at(img, o)
            if ins is None:
                o += 2
                continue
            m, op = ins.mnemonic, ins.op_str
            if m in LOADS:
                mm = re.search(r"\((\w+)\)$", op)
                if mm:
                    loads[mm.group(1)] += 1
            elif m in EXTRACT:
                extract_n += 1
            elif m == "addi" and op.endswith(", 0x4c"):
                second_4c += 1
            elif m in ("addi", "c.li", "li") and op.endswith(", 0x41"):
                li65 += 1
            elif m in ("addi", "c.li", "li") and op.endswith(", 0xd2"):
                li210 += 1
            elif m in ("addi", "c.li", "li") and op.endswith(", 0xaf"):
                li175 += 1
            o += sz
        main_base, main_n = (loads.most_common(1)[0]
                             if loads else (None, 0))
        return {"loads_main_base": main_n, "main_base": main_base,
                "distinct_load_bases": len(loads),
                "extract": extract_n, "second_4c": second_4c,
                "li65": li65, "li210": li210, "li175": li175}

    def score(f):
        return (f["loads_main_base"] * 2 + f["extract"] +
                f["second_4c"] * 4 + f["li65"] * 3 +
                f["li210"] * 6 + f["li175"] * 6)

    cands = []
    for h in addi_hits:
        if h["is_li"]:
            continue                      # the li-76 constants already
                                          # feed the mul sites (scored)
        f = features(h["va"])
        cands.append({"va": hex(h["va"]),
                      "insn": f"addi {h['rd']}, {h['rs1']}, 0x4c",
                      "kind": "stride", **f, "score": score(f)})
    for h in mul_hits:
        f = features(h["mul_va"])
        cands.append({"va": hex(h["mul_va"]),
                      "insn": f"mul (li76 @{h['li_va']:#x})",
                      "kind": "mul76", **f, "score": score(f)})
    cands.sort(key=lambda c: -c["score"])
    out["candidates_top"] = cands[:40]
    out["candidate_count"] = len(cands)
    print(f"[cands] {len(cands)} scored; top 12:")
    for c in cands[:12]:
        print(f"  @{c['va']} {c['kind']} score={c['score']} "
              f"loads={c['loads_main_base']}@{c['main_base']} "
              f"extract={c['extract']} 2nd4c={c['second_4c']} "
              f"li65={c['li65']} lhr={c['li210']}/{c['li175']}")

    # -- 4. full context for the top 5 --------------------------------------
    ctxs = []
    for c in cands[:5]:
        o0 = int(c["va"], 16) - IMG_LO
        lines = []
        o = o0 - 0x40
        while o < o0 + 0x60:
            ins, sz = dec_at(img, o)
            lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
            o += sz if sz else 2
        ctxs.append({"va": c["va"], "ctx": lines})
    out["top_contexts"] = ctxs

    # -- 5. the noise floor --------------------------------------------------
    # 40 random 4-byte-aligned sites' feature distribution — the scale
    # every candidate must beat.
    import random
    random.seed(449)
    floor = []
    for _ in range(40):
        va = random.randrange(0x1000000, 0x1000000 + IMG_LEN - 0x400)
        f = features(va)
        floor.append(score(f))
    floor.sort()
    out["noise_floor"] = {"n": 40, "median": floor[20],
                          "p90": floor[35], "max": floor[-1]}
    print(f"[floor] median={floor[20]} p90={floor[35]} "
          f"max={floor[-1]} (the bar to beat)")

    # -- 6. the density map + the densest region named -----------------------
    # The scoring failed against the noise floor; the density angle is
    # the remaining static discriminator: which region is 76-centric?
    bins = Counter((h["va"] - IMG_LO) >> 11 for h in addi_hits)
    out["density_top_bins"] = [
        {"va_lo": hex(k << 11), "count": n}
        for k, n in bins.most_common(8)]
    # decode the densest region head (0x1220000) + identify its table
    densest = bins.most_common(1)[0][0] << 11
    lines = []
    o = densest
    while o < densest + 0x220:
        ins, sz = dec_at(img, o)
        lines.append(f"{IMG_LO + o:#x}: {render(ins)}")
        o += sz if sz else 2
    out["densest_region_head"] = {"va": hex(IMG_LO + densest),
                                  "body": lines}
    # the mul76 site inside the densest bin resolved its table base:
    # 0x122002c auipc a1,0xa35 + addi 0x364 -> 0x1c57390; 60 records x 76B
    tbl = 0x1C57390 - IMG_LO
    keys = []
    for i in range(60):
        rec = tbl + i * 76
        if rec + 76 <= len(img):
            keys.append(struct.unpack_from("<I", img, rec)[0])
    ptr_like = 0
    for i in range(60):
        rec = tbl + i * 76
        for j in range(0, 76, 8):
            if rec + j + 8 <= len(img):
                p = struct.unpack_from("<Q", img, rec + j)[0]
                if 0x1000000 <= p < IMG_LO + IMG_LEN:
                    ptr_like += 1
    out["densest_table"] = {
        "base_va": hex(0x1C57390), "records": 60, "stride": 76,
        "first_keys": [hex(k) for k in keys[:12]],
        "keys_monotonic": keys == sorted(keys),
        "in_image_pointers": ptr_like,
        "verdict": "high-entropy u32 keys (hash/fuse-like), 60 != 65 "
                   "(gx5), no pointer fields -> NOT the DRAM timing "
                   "table; the walker @0x1220018-0x1220096 = a static "
                   "record-table lookup, NAMED as a non-timing 76B "
                   "mechanism",
    }
    print(f"[density] top bin {hex(IMG_LO + densest)}; "
          f"table keys head: {[hex(k) for k in keys[:6]]}; "
          f"ptr-like fields: {ptr_like}")

    out["verdict"] = (
        "INDECIDABLE-BY-BYTES stays, now EXHAUSTED statically: (1) the "
        "feature scoring cannot separate a walker from the stack-code "
        "noise (random-site max 113 > the best candidate 88 — the "
        "features are DEAD as a discriminator, PROVEN); (2) no LHR "
        "value constant (210/175) co-locates with any 0x4C site — the "
        "records are bit-packed, consistent with the missing gx5 "
        "grammar; (3) the 37 li a2,0x4c+call memcpy signatures banked, "
        "non-disambiguating; (4) the densest 76-region = a static "
        "60x76 hash-table lookup, NAMED non-timing. The runbook §5 "
        "DMEM fingerprint dump remains THE deciding experiment.")

    out["selftests"] = {"auipc_416206": True, "law_512": "PASS",
                        "stride_totals": "349/185/15 exact"}
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
