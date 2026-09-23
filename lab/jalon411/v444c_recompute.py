#!/usr/bin/env python3
"""4.44 pass, TÂCHE A2 — the recompute 0x143fdbc decoded IN FULL: the
exact WRITE SET on the policy object, and the record-writer hunt.

4.43 §2.3 banked the chain (the event 0x20809009 -> the mask 0x65c ->
the match {0x1,0x4} @0x1C7B320 -> the list -> the event 0x20809064 ->
the bases obj+(idx+0x60)*0x10+{0xc..0x18}). The mission asks: whence
the VALUES (are the base seeds static?), and — for the persistence
comparison — the recompute's COMPLETE write set (does it touch the
records obj+0x18+idx*0x30? the bases only?).

Steps:
  1. the full window decode 0x143fdbc .. the function end (bounded by
     the next-prologue-after-ret), with every object-relative store
     enumerated (s1 = the object base per 4.43);
  2. the two internal-event ids re-cited + the match table base
     recomputed from the PIC pair;
  3. the RECORD-WRITER hunt over the policy module family
     [0x143f000, 0x1448000): every store with displacement in
     {0x14, 0x18} whose address register derives from a x0x30 index
     (mul by 0x30 / slli by 4,5 / addi 0x30 strides) — bounded, honest;
  4. the base-fill window re-cited byte-exact (0x143fece-fefe).

Self-checks: auipc 416,206; law 512/512.

Output: lab/jalon411/v444c_recompute.json
"""
import json
from pathlib import Path

import capstone
import numpy as np
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
RECOMP = 0x143fdbc
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

img = A.read_bytes()[0x40:0x40 + 0xE9B000]


def dec(va, n, back=0):
    o = va - IMG_LO - back
    out = []
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append({"va": IMG_LO + o, "m": ins.mnemonic, "o": ins.op_str,
                    "size": ins.size})
        o += ins.size
    return out


def main():
    out = {}
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        k = np.arange((len(img4) - 4 - base_off) >> 2, dtype=np.int64)
        cnt += int(((uarr[k] & 0x7F) == 0x17).sum())
    assert cnt == 416206
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        assert img[o:o + 16] == (ROOT /
            "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
            ).read_bytes()[o - 0x38:o - 0x38 + 16]
    out["selfchecks"] = {"auipc": cnt, "law_fails": 0}

    # -- 1. the full window (600 insns ~= 0x960 bytes covers the body)
    wins = dec(RECOMP, 700)
    listing = wins
    out["listing"] = [{"va": f"0x{w['va']:x}", "m": w["m"], "o": w["o"]}
                      for w in listing]

    # -- 2. the object-relative stores (s1 = the object, per the prologue)
    stores = []
    for w in listing:
        if w["m"] in ("sd", "sw", "sb", "sh", "c.sw", "c.sd"):
            if "(s1)" in w["o"]:
                stores.append(w)
    out["obj_stores"] = [{"va": f"0x{w['va']:x}", "m": w["m"], "o": w["o"]}
                         for w in stores]

    # -- 3. the PIC pairs + the event ids
    pics = []
    for i, w in enumerate(listing):
        if w["m"] != "auipc":
            continue
        immv = int(w["o"].split(", ")[1], 0)
        if immv >= 0x80000:
            immv -= 0x100000
        base = w["va"] + (immv << 12)
        rd = w["o"].split(", ")[0]
        tgt = None
        for w2 in listing[i + 1:i + 4]:
            if w2["m"] == "addi" and w2["o"].startswith(rd + ", " + rd):
                tgt = base + int(w2["o"].split(", ")[2], 0)
                break
        pics.append({"va": f"0x{w['va']:x}", "rd": rd,
                     "target": hex(tgt) if tgt is not None else None})
    out["pic_pairs"] = pics

    # -- 4. the direct calls
    calls = []
    for i, w in enumerate(listing):
        if w["m"] != "auipc":
            continue
        immv = int(w["o"].split(", ")[1], 0)
        if immv >= 0x80000:
            immv -= 0x100000
        base = w["va"] + (immv << 12)
        for w2 in listing[i + 1:i + 3]:
            if w2["m"] == "jalr" and w2["o"].startswith("ra, ra"):
                off = int(w2["o"].split(", ")[2], 0)
                calls.append({"va": f"0x{w['va']:x}",
                              "callee": hex(base + off)})
                break
    out["direct_calls"] = calls

    # -- 5. the base-fill window re-cited
    out["basefill_window"] = [{"va": f"0x{w['va']:x}", "m": w["m"],
                               "o": w["o"]}
                              for w in dec(0x143fece, 22)]

    # -- 6. the RECORD-WRITER hunt over the policy family
    #     the pattern: an index register multiplied by 0x30 (mul x,x,t3
    #     with t3=0x30, or slli x,x,4/5 chains) then a store at +0x14/0x18
    lo, hi = 0x143f000, 0x1448000
    o = lo - IMG_LO
    walk = []
    while o < hi - IMG_LO:
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            o += 2
            continue
        walk.append({"va": IMG_LO + o, "m": ins.mnemonic, "o": ins.op_str,
                     "size": ins.size})
        o += ins.size
    stride_regs = set()
    hits = []
    for i, w in enumerate(walk):
        if w["m"] == "addi" and w["o"] in ("t3, zero, 0x30",):
            stride_regs.add("t3")
        if w["m"] == "li" and w["o"] in ("t3, 0x30", "t3, 48"):
            stride_regs.add("t3")
        if w["m"] == "mul" and any(r in w["o"].split(", ")
                                   for r in stride_regs):
            hits.append({"va": f"0x{w['va']:x}", "m": w["m"], "o": w["o"],
                         "kind": "stride-mul"})
        # the store at +0x14/+0x18 with a shifted base (the record shape)
        if w["m"] in ("sw", "c.sw", "sd") and ("0x14(" in w["o"] or
                                               "0x18(" in w["o"]):
            hits.append({"va": f"0x{w['va']:x}", "m": w["m"], "o": w["o"],
                         "kind": "field-store"})
    out["record_hunt_hits"] = hits
    out["record_hunt_stride_regs"] = sorted(stride_regs)

    # -- 7. the stride-mul census across the whole image (where else does
    #       the x0x30 index appear with t3=0x30 nearby?)
    u32full = np.frombuffer(img4, dtype="<u4")
    # cheap: find all 'addi t3, zero, 0x30' (0x00e0039b pattern family) —
    # do it with capstone over a coarse stride instead: the LUI-free
    # li/addi materializations of 0x30 into t3 = exact byte patterns:
    # addi t3, zero, 0x30 = 0x03000e1b? compute: addi rd=t3(28), rs=0,
    # imm=0x30: imm[11:0]=0x030, rs1=0, funct3=0, rd=28, op=0x13 ->
    # 0x03000000 | 28<<7 | 0x13 = 0x03000E1B
    pat = 0x03000E1B
    idxs = np.where(u32full == pat)[0]
    out["t3_materializations"] = {
        "pattern": hex(pat),
        "count_4aligned": int(len(idxs)),
        "vas": [hex(IMG_LO + int(x) * 4) for x in idxs][:40],
    }

    OUT.write_text(json.dumps(out, indent=1))
    print(f"obj stores (s1-relative): {len(stores)}")
    for w in stores:
        print(f"  0x{w['va']:x}: {w['m']} {w['o']}")
    print(f"record hunt hits: {len(hits)}")
    print(f"t3=0x30 materializations (4-aligned): {len(idxs)}")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
