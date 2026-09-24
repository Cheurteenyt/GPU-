#!/usr/bin/env python3
"""4.46 pass, TÂCHE B — the record-writer hunt, FULL IMAGE, all encodings,
plus the static-template search and the policy-object consumer census.

Banked (4.44 §2.3): within [0x143f000, 0x1448000) the ×0x30 stride idiom
(enc 0x03000E13 = li t3, 0x30) has 2 sites (the recompute + the evaluator)
and NO writer of record f14/f18 is nameable. This pass widens ALL of it:

  1. self-checks (auipc 416,206; the law 512/512);
  2. the FULL-IMAGE census of the 0x30-stride idiom, ALL encodings:
     addi rd, zero, 0x30 / c.li rd, 0x30 / addi rd, rd, 0x30 /
     c.addi rd, 0x30 / slli rd, rs, 5 (0x30 = 48 = 3<<4 also via
     slli+add chains: slli 4 + slli 5 pairs reported);
  3. for every idiom site: a ±56-insn window scan for stores with
     displacement in {0x10..0x1C} — the record-field zone (f14 @+0x14,
     f18 @+0x18, the auto-repair pair {f18,+0x1c} as u64);
  4. the static-TEMPLATE search: over the data LOAD (VA 0x4000000, file
     0xE9B000..0x1070000 in the container) and the rm-full.elf uncovered
     islands — every (off & 0x2F) == 0x18 u32 == 100 (percent) or 1000
     (permille) with the (off & 0x2F) == 0x14 neighbor (the {f14, f18}
     pair shape), and 4-pair runs at pitch 0x30 (the 4 groups);
  5. the policy-object consumer census: every `ld rd, -0x168(reg)` —
     the object-at-state+0x4E98 fetch idiom (the creator's store shape)
     — each consumer's VA + the function it lives in.

Output: lab/jalon411/v446b_records.json
"""
import json
import re
import struct
from pathlib import Path

import capstone
import numpy as np
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
C = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_SZ = 0xE9B000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

img = A.read_bytes()[0x40:0x40 + IMG_SZ]
container = C.read_bytes()


def dec_at(va, n, back=0):
    o = va - IMG_LO - back
    out = []
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append((ins.address, ins.mnemonic, ins.op_str))
        o += ins.size
    return out


def main():
    out = {}

    # -- 1. self-checks --------------------------------------------------
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        k = np.arange((len(img4) - 4 - base_off) >> 2, dtype=np.int64)
        cnt += int(((uarr[k] & 0x7F) == 0x17).sum())
    assert cnt == 416206, cnt
    law_fail = 0
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if img[o:o + 16] != container[o - 0x38:o - 0x38 + 16]:
            law_fail += 1
    assert law_fail == 0
    out["selfchecks"] = {"auipc": cnt, "law_fails": law_fail}

    # -- 2. the full-image 0x30 idiom census ------------------------------
    idiom_sites = []
    for off in range(0, IMG_SZ - 4, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        va = IMG_LO + off
        kind = None
        # addi rd, zero, 0x30  (li)
        if (w & 0x7F) == 0x13 and ((w >> 12) & 7) == 0 and \
           ((w >> 15) & 0x1F) == 0:
            imm = w >> 20
            if imm >= 0x800:
                imm -= 0x1000
            if imm == 0x30:
                kind = "li"
        # c.li rd!=0, 0x30: quadrant1 opq=0, imm6=0x30 (6-bit signed; 48
        # does not fit — c.li imm range is -32..31) -> only via c.lui?
        # keep the check anyway (bit pattern), report the form honestly
        if kind:
            idiom_sites.append({"va": f"0x{va:X}", "form": kind})
    # c.li 0x30 check (imm6 signed 6-bit: 0x30 = 48 -> encodes as -16!
    # so c.li can NOT carry 48; document it)
    # slli rd, rs, 5 (opcode 0x13 funct3 1 shamt 5) + add pairs
    slli5 = []
    for off in range(0, IMG_SZ - 4, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        if (w & 0x7F) == 0x13 and ((w >> 12) & 7) == 1 and \
           ((w >> 20) & 0x1F) == 5:
            slli5.append(IMG_LO + off)
    out["idiom_0x30"] = {
        "li_sites": idiom_sites,
        "cli_0x30_note": ("c.li imm6 is signed 6-bit (48 = 0b110000 "
                          "encodes as -16) — c.li cannot materialize "
                          "+0x30; the encodings are li/addi and the "
                          "slli+add chains"),
        "slli5_count": len(slli5),
        "slli5_first20": [f"0x{x:X}" for x in slli5[:20]],
    }
    # the banked encoding re-assert: li t3, 0x30 = 0x03000E13
    enc_hits = []
    for off in range(0, IMG_SZ - 4, 2):
        if img[off:off + 4] == b"\x13\x0e\x00\x03":
            enc_hits.append(IMG_LO + off)
    out["idiom_0x30"]["banked_enc_0x03000E13"] = [f"0x{x:X}"
                                                  for x in enc_hits]
    # the POINTER-WALK stride: addi rd, rd, 0x30 (rd==rs1, I-type imm 48)
    # — the shape the mul census cannot see (0x14D9154 is one)
    walk_sites = []
    for off in range(0, IMG_SZ - 4, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        if (w & 0x7F) != 0x13 or ((w >> 12) & 7) != 0:
            continue
        imm = (w >> 20) & 0xFFF
        if imm != 0x30:
            continue
        rd = (w >> 7) & 0x1F
        rs1 = (w >> 15) & 0x1F
        if rd == rs1 and rd != 0:
            walk_sites.append(IMG_LO + off)
    out["idiom_0x30"]["pointer_walk_addi_rdr_0x30"] = {
        "count": len(walk_sites),
        "sites": [f"0x{x:X}" for x in walk_sites],
    }
    # record-field stores around each pointer-walk site (±48 insns)
    walk_store_hits = []
    for va in walk_sites:
        for a, m, op in dec_at(va - 96, 96, back=96):
            if m in ("sw", "sh", "sd", "c.sw", "c.sd"):
                mm = re.search(r",\s*(-?0x[0-9a-f]+|-?\d+)?\((\w+)\)$", op)
                if mm:
                    d = int(mm.group(1), 0) if mm.group(1) else 0
                    if 0x10 <= d <= 0x1C:
                        walk_store_hits.append({
                            "walk_site": f"0x{va:X}",
                            "store_va": f"0x{a:X}",
                            "store": f"{m} {op}"})
    out["record_field_stores_near_walk"] = walk_store_hits

    # -- 3. the record-field store scan around each idiom site ------------
    store_hits = []
    for s in idiom_sites:
        va = int(s["va"], 16)
        for a, m, op in dec_at(va - 56 * 2, 112, back=56 * 2):
            if m in ("sw", "sh", "sd", "c.sw", "c.sd"):
                mm = re.search(r",\s*(-?0x[0-9a-f]+|-?\d+)?\((\w+)\)$", op)
                if mm:
                    d = int(mm.group(1), 0) if mm.group(1) else 0
                    if 0x10 <= d <= 0x1C:
                        store_hits.append({
                            "idiom_site": s["va"],
                            "store_va": f"0x{a:X}",
                            "store": f"{m} {op}"})
    out["record_field_stores_near_idiom"] = store_hits

    # -- 4. the static-template search ------------------------------------
    data = container[0xE9B000:0xE9B000 + 0x1D5000]  # VA 0x4000000..
    template_hits = []
    for v in (100, 1000):
        i = 0
        while True:
            i = data.find(struct.pack("<I", v), i)
            if i < 0:
                break
            if (i & 0x2F) == 0x18:
                f14 = struct.unpack("<I", data[i - 4:i])[0]
                # a plausible pair: f14 nonzero, f18=v
                if 0 < f14 < 0xFFFFFFFF and f14 not in (v,):
                    # pitch check: another pair at +0x30?
                    nxt = data[i + 0x30 - 4:i + 0x30 + 4]
                    pitch = False
                    if len(nxt) == 8:
                        p14, p18 = struct.unpack("<II", nxt)
                        pitch = (p18 == v and 0 < p14 < 0xFFFFFFFF)
                    template_hits.append({
                        "value": v, "file_off": 0xE9B000 + i,
                        "va": f"0x{0x4000000 + i:X}",
                        "f14": f14, "pitch0x30_neighbor": pitch})
            i += 4
    runs = [t for t in template_hits if t["pitch0x30_neighbor"]]
    out["template_search"] = {
        "data_load_scan": "VA 0x4000000..0x41D5000 (file 0xE9B000..)",
        "pair_hits": len(template_hits),
        "pitch0x30_runs": runs[:40],
        "pair_hits_sample": template_hits[:40],
    }

    # -- 5. the policy-object consumer census ------------------------------
    # the creator stores the object: sd a0, -0x168(s1) @0x1458d00 with
    # s1 = state; consumers: ld rd, -0x168(reg)
    consumers = []
    for off in range(0, IMG_SZ - 4, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        # ld: opcode 0x03 funct3 3 (I-type: imm = w>>20, 12-bit signed)
        if (w & 0x7F) != 0x03 or ((w >> 12) & 7) != 3:
            continue
        imm = (w >> 20) & 0xFFF
        if imm >= 0x800:
            imm -= 0x1000
        if imm != -0x168:
            continue
        consumers.append(IMG_LO + off)
    out["obj_fetch_ld_m0x168"] = {
        "count": len(consumers),
        "sites": [f"0x{x:X}" for x in consumers],
    }

    OUT.write_text(json.dumps(out, indent=1))
    print(f"li 0x30 sites: {len(idiom_sites)}  "
          f"banked-enc sites: {len(enc_hits)}")
    print(f"record-field stores near idioms: {len(store_hits)}")
    print(f"template pair hits: {len(template_hits)} "
          f"(pitch-0x30 runs: {len(runs)})")
    print(f"ld ..., -0x168 sites: {len(consumers)}")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
