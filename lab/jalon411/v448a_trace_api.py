#!/usr/bin/env python3
"""4.48 TASK A — the trace/step API @0x1a9e624 decoded, the callers census,
the TLS object map.

The 4.47 pass banked two "lookup-by-name knob" windows (RmClkMclkProg,
RML2MaxWaysSysmem) whose xref sites BOTH call 0x1a9e624. Before any knob
story is told, the API itself must be decoded: what does it do with
(a0, a1=name, a2, a3, ...)?

This instrument:
  1. decodes the FULL body of the function @0x1a9e624 (bounds proven:
     prologue -> c.jr ra), with ALL branch targets resolved (the RVC
     c.beqz/c.bnez/c.j bit surgery done manually and cross-checked
     against capstone's printed offset);
  2. censuses EVERY caller of 0x1a9e624 image-wide (auipc ra + jalr
     ra,ra,imm pairs, signed imm20 — the 4.42 lesson): per caller, the
     a0 class tag (back-walk), the a1 pointer (auipc+addi resolution ->
     the interned string when file-backed, OPAQUE when in the
     0x20000000 region), and the pushed-arg count (a0+1);
  3. maps the TLS object: for every `lui rd,0 + add rd,rd,tp` pair
     (154 banked by the probe), the ret-bounded function walk collects
     every `imm(rd)` base access and `addi x,rd,imm` derivation — the
     offset histogram, and the explicit list of functions touching the
     ring-header window (+0x80..+0xa0).

Selftests: the auipc census 416,206; the law 512/512; the API bounds
(prologue/jr bytes); the RVC branch decoder vs capstone on the body.

Output: lab/jalon411/v448a_trace_api.json
"""
import json
import re
import struct
import zlib
from collections import Counter
from pathlib import Path

import capstone
import numpy as np
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_LEN = 0xE9B000
API_VA = 0x1A9E624
OPQ_LO, OPQ_HI = 0x2000000C, 0x203C5AEF  # the 4.46 opaque rodata region

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

REG = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
       "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
       "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
       "t3", "t4", "t5", "t6"]


def dec_at(img, off):
    """Decode one insn at img offset; returns (mnemonic, op_str, size)."""
    if img[off] & 3 == 3:
        ins = next(md.disasm(img[off:off + 4], off), None)
        return (ins.mnemonic, ins.op_str, 4) if ins else (None, None, 0)
    ins = next(md.disasm(img[off:off + 2], off), None)
    return (ins.mnemonic, ins.op_str, 2) if ins else (None, None, 0)


# ---------------------------------------------------------------- RVC B-imm
def rvc_branch_imm(hw):
    """c.beqz/c.bnez (funct3 110/111) and c.j/c.jal (110/101) signed
    byte offset, from the 16-bit halfword. Returns None if not those."""
    op = hw & 3
    f3 = (hw >> 13) & 7
    if op == 1 and f3 in (6, 7):          # c.beqz / c.bnez (CB)
        imm8 = (hw >> 12) & 1
        imm43 = (hw >> 10) & 3
        imm76 = (hw >> 5) & 3
        imm21 = (hw >> 3) & 3
        imm5 = (hw >> 2) & 1              # imm[5] lives at hw[2] — the
        val = ((imm8 << 8) | (imm43 << 3) | (imm76 << 6) | (imm21 << 1) |
               (imm5 << 5))               # bit the first pass dropped
        if val & 0x100:
            val -= 0x200
        return val
    if op == 1 and f3 == 5:               # c.j / c.jal
        t = (hw >> 12) & 1                 # imm[11]
        i2 = (hw >> 11) & 1                # imm[4]
        i3 = (hw >> 10) & 1                # imm[3]? -> layout below
        # RVC c.j immediate: [11|4|9:8|10|6|7|3:1|5] bits scrambled:
        imm11 = (hw >> 12) & 1
        imm4 = (hw >> 11) & 1
        imm98 = (hw >> 9) & 3
        imm10 = (hw >> 8) & 1
        imm6 = (hw >> 7) & 1
        imm7 = (hw >> 6) & 1
        imm31 = (hw >> 3) & 7
        imm5 = (hw >> 2) & 1
        val = ((imm11 << 11) | (imm4 << 4) | (imm98 << 8) | (imm10 << 10) |
               (imm6 << 6) | (imm7 << 7) | (imm31 << 1) | (imm5 << 5))
        if val & 0x800:
            val -= 0x1000
        return val
    return None


def insn_bytes(img, off):
    return (img[off] & 3 == 3) and 4 or 2


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    img = da[0x40:0x40 + IMG_LEN]
    blob = zlib.decompress(MAP.read_bytes())
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        assert img[o:o + 16] == db[o - 0x38:o - 0x38 + 16]

    # banked auipc census (byte-level, both alignments)
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        cnt += int((uarr & 0x7F == 0x17).sum())
    assert cnt == 416206, f"auipc census {cnt} != 416206"

    out = {"pass": "4.48", "task": "A", "instrument": "v448a_trace_api",
           "baseline": {"auipc": cnt, "law": "512/512"}}

    # -- 1. the API body ---------------------------------------------------
    b0 = API_VA - IMG_LO
    m0, o0, s0_ = dec_at(img, b0)
    assert m0 == "c.addi16sp" and "-0x60" in o0, (m0, o0)
    # the true end = the NEXT function's prologue: c.addi16sp sp,-0x20
    # @0x1a9e6f0 (the fast-path return c.jr ra @0x1a9e6c2 is a MID-function
    # return; the cold tail 0x1a9e6c4..0x1a9e6ee belongs to this function)
    end_off = 0x1A9E6F0 - IMG_LO
    m1, o1, _ = dec_at(img, end_off)
    # capstone prints c.addi16sp as 'c.addi sp, -0x20' on this build
    assert (m1 in ("c.addi16sp", "c.addi")) and "sp, -0x20" in o1, (m1, o1)
    api_len = end_off - b0
    out["api"] = {"va": hex(API_VA), "bytes": api_len,
                  "end_va": hex(IMG_LO + end_off),
                  "fastpath_return": hex(0x1A9E6C2),
                  "cold_tail": [hex(0x1A9E6C4), hex(0x1A9E6EE)],
                  "semantics": {
                      "kind": "per-task event/step push (NOT a knob setter)",
                      "ring": {"count": "tp+TLS+0x88", "cap": "tp+TLS+0x90",
                               "base": "tp+TLS+0x98", "flag": "tp+TLS+0xA0",
                               "wrap": "count -> 1 at cap (never 0)",
                               "slot_size": 8},
                      "push": "N = a0+1 words: raw args for i < a0-1; "
                              "packed = ((arg[a0-1] - 0x20000038) & 0xFFFF) "
                              "| flag<<56 | N<<48 at i = a0-1; rdtime "
                              "(1 ns, proven 4.34) at i = a0",
                      "counter": "[base] += N after the loop",
                      "uninit": "count==0 or base==0 -> return (no push)",
                      "pack_base": "0x20000038 (the 4.46 opaque rodata "
                                   "region: ids = low16 offsets from it)",
                  }}

    body = []
    o = b0
    branch_cross = []
    while o < end_off:
        hw = struct.unpack_from("<H", img, o)[0]
        m, op, sz = dec_at(img, o)
        e = {"va": hex(IMG_LO + o), "m": m, "op": op}
        # manual branch resolution for c.beqz/c.bnez/c.j
        if (hw & 3) == 1 and ((hw >> 13) & 7) in (5, 6, 7):
            man = rvc_branch_imm(hw)
            e["manual_target"] = hex(IMG_LO + o + man) if man is not None else None
            branch_cross.append((hex(IMG_LO + o), m, op, e["manual_target"]))
        body.append(e)
        o += sz
    out["api"]["body"] = body
    out["api"]["branch_crosscheck"] = branch_cross

    # -- 2. the callers census --------------------------------------------
    callers = []
    # auipc ra = (imm20<<12)|(1<<7)|0x17 — scan BOTH 2-byte alignments
    # (compressed code: the auipc sits at 2-mod-4 too)
    cands = []
    for base in (0, 2):
        sub = img[base:(len(img) - base) & ~3 + base]
        sub = sub[:len(sub) - (len(sub) % 4)]
        u32 = np.frombuffer(sub, dtype="<u4")
        idx = np.nonzero((u32 & 0x7F) == 0x17)[0]
        for k in idx:
            u = int(u32[k])
            if ((u >> 7) & 31) != 1:
                continue  # rd != ra
            cands.append((base + int(k) * 4, u))
    for va, u in cands:
        # the next insn must be jalr ra, ra, imm (any 4-byte)
        if va + 8 > len(img):
            continue
        u2 = struct.unpack_from("<I", img, va + 4)[0]
        if (u2 & 0x7F) != 0x67:
            continue
        # jalr fields: rd[11:7] ra; funct3[14:12]=0; rs1[19:15] = ra
        if ((u2 >> 7) & 31) != 1 or ((u2 >> 12) & 7) != 0 or \
           ((u2 >> 15) & 31) != 1:
            continue
        imm12 = (u2 >> 20) & 0xFFF
        if imm12 & 0x800:
            imm12 -= 0x1000
        auipc_va = IMG_LO + va
        imm20 = (u >> 12) & 0xFFFFF
        if imm20 & 0x80000:
            imm20 -= 0x100000
        target = auipc_va + (imm20 << 12) + imm12
        if target != API_VA:
            continue
        # back-walk: find the a0 tag and the a1 pointer (<= 14 insns back)
        tag = None
        a1 = None
        a1_reg = None
        a2_src = None
        o = va
        steps = 0
        while o > 0 and steps < 14:
            szp = insn_bytes(img, o - 4 if img[o - 4] & 3 == 3 else o - 2)
            po = o - szp
            m, op, sz = dec_at(img, po)
            steps += 1
            if m in ("c.li", "li", "addi", "c.addi", "addiw") and \
                    op.startswith("a0,"):
                mm = re.match(r"a0, (-?0x[0-9a-f]+|-?\d+)$", op)
                if mm:
                    v = mm.group(1)
                    try:
                        tag = int(v, 16) if v.startswith(("0x", "-0x")) \
                            else int(v)
                    except ValueError:
                        pass
                    else:
                        break
            o = po
        # a1: scan back for auipc a1 + addi a1 (the PIC pointer idiom)
        o = va
        steps = 0
        while o > 0 and steps < 14:
            szp = insn_bytes(img, o - 4 if img[o - 4] & 3 == 3 else o - 2)
            po = o - szp
            u = struct.unpack_from("<I", img, po)[0] if img[po] & 3 == 3 else None
            if u is not None and (u & 0x7F) == 0x17 and ((u >> 7) & 31) == 11:
                # auipc a1; the following addi a1 completes it
                u3 = struct.unpack_from("<I", img, po + 4)[0]
                if (u3 & 0x7F) == 0x13 and ((u3 >> 7) & 31) == 11 and \
                   ((u3 >> 15) & 31) == 11:
                    i20 = (u >> 12) & 0xFFFFF
                    if i20 & 0x80000:
                        i20 -= 0x100000
                    i12 = (u3 >> 20) & 0xFFF
                    if i12 & 0x800:
                        i12 -= 0x1000
                    a1 = hex(IMG_LO + po + (i20 << 12) + i12)
                    break
            steps += 1
            o = po
        # a2 provenance: the insn right before the call block that writes a2
        o = va
        steps = 0
        while o > 0 and steps < 10:
            szp = insn_bytes(img, o - 4 if img[o - 4] & 3 == 3 else o - 2)
            po = o - szp
            m, op, sz = dec_at(img, po)
            if m and (op.startswith("a2,") or op.startswith("a3,")):
                a2_src = f"{m} {op}"
                break
            steps += 1
            o = po
        # resolve a1 -> the string if file-backed
        name = None
        if a1:
            v = int(a1, 16)
            if OPQ_LO <= v <= OPQ_HI:
                name = "OPAQUE-REGION"
            elif IMG_LO <= v < IMG_LO + len(img):
                fo = v - IMG_LO
                endx = img.find(b"\x00", fo, fo + 96)
                if endx > 0:
                    s = img[fo:endx]
                    if all(0x20 <= c < 0x7F for c in s) and len(s) >= 3:
                        name = s.decode("ascii")
                    else:
                        name = f"<non-string {len(s)}B>"
        callers.append({
            "site": hex(auipc_va), "tag_a0": tag,
            "push_count": (tag + 1) if tag is not None else None,
            "a1": a1, "a1_name": name, "a2_src": a2_src,
        })
    out["callers"] = callers
    tags = Counter(str(c["tag_a0"]) for c in callers)
    names = Counter(c["a1_name"] for c in callers if c["a1_name"])
    out["caller_summary"] = {
        "total": len(callers),
        "tags": dict(tags),
        "resolved_names": dict(names),
    }
    print(f"[callers] {len(callers)} sites calling {API_VA:#x}")
    for c in callers:
        print(f"  @{c['site']} a0={c['tag_a0']} push={c['push_count']} "
              f"a1={c['a1']} name={c['a1_name']} a2<={c['a2_src']}")

    # -- 3. the TLS map ----------------------------------------------------
    pairs = []
    for rd in range(32):
        pat = struct.pack("<I", (rd << 7) | 0x37) + \
              struct.pack("<I", (4 << 20) | (rd << 15) | (rd << 7) | 0x33)
        start = 0
        while True:
            i = img.find(pat, start)
            if i < 0:
                break
            pairs.append((i, rd))
            start = i + 4
    hist = Counter()
    ring_sites = []
    fn_of_ring = []
    for (i, rd) in pairs:
        rn = REG[rd]
        # ret-bounded walk from the pair
        off = i + 8
        end = off
        for _ in range(2000):
            if off + 2 > len(img):
                break
            hw = struct.unpack_from("<H", img, off)[0]
            if hw == 0x8082 or struct.unpack_from("<I", img, off)[0] == 0x8067:
                end = off
                break
            off += insn_bytes(img, off)
        else:
            end = min(i + 8 + 4000, len(img))
        # collect every imm(rn) base + addi x, rn, imm in [i, end]
        off = i
        derived = set()
        while off < end:
            m, op, sz = dec_at(img, off)
            if m is None:
                break
            mm = re.search(rf"(-?0x[0-9a-f]+)\({rn}\)", op or "")
            if mm:
                v = int(mm.group(1), 16) if mm.group(1).startswith("0x") \
                    else -int(mm.group(1)[3:], 16)
                hist[v] += 1
                if 0x80 <= v <= 0xA0:
                    ring_sites.append(
                        {"pair": hex(IMG_LO + i), "site": hex(IMG_LO + off),
                         "insn": f"{m} {op}", "off": hex(v)})
            mm2 = re.match(rf"(\w+), {rn}, (-?0x[0-9a-f]+)$", op or "")
            if mm2 and m in ("addi", "c.addi", "addiw"):
                dv = int(mm2.group(2), 16) if mm2.group(2).startswith("0x") \
                    else -int(mm2.group(2)[3:], 16)
                hist[dv] += 1
                if 0x80 <= dv <= 0xA0:
                    ring_sites.append(
                        {"pair": hex(IMG_LO + i), "site": hex(IMG_LO + off),
                         "insn": f"{m} {op}", "off": hex(dv)})
                derived.add(mm2.group(1))
            # accesses through a derived register also count (one hop)
            for dr in derived:
                mmd = re.search(rf"(-?0x[0-9a-f]+)\({dr}\)", op or "")
                if mmd:
                    v = int(mmd.group(1), 16) if mmd.group(1).startswith("0x") \
                        else -int(mmd.group(1)[3:], 16)
                    hist[v] += 1
                    if 0x80 <= v <= 0xA0:
                        ring_sites.append(
                            {"pair": hex(IMG_LO + i), "site": hex(IMG_LO + off),
                             "insn": f"{m} {op}", "off": hex(v)})
            off += sz
    out["tls_map"] = {
        "pairs": len(pairs),
        "offset_histogram": {hex(k) if k >= 0 else f"-{hex(-k)}": v
                             for k, v in hist.most_common(40)},
        "ring_window_sites": ring_sites,
    }
    # dedupe the ring sites (same insn matched via two paths)
    seen = set()
    uniq = []
    for s in ring_sites:
        key = (s["site"], s["insn"])
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    out["tls_map"]["ring_window_sites"] = uniq
    print(f"[tls] pairs={len(pairs)} ring-window sites={len(uniq)}")
    for s in uniq[:20]:
        print("  ", s)

    # the selftest: RVC decoder vs capstone on the body branches
    ok = 0
    for (va, m, cap_op, man) in branch_cross:
        cap_imm = cap_op.rsplit(",", 1)[-1].strip()
        if cap_imm.startswith("-0x"):
            cv = -int(cap_imm[3:], 16)
        elif cap_imm.startswith("0x"):
            cv = int(cap_imm, 16)
        else:
            cv = int(cap_imm)
        target = int(va, 16) + cv
        if man is not None and int(man, 16) == target:
            ok += 1
    out["selftests"] = {
        "auipc_416206": True,
        "law_512": "PASS",
        "api_bounds": "PASS",
        "rvc_branch_crosscheck": f"{ok}/{len(branch_cross)}",
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
