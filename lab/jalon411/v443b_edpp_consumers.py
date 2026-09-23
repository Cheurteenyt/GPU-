#!/usr/bin/env python3
"""4.43 pass, TÂCHE 2 instrument — the EDPp policy object (0x6d0 at
state+0x4E98): the CONSUMER map (who READS the policy) and the clamp.

4.38a banked the WRITER map (34 WRITE-FIELD uses, all runtime-fed).
The mission's question is the OTHER half: who reads the policy fields
(0x65c/0x660/0x668-0x684) — the enforcement path — plus:
  1. the census reproduction (17/17, the map law);
  2. per-site READ-FIELD / PASS-TO-CALL / WRITE-FIELD uses with the
     copy chain (the 438a trace, all classes kept);
  3. the 0x15fbad6 outlier decoded in full (the only lw consumer 4.20
     flagged);
  4. the worker listener-list (state+0x2050, fn=*(node+0x420)) — the
     notification path of the refresh worker (4.21 §1) — plus the
     creation call window @0x1458cf8 re-decoded;
  5. the assert-string %lo-idiom xref extension (auipc+ld/addi): the
     PMGR assert strings 4.43a found at 0x1E88xxx with 0 addi-xrefs —
     the load-idiom census (the 4.37 trap, closed here for strings).

Self-checks: census 17/17; the coordinate law (512 windows).

Output: lab/jalon411/v443b_edpp_consumers.json
"""
import json
import re
import struct
import zlib
from collections import defaultdict
from pathlib import Path

import numpy as np
import capstone
from capstone import (CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC,
                      CS_OP_REG, CS_OP_MEM)

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
V420 = ROOT / "lab/jalon411/v420_edpp.json"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
            "bltz", "bgez", "blez", "bgtz", "c.beqz", "c.bnez"}
STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp"}
CALLS = {"jal", "jalr", "c.jal", "c.jalr"}
LOADS = {"ld", "lw", "lbu", "lhu", "c.ld", "c.lw"}
COPIES = {"mv", "c.mv", "addi", "c.addi", "add", "c.add", "or", "c.or"}
REGS = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6"]


def rw(ins):
    m = ins.mnemonic
    ops = ins.operands
    regs = [o.reg for o in ops if o.type == CS_OP_REG]
    mems = [o.mem.base for o in ops if o.type == CS_OP_MEM]

    def nm(r):
        try:
            return ins.reg_name(r)
        except Exception:
            return str(r)
    if m in STORES or m in BRANCHES or m == "c.jr":
        return [], [nm(r) for r in regs] + [nm(b) for b in mems]
    if m == "c.jalr":
        return ["ra"], [nm(r) for r in regs]
    if m in ("ret", "c.ret"):
        return [], ["ra"]
    if m in ("j", "c.j", "ecall", "ebreak", "fence", "fence.i", "nop",
             "c.nop", "wfi", "mret", "rdtime"):
        return [], [nm(r) for r in regs] + [nm(b) for b in mems]
    if regs:
        return [nm(regs[0])], [nm(r) for r in regs[1:]] + [nm(b) for b in mems]
    return [], [nm(b) for b in mems]


def regions(covered):
    starts, ends = [], []
    i, n = 0, len(covered)
    while i < n:
        if covered[i]:
            j = i
            while j < n and covered[j]:
                j += 1
            if j - i >= 2:
                starts.append(i)
                ends.append(j)
            i = j
        else:
            i += 1
    return starts, ends


def field_of(op):
    m = re.search(r"(-?0x[0-9a-f]+|-?\d+)\s*\(", op)
    return int(m.group(1), 0) if m else None


def census_page5(img, s0, e0):
    off_pat = "-0x168("
    hits = []
    off = s0
    window = []
    while off < e0:
        try:
            ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
        except StopIteration:
            break
        if off + ins.size > e0:
            break
        m, o = ins.mnemonic, ins.op_str
        if m in ("ld", "lw", "lbu", "sd", "sw", "sb") and off_pat in o:
            rs1 = o.split("(")[1].rstrip(")")
            hit = None
            for i2 in range(len(window) - 1, max(-1, len(window) - 8), -1):
                w = window[i2]
                if w[1] in ("c.add", "add") and w[2].split(", ")[0] == rs1:
                    rd_add = w[2].split(", ")[0]
                    rs_add = w[2].split(", ")[1]
                    for i3 in range(i2 - 1, max(-1, i2 - 4), -1):
                        w3 = window[i3]
                        if w3[1] in ("c.lui", "lui") and re.match(
                                r"^\w+, (0x5|5)$", w3[2]):
                            rd_lui = w3[2].split(", ")[0]
                            if rd_lui == rs_add or (rd_lui == rd_add == rs1):
                                hit = (w3[0], w[0],
                                       "A" if rd_lui == rs_add else "B")
                                break
                    if hit:
                        break
            if hit:
                hits.append({"va": IMG_LO + off, "insn": f"{m} {o}",
                             "reg": o.split(",")[0].strip()})
        window.append((IMG_LO + off, m, o))
        window = window[-8:]
        off += ins.size
    return hits


def trace_object_use(img, walk, idx, oreg, max_insns=160):
    """forward trace with COPY-CHAIN — ALL use classes kept."""
    uses = []
    tracked = {oreg: None}
    for w in walk[idx + 1: idx + 1 + max_insns]:
        wr, rd_ = rw(w["ins"])
        fld = field_of(w["o"]) if "(" in w["o"] and w["m"] not in CALLS \
            else None
        hit_reg = next((r for r in tracked if r in rd_), None)
        if hit_reg is not None:
            if w["m"] in STORES:
                uses.append({"va": hex(w["va"]), "m": w["m"], "o": w["o"],
                             "class": "WRITE-FIELD",
                             "field": fld if fld is not None else "spill",
                             "via": "direct" if hit_reg == oreg
                             else f"copy({hit_reg})",
                             "value_reg": w["o"].split(",")[0].strip()})
            elif w["m"] in LOADS and fld is not None:
                uses.append({"va": hex(w["va"]), "m": w["m"], "o": w["o"],
                             "class": "READ-FIELD",
                             "field": fld,
                             "via": "direct" if hit_reg == oreg
                             else f"copy({hit_reg})"})
            elif w["m"] in CALLS:
                uses.append({"va": hex(w["va"]), "m": w["m"], "o": w["o"],
                             "class": "PASS-TO-CALL"})
        if hit_reg is not None and w["m"] in ("addi", "c.addi", "add",
                                              "c.add"):
            parts = [p.strip() for p in w["o"].split(",")]
            if len(parts) == 3 and parts[0] == hit_reg:
                try:
                    k = int(parts[2], 0)
                except ValueError:
                    k = 0
                tracked[hit_reg] = (tracked[hit_reg] or 0) + k
                continue
        if w["m"] in ("mv", "c.mv"):
            parts = [p.strip() for p in w["o"].split(",")]
            if len(parts) == 2 and parts[1] in tracked:
                tracked[parts[0]] = tracked[parts[1]]
                continue
        for r in list(tracked):
            if r in wr and w["m"] not in STORES and w["m"] not in CALLS:
                if w["m"] not in ("addi", "c.addi", "add", "c.add", "mv",
                                  "c.mv"):
                    del tracked[r]
        if not tracked:
            break
    return uses


def decode_window(img, va, n, back=0):
    out = []
    o = va - IMG_LO - back
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append(f"0x{IMG_LO + o:x}: {ins.mnemonic:<8} {ins.op_str}")
        o += ins.size
    return out


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    starts, ends = regions(covered)

    def enclosing(a_off):
        for s0, e0 in zip(starts, ends):
            if s0 <= a_off < e0:
                return s0, e0
        return None

    out = {}

    # -- the coordinate law
    fails = 0
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    assert fails == 0
    out["law_fails"] = 0

    # -- 1. the census reproduction
    banked = []
    for s0, e0 in zip(starts, ends):
        banked += census_page5(img, s0, e0)
    v420_sites = {s["va"]: s["insn"] for s in json.load(open(V420))["sites"]}
    mine = {hex(h["va"]): h["insn"] for h in banked}
    rep = {"v420_count": len(v420_sites), "this_count": len(mine),
           "missing": sorted(set(v420_sites) - set(mine)),
           "extra": sorted(set(mine) - set(v420_sites))}
    print("census reproduction:", json.dumps(rep))
    assert not rep["missing"], "map law broken"
    out["census_reproduction"] = rep

    # -- 2. the full use-class trace
    results = []
    for h in banked:
        a_off = h["va"] - IMG_LO
        reg = enclosing(a_off)
        if not reg:
            results.append({"va": hex(h["va"]), "insn": h["insn"],
                            "status": "island", "uses": []})
            continue
        s0, e0 = reg
        walk = []
        off = s0
        while off < e0:
            try:
                ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
            except StopIteration:
                break
            if off + ins.size > e0:
                break
            walk.append({"va": IMG_LO + off, "m": ins.mnemonic,
                         "o": ins.op_str, "size": ins.size, "ins": ins})
            off += ins.size
        idx = next((i for i, w in enumerate(walk) if w["va"] == h["va"]),
                   None)
        if idx is None:
            results.append({"va": hex(h["va"]), "error": "walk desync"})
            continue
        uses = trace_object_use(img, walk, idx, h["reg"])
        results.append({"va": hex(h["va"]), "insn": h["insn"],
                        "region": [hex(IMG_LO + s0), hex(IMG_LO + e0)],
                        "uses": uses})
    reads = [u for r in results for u in r.get("uses", [])
             if u["class"] == "READ-FIELD"]
    writes = [u for r in results for u in r.get("uses", [])
              if u["class"] == "WRITE-FIELD"]
    passes = [u for r in results for u in r.get("uses", [])
              if u["class"] == "PASS-TO-CALL"]
    print(f"uses: READ={len(reads)} WRITE={len(writes)} "
          f"PASS={len(passes)}")
    out["traces"] = results

    # -- 3. the 0x15fbad6 outlier, full window
    out["outlier_15fbad6"] = {
        "window_before": decode_window(img, 0x15fbad6, 24, back=24 * 4),
        "window_after": decode_window(img, 0x15fbad6, 40)}

    # -- 4. the creation window @0x1458cf8 and the worker listener tail
    out["creation_window_1458cf8"] = decode_window(img, 0x1458cf8, 32,
                                                   back=64)
    out["worker_tail_14400c6"] = decode_window(img, 0x1440180, 48)

    # -- 5. the assert-string %lo-idiom xref (auipc + ld/sd/lbu/lhu/addi)
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    u0 = np.frombuffer(img4, dtype="<u4")
    u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    bases = []
    for base_off, uarr in ((0, u0), (2, u2)):
        kmax = (len(img4) - 4 - base_off) >> 2
        k = np.arange(kmax, dtype=np.int64)
        mask = (uarr[k] & 0x7F) == 0x17
        kk = k[mask]
        w = uarr[kk]
        rd = ((w >> 7) & 0x1F).astype(np.int64)
        hi20 = (w >> 12).astype(np.int64)
        hi20[hi20 >= 0x80000] -= 0x100000
        aoff = (kk << 2) + base_off
        pc = IMG_LO + aoff + 0x38
        base = pc + (hi20 << 12)
        bases.append(np.stack([base, aoff.astype(np.int64), rd], axis=1))
    Bm = np.concatenate(bases)
    order = np.argsort(Bm[:, 0])
    Bs = Bm[order]

    LOAD_OPCS = {0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B}

    def idiom_xrefs(target_va):
        """auipc rd + NEXT-or-gap<=8 insn using rd as base/dest with the
        exact lo12 — covers the ld/sd/lbu/lhu-on-the-load idiom."""
        lo_win = np.searchsorted(Bs[:, 0], target_va - 0x7FF, side="left")
        hi_win = np.searchsorted(Bs[:, 0], target_va + 0x800, side="left")
        hits = []
        for row in Bs[lo_win:hi_win]:
            base, aoff, rd = int(row[0]), int(row[1]), int(row[2])
            lo_need = target_va - base
            if not (-2048 <= lo_need <= 2047):
                continue
            for d in (4, 8, 12, 16):
                if aoff + d + 4 > len(img):
                    break
                w2 = int.from_bytes(img[aoff + d:aoff + d + 4], "little")
                if (w2 & 0x7F) not in LOAD_OPCS:
                    continue
                if ((w2 >> 15) & 0x1F) != rd:
                    continue
                imm = (w2 >> 20) & 0xFFF
                if imm >= 0x800:
                    imm -= 0x1000
                if imm == lo_need:
                    # decode the consumer insn
                    ins = next(md.disasm(img[aoff + d:aoff + d + 4],
                                         IMG_LO + aoff + d), None)
                    hits.append({"auipc_va": hex(IMG_LO + aoff),
                                 "use_va": hex(IMG_LO + aoff + d),
                                 "rd": REGS[rd],
                                 "use": f"{ins.mnemonic} {ins.op_str}"
                                 if ins else "?"})
                    break
        return hits

    targets = {
        "PstateEstLUT_assert": 0x1E88030,
        "OutputVoltage1x_assert": 0x1E880A0,
        "PwrChannelPolicy_assert": 0x1E87F10,
        "PwrDevIdx_assert": 0x1E88100,
        "TgpIface_fb_assert": 0x1E88238,
        "TgpIface_core_assert": 0x1E882D0,
        "Die2x_assert": 0x1E886A0,
        "tgtPwrPolicy_assert": 0x1E88908,
        "floorPolicy_assert": 0x1E889A0,
        "ceilingPolicy_assert": 0x1E889F0,
        "RMDisableSpi": 0x1E88E28,
        "RMLpwrVbiosSwTable": 0x1E87410,
        "RMI2cPmgrMutexTimeoutus": 0x1E87E48,
    }
    idioms = {}
    for name, tva in targets.items():
        # the stored VA may be the string start; the census VAs are
        # container-universe — same universe as Bs (both +0x38)
        xs = idiom_xrefs(tva)
        idioms[name] = xs
        print(f"[idiom] {name}: {len(xs)} xrefs")
        for x in xs[:4]:
            print("   ", x["auipc_va"], x["use_va"], x["use"])
    out["assert_idiom_xrefs"] = idioms

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
