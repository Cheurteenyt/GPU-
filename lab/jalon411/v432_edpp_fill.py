#!/usr/bin/env python3
"""4.32 pass, instrument 3 (T3) — the EDPp policy object (0x6d0 B,
pointer at state+0x4E98): WHO fills it and WHERE the values come from.

The mission's question: the fill sites (the 17 accesses of pass 4.20,
the 0x144xxxx cluster) read their values from where — the stack, the
RPC (the argument), the static tables? If the policy is built from
RECEIVED data, the injection point is the transport; if from firmware
constants, the rm.elf patch is the way.

Method:
  1. re-derive the v420 census on this substrate (assert 17/17 equality
     with v420_edpp.json — the map law is proven, so this must hold);
  2. for each census site: the enclosing covered region, the object
     register, a bounded forward trace (region-bounded, <=120 insns):
     every USE of the object pointer — field reads, field WRITES
     (offset + value register), passes to calls;
  3. for every WRITE: the value register's source class decided by a
     backward look: CALL-RESULT (a jalr/jalr within 8 insns),
     FIELD-COPY (a load from another object/state field),
     CONSTANT (lui/auipc formation), ARG (a0-a7 with no def seen),
     UNKNOWN (honest);
  4. the three named anchors decoded in full windows: the GET handler
     (0x1458bec — the 0x6d0 memset), the recomputation worker
     (0x14400c6 — the 0x2080A080 call + the +0x660 store), the UPDATE
     stub (0x1862480 — the claimed c.jr ra).

Output: lab/jalon411/v432_edpp_fill.json
"""
import json
import re
import struct
import zlib
from pathlib import Path

import capstone
from capstone import (CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC,
                      CS_OP_REG, CS_OP_MEM)

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
V420 = ROOT / "lab/jalon411/v420_edpp.json"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
SHIFT = 0x38
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
            "bltz", "bgez", "blez", "bgtz", "c.beqz", "c.bnez"}
STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp"}
CALLS = {"jal", "jalr", "c.jal", "c.jalr"}


def rw_regs(ins):
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
        return [], [nm(r) for r in regs]
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


def walk_region(img, s0, e0):
    walk = []
    off = s0
    while off < e0:
        try:
            ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
        except StopIteration:
            break
        if off + ins.size > e0:
            break
        walk.append({"va": IMG_LO + off, "m": ins.mnemonic, "o": ins.op_str,
                     "size": ins.size, "ins": ins})
        off += ins.size
    return walk


def field_of(op):
    m = re.search(r"(-?0x[0-9a-f]+|-?\d+)\s*\(", op)
    return int(m.group(1), 0) if m else None


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

    # ---- 1. re-derive the census (v420 law, this substrate) ---------------
    off_pat = "-0x168("
    census = []
    for s0, e0 in zip(starts, ends):
        window = []
        off = s0
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
                            if w3[1] in ("c.lui", "lui") and re.match(r"^\w+, (0x5|5)$", w3[2]):
                                rd_lui = w3[2].split(", ")[0]
                                if rd_lui == rs_add or (rd_lui == rd_add == rs1):
                                    hit = (w3[0], w[0],
                                           "A" if rd_lui == rs_add else "B")
                                    break
                        if hit:
                            break
                if hit:
                    census.append({"va": hex(IMG_LO + off), "insn": f"{m} {o}",
                                   "region": [hex(IMG_LO + s0), hex(IMG_LO + e0)],
                                   "reg": o.split(",")[0].strip()})
            window.append((IMG_LO + off, m, o))
            window = window[-8:]
            off += ins.size

    v420_sites = {s["va"]: s["insn"] for s in json.load(open(V420))["sites"]}
    mine = {s["va"]: s["insn"] for s in census}
    reproduce = {"v420_count": len(v420_sites), "this_count": len(mine),
                 "missing": sorted(set(v420_sites) - set(mine)),
                 "extra": sorted(set(mine) - set(v420_sites)),
                 "insn_mismatch": {k: (v420_sites[k], mine.get(k))
                                   for k in sorted(set(v420_sites) & set(mine))
                                   if v420_sites[k] != mine.get(k)}}
    print("census reproduction:", json.dumps(reproduce))

    def classify_value(walk, w, vreg):
        """backward look (<=8 insns) for the value register's def."""
        i = next(i for i, x in enumerate(walk) if x["va"] == w["va"])
        for back in range(1, 9):
            if i - back < 0:
                break
            p = walk[i - back]
            if p["m"] in ("jal", "jalr", "c.jal", "c.jalr"):
                return "CALL-RESULT"
            wr, rd_ = rw_regs(p["ins"])
            if vreg in wr:
                if p["m"] in ("ld", "lw", "c.ld", "c.lw", "lbu", "lhu"):
                    return "FIELD-COPY(mem)"
                if p["m"] in ("lui", "auipc", "c.lui", "addi", "c.addi"):
                    return "CONSTANT-FORM"
                return f"DEF({p['m']})"
        return "ARG/UNKNOWN"

    # ---- 2+3. per-site use trace ------------------------------------------
    results = []
    for c in census:
        va = int(c["va"], 16)
        a_off = va - IMG_LO
        reg = enclosing(a_off)
        if not reg:
            results.append({"va": c["va"], "error": "no region"})
            continue
        s0, e0 = reg
        walk = walk_region(img, s0, e0)
        idx = next((i for i, w in enumerate(walk) if w["va"] == va), None)
        if idx is None:
            results.append({"va": c["va"], "error": "walk desync"})
            continue
        oreg = c["reg"]
        uses = []
        cur = oreg
        for w in walk[idx + 1: idx + 121]:
            wr, rd_ = rw_regs(w["ins"])
            fld = field_of(w["o"]) if "(" in w["o"] and w["m"] not in ("jalr", "c.jalr") else None
            if cur in rd_:
                use = {"va": hex(w["va"]), "m": w["m"], "o": w["o"]}
                if w["m"] in STORES and fld is not None:
                    # write through the object: value register = first reg op
                    vreg = w["o"].split(",")[0].strip()
                    use["class"] = "WRITE-FIELD"
                    use["field"] = fld
                    use["value_reg"] = vreg
                    use["value_source"] = classify_value(walk, w, vreg)
                elif w["m"] in STORES:
                    use["class"] = "ADDR-ARITH/STORE-BASE"
                elif w["m"] in CALLS:
                    use["class"] = "PASS-TO-CALL"
                elif "(" in w["o"]:
                    use["class"] = "READ-FIELD"
                    use["field"] = fld
                else:
                    use["class"] = "ARITH/OTHER"
                uses.append(use)
            if cur in wr and w["m"] not in STORES and w["m"] not in CALLS:
                cur = None
            if cur is None:
                break
        results.append({"va": c["va"], "insn": c["insn"], "region": c["region"],
                        "uses": uses})

    # ---- 4. the three anchors ---------------------------------------------
    anchors = {}
    for name, va, n_ins in [("GET_handler", 0x1458BEC, 70),
                            ("worker", 0x14400C6, 90),
                            ("UPDATE_stub", 0x1862480, 6)]:
        a_off = va - IMG_LO
        reg = enclosing(a_off)
        o = a_off
        w = []
        for _ in range(n_ins):
            try:
                ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
            except StopIteration:
                break
            w.append({"va": hex(IMG_LO + o), "m": ins.mnemonic, "o": ins.op_str})
            o += ins.size
        anchors[name] = {"region": [hex(IMG_LO + reg[0]), hex(IMG_LO + reg[1])] if reg else None,
                         "window": w}
        print(f"--- {name} ({hex(va)}):")
        for x in w[:40]:
            print(f"    {x['va']}: {x['m']:<8} {x['o']}")

    out = {
        "census_reproduction": reproduce,
        "sites": results,
        "anchors": anchors,
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
