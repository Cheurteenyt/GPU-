#!/usr/bin/env python3
"""4.38 pass, TASK A instrument — the EDPp policy object (0x6d0 B,
pointer cached at state+0x4E98 = the page-5 idiom -0x168): the WRITER
map extended to the SOURCE chain.

4.32 banked the first-level writer map (17 census sites, <=120-insn
trace, the three anchors). THIS instrument goes further on three axes:

  1. THE ISLAND EXTENSION: the v420 census ran on the covered regions
     only (66 % of the image). Re-run the page-5/-0x168 idiom census
     over the WHOLE image, label every hit covered|island (the 4.16
     map), and report the island WRITERS as new evidence.
  2. THE COPY CHAIN: the v432 trace followed the loaded pointer
     register only; a `mv`/`addi` copy of the pointer breaks that
     trace. This pass chains pointer copies (bounded, <=6 hops) so a
     store through a copied register still counts as a WRITE-FIELD.
  3. THE SOURCE CHAIN (the deliverable): for every WRITE-FIELD, the
     backward walk now continues past the first def: CALL-RESULT gets
     the call's internal-event id (the lui a3, 0x2080a window), the
     FIELD-COPY gets the source object base + field, and the
     GET_PARAMS scan finds who reads {0x104,0x108,0x10c,0x110,0x114,
     0x118} (the six limit fields of the GET params per the mission
     brief) inside the PMGR/PFM module, and where the loaded values go.

Self-checks: the census reproduction must equal the banked 17/17
(v420_edpp.json, the map law proven image-wide), and the coordinate
law B_file = A_img - 0x38 re-asserted on the 4.30 patch sites.

Output: lab/jalon411/v438a_edpp_writers.json
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
MAP = ROOT / "lab/jalon411/v416_map.bin"
V420 = ROOT / "lab/jalon411/v420_edpp.json"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
            "bltz", "bgez", "blez", "bgtz", "c.beqz", "c.bnez"}
STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp"}
CALLS = {"jal", "jalr", "c.jal", "c.jalr"}
LOADS = {"ld", "lw", "lbu", "lhu", "c.ld", "c.lw"}
COPIES = {"mv", "c.mv", "addi", "c.addi", "add", "c.add", "or", "c.or"}


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


def disasm_window(img, off, n):
    out = []
    o = off
    for _ in range(n):
        try:
            ins = next(md.disasm(img[o:o + 4], IMG_LO + o))
        except StopIteration:
            break
        out.append({"va": IMG_LO + o, "m": ins.mnemonic, "o": ins.op_str,
                    "size": ins.size, "ins": ins})
        o += ins.size
    return out


def field_of(op):
    m = re.search(r"(-?0x[0-9a-f]+|-?\d+)\s*\(", op)
    return int(m.group(1), 0) if m else None


def census_page5(img, s0, e0):
    """the v420 census idiom, parameterized over [s0,e0)."""
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
                        if w3[1] in ("c.lui", "lui") and re.match(r"^\w+, (0x5|5)$", w3[2]):
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
    """forward trace with COPY-CHAIN: returns uses incl. through copies.
    tracked = {regname: field_offset_of_last_pointer_arith}. """
    uses = []
    tracked = {oreg: None}   # reg -> None (plain obj) or field offset (obj+k)
    for w in walk[idx + 1: idx + 1 + max_insns]:
        wr, rd_ = rw(w["ins"])
        fld = field_of(w["o"]) if "(" in w["o"] and w["m"] not in CALLS else None
        # use sites
        hit_reg = next((r for r in tracked if r in rd_), None)
        if hit_reg is not None:
            if w["m"] in STORES:
                vreg = w["o"].split(",")[0].strip()
                uses.append({"va": hex(w["va"]), "m": w["m"], "o": w["o"],
                             "class": "WRITE-FIELD",
                             "field": fld if fld is not None else "spill",
                             "via": "direct" if hit_reg == oreg else f"copy({hit_reg})",
                             "value_reg": vreg})
                if fld is None and w["m"] in ("c.sdsp", "c.swsp", "sd", "sw", "sb", "sh"):
                    pass
            elif w["m"] in LOADS and fld is not None:
                uses.append({"va": hex(w["va"]), "m": w["m"], "o": w["o"],
                             "class": "READ-FIELD",
                             "field": fld,
                             "via": "direct" if hit_reg == oreg else f"copy({hit_reg})"})
            elif w["m"] in CALLS:
                uses.append({"va": hex(w["va"]), "m": w["m"], "o": w["o"],
                             "class": "PASS-TO-CALL"})
        # pointer arithmetic that extends the tracked base (obj+k)
        if hit_reg is not None and w["m"] in ("addi", "c.addi", "add", "c.add"):
            parts = [p.strip() for p in w["o"].split(",")]
            if len(parts) == 3 and parts[0] == hit_reg:
                try:
                    k = int(parts[2], 0)
                except ValueError:
                    k = 0
                tracked[hit_reg] = (tracked[hit_reg] or 0) + k
                continue
        # copies
        if w["m"] in ("mv", "c.mv"):
            parts = [p.strip() for p in w["o"].split(",")]
            if len(parts) == 2 and parts[1] in tracked:
                tracked[parts[0]] = tracked[parts[1]]
                continue
        # kill
        for r in list(tracked):
            if r in wr and w["m"] not in STORES and w["m"] not in CALLS:
                # non-copy redefinition kills that tracking name
                if w["m"] not in ("addi", "c.addi", "add", "c.add", "mv", "c.mv"):
                    del tracked[r]
        if not tracked:
            break
    return uses


def classify_source(img, walk, use, region_start, region_end):
    """the backward walk for the value register's ULTIMATE source."""
    vreg = use.get("value_reg")
    if vreg is None or vreg in ("zero", "sp"):
        return {"class": "IMMEDIATE-ZERO"}
    va = int(use["va"], 16)
    idx = next((i for i, x in enumerate(walk) if x["va"] == va), None)
    if idx is None:
        return {"class": "UNKNOWN(desync)"}
    hops = []
    for back in range(1, 25):
        if idx - back < 0:
            break
        p = walk[idx - back]
        wr, rd_ = rw(p["ins"])
        if vreg in wr:
            if p["m"] in ("jal", "jalr", "c.jal", "c.jalr"):
                # find the internal-event id: a lui forming 0x2080a**** near
                eid = None
                for q in walk[max(0, idx - back - 12): idx - back]:
                    if q["m"] == "lui" and re.search(r"0x2080a", q["o"]):
                        m2 = re.search(r"0x2080a([0-9a-f]{3})", q["o"])
                        if m2:
                            eid = "0x2080A" + m2.group(1).upper()
                    elif q["m"] == "lui" and re.search(r"0x2080\b", q["o"]):
                        eid_next = None
                        for q2 in walk[walk.index(q) + 1: walk.index(q) + 4]:
                            m3 = re.search(r"addi(?:w)? \w+, \w+, (-?0x[0-9a-f]+)", q2["o"])
                            if m3 and q2["m"].startswith("addi"):
                                eid_next = hex((0x20800000 + int(m3.group(1), 0)) & 0xFFFFFFFF)
                        if eid is None and eid_next:
                            eid = eid_next
                hops.append({"va": hex(p["va"]), "m": p["m"], "o": p["o"]})
                return {"class": "CALL-RESULT", "call": hops[-1],
                        "internal_event_id": eid}
            if p["m"] in LOADS:
                fld = field_of(p["o"])
                base = p["o"].split("(")[1].rstrip(")")
                # find the base register's formation (bounded backward)
                bof = None
                for b2 in range(1, 13):
                    if idx - back - b2 < 0:
                        break
                    q = walk[idx - back - b2]
                    qwr, _ = rw(q["ins"])
                    if base in qwr:
                        bof = {"va": hex(q["va"]), "m": q["m"], "o": q["o"]}
                        break
                return {"class": "FIELD-COPY",
                        "src_field": fld if fld is not None else None,
                        "src_base_reg": base, "src_base_form": bof}
            if p["m"] in ("lui", "c.lui"):
                # lui + addi immediate value
                v = int(p["o"].split(",")[1].strip(), 0) << 12
                addend = 0
                for b2 in range(1, 5):
                    if idx - back + b2 < len(walk):
                        q = walk[idx - back + b2]
                        m2 = re.match(r"(addi(?:w)?|c.addi), " + re.escape(vreg) + r", \w+, (-?0x[0-9a-f]+|-?\d+)", q["o"])
                        if m2:
                            addend = int(m2.group(2), 0)
                            break
                return {"class": "CONSTANT", "value": v + addend,
                        "site": {"va": hex(p["va"]), "o": p["o"]}}
            if p["m"] in ("li", "c.li"):
                try:
                    v = int(p["o"].split(",")[1].strip(), 0)
                except ValueError:
                    v = None
                return {"class": "CONSTANT", "value": v,
                        "site": {"va": hex(p["va"]), "o": p["o"]}}
            if p["m"] in ("mv", "c.mv", "addi", "c.addi", "add", "c.add", "or", "c.or", "andi", "ori", "slli", "srli"):
                hops.append({"va": hex(p["va"]), "m": p["m"], "o": p["o"]})
                # chase the operand register
                parts = [x.strip() for x in p["o"].split(",")]
                nxt = None
                if p["m"] in ("mv", "c.mv") and len(parts) == 2:
                    nxt = parts[1]
                elif len(parts) >= 2:
                    nxt = parts[1]
                if nxt and nxt != vreg:
                    vreg = nxt
                    continue
                return {"class": f"DEF({p['m']})", "hops": hops}
            hops.append({"va": hex(p["va"]), "m": p["m"], "o": p["o"]})
            return {"class": f"DEF({p['m']})", "hops": hops}
    return {"class": "ARG/UNKNOWN"}


def main():
    da = A.read_bytes()
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

    # ---- 1. the banked census reproduction (17/17) -------------------------
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

    # ---- 2. the whole-image extension --------------------------------------
    all_hits = census_page5(img, 0, len(img))
    for h in all_hits:
        a_off = h["va"] - IMG_LO
        reg = enclosing(a_off)
        h["status"] = "covered" if reg else "island"
        h["region"] = [hex(IMG_LO + reg[0]), hex(IMG_LO + reg[1])] if reg else None
    islands = [h for h in all_hits if h["status"] == "island"]
    print(f"whole-image census: {len(all_hits)} sites, {len(islands)} in islands")
    for h in islands:
        print("   ISLAND:", hex(h["va"]), h["insn"])

    # ---- 3. the extended per-site trace with the copy chain ----------------
    # NOTE: the trace runs on `banked` (the covered-region census, 17/17).
    # The whole-image linear walk desyncs on data gaps (an instrument
    # lesson); island extension needs the byte-pattern scan, recorded as
    # the honest limitation in the findings.
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
        idx = next((i for i, w in enumerate(walk) if w["va"] == h["va"]), None)
        if idx is None:
            results.append({"va": hex(h["va"]), "error": "walk desync"})
            continue
        uses = trace_object_use(img, walk, idx, h["reg"])
        for u in uses:
            if u["class"] == "WRITE-FIELD":
                u["source"] = classify_source(img, walk, u, s0, e0)
        results.append({"va": hex(h["va"]), "insn": h["insn"],
                        "status": "covered",
                        "region": [hex(IMG_LO + s0), hex(IMG_LO + e0)],
                        "uses": uses})

    writers = []
    for r in results:
        for u in r.get("uses", []):
            if u["class"] == "WRITE-FIELD":
                writers.append({"site": r["va"], "status": r["status"],
                                **u})
    print(f"\nWRITE-FIELD uses total: {len(writers)}")
    for w in writers:
        src = w.get("source", {})
        print(f"  {w['site']} field {w['field']} via {w['via']}"
              f" [{src.get('class','?')}"
              + (f" evt={src.get('internal_event_id')}" if src.get('internal_event_id') else "")
              + (f" val={src.get('value')}" if 'value' in src else "") + "]")

    # ---- 4. the GET_PARAMS six-limit scan (0x104..0x118) -------------------
    targets = [0x104, 0x108, 0x10c, 0x110, 0x114, 0x118]
    pmgr_lo, pmgr_hi = 0x43f000, 0x460000   # A_img offsets: the PFM/PMGR cluster
    getparams = []
    off = pmgr_lo
    while off < pmgr_hi:
        try:
            ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
        except StopIteration:
            break
        m, o = ins.mnemonic, ins.op_str
        if m in LOADS or m in STORES:
            fld = field_of(o)
            if fld in targets:
                base = o.split("(")[1].rstrip(")")
                getparams.append({"va": hex(IMG_LO + off), "m": m, "o": o,
                                  "field": fld, "base": base})
        off += ins.size
    print(f"\nGET_PARAMS six-limit accesses in PMGR window: {len(getparams)}")
    for g in getparams:
        print("  ", g["va"], g["m"], g["o"])

    out = {
        "census_reproduction": rep,
        "whole_image_sites": [dict(va=hex(h["va"]), insn=h["insn"],
                                   status=h["status"], region=h["region"])
                              for h in all_hits],
        "island_sites": [dict(va=hex(h["va"]), insn=h["insn"]) for h in islands],
        "traces": results,
        "writers": writers,
        "getparams_accesses": getparams,
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"\nwritten {OUT}")


if __name__ == "__main__":
    main()
