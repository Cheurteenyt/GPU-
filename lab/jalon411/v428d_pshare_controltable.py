#!/usr/bin/env python3
"""
v428d — wave 2 of the pfmreqhndlr ring: the control table, the FINN-name xref
by symbol, and the two hub functions.

Inputs (evidence): the committed substrate (sha256 48096db0…). Corrections
carried from v428c: RELA file_off = TARGET-section-relative (sh_info).

Sections:
  A. dump `_PfmreqhndlrControlTable` (0x3e2e00, .data) raw + every reloc in range
  B. FINN-name xref: is `PmgrPfmReqHndlrGetEdppLimitInfo` a SYMBOL? which
     relocs reference that symbol (addend scan +-0x40)?
  C. disasm `_pfmreqhndlrCallPshareStatus` (0x338820, 0x492 B) — the EDPp hub
  D. disasm `pfmreqhndlrPcontrol_IMPL` (0x336120, 0x311 B) — the meta-control
     passthrough (cmd-as-data candidate)
Register: lab/jalon411/v428d_pshare_controltable.json
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries",
                   "nv-kernel.o_binary")
REG = os.path.join(HERE, "v428d_pshare_controltable.json")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, HERE)
from v428c_pfmreqhndlr import load_sections, parse_symbols, parse_rela

TARGETS = ["_pfmreqhndlrCallPshareStatus", "pfmreqhndlrPcontrol_IMPL"]


def main():
    buf = open(BIN, "rb").read()
    secs = load_sections(buf)
    syms = parse_symbols(buf, secs)
    name_of = {s["sym_index"]: s["name"] for s in syms if s["name"]}
    relas = parse_rela(buf, secs, name_of)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    reg = {"binary": {"sha256": hashlib.sha256(buf).hexdigest(), "size": len(buf)}}

    # A — the control table
    tbl = next(s for s in syms if s["name"] == "_PfmreqhndlrControlTable")
    lo, hi = tbl["file_start"], tbl["file_start"] + tbl["size"]
    reg["control_table"] = {
        "range": "0x%x..0x%x" % (lo, hi), "size": tbl["size"],
        "section": tbl["section"],
        "raw": buf[lo:hi].hex(),
        "relocs": [
            {"off": "0x%x" % r["file_off"], "sym": r["sym_name"],
             "addend": r["addend"], "type": r["type"]}
            for r in sorted(relas, key=lambda x: x["file_off"])
            if lo <= r["file_off"] < hi],
    }
    # every object referenced by those relocs: dump their ranges too
    refd = {}
    for r in reg["control_table"]["relocs"]:
        s = next((x for x in syms if x["name"] == r["sym"]), None)
        if s and s["file_start"] is not None and r["sym"] not in refd:
            refd[r["sym"]] = {"range": "0x%x..0x%x" % (s["file_start"],
                                                       s["file_start"] + s["size"]),
                              "size": s["size"], "section": s["section"]}
    reg["control_table"]["referenced_objects"] = refd

    # B — FINN-name xref by symbol
    nm = "PmgrPfmReqHndlrGetEdppLimitInfo"
    sym = next((s for s in syms if s["name"] == nm), None)
    reg["finn_name_symbol"] = ({"found": True, "type": sym["type"],
                                "section": sym["section"],
                                "range": "0x%x..0x%x" % (sym["file_start"],
                                                         sym["file_start"] + sym["size"])}
                               if sym else {"found": False})
    refs = []
    if sym:
        for r in relas:
            if r["sym_name"] == nm and -0x40 <= r["addend"] <= 0x40:
                refs.append({"sec": r["sec"], "target": r["target"],
                             "off": "0x%x" % r["file_off"], "addend": r["addend"]})
    reg["finn_name_xrefs"] = refs

    # also: who references ANY 'PfmReqHndlr' symbol string? (one level up)
    near_refs = []
    for r in relas:
        if "PfmReqHndlr" in r["sym_name"] and r["target"] in (".data", ".rodata"):
            near_refs.append({"sym": r["sym_name"], "target": r["target"],
                              "off": "0x%x" % r["file_off"], "addend": r["addend"]})
    reg["pfmreq_data_refs"] = near_refs[:60]

    # C/D — hub disasm
    reg["disasm"] = {}
    for tname in TARGETS:
        s = next((x for x in syms if x["name"] == tname), None)
        if not s:
            continue
        insns = list(md.disasm(buf[s["file_start"]:s["file_start"] + s["size"]],
                               s["file_start"]))
        rows = []
        for ins in insns:
            e = {"a": "0x%x" % ins.address, "m": ins.mnemonic, "ops": ins.op_str}
            if ins.mnemonic in ("call", "jmp") and ins.size >= 5:
                d = ins.address + ins.size - 4
                hit = next((x for x in relas
                            if x["target"] == ".text" and x["file_off"] == d
                            and x["type"] in (2, 11)), None)
                e["target"] = ("%s%+d" % (hit["sym_name"], hit["addend"])
                               if hit else "0x%x" % ((ins.address + ins.size +
                               struct.unpack("<i", buf[d:d + 4])[0])
                               & 0xFFFFFFFFFFFFFFFF))
            rows.append(e)
        reg["disasm"][tname] = {"range": "0x%x..0x%x" % (
            s["file_start"], s["file_start"] + s["size"]), "insns": rows}

    with open(REG, "w") as f:
        json.dump(reg, f, indent=1, sort_keys=True)

    print("== v428d ==")
    ct = reg["control_table"]
    print("control_table %s (%d B, %s):" % (ct["range"], ct["size"], ct["section"]))
    print("  raw:", ct["raw"])
    for r in ct["relocs"]:
        print("  reloc @%s sym=%s addend=%+d" % (r["off"], r["sym"], r["addend"]))
    for k, v in ct["referenced_objects"].items():
        print("  referenced: %-44s %s (%d B, %s)" % (k[:44], v["range"], v["size"],
                                                     v["section"]))
    print("finn_name_symbol:", reg["finn_name_symbol"])
    print("finn_name_xrefs (%d):" % len(refs))
    for r in refs:
        print("   %s -> %s addend=%+d" % (r["sec"], r["off"], r["addend"]))
    print("pfmreq_data_refs (%d shown):" % len(reg["pfmreq_data_refs"]))
    for r in reg["pfmreq_data_refs"]:
        print("   %-56s -> %s @%s addend=%+d" % (r["sym"][:56], r["target"],
                                                 r["off"], r["addend"]))
    for tname, d in reg["disasm"].items():
        print("--- %s %s (%d insns)" % (tname, d["range"], len(d["insns"])))
        for e in d["insns"]:
            print("  %s %-8s %s%s" % (e["a"], e["m"], e["ops"],
                                      "   -> " + e["target"] if "target" in e else "")[:150])
    print("register written:", os.path.relpath(REG, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
