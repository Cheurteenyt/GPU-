#!/usr/bin/env python3
"""
v428e — FINN-name string xref, done right.

The 4.28c/4.28d addend scans found zero references to the .rodata string
`PmgrPfmReqHndlrGetEdppLimitInfo` @0xc06ef8 — because a code reference is a
R_X86_64_PC32 against the *section symbol* of .rodata, whose stored addend is
`string_off_in_section - (r_off + 4)`. This ring scans ALL relas of the
committed substrate and decodes every such reference to the string
(effective = addend + r_off + 4 == string_off_in_section), then disassembles
the referencing instruction(s) with full symbol context.

Also scanned: 64-byte-precision near-references (±0x200) in case the compiler
referenced a neighbouring string and reached ours by extension.
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries",
                   "nv-kernel.o_binary")
REG = os.path.join(HERE, "v428e_finn_string_xref.json")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, HERE)
from v428c_pfmreqhndlr import load_sections, parse_symbols, parse_rela

STRING = b"PmgrPfmReqHndlrGetEdppLimitInfo"


def main():
    buf = open(BIN, "rb").read()
    secs = load_sections(buf)
    syms = parse_symbols(buf, secs)
    name_of = {s["sym_index"]: s["name"] for s in syms if s["name"]}
    relas = parse_rela(buf, secs, name_of)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    ro = next(s for s in secs if s["name"] == ".rodata")

    str_abs = buf.find(STRING, ro["offset"], ro["offset"] + ro["size"])
    str_rel = str_abs - ro["offset"]

    # the enclosing symbol of each candidate call site (for context)
    def sym_of(off):
        c = [s for s in syms if s["section"] == ".text" and s["type"] == 2
             and s["file_start"] <= off < s["file_start"] + s["size"]]
        return c[0]["name"] if c else "<none>"

    exact, near = [], []
    for r in relas:
        if r["target"] not in (".text", ".data", ".rodata"):
            continue
        if not r["sym_name"].startswith("."):
            continue  # section symbols only (rodata base references)
        eff = r["addend"] + r["r_off"] + 4
        row = {"ref_site": "0x%x" % r["file_off"], "target_sec": r["target"],
               "sym": r["sym_name"], "type": r["type"]}
        if eff == str_rel:
            exact.append(row)
        elif abs(eff - str_rel) <= 0x200:
            row["effective_off_in_rodata"] = "0x%x" % eff
            row["delta"] = eff - str_rel
            near.append(row)

    # disasm context for exact hits
    hits = []
    for row in exact:
        off = int(row["ref_site"], 16)
        fn = next((s for s in syms if s["section"] == ".text" and s["type"] == 2
                   and s["file_start"] <= off < s["file_start"] + s["size"]), None)
        d = {"ref_site": row["ref_site"], "function": fn["name"] if fn else "<none>"}
        if fn:
            insns = list(md.disasm(buf[fn["file_start"]:fn["file_start"] + fn["size"]],
                                   fn["file_start"]))
            idx = next((i for i, ins in enumerate(insns)
                        if ins.address <= off < ins.address + ins.size), None)
            if idx is not None:
                d["context"] = [
                    {"a": "0x%x" % i.address, "m": i.mnemonic, "ops": i.op_str}
                    for i in insns[max(0, idx - 6):idx + 8]]
        hits.append(d)

    reg = {
        "binary": {"sha256": hashlib.sha256(buf).hexdigest(), "size": len(buf)},
        "string": {"abs": "0x%x" % str_abs, "off_in_rodata": "0x%x" % str_rel},
        "exact_refs": exact, "exact_disasm": hits,
        "near_refs": near[:80],
    }
    with open(REG, "w") as f:
        json.dump(reg, f, indent=1, sort_keys=True)

    print("== v428e finn string xref ==")
    print("string abs=0x%x off_in_rodata=0x%x" % (str_abs, str_rel))
    print("exact refs (%d):" % len(exact))
    for h in hits:
        print("  site %s in %s" % (h["ref_site"], h["function"]))
        for e in h.get("context", []):
            print("    %s %-8s %s" % (e["a"], e["m"], e["ops"])[:140])
    print("near refs (%d, first 40):" % len(near))
    for r in near[:40]:
        print("  %s @%s eff=0x%s delta=%+d" % (r["target_sec"], r["ref_site"],
                                               r.get("effective_off_in_rodata"),
                                               r.get("delta")))
    print("register written:", os.path.relpath(REG, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
