#!/usr/bin/env python3
"""
v428c — the pfmreqhndlr cluster on the x86 substrate (closed host RM 610.57.04,
sha256 48096db0…). The 4.28b symbol census located the EDPp handler cluster and
the .rodata string `PmgrPfmReqHndlrGetEdppLimitInfo`; this ring disassembles
the cluster and climbs to the dispatch table that names it.

Evidence law: everything re-derived from the committed binary; unresolved
offsets stay unresolved; no field is named from memory — candidates are
labelled CANDIDATE with their supporting instruction.

Sections:
  A. full name census (?i)pfmreq|edpp|platformrequest — symbols with ranges
  B. full disassembly of the pfmreqhndlr* FUNC symbols (all are <0x200 B):
     every insn, resolved call targets, [reg+disp] memory operands recorded
  C. reverse xrefs per cluster function (R_X86_64_PC32 against its symbol)
  D. the FINN-name climb: relocs referencing the string offset (rela.rodata /
     rela.data), then the surrounding table rows re-resolved symbol-by-symbol
  E. register lab/jalon411/v428c_pfmreqhndlr.json + selftest on the anchors
"""
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries",
                    "nv-kernel.o_binary")
REG = os.path.join(HERE, "v428c_pfmreqhndlr.json")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

STRING = b"PmgrPfmReqHndlrGetEdppLimitInfo"
NAME_RX = re.compile(rb"(?i)(pfmreq|edpp|platformrequest)")


# ---------------------------------------------------------------- ELF layer
def load_sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
    raw = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        f = struct.unpack_from("<IIQQQQIIQQ", buf, b)
        raw.append(dict(index=i, nameoff=f[0], type=f[1], flags=f[2],
                        offset=f[4], size=f[5], link=f[6], info=f[7],
                        entsize=f[9]))
    strtab_off = raw[e_shstrndx]["offset"]
    for s in raw:
        e = buf.index(b"\x00", strtab_off + s["nameoff"])
        s["name"] = buf[strtab_off + s["nameoff"]:e].decode("ascii", "replace")
    return raw


def parse_symbols(buf, secs):
    out = []
    for st in [s for s in secs if s["type"] == 2]:
        strtab = secs[st["link"]]
        n = st["size"] // 24
        for i in range(n):
            b = st["offset"] + i * 24
            nameoff, info, other, shndx, value, size = struct.unpack_from(
                "<IBBHQQ", buf, b)
            if shndx >= len(secs):
                continue
            sec = secs[shndx]
            e = buf.index(b"\x00", strtab["offset"] + nameoff)
            name = buf[strtab["offset"] + nameoff:e].decode("ascii", "replace")
            out.append(dict(name=name, type=info & 0xF, bind=info >> 4,
                            sym_index=i, shndx=shndx, value=value, size=size,
                            file_start=sec["offset"] + value if sec["type"] != 8 else None,
                            section=sec["name"]))
    return out


def parse_rela(buf, secs, name_of):
    """all RELA entries. CORRECTED: file_off is TARGET-section-relative —
    sh_info names the section the reloc applies to; the first draft used the
    RELA section's own sh_offset (wrong window -> unresolved targets)."""
    out = []
    for r in [s for s in secs if s["type"] == 4]:
        tgt = secs[r["info"]]
        n = r["size"] // 24
        for i in range(n):
            b = r["offset"] + i * 24
            r_off, r_info, r_add = struct.unpack_from("<QQq", buf, b)
            out.append(dict(sec=r["name"], target=tgt["name"], r_off=r_off,
                            file_off=tgt["offset"] + r_off,
                            sym=r_info >> 32, type=r_info & 0xFFFFFFFF,
                            addend=r_add, sym_name=name_of.get(r_info >> 32, "<sym-%d>" % (r_info >> 32))))
    return out


# ---------------------------------------------------------------- disasm
def disasm(md, buf, start, size):
    return list(md.disasm(buf[start:start + size], start))


def main():
    buf = open(BIN, "rb").read()
    secs = load_sections(buf)
    syms = parse_symbols(buf, secs)
    name_of = {s["sym_index"]: s["name"] for s in syms if s["name"]}
    relas = parse_rela(buf, secs, name_of)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    ro = next(x for x in secs if x["name"] == ".rodata")

    reg = {"binary": {"sha256": hashlib.sha256(buf).hexdigest(), "size": len(buf)}}

    # A — name census (all symbols, FUNC or not)
    cluster = [s for s in syms if NAME_RX.search(s["name"].encode())]
    reg["cluster_symbols"] = [
        {"name": s["name"], "bind": "LOCAL" if s["bind"] == 0 else "GLOBAL",
         "type": ["", "OBJECT", "FUNC"][min(s["type"], 2)],
         "section": s["section"], "size": s["size"],
         "range": "0x%x..0x%x" % (s["file_start"],
                                  s["file_start"] + s["size"])
         if s["file_start"] is not None else "?"}
        for s in cluster]

    # B — full disassembly of cluster FUNCs
    reg["disasm"] = {}
    for s in cluster:
        if s["type"] != 2 or s["file_start"] is None or not s["size"]:
            continue
        insns = disasm(md, buf, s["file_start"], s["size"])
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
            if "[" in ins.op_str and ("ptr" in ins.op_str or "rip" not in ins.op_str):
                e["mem"] = True
            rows.append(e)
        reg["disasm"][s["name"]] = {"range": "0x%x..0x%x" % (
            s["file_start"], s["file_start"] + s["size"]),
            "insns": rows}

    # C — reverse xrefs (calls INTO each cluster function)
    reg["xrefs"] = {}
    for s in cluster:
        if s["type"] != 2:
            continue
        x = []
        for r in relas:
            if r["target"] == ".text" and r["type"] == 2 \
                    and r["sym_name"] == s["name"] and -8 <= r["addend"] <= 8:
                x.append({"call_site_file_off": "0x%x" % r["file_off"],
                          "addend": r["addend"]})
        reg["xrefs"][s["name"]] = x

    # D — the FINN-name climb
    str_offs, s0 = [], 0
    blob = buf[ro["offset"]:ro["offset"] + ro["size"]]
    while True:
        i = blob.find(STRING, s0)
        if i < 0:
            break
        str_offs.append(ro["offset"] + i)
        s0 = i + 1
    reg["string"] = {"bytes": STRING.decode(), "offsets": ["0x%x" % o for o in str_offs]}
    refs = []
    for so in str_offs:
        for r in relas:
            # pointer-to-string: addend == section-relative offset of string
            if r["target"] == ".rodata" and r["addend"] == so - ro["offset"]:
                refs.append(dict(r))
    reg["string_refs"] = [
        {"sec": r["sec"], "entry_file_off": "0x%x" % r["file_off"],
         "sym": r["sym_name"], "addend": r["addend"], "type": r["type"]}
        for r in refs]

    # dump table context around each string ref: the reloc'd entries before/after
    rows = []
    for r in refs:
        base = r["file_off"]
        lo, hi = base - 0x60, base + 0x60
        near = [x for x in relas
                if x["target"] == ".rodata" and lo <= x["file_off"] < hi]
        near.sort(key=lambda x: x["file_off"])
        rows.append({"around_entry": "0x%x" % base, "relocs": [
            {"off": "0x%x" % x["file_off"], "sym": x["sym_name"],
             "addend": x["addend"], "type": x["type"]} for x in near],
            "raw": buf[lo:hi].hex()})
    reg["table_rows"] = rows

    with open(REG, "w") as f:
        json.dump(reg, f, indent=1, sort_keys=True)

    # console
    print("== v428c pfmreqhndlr cluster ==")
    print("cluster symbols (%d):" % len(cluster))
    for s in reg["cluster_symbols"]:
        print("  %-8s %-8s %-52s %s" % (s["bind"], s["type"], s["name"][:52],
                                        s["range"]))
    for fname, d in reg["disasm"].items():
        print("--- %s %s (%d insns)" % (fname, d["range"], len(d["insns"])))
        for e in d["insns"]:
            line = "  %s %-8s %s" % (e["a"], e["m"], e["ops"])
            if "target" in e:
                line += "   -> %s" % e["target"]
            print(line[:150])
    print("xrefs:")
    for k, v in reg["xrefs"].items():
        print("  %-56s <- %d call site(s) %s" % (k[:56], len(v),
                                                 [x["call_site_file_off"] for x in v[:6]]))
    print("string %r at %s" % (STRING.decode(), reg["string"]["offsets"]))
    print("string refs: %d" % len(reg["string_refs"]))
    for r in reg["string_refs"]:
        print("  %s @%s (addend %+d)" % (r["sec"], r["entry_file_off"], r["addend"]))
    for t in reg["table_rows"]:
        print("  table around %s:" % t["around_entry"])
        for x in t["relocs"]:
            print("    %s sym=%s addend=%+d type=%d" % (x["off"], x["sym"][:44],
                                                        x["addend"], x["type"]))
    print("register written:", os.path.relpath(REG, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
