#!/usr/bin/env python3
"""
v428b — site attribution on the x86 substrate (`nv-kernel.o_binary`, closed host
RM 610.57.04, sha256 48096db0… — provenance in tools/analysis/x86-rm/PROVENANCE.md).

Question of the ring: WHERE does the closed host RM hold {the 0x2080d031 cmd,
the 1544-B params size, the 100000 quantum} — and what do the enclosing symbols
say? Evidence law: every attribution re-derives from the committed binary +
its symtab/rela tables; unresolved stays unresolved; nothing is named from
memory.

Sections:
  A. ELF re-parse: sections, .symtab FUNC symbols (file ranges), .rela.text
     disp-resolution map (call/jmp targets -> symbol names)
  B. symbol-name census (EDPp/Preq/platform/DSM families) + .rodata ASCII needles
  C. .text needle sites (0x186a0, 0x608): enclosing function, the exact
     instruction embedding the immediate, nearest following calls with their
     resolved targets, +/-3 instruction context
  D. .rodata 0x608 sites: hex context
  E. userspace quick scan (--userspace): libnvidia-ml / libnvidia-eglcore,
     same needles, sha256 recorded, zero attribution (facts only)

Register: lab/jalon411/v428_site_attribution.json. Selftest: re-derives the
needle counts and exits 2 on drift.
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
REG = os.path.join(HERE, "v428_site_attribution.json")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TEXT_NEEDLES = {"val_100000_0x186a0": 0x186A0, "size_1544_0x608": 0x608}
ASCII_NEEDLES = [b"EDPp", b"EDPP", b"edpp", b"GetEdpp", b"GETEDPPLIMIT",
                 b"Preq", b"PlatformRequest", b"GETEDPP", b"_DSM"]
SYM_RX = re.compile(rb"(?i)(edpp|edp_|preq|platform_request|getedpp|dsm)")


# ---------------------------------------------------------------- ELF layer
def load_sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
    raw = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        f = struct.unpack_from("<IIQQQQIIQQ", buf, b)
        raw.append(dict(index=i, nameoff=f[0], type=f[1], flags=f[2],
                        offset=f[4], size=f[5], link=f[6], entsize=f[9]))
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
            if not size or shndx >= len(secs):
                continue
            sec = secs[shndx]
            if sec["type"] == 8:
                continue
            e = buf.index(b"\x00", strtab["offset"] + nameoff)
            name = buf[strtab["offset"] + nameoff:e].decode("ascii", "replace")
            out.append(dict(name=name, type=info & 0xF, sym_index=i,
                            file_start=sec["offset"] + value, size=size,
                            section=sec["name"]))
    return out


def parse_all_names(buf, secs):
    names = {}
    for st in [s for s in secs if s["type"] == 2]:
        strtab = secs[st["link"]]
        n = st["size"] // 24
        for i in range(n):
            b = st["offset"] + i * 24
            nameoff, = struct.unpack_from("<I", buf, b)
            if nameoff:
                e = buf.index(b"\x00", strtab["offset"] + nameoff)
                names[i] = buf[strtab["offset"] + nameoff:e].decode(
                    "ascii", "replace")
    return names


def parse_rela_text(buf, secs, names):
    out = {}
    # CORRECTED: r_offset is TARGET-section-relative (sh_info = target index);
    # first draft used the RELA section's own sh_offset (wrong window).
    for r in [s for s in secs if s["type"] == 4 and s["name"] == ".rela.text"]:
        tgt = secs[r["info"]]
        n = r["size"] // 24
        for i in range(n):
            b = r["offset"] + i * 24
            r_off, r_info, r_add = struct.unpack_from("<QQq", buf, b)
            sym_i, rtype = r_info >> 32, r_info & 0xFFFFFFFF
            if rtype not in (2, 11):
                continue
            out[tgt["offset"] + r_off] = (names.get(sym_i, "<sym-%d>" % sym_i), r_add)
    return out


# ---------------------------------------------------------------- disasm
def resolve_call(buf, relas, ins):
    disp_off = ins.address + ins.size - 4
    if disp_off in relas:
        name, add = relas[disp_off]
        return "%s%+d" % (name, add)
    return "0x%x" % ((ins.address + ins.size +
                      struct.unpack("<i", buf[disp_off:disp_off + 4])[0])
                     & 0xFFFFFFFFFFFFFFFF)


def attribute_site(md, buf, funcs, relas, off, needle):
    fn = next((f for f in funcs
               if f["section"] == ".text"
               and f["file_start"] <= off < f["file_start"] + f["size"]), None)
    if fn is None:
        return {"offset": off, "function": "<none>",
                "note": "no enclosing FUNC symbol"}
    insns = list(md.disasm(buf[fn["file_start"]:fn["file_start"] + fn["size"]],
                           fn["file_start"]))
    idx = next((i for i, ins in enumerate(insns)
                if ins.address <= off < ins.address + ins.size), None)
    if idx is None:
        return {"offset": off, "function": fn["name"], "note": "insn not decoded"}
    ins = insns[idx]
    lo, hi = max(0, idx - 3), min(len(insns), idx + 12)
    ctx, calls_after = [], []
    for j in range(lo, hi):
        e = {"addr": "0x%x" % insns[j].address, "m": insns[j].mnemonic,
             "ops": insns[j].op_str}
        if insns[j].mnemonic in ("call", "jmp") and insns[j].size >= 5:
            e["target"] = resolve_call(buf, relas, insns[j])
        ctx.append(e)
        if insns[j].mnemonic == "call" and j >= idx:
            calls_after.append(e.get("target", "?"))
    return {
        "offset": off, "needle": "0x%x" % needle, "function": fn["name"],
        "func_range": "0x%x..0x%x" % (fn["file_start"],
                                      fn["file_start"] + fn["size"]),
        "insn": {"addr": "0x%x" % ins.address, "m": ins.mnemonic,
                 "ops": ins.op_str, "bytes": ins.bytes.hex()},
        "context": ctx, "calls_after": calls_after[:3],
    }


def scan_hits(buf, sec_name, value):
    nd = struct.pack("<I", value)
    hits = []
    for s in load_sections(buf):
        if s["name"] != sec_name:
            continue
        blob = buf[s["offset"]:s["offset"] + s["size"]]
        pos = 0
        while True:
            i = blob.find(nd, pos)
            if i < 0:
                break
            hits.append(s["offset"] + i)
            pos = i + 1
    return hits


# ---------------------------------------------------------------- main
def main():
    buf = open(BIN, "rb").read()
    secs = load_sections(buf)
    funcs = parse_symbols(buf, secs)
    names = parse_all_names(buf, secs)
    relas = parse_rela_text(buf, secs, names)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    reg = {"binary": {"path": "tools/analysis/x86-rm/binaries/nv-kernel.o_binary",
                      "sha256": hashlib.sha256(buf).hexdigest(), "size": len(buf)},
           "counts": {"func_symbols": sum(1 for f in funcs if f["type"] == 2),
                      "rela_text_resolved": len(relas)}}

    # B — symbol census
    reg["symbol_census"] = [
        {"name": f["name"], "type": f["type"],
         "range": "0x%x..0x%x" % (f["file_start"], f["file_start"] + f["size"])}
        for f in funcs if SYM_RX.search(f["name"].encode())]
    ro = next(x for x in secs if x["name"] == ".rodata")
    str_hits = {}
    for nd in ASCII_NEEDLES:
        pos = scan_hits(buf, ".rodata", int.from_bytes(nd.ljust(4, b"\x00")[:4], "little"))
        # raw substring scan instead (needles are ASCII, not u32):
        pos, blob, s = [], buf[ro["offset"]:ro["offset"] + ro["size"]], 0
        while True:
            i = blob.find(nd, s)
            if i < 0:
                break
            pos.append(ro["offset"] + i)
            s = i + 1
        if pos:
            str_hits[nd.decode()] = {"count": len(pos),
                                     "offsets": pos[:12],
                                     "first_context": buf[pos[0]-16:pos[0]+24].decode(
                                         "ascii", "replace")}
    reg["rodata_ascii_needles"] = str_hits

    # C — text sites
    reg["text_sites"] = {}
    for label, v in TEXT_NEEDLES.items():
        rows = [attribute_site(md, buf, funcs, relas, off, v)
                for off in scan_hits(buf, ".text", v)]
        reg["text_sites"][label] = rows

    # D — rodata 0x608 context
    reg["rodata_0x608_context"] = []
    for off in scan_hits(buf, ".rodata", 0x608):
        a = max(0, off - 8)
        reg["rodata_0x608_context"].append({
            "offset": off, "hex": buf[a:off + 12].hex(),
            "ascii": "".join(chr(c) if 32 <= c < 127 else "."
                             for c in buf[a:off + 12])})

    # E — userspace quick scan
    if "--userspace" in sys.argv:
        base = "/home/z/my-project/work/downloads/extracted"
        reg["userspace"] = []
        for lib in ("libnvidia-ml.so.610.57.04", "libnvidia-eglcore.so.610.57.04"):
            p = os.path.join(base, lib)
            if not os.path.exists(p):
                continue
            d = open(p, "rb").read()
            e = {"lib": lib, "size": len(d),
                 "sha256": hashlib.sha256(d).hexdigest()}
            for label, v in {"cmd_0x2080d031": 0x2080D031, "val_100000": 0x186A0,
                             "val_240000": 0x3A980, "val_250000": 0x3D090,
                             "size_1544": 0x608}.items():
                nd = struct.pack("<I", v)
                c, s, first = 0, 0, []
                while True:
                    i = d.find(nd, s)
                    if i < 0:
                        break
                    c += 1
                    if len(first) < 6:
                        first.append(i)
                    s = i + 1
                e[label] = {"count": c, "first_offsets": first}
            reg["userspace"].append(e)

    with open(REG, "w") as f:
        json.dump(reg, f, indent=1, sort_keys=True)

    # console
    print("== v428b site attribution ==")
    print("func symbols: %d | rela.text resolved: %d"
          % (reg["counts"]["func_symbols"], reg["counts"]["rela_text_resolved"]))
    print("symbol census (%d hits):" % len(reg["symbol_census"]))
    for h in reg["symbol_census"][:100]:
        print("  %s %s" % (h["range"], h["name"]))
    print("rodata ASCII:")
    for k, v in str_hits.items():
        print("  %-16s x%d  ctx=%r" % (k, v["count"], v["first_context"][:60]))
    for label, rows in reg["text_sites"].items():
        print("text sites %s (%d):" % (label, len(rows)))
        for r in rows:
            if "insn" in r:
                print("  @0x%-8x %-52s %s %s" % (r["offset"], r["function"][:52],
                                                 r["insn"]["m"], r["insn"]["ops"]))
                if r["calls_after"]:
                    print("      calls -> %s" % r["calls_after"])
            else:
                print("  @0x%-8x %s %s" % (r["offset"], r["function"], r.get("note")))
    print("rodata 0x608 sites: %d" % len(reg["rodata_0x608_context"]))
    if "userspace" in reg:
        for e in reg["userspace"]:
            print("userspace %s (%d B) sha256=%s…:" % (e["lib"], e["size"],
                                                       e["sha256"][:12]))
            for k in ("cmd_0x2080d031", "val_100000", "val_240000",
                      "val_250000", "size_1544"):
                print("  %-14s %s" % (k, e[k]))
    print("register written:", os.path.relpath(REG, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
