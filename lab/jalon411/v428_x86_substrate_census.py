#!/usr/bin/env python3
"""
v428 — x86 substrate census: `nv-kernel.o_binary` (the closed host RM, 610.57.04).

Evidence law (AGENTS.md 1): every fact below is re-derived from the committed
artifact `tools/analysis/x86-rm/binaries/nv-kernel.o_binary`
(sha256 48096db025a439328592250b1c79e7f27943b37b733583778407f3cf46bca251,
provenance in the sibling PROVENANCE.md — official 610.57.04 package,
makeself extraction, no modification). Nothing is reasoned from memory.

Scope of THIS instrument (a census, facts only — no naming):
  A. ELF identity + full section census (name, type, flags, size, compression)
  B. symbol census (count + the syslink anchors that name the RM build)
  C. relocation census (type histogram, per-section counts)
  D. u32 needle scans over the raw file AND attributed to sections:
       the EDPp control 0x2080d031, the 1544-B closed siblings
       0x20809004 / 0x20809030 (the 4.25-x86 trio), the size constant
       1544 (0x608), and the five captured values {255, 3, 257, 257,
       250000} + the transport triple {100000, 240000, 250000}
  E. the full 0x2080d0xx family census (every dword in range, attributed)
Register: lab/jalon411/v428_x86_substrate_census.json (written, then frozen).
Selftest: re-derives A/D anchors and exits 2 on drift vs the register.
"""
import json
import os
import struct
import sys
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries",
                   "nv-kernel.o_binary")
REG = os.path.join(HERE, "v428_x86_substrate_census.json")

SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
       6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM",
       0x11: "GNU_HASH", 0x2006: "GNU_ATTRIBUTES", 0x6ffffff6: "GNU_HASH",
       0x6ffffffe: "VERNEED", 0x6fffffff: "VERSYM"}
SHF_COMPRESSED = 0x800
ELFCOMPRESS = {0: "none", 1: "zlib", 2: "zstd"}


def u32_at(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def load_sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
    raw = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        nameoff, sh_type, flags, addr, off, size, link, info, align, entsz = \
            struct.unpack_from("<IIQQQQIIQQ", buf, b)
        raw.append(dict(index=i, nameoff=nameoff, type=sh_type, flags=flags,
                        offset=off, size=size, link=link, info=info,
                        entsize=entsz))
    strtab_off = raw[e_shstrndx]["offset"]
    for s in raw:
        end = buf.index(b"\x00", strtab_off + s["nameoff"])
        s["name"] = buf[strtab_off + s["nameoff"]:end].decode("ascii", "replace")
    return raw


def section_of(sections, off):
    for s in sections:
        if s["type"] != 8 and s["offset"] <= off < s["offset"] + s["size"]:
            return s["name"]
    return "<none>"


def census(buf):
    reg = {}
    sha = hashlib.sha256(buf).hexdigest()
    reg["identity"] = {
        "size": len(buf), "sha256": sha,
        "magic": buf[:4].hex(),
        "ei_class": buf[4], "ei_data": buf[5],
        "e_type": u32_at(buf, 16) & 0xFFFF,
        "e_machine": struct.unpack_from("<H", buf, 18)[0],
    }

    # A. sections
    secs = load_sections(buf)
    reg["sections"] = [{
        "index": s["index"], "name": s["name"],
        "type": SHT.get(s["type"], hex(s["type"])),
        "flags": "0x%x" % s["flags"],
        "compressed": bool(s["flags"] & SHF_COMPRESSED),
        "size": s["size"], "offset": s["offset"],
    } for s in secs]
    reg["any_section_compressed"] = any(s["flags"] & SHF_COMPRESSED for s in secs)

    # B. symbols
    symtabs = [s for s in secs if s["type"] == 2]
    reg["symtab_sections"] = [s["name"] for s in symtabs]
    syms = {}
    for st in symtabs:
        strtab = secs[st["link"]]
        n = st["size"] // st["entsize"] if st["entsize"] else 0
        syms[st["name"]] = n
        names = 0
        anchors = []
        want = (b"rm", b"Rm", b"RM", b"control", b"Control", b"api", b"Api")
        for i in range(n):
            b = st["offset"] + i * st["entsize"]
            nameoff, = struct.unpack_from("<I", buf, b)
            if nameoff:
                names += 1
                sbo = strtab["offset"] + nameoff
                e = buf.index(b"\x00", sbo)
                nm = buf[sbo:e]
                if len(anchors) < 64 and any(w in nm for w in want):
                    anchors.append(nm.decode("ascii", "replace"))
        syms[st["name"] + "_named"] = names
        reg["symbol_anchors"] = anchors[:40]
    reg["symbol_counts"] = syms

    # C. relocations
    reloc = {}
    for s in secs:
        if s["type"] == 4:  # SHT_RELA
            n = s["size"] // s["entsize"] if s["entsize"] else 0
            types = {}
            for i in range(min(n, 400000)):
                b = s["offset"] + i * s["entsize"]
                r_info, = struct.unpack_from("<Q", buf, b + 8)
                t = r_info & 0xFFFFFFFF
                types[t] = types.get(t, 0) + 1
            reloc[s["name"]] = {"count": n,
                                "type_histogram": {"R_X86_64_%d" % k: v
                                                   for k, v in sorted(types.items())}}
    reg["relocations"] = reloc

    # D/E. needle scans (raw file, then section-attributed)
    def scan32(value):
        needle = struct.pack("<I", value)
        hits = []
        start = 0
        while True:
            i = buf.find(needle, start)
            if i < 0:
                break
            hits.append({"offset": i, "section": section_of(secs, i)})
            start = i + 1
        return hits

    needles = {
        "cmd_get_edpp_limit_info_0x2080d031": 0x2080d031,
        "sibling_0x20809004": 0x20809004,
        "sibling_0x20809030": 0x20809030,
        "size_1544_0x608": 0x608,
        "val_255": 255, "val_3": 3, "val_257": 257,
        "val_250000_0x3d090": 250000,
        "val_100000_0x186a0": 100000,
        "val_240000_0x3a980": 240000,
    }
    scans = {}
    for label, v in needles.items():
        hits = scan32(v)
        scans[label] = {"value": v, "count": len(hits),
                        "sections": sorted({h["section"] for h in hits}),
                        "hits": hits[:24]}
    reg["u32_scans"] = scans

    # E. the 0x2080d0xx family census (attributed)
    # little-endian layout of 0x2080dXYZ = bytes [YZ, dX, 80, 20]:
    # the dword BASE sits at (prefix_pos - 2), byte1 at (prefix_pos - 1).
    # (first draft scanned at i-1 and read a misaligned dword — the numpy
    #  calibration run caught it; corrected, re-run, register frozen)
    fam = {}
    lo, hi = 0x2080d000, 0x2080dfff
    pref = b"\x80\x20"
    start = 0
    while True:
        i = buf.find(pref, start)
        if i < 0:
            break
        start = i + 1
        if i < 2:
            continue
        b1 = buf[i - 1]
        if 0xD0 <= b1 <= 0xDF:
            v = u32_at(buf, i - 2)
            if lo <= v <= hi:
                key = "0x%08x" % v
                e = fam.setdefault(key, {"count": 0, "sites": []})
                e["count"] += 1
                if len(e["sites"]) < 8:
                    e["sites"].append({"offset": i - 2,
                                       "section": section_of(secs, i - 2)})
    reg["family_0x2080d0xx"] = {
        "distinct": len(fam), "total_occurrences": sum(e["count"] for e in fam.values()),
        "values": dict(sorted(fam.items())),
    }
    return reg


def selftest(reg, buf):
    errs = []
    if reg["identity"]["sha256"] != hashlib.sha256(buf).hexdigest():
        errs.append("sha256 drift")
    for label in ("cmd_get_edpp_limit_info_0x2080d031",):
        c = reg["u32_scans"][label]["count"]
        # the anchor that decides the pass verdict: re-scan and compare
        needle = struct.pack("<I", reg["u32_scans"][label]["value"])
        c2 = 0
        start = 0
        while True:
            i = buf.find(needle, start)
            if i < 0:
                break
            c2 += 1
            start = i + 1
        if c != c2:
            errs.append("%s drift (%d vs %d)" % (label, c, c2))
    if reg["any_section_compressed"]:
        errs.append("new: a section became compressed")
    return errs


def main():
    buf = open(BIN, "rb").read()
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        reg = json.load(open(REG))
        errs = selftest(reg, buf)
        if errs:
            print("SELFTEST FAIL:", *errs, sep="\n  ")
            return 2
        print("selftest OK — %d sections, cmd hits=%d, family distinct=%d"
              % (len(reg["sections"]),
                 reg["u32_scans"]["cmd_get_edpp_limit_info_0x2080d031"]["count"],
                 reg["family_0x2080d0xx"]["distinct"]))
        return 0
    reg = census(buf)
    with open(REG, "w") as f:
        json.dump(reg, f, indent=1, sort_keys=True)
    print("== v428 x86 substrate census ==")
    print("identity: size=%d type=%d machine=%d" %
          (reg["identity"]["size"], reg["identity"]["e_type"],
           reg["identity"]["e_machine"]))
    print("sections: %d, any compressed: %s" %
          (len(reg["sections"]), reg["any_section_compressed"]))
    for s in reg["sections"]:
        print("  [%2d] %-24s %-12s size=%-10d off=%d%s"
              % (s["index"], s["name"], s["type"], s["size"], s["offset"],
                 "  COMPRESSED" if s["compressed"] else ""))
    print("symbols: %s" % reg["symbol_counts"])
    for k, v in reg["relocations"].items():
        print("relocs %s: %d %s" % (k, v["count"], v["type_histogram"]))
    print("u32 scans:")
    for label, e in reg["u32_scans"].items():
        print("  %-36s = 0x%08x : %d hit(s) %s"
              % (label, e["value"], e["count"], e["sections"]))
    f = reg["family_0x2080d0xx"]
    print("family 0x2080d0xx: distinct=%d total=%d" % (f["distinct"], f["total_occurrences"]))
    for k, e in sorted(f["values"].items()):
        print("  %s x%d %s" % (k, e["count"], e["sites"][0]["section"]))
    print("register written:", os.path.relpath(REG, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
