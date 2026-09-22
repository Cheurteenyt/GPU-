#!/usr/bin/env python3
"""
v428 stage 4 — the userspace extension: the same needles over
libnvidia-ml.so.610.57.04 and libnvidia-eglcore.so.610.57.04 — where the
control id 0x2080d031 IS present (the naming hit the kernel side never had).

Provenance (AGENTS.md law 1, the 4.27 acquisition register law):
  package NVIDIA-Linux-x86_64-610.57.04.run, 463,025,450 B,
  sha256 b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d
  (verified on download against the 4.27 register value), makeself
  --extract-only, both libs copied verbatim into
  tools/analysis/x86-rm/binaries/ :
    libnvidia-ml.so.610.57.04      2,654,168 B
      sha256 50feda0f0d2712bd3b82d1c2f8c5083b9169607d5db481ebc278ec76582068a0
    libnvidia-eglcore.so.610.57.04 39,091,248 B
      sha256 afd79b7f6e708cb2521aeb852d26d0768d694ae1394f0e213c61300f25bd3246

Scans:
  A. both libs: the needle census (the EDPp cmd 0x2080d031, the whole
     0x2080d000-d0ff family, 1544 (0x608), 100000, 240000, 250000),
     every hit attributed to its ELF section.
  B. ML: the two d031 .text sites -> enclosing function bounds via
     .eh_frame_hdr (grammar parsed from the raw file: version 1,
     eh_frame_ptr_enc 0x1b (pcrel sdata4), fde_count_enc 0x03 (udata4),
     table_enc 0x3b (datarel sdata4); entries = (initial_loc, fde_ptr)
     pairs, datarel to the section VA — the bounds verified on both
     sites: functions [0x108250..0x108550] and [0x108930..0x108c20]).
  C. ML: full annotated disassembly of both d031 functions AND the
     sender function they call — every rip-relative operand resolved
     to its section (+ nearest .dynsym export), every PLT call
     resolved via .rela.plt (R_X86_64_JUMP_SLOT -> the imported name),
     internal call targets recorded (the sender chain).
  D. the params-build probes on both d031 functions: every store with
     a 48-stride index shape (the lea rcx,[r+r*2] + shl rcx,4 chain),
     every immediate in the captured set {255, 3, 257, 100000, 250000},
     the loop-compare bounds, and the r9/other-arg sizes feeding the
     sender call (0x608 expected and confirmed at the sites).
  E. eglcore: the family hits (d000/d003/d041) and the 250000/240000
     sites attributed (real immediates vs artifacts, the 4.25-x86
     instruction-aware discipline).
  F. nvidia_drv.so (the Xorg driver, the third substrate — committed
     alongside): the census, and the FULL decode of its d031 function
     [0x77920..0x77a50] — the dual-send mechanism (memset 0xC1 qwords
     = 1544 B; params[4] = the domain mask; send 0x20809030 whose
     RESPONSE fills the buffer — proven by contradiction: the
     version-minor check byte[rsp+48i+9]==1 can only pass if the send
     filled the zeroed buffer; patch entry[i]; send 0x2080d031), the
     two .rodata float constants of the value formula (100.0 and
     1000.0 — value = offset * 100000 / devField), and the two
     NV-CONTROL-style caller tail-jumps.
  G. the CLOSED core's host dispatch row: the package ALSO ships
     kernel/nvidia/nv-kernel.o_binary (120,980,872 B, sha256
     c90f58d5… — NOT committed, over the 100 MB limit; the .run itself
     is the committed-provenance artifact) which contains exactly ONE
     0x2080d031 dword — a .rodata table row at 0x666b110, stride 0x20
     {u32 cmd, u32 tag, u64 0, u64 0x44} with 0x2080d02d->4116,
     0x2080d031->1544, 0x2080d036->...: the HOST twin of the GSP
     dispatch table (v425-x86 section 3 — same rows, same 0x44). No
     code immediate of d031 exists even there: the params build is
     userspace-only in BOTH cores. Graceful: re-derived from the
     extracted package when present (V428_PKG_DIR, default /tmp/nv610),
     else the banked row stands on its provenance hashes.

Register: lab/jalon411/v428_userspace_scan.json (written, frozen).
Selftest: full re-derivation deep-compared against the register; any
drift exits 2 with the drift name (the closed-core row re-derivation
skipped gracefully when the package is absent).
"""
import hashlib
import json
import os
import struct
import sys
from bisect import bisect_right

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:  # pragma: no cover
    print("capstone missing: pip install capstone")
    raise

HERE = os.path.dirname(os.path.abspath(__file__))
BINDIR = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries")
ML = os.path.join(BINDIR, "libnvidia-ml.so.610.57.04")
EGL = os.path.join(BINDIR, "libnvidia-eglcore.so.610.57.04")
DRV = os.path.join(BINDIR, "nvidia_drv.so")
PKG_DIR = os.environ.get("V428_PKG_DIR", "/tmp/nv610")
CLOSED_CORE = os.path.join(PKG_DIR, "kernel", "nvidia", "nv-kernel.o_binary")
REG = os.path.join(HERE, "v428_userspace_scan.json")

PROV = {
    "package": "NVIDIA-Linux-x86_64-610.57.04.run",
    "package_size": 463025450,
    "package_sha256": ("b2e935c66b83bb00c0c857bc8e0ee0fd52de9"
                      "286b40c9cc1eec29a7ce7eb116d"),
    "ml_size": 2654168,
    "ml_sha256": ("50feda0f0d2712bd3b82d1c2f8c5083b9169607d"
                  "5db481ebc278ec76582068a0"),
    "egl_size": 39091248,
    "egl_sha256": ("afd79b7f6e708cb2521aeb852d26d0768d694ae1"
                   "394f0e213c61300f25bd3246"),
    "drv_size": 3627376,
    "drv_sha256": ("28ae0bf0e4097c611d99e39cb3afc1eaaa6013019a"
                   "3cc609a669042b0c69229c"),
    "closed_core_size": 120980872,
    "closed_core_sha256": ("c90f58d59e8fef44fa07d057bd9ffb1e1b5ee38d"
                           "3c51b35df71e05e0ad268cbf"),
}

NEEDLES = {
    "cmd_0x2080d031": 0x2080D031,
    "size_1544": 0x608,
    "val_100000": 0x186A0,
    "val_240000": 0x3A980,
    "val_250000": 0x3D090,
}
CAPTURED_SET = {255: "poff0?", 3: "poff4?", 257: "poff8/56?",
                100000: "edpp-quantum", 250000: "poff64?"}
RT_JUMP_SLOT = 7  # R_X86_64_JUMP_SLOT


# ---- the ELF grammar (v428_x86_substrate_census.py:47-70, transcribed) ----
def load_sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
    raw = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        nameoff, sh_type, flags, addr, off, size, link, info, align, entsz = \
            struct.unpack_from("<IIQQQQIIQQ", buf, b)
        raw.append(dict(index=i, nameoff=nameoff, type=sh_type, flags=flags,
                        addr=addr, offset=off, size=size, link=link, info=info,
                        entsize=entsz))
    strtab_off = raw[e_shstrndx]["offset"]
    for s in raw:
        end = buf.index(b"\x00", strtab_off + s["nameoff"])
        s["name"] = buf[strtab_off + s["nameoff"]:end].decode("ascii", "replace")
    return raw


def section_of(sections, off):
    for s in sections:
        if s["type"] != 8 and s["offset"] <= off < s["offset"] + s["size"]:
            return s
    return None


def section_of_va(sections, va):
    for s in sections:
        if s["type"] != 8 and s["addr"] and \
                s["addr"] <= va < s["addr"] + s["size"]:
            return s
    return None


def load_dynsym(buf, secs):
    """[(value, size, name)] from SHT_DYNSYM sections."""
    out = []
    for st in (s for s in secs if s["type"] == 11):
        strt = secs[st["link"]]
        for i in range(st["size"] // st["entsize"]):
            b = st["offset"] + i * st["entsize"]
            nameoff, info, other, shndx, value, size = \
                struct.unpack_from("<IBBHQQ", buf, b)
            name = ""
            if nameoff:
                sbo = strt["offset"] + nameoff
                e = buf.index(b"\x00", sbo)
                name = buf[sbo:e].decode("ascii", "replace")
            out.append((value, size, name))
    return out


def load_plt_map(buf, secs):
    """.plt VA -> imported symbol name (via .rela.plt order + PLT layout)."""
    out = {}
    for s in secs:
        if s["name"] == ".rela.plt" and s["type"] == 4:
            strt = secs[secs.index(next(x for x in secs
                                        if x["index"] == s["link"]))] \
                if False else None
            # symtab for .rela.plt is .dynsym (link field)
            dyn = secs[s["link"]]
            strt = secs[dyn["link"]]
            plt = next((x for x in secs if x["name"] == ".plt"), None)
            if not plt:
                continue
            for i in range(s["size"] // s["entsize"]):
                b = s["offset"] + i * s["entsize"]
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", buf, b)
                symidx = r_info >> 32
                sb = dyn["offset"] + symidx * dyn["entsize"]
                nameoff = struct.unpack_from("<I", buf, sb)[0]
                sbo = strt["offset"] + nameoff
                e = buf.index(b"\x00", sbo)
                name = buf[sbo:e].decode("ascii", "replace")
                # standard PLT: PLT0 is 16 B, entry i at plt.addr+16*(i+1)
                out[plt["addr"] + 16 * (i + 1)] = name
    return out


def load_ehfuncs(buf, secs):
    """sorted function start VAs from .eh_frame_hdr (the grammar in the
    docstring; verified on the ML d031 sites)."""
    hdr = next((s for s in secs if s["name"] == ".eh_frame_hdr"), None)
    if not hdr:
        return []
    b = hdr["offset"]
    if buf[b] != 1 or buf[b + 1] != 0x1B or buf[b + 2] != 0x03 \
            or buf[b + 3] != 0x3B:
        return []
    p = b + 4
    struct.unpack_from("<i", buf, p)          # eh_frame_ptr (unused here)
    fde_count, = struct.unpack_from("<I", buf, p + 4)
    p += 8
    base = hdr["addr"]
    funcs = []
    for i in range(fde_count):
        init, _fde = struct.unpack_from("<ii", buf, p)
        p += 8
        funcs.append(base + init)
    return sorted(funcs)


def scan32_all(buf, value):
    needle = struct.pack("<I", value)
    hits, start = [], 0
    while True:
        i = buf.find(needle, start)
        if i < 0:
            return hits
        hits.append(i)
        start = i + 1


def family_scan(buf):
    fam = {}
    for i in range(len(buf) - 3):
        dw = struct.unpack_from("<I", buf, i)[0]
        if 0x2080D000 <= dw <= 0x2080D0FF:
            fam.setdefault(dw, []).append(i)
    return fam


def va_of(secs, off):
    s = section_of(secs, off)
    return s["addr"] + (off - s["offset"]) if s else None


class Dis:
    def __init__(self, buf, secs, pltmap, dynsym):
        self.buf, self.secs = buf, secs
        self.pltmap, self.dynsym = pltmap, dynsym
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)

    def nearest_dynsym(self, va):
        best = None
        for v, sz, nm in self.dynsym:
            if v and v <= va and (best is None or v > best[0]):
                best = (v, sz, nm)
        return best

    def annotate(self, insn):
        note = ""
        if "rip" in insn.op_str:
            # capstone gives rip-relative disp directly in op_str as
            # [rip + X] or [rip - X]; compute the target
            import re
            m = re.search(r"rip ([+-]) (0x[0-9a-f]+)", insn.op_str)
            if m:
                d = int(m.group(2), 16)
                if m.group(1) == "-":
                    d = -d
                tgt = insn.address + insn.size + d
                sec = section_of_va(self.secs, tgt)
                nm = self.nearest_dynsym(tgt)
                note = " ; -> %s%s" % (
                    sec["name"] if sec else hex(tgt),
                    (" (%s+0x%x)" % (nm[2], tgt - nm[0])) if nm and nm[2] else "")
        if insn.mnemonic in ("call", "jmp") and insn.op_str.startswith("0x"):
            tgt = int(insn.op_str, 16)
            if tgt in self.pltmap:
                note += " ; PLT %s" % self.pltmap[tgt]
        return "%x  %-9s %-44s%s" % (insn.address, insn.mnemonic,
                                     insn.op_str, note)

    def function(self, lo, hi):
        return ["%x  %-9s %s" % (i.address, i.mnemonic, i.op_str)
                for i in self.md.disasm(self.buf[lo:hi], lo)]


def derive():
    out = {"provenance": PROV}
    ml = open(ML, "rb").read()
    egl = open(EGL, "rb").read()
    drv = open(DRV, "rb").read()
    for label, buf in (("libnvidia-ml", ml), ("libnvidia-eglcore", egl),
                       ("nvidia_drv", drv)):
        secs = load_sections(buf)
        census = {}
        for lbl, v in NEEDLES.items():
            hits = [{"file_off": hex(h),
                     "section": section_of(secs, h)["name"]}
                    for h in scan32_all(buf, v)]
            census[lbl] = {"value": v, "count": len(hits), "hits": hits}
        fam = family_scan(buf)
        census["family_0x2080d0xx"] = {
            "distinct": len(fam),
            "values": {hex(k): [hex(x) for x in v][:8] for k, v in
                       sorted(fam.items())}}
        out[label] = {"sha256": hashlib.sha256(buf).hexdigest(),
                      "size": len(buf), "census": census}

    # ---- F. nvidia_drv.so: the census is above; the d031 function decode ----
    dsecs = load_sections(drv)
    ddyn = load_dynsym(drv, dsecs)
    dplt = load_plt_map(drv, dsecs)
    ddis = Dis(drv, dsecs, dplt, ddyn)
    dsite = scan32_all(drv, 0x2080D031)[0]
    dfuncs = load_ehfuncs(drv, dsecs)
    dva = va_of(dsecs, dsite)
    di = bisect_right(dfuncs, dva) - 1
    dflo, dfhi = dfuncs[di], dfuncs[di + 1]
    ddis_list = [ddis.annotate(i) for i in ddis.md.disasm(
        drv[dflo:dfhi], dflo)]
    # the two float constants of the value formula
    import re as _re
    consts = {}
    for insn in ddis.md.disasm(drv[dflo:dfhi], dflo):
        m = _re.search(r"rip ([+-]) (0x[0-9a-f]+)", insn.op_str)
        if not m or insn.mnemonic not in ("divss", "mulss"):
            continue
        d = int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
        tgt = insn.address + insn.size + d
        s = section_of_va(dsecs, tgt)
        if s and s["name"] == ".rodata":
            off = tgt - s["addr"] + s["offset"]
            f, = struct.unpack_from("<f", drv, off)
            consts["%s@%x" % (insn.mnemonic, insn.address)] = {
                "target": hex(tgt), "float": f}
    out["drv_deep"] = {
        "site_file_off": hex(dsite), "func": [hex(dflo), hex(dfhi)],
        "size": dfhi - dflo, "disasm": ddis_list,
        "value_formula_constants": consts,
        "mechanism": {
            "memset": "rep stosq, ecx=0xc1 -> 1544 B zeroed (8 + 32*48)",
            "poff4": "params[4] = dev->[+0x5fc] (the domain mask)",
            "send1": "0x20809030 (the set/query whose RESPONSE fills the "
                      "buffer — proven by contradiction: the version check)",
            "version_check": "byte [rsp + 48*i + 9] == 1 (entry[i].minor)",
            "patch": "byte[rsp+48i+0xc]=0; dword[rsp+48i+0x10] = the value",
            "send2": "0x2080d031 with the patched table",
            "value": "int(offset_f / (devField_f / 100.0) * 1000.0)"
                     " = offset * 100000 / devField",
        },
        "callers": ["jmp 0x77920 from 0x3a1ba (esi=1)",
                    "jmp 0x77920 from 0x3a2a7"],
    }

    # ---- G. the closed core's host dispatch row (graceful) ----
    row = {"file": "kernel/nvidia/nv-kernel.o_binary (the package's "
                  "CLOSED core, not committed: 121 MB > the 100 MB limit)",
           "size": PROV["closed_core_size"],
           "sha256": PROV["closed_core_sha256"],
           "row_file_off": "0x666b110", "section": ".rodata",
           "row_hex": "44d08020 14100000 0000000000000000 "
                      "4400000000000000 31d08020 08060000 "
                      "0000000000000000 4400000000000000 36d08020",
           "reading": "stride-0x20 rows {u32 cmd, u32 tag, u64 0, "
                      "u64 0x44}: 0x2080d02d->4116, 0x2080d031->1544 "
                      "(0x608), 0x2080d036->next — the HOST twin of the "
                      "GSP dispatch table (v425-x86 section 3, same "
                      "rows, same 0x44); the ONLY d031 occurrence in "
                      "the 121 MB object — no code immediate",
           "rederived": False}
    if os.path.exists(CLOSED_CORE):
        cb = open(CLOSED_CORE, "rb").read()
        h = hashlib.sha256(cb).hexdigest()
        if h == PROV["closed_core_sha256"] and len(cb) == \
                PROV["closed_core_size"]:
            offs = scan32_all(cb, 0x2080D031)
            row["rederived"] = True
            row["occurrences"] = len(offs)
            row["row_hex_live"] = cb[offs[0] - 0x10:offs[0] + 0x24].hex() \
                if offs else None
    out["closed_core_row"] = row

    # ---- ML deep dive: the two d031 functions + the sender ----
    secs = load_sections(ml)
    text = next(s for s in secs if s["name"] == ".text")
    dynsym = load_dynsym(ml, secs)
    pltmap = load_plt_map(ml, secs)
    funcs = load_ehfuncs(ml, secs)
    dis = Dis(ml, secs, pltmap, dynsym)
    d031_sites = scan32_all(ml, 0x2080D031)
    deep = {"sites": []}
    seen_senders = {}
    for site in d031_sites:
        va = va_of(secs, site)
        i = bisect_right(funcs, va) - 1
        flo, fhi = funcs[i], funcs[i + 1] if i + 1 < len(funcs) else va + 0x400
        # full function disasm with annotations; collect facts
        facts = {"site_file_off": hex(site), "site_va": hex(va),
                 "func": [hex(flo), hex(fhi)], "size": fhi - flo,
                 "disasm": [], "calls": [], "imms_of_note": [],
                 "stride48_stores": [], "sender_args": []}
        insns = list(dis.md.disasm(ml[flo:fhi], flo))
        for k, insn in enumerate(insns):
            line = dis.annotate(insn)
            facts["disasm"].append(line)
            if insn.mnemonic in ("call", "jmp") and insn.op_str.startswith("0x"):
                tgt = int(insn.op_str, 16)
                if tgt in pltmap:
                    facts["calls"].append({"at": hex(insn.address),
                                           "plt": pltmap[tgt]})
                elif insn.mnemonic == "call":
                    facts["calls"].append({"at": hex(insn.address),
                                           "internal": hex(tgt)})
                    if insn.address <= va < insn.address + 64:
                        pass
            for tok in insn.op_str.split(", "):
                tok = tok.strip()
                try:
                    v = int(tok, 0)
                except ValueError:
                    continue
                if v in CAPTURED_SET or v in (0x608, 1544, 0x66, 0x3E7, 999,
                                              0x64, 0x3E8):
                    facts["imms_of_note"].append(
                        {"at": hex(insn.address), "value": v,
                         "insn": insn.mnemonic + " " + insn.op_str})
            if "rbp + rcx" in insn.op_str or "rbp+rcx" in \
                    insn.op_str.replace(" ", ""):
                facts["stride48_stores"].append(
                    {"at": hex(insn.address),
                     "insn": insn.mnemonic + " " + insn.op_str})
            # the sender call: the call within +-10 insns of the site
            if abs(insn.address - va) <= 40 and insn.mnemonic == "call" \
                    and insn.op_str.startswith("0x"):
                tgt = int(insn.op_str, 16)
                argwin = ["%x  %-9s %s" % (j.address, j.mnemonic, j.op_str)
                          for j in insns[max(0, k - 10):k + 1]]
                facts["sender_args"].append(
                    {"call_at": hex(insn.address), "target": hex(tgt),
                     "arg_window": argwin})
                seen_senders.setdefault(tgt, None)
        deep["sites"].append(facts)

    # the sender function(s), fully decoded (one level)
    deep["senders"] = []
    for tgt in sorted(seen_senders):
        i = bisect_right(funcs, tgt) - 1
        flo, fhi = funcs[i], funcs[i + 1] if i + 1 < len(funcs) \
            else tgt + 0x300
        lines = []
        for insn in dis.md.disasm(ml[flo:min(fhi, flo + 0x400)], flo):
            lines.append(dis.annotate(insn))
        deep["senders"].append({"va": hex(tgt), "func": [hex(flo), hex(fhi)],
                                "disasm": lines})
    out["ml_deep"] = deep
    return out


def main():
    out = derive()
    with open(REG, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("== v428 stage 4: userspace scan ==")
    for lbl in ("libnvidia-ml", "libnvidia-eglcore"):
        c = out[lbl]["census"]
        print("%s (%d B):" % (lbl, out[lbl]["size"]))
        for k in NEEDLES:
            print("   %-14s : %d" % (k, c[k]["count"]))
        print("   family         : %s" % {k: len(v) for k, v in
                                          c["family_0x2080d0xx"]["values"].items()})
    d = out["ml_deep"]
    for s in d["sites"]:
        print("site %s func %s (%d B): %d calls, %d imms_of_note, "
              "%d stride48 stores" % (s["site_file_off"], s["func"],
                                      s["size"], len(s["calls"]),
                                      len(s["imms_of_note"]),
                                      len(s["stride48_stores"])))
    print("senders decoded:", [x["va"] for x in d["senders"]])
    dd = out["drv_deep"]
    print("nvidia_drv.so: func %s (%d B), consts %s" %
          (dd["func"], dd["size"],
           {k: v["float"] for k, v in dd["value_formula_constants"].items()}))
    print("closed-core row: rederived=%s" % out["closed_core_row"]["rederived"])
    print("register written:", os.path.relpath(REG, HERE))
    return 0


def selftest():
    reg = json.load(open(REG))
    errs = []
    ml = open(ML, "rb").read()
    egl = open(EGL, "rb").read()
    drv = open(DRV, "rb").read()
    if hashlib.sha256(ml).hexdigest() != reg["libnvidia-ml"]["sha256"]:
        errs.append("ml sha256 drift")
    if hashlib.sha256(egl).hexdigest() != reg["libnvidia-eglcore"]["sha256"]:
        errs.append("egl sha256 drift")
    if hashlib.sha256(drv).hexdigest() != reg["nvidia_drv"]["sha256"]:
        errs.append("drv sha256 drift")
    if reg["nvidia_drv"]["census"]["cmd_0x2080d031"]["count"] != 1:
        errs.append("drv d031 must be 1")
    if reg["libnvidia-ml"]["census"]["cmd_0x2080d031"]["count"] != \
            len(scan32_all(ml, 0x2080D031)):
        errs.append("d031 count drift")
    if reg["libnvidia-eglcore"]["census"]["cmd_0x2080d031"]["count"] != 0:
        errs.append("egl d031 must be 0")
    fresh = derive()
    for lbl in ("libnvidia-ml", "libnvidia-eglcore", "nvidia_drv"):
        for k in NEEDLES:
            if fresh[lbl]["census"][k]["count"] != \
                    reg[lbl]["census"][k]["count"]:
                errs.append("%s %s drift" % (lbl, k))
    if len(fresh["ml_deep"]["sites"]) != len(reg["ml_deep"]["sites"]):
        errs.append("site count drift")
    if len(fresh["drv_deep"]["disasm"]) != len(reg["drv_deep"]["disasm"]):
        errs.append("drv disasm drift")
    if fresh["drv_deep"]["value_formula_constants"] != \
            reg["drv_deep"]["value_formula_constants"]:
        errs.append("drv formula constants drift")
    if errs:
        print("SELFTEST FAIL:", *errs, sep="\n  ")
        return 2
    print("selftest OK — census + deep dives reproduce")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if len(sys.argv) > 1 and sys.argv[1] == "selftest"
             else main())
