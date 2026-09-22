#!/usr/bin/env python3
"""
v428 stage 2 — the x86 site attributor: the corrected marshal hunt on the
landed substrate (findings-4.28-x86-substrate.md section 5, queue item 1).

Substrate: tools/analysis/x86-rm/binaries/nv-kernel.o_binary
(sha256 48096db025a439328592250b1c79e7f27943b37b733583778407f3cf46bca251,
provenance in the sibling PROVENANCE.md; the census stage froze: 13
sections, 23,713 symbols / 23,705 named, 165,214 relocs, .text 4,021,333 B,
.rodata 9,870,893 B — v428_x86_substrate_census.py, register frozen).

THE SCOPE (this instrument ATTRIBUTES, it does not name — the copy-graph
stage v428_x86_copygraph.py consumes this register and does the naming):
  A. the full symtab map (name/bind/type/shndx/value/size per symbol) and
     the .text relocation map (R_X86_64_PC32 + R_X86_64_32S: .text offset
     -> referenced symbol + addend).
       grammar sources (AGENTS.md law 1, cited per construct):
       - the ELF section parser: v428_x86_substrate_census.py:47-70
         (load_sections / section_of / u32_at, transcribed verbatim);
       - Elf64_Sym layout st_name(4) st_info(1) st_other(1) st_shndx(2)
         st_value(8) st_size(8) = 24 B (read at symtab offset + i*24);
       - Elf64_Rela layout r_offset(8) r_info(8) r_addend(8) = 24 B
         (r_info = sym<<32 | type — v428_x86_substrate_census.py:121-129).
  B. the FULL needle re-scan (the census register truncated hit lists at
     24 — this stage enumerates every hit): 1544 (0x608) x35, 100000
     (0x186a0) x14, 240000 / 250000 (0 / 0), and the three family dwords
     the census froze (0x2080d2a5, 0x2080d2e9 x2, 0x2080d338).
  C. .text hit classification, instruction-aware (the 4.25-x86
     discipline, v425_x86_marshal.py section B: "an x86 u32 that begins
     at a modrm byte preceded by an opcode is the modrm+disp32 overlap
     ... NOT the value"): capstone linear sweep from the enclosing
     function symbol, multi-start consensus fallback, then the ROLE:
       IMM     — the needle is an operand immediate (a real value use)
       DISP    — the needle is a mem displacement (a struct-offset
                 access [reg+1544]: real, but an OFFSET not a size)
       OVERLAP — covered bytes but neither field (the modrm+disp32
                 artifact shape, e.g. call [rax+0x3d0])
       CROSS   — an instruction boundary falls inside the dword
       NOSYNC  — no decode covers the hit start (data island)
     plus a semantic class per IMM/DISP site (compare / store-imm /
     mov-imm / arith / push-arg / lea-member / load-member /
     store-member / call-dispatch) and the +-6-insn window text.
  D. non-.text attribution: .rodata/.data -> enclosing symbol (+-16 B
     hex context); .symtab -> the exact entry and FIELD (a hit at
     entry+16 reading 1544 = a symbol whose st_size is 1544 — named);
     .rela.* -> the exact entry (addend 1544 = a sym+1544 member
     reference; the referencing site r_offset named).
  E. the per-function fingerprint for every function holding a REAL
     (IMM or DISP) 0x608 / 0x186a0 site: every symbol it references
     (relocs with r_offset inside the function), every dword store
     mov [reg+disp],imm with imm in the captured set {255, 3, 257}, and
     every [reg+0x40] dword/qword store (the params+64 lane — 250000
     has ZERO raw occurrences in the whole object, so the @64 copy must
     be register/memory-fed; those stores are the copy-graph hooks).

Register: lab/jalon411/v428_x86_site_attributor.json (written, frozen).
Selftest: FULL re-derivation, deep-compared against the frozen register;
any drift exits 2 with the drift name.
"""
import hashlib
import json
import os
import struct
import sys
from bisect import bisect_right

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
except ImportError:  # pragma: no cover
    print("capstone missing: pip install capstone")
    raise

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries",
                   "nv-kernel.o_binary")
REG = os.path.join(HERE, "v428_x86_site_attributor.json")

STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}
RT = {1: "R_X86_64_64", 2: "R_X86_64_PC32", 4: "R_X86_64_PLT32",
      10: "R_X86_64_32", 11: "R_X86_64_32S"}

NEEDLES = {
    "size_1544": 0x608,
    "val_100000": 0x186A0,
    "val_240000": 0x3A980,
    "val_250000": 0x3D090,
    "fam_0x2080d2a5": 0x2080D2A5,
    "fam_0x2080d2e9": 0x2080D2E9,
    "fam_0x2080d338": 0x2080D338,
}
# the five captured values (findings-4.24-payload-fieldmap.md section 1:
# poff {0:255, 4:3, 8:257, 56:257, 64:250000} — re-derived from
# tools/edpp/edpp_payload_1616.bin by this campaign, sha256 573a2836...)
CAPTURED_SET = {255: "poff0", 3: "poff4", 257: "poff8_poff56"}


def u32_at(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


# ---- the ELF section parser: v428_x86_substrate_census.py:47-70, verbatim ----
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
            return s
    return None


# ---- A. symbols + relocations ----
def load_symbols(buf, secs):
    out = []
    for st in (s for s in secs if s["type"] == 2):  # SHT_SYMTAB
        strtab = secs[st["link"]]
        n = st["size"] // st["entsize"]
        for i in range(n):
            b = st["offset"] + i * st["entsize"]
            nameoff, info, other, shndx, value, size = \
                struct.unpack_from("<IBBHQQ", buf, b)
            name = ""
            if nameoff:
                sbo = strtab["offset"] + nameoff
                e = buf.index(b"\x00", sbo)
                name = buf[sbo:e].decode("ascii", "replace")
            out.append(dict(name=name, bind=info >> 4, stype=info & 0xF,
                            shndx=shndx, value=value, size=size))
    return out


def load_relocs(buf, secs):
    """{target section name: {target-relative offset: (type, sym, addend)}}"""
    out = {}
    for s in secs:
        if s["type"] != 4:  # SHT_RELA
            continue
        if s["info"] >= len(secs):
            continue
        target = secs[s["info"]]
        m = out.setdefault(target["name"], {})
        for i in range(s["size"] // s["entsize"]):
            b = s["offset"] + i * s["entsize"]
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", buf, b)
            m[r_offset] = (r_info & 0xFFFFFFFF, r_info >> 32, r_addend)
    return out


# ---- B. full needle scan ----
def scan32_all(buf, value):
    needle = struct.pack("<I", value)
    hits, start = [], 0
    while True:
        i = buf.find(needle, start)
        if i < 0:
            return hits
        hits.append(i)
        start = i + 1


# ---- C. the disassembler ----
class Dis:
    def __init__(self, text_bytes):
        self.tb = text_bytes
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.cache = {}

    def sweep(self, start, end):
        out = {}
        for insn in self.md.disasm(self.tb[start:end], start):
            out[insn.address] = dict(
                addr=insn.address, size=insn.size, bytes=insn.bytes,
                mnem=insn.mnemonic, ops=insn.op_str,
                imm=[o.imm for o in insn.operands if o.type == X86_OP_IMM],
                disp=[o.mem.disp for o in insn.operands
                      if o.type == X86_OP_MEM])
        return out

    def function(self, fstart, fend):
        if fstart not in self.cache:
            self.cache[fstart] = self.sweep(fstart, fend)
        return self.cache[fstart]

    @staticmethod
    def _seek(fmap, hit):
        addrs = sorted(fmap)
        if not addrs:
            return None
        i = bisect_right(addrs, hit) - 1
        if i < 0:
            return None
        a = addrs[i]
        if a <= hit < a + fmap[a]["size"]:
            return a
        return None

    def cover(self, hit, fstart=None, fend=None):
        """(method, insn, stream) for the instruction covering `hit`."""
        if fstart is not None:
            f = self.function(fstart, fend)
            a = self._seek(f, hit)
            if a is not None:
                return "symbol-sweep", f[a], f
        votes = {}
        for back in range(1, 16):
            s = hit - back
            if s < 0:
                break
            f = self.sweep(s, min(hit + 24, len(self.tb)))
            a = self._seek(f, hit)
            if a is not None:
                key = (f[a]["addr"], f[a]["size"], f[a]["bytes"])
                votes[key] = votes.get(key, 0) + 1
        if votes:
            (addr, size, bb), n = max(votes.items(), key=lambda kv: kv[1])
            f = self.sweep(addr, addr + size)
            return "multi-start %d/15" % n, f[addr], f
        return "none", None, None


def classify_role(ins, hit):
    """role of the needle dword at `hit` inside instruction `ins`."""
    pos = hit - ins["addr"]
    if pos + 4 > ins["size"]:
        return "CROSS", None
    sub = bytes(ins["bytes"][pos:pos + 4])
    needle = struct.unpack("<I", sub)[0]
    for v in ins["imm"]:
        if v == needle and struct.pack("<i", v) == sub:
            return "IMM", v
    for d in ins["disp"]:
        if d == needle and struct.pack("<i", d) == sub:
            return "DISP", d
    return "OVERLAP", None


def semantic(ins, role):
    m, ops = ins["mnem"], ins["ops"]
    if role == "IMM":
        if m in ("cmp", "test"):
            return "compare"
        if m in ("mov", "movl", "movq") and "[" in ops:
            return "store-imm"
        if m in ("mov", "movl", "movq"):
            return "mov-imm"
        if m == "push":
            return "push-arg"
        if m in ("add", "sub", "and", "or", "xor", "shl", "shr", "imul",
                 "idiv", "div"):
            return "arith"
        return "imm-" + m
    if role == "DISP":
        if m == "lea":
            return "lea-member"
        if m in ("call", "jmp", "callq", "jmpq"):
            return "call-dispatch"
        if ops.startswith("[") or ("," in ops and "[" in ops.split(",")[0]):
            return "load-member"
        return "store-member"
    return "-"


def window(fmap, hit, n=6):
    if not fmap or hit not in [fmap[a]["addr"] for a in ()]:  # cheap guard
        pass
    addrs = sorted(a for a in fmap if abs(a - hit) <= 192)
    if not addrs:
        return []
    i = min(range(len(addrs)), key=lambda k: abs(addrs[k] - hit))
    lo, hi = max(0, i - n), min(len(addrs), i + n + 1)
    return ["%x %-9s %s" % (addrs[k], fmap[addrs[k]]["mnem"],
                            fmap[addrs[k]]["ops"]) for k in range(lo, hi)]


def derive(buf):
    """the full register derivation (main and selftest share it)."""
    secs = load_sections(buf)
    sec_by_name = {s["name"]: s for s in secs}
    text = sec_by_name[".text"]
    syms = load_symbols(buf, secs)
    relocs = load_relocs(buf, secs)
    named = [s for s in syms if s["name"]]

    funcs = sorted((s for s in syms
                    if s["stype"] == 2 and s["shndx"] == text["index"]
                    and s["name"]),
                   key=lambda s: s["value"])
    fstarts = [f["value"] for f in funcs]

    def enclosing_func(trel):
        i = bisect_right(fstarts, trel) - 1
        if i < 0:
            return None
        f = funcs[i]
        nxt = fstarts[i + 1] if i + 1 < len(fstarts) else text["size"]
        end = f["value"] + f["size"] if f["size"] else nxt
        return f, min(max(end, f["value"] + 1), text["size"])

    def sym_name(idx):
        return syms[idx]["name"] if 0 < idx < len(syms) else None

    dis = Dis(buf[text["offset"]:text["offset"] + text["size"]])

    out = {"substrate_sha256": hashlib.sha256(buf).hexdigest(),
           "needles": {k: v for k, v in NEEDLES.items()}}
    scans = {}
    role_census = {}
    fp_inputs = {}   # fname -> (fstart, fend, sites)
    for label, val in NEEDLES.items():
        entries = []
        for h in scan32_all(buf, val):
            sec = section_of(secs, h)
            sname = sec["name"] if sec else "<none>"
            e = {"file_off": h, "section": sname}
            if sname == ".text":
                trel = h - text["offset"]
                ef = enclosing_func(trel)
                if ef:
                    f, fend = ef
                    e["func"] = f["name"]
                    e["func_size"] = f["size"]
                    method, ins, stream = dis.cover(trel, f["value"], fend)
                else:
                    method, ins, stream = dis.cover(trel)
                e["method"] = method
                if ins:
                    role, v = classify_role(ins, trel)
                    e.update(role=role, mnemonic=ins["mnem"],
                             operands=ins["ops"], sem=semantic(ins, role),
                             insn_hex=ins["bytes"].hex(),
                             window=window(stream, trel))
                    if role in ("IMM", "DISP"):
                        r = relocs.get(".text", {}).get(trel)
                        if r:
                            e["reloc"] = {"type": RT.get(r[0], hex(r[0])),
                                          "sym": sym_name(r[1]),
                                          "addend": r[2]}
                        if ef:
                            ent = fp_inputs.setdefault(
                                f["name"], (f["value"], fend, []))
                            ent[2].append({"off": trel, "needle": label,
                                           "role": role})
                else:
                    e["role"] = "NOSYNC"
                role_census[e.get("role", "NOSYNC")] = \
                    role_census.get(e.get("role", "NOSYNC"), 0) + 1
            else:
                if sname in (".rodata", ".data"):
                    rel = h - sec["offset"]
                    cand = [s for s in named if s["shndx"] == sec["index"]
                            and s["value"] <= rel < s["value"] +
                            max(s["size"], 1)]
                    cand.sort(key=lambda s: (s["value"], -s["size"]))
                    if cand:
                        best = cand[-1]
                        e["enclosing_symbol"] = best["name"]
                        e["symbol_size"] = best["size"]
                        e["symbol_off_in"] = rel - best["value"]
                elif sname == ".symtab":
                    idx, field = divmod(h - sec["offset"], sec["entsize"])
                    e["symtab_entry"] = idx
                    e["field"] = {0: "st_name", 4: "st_info", 5: "st_other",
                                  6: "st_shndx", 8: "st_value",
                                  16: "st_size"}.get(field, "byte+%d" % field)
                    if field == 16:
                        e["the_symbol"] = syms[idx]["name"]
                        e["the_symbol_type"] = STT.get(syms[idx]["stype"])
                        e["the_symbol_size"] = syms[idx]["size"]
                        e["the_symbol_shndx"] = syms[idx]["shndx"]
                elif sname.startswith(".rela"):
                    idx, field = divmod(h - sec["offset"], sec["entsize"])
                    target = secs[sec["info"]]["name"]
                    r_offset, r_info, r_addend = struct.unpack_from(
                        "<QQq", buf, sec["offset"] + idx * sec["entsize"])
                    e.update(rela_entry=idx,
                             rela_field={0: "r_offset", 8: "r_info",
                                         16: "r_addend"}.get(
                                             field, "byte+%d" % field),
                             rela_target=target, rela_roffset=r_offset,
                             rela_type=RT.get(r_info & 0xFFFFFFFF,
                                              hex(r_info & 0xFFFFFFFF)),
                             rela_sym=sym_name(r_info >> 32),
                             rela_addend=r_addend)
                e["ctx_hex"] = buf[max(0, h - 16):h + 20].hex()
                role_census["non-text"] = role_census.get("non-text", 0) + 1
            entries.append(e)
        scans[label] = {"value": val, "count": len(entries), "sites": entries}
    out["scans"] = scans
    out["role_census"] = role_census

    # ---- E. per-function fingerprints ----
    fps = {}
    for fname, (fstart, fend, sites) in fp_inputs.items():
        fp = {"func_start": fstart, "func_size": fend - fstart,
              "real_sites": sites, "referenced_symbols": {},
              "captured_set_stores": [], "poff64_stores": []}
        fmap = dis.function(fstart, fend)
        for roff in range(fstart, fend):
            r = relocs.get(".text", {}).get(roff)
            if r:
                nm = sym_name(r[1]) or RT.get(r[0], hex(r[0]))
                key = "%s%s" % (nm, ("+0x%x" % r[2]) if r[2] else "")
                fp["referenced_symbols"][key] = \
                    fp["referenced_symbols"].get(key, 0) + 1
        if fmap and fmap.get(fstart) is not None or fmap:
            for a in sorted(fmap):
                d = fmap[a]
                if d["mnem"] not in ("mov", "movl", "movq") \
                        or "[" not in d["ops"]:
                    continue
                dst, src = d["ops"].split(",", 1)
                if "[" not in dst:
                    continue
                for v in d["imm"]:
                    if v in CAPTURED_SET:
                        fp["captured_set_stores"].append(
                            {"off": a, "insn": d["mnem"] + " " + d["ops"],
                             "imm": v, "field": CAPTURED_SET[v]})
                if "+0x40]" in dst.replace(" ", ""):
                    fp["poff64_stores"].append(
                        {"off": a, "insn": d["mnem"] + " " + d["ops"]})
        fps[fname] = fp
    out["fingerprints"] = fps
    return out


def main():
    buf = open(BIN, "rb").read()
    out = derive(buf)
    with open(REG, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("== v428 stage 2: site attributor ==")
    print("substrate:", out["substrate_sha256"][:16])
    for label in NEEDLES:
        sc = out["scans"][label]
        print("%-16s 0x%08x : %d hit(s)" % (label, sc["value"], sc["count"]))
    print("role census:", json.dumps(out["role_census"], sort_keys=True))
    print("fingerprinted functions:", len(out["fingerprints"]))
    for fn, fp in out["fingerprints"].items():
        print("  %-46s sites=%d refs=%d cap_stores=%d p64=%d"
              % (fn[:46], len(fp["real_sites"]),
                 len(fp["referenced_symbols"]),
                 len(fp["captured_set_stores"]), len(fp["poff64_stores"])))
    print("register written:", os.path.relpath(REG, HERE))
    return 0


def selftest():
    buf = open(BIN, "rb").read()
    reg = json.load(open(REG))
    errs = []
    if reg["substrate_sha256"] != hashlib.sha256(buf).hexdigest():
        errs.append("substrate sha256 drift")
    fresh = derive(buf)
    for label in NEEDLES:
        a, b = reg["scans"][label]["count"], fresh["scans"][label]["count"]
        if a != b:
            errs.append("%s count drift (%d vs %d)" % (label, a, b))
    if reg["role_census"] != fresh["role_census"]:
        errs.append("role census drift: %s vs %s"
                    % (reg["role_census"], fresh["role_census"]))
    if len(reg["fingerprints"]) != len(fresh["fingerprints"]):
        errs.append("fingerprint count drift")
    else:
        for fn, fp in reg["fingerprints"].items():
            o = fresh["fingerprints"].get(fn)
            if not o or len(o["real_sites"]) != len(fp["real_sites"]) or \
                    len(o["captured_set_stores"]) != len(fp["captured_set_stores"]) \
                    or len(o["poff64_stores"]) != len(fp["poff64_stores"]):
                errs.append("fingerprint drift: %s" % fn)
    if errs:
        print("SELFTEST FAIL:", *errs, sep="\n  ")
        return 2
    tot = sum(v for k, v in fresh["role_census"].items())
    print("selftest OK — full re-derivation equal: %d sites, %d functions"
          % (tot, len(fresh["fingerprints"])))
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if len(sys.argv) > 1 and sys.argv[1] == "selftest"
             else main())
