#!/usr/bin/env python3
"""gspbuild — the gsp_ga10x.bin container reader / verifier / rebuilder (pass 4.27).

THE CONTAINER ANATOMY (proven 2026-09-22 on the official 610.57.04 driver
package, `firmware/gsp_ga10x.bin`, 84,310,168 B):

  - an ELF64 WRAPPER: e_machine=EM_RISCV(0xf3), e_type=1, NO program
    headers, 19 section headers, table at e_shoff — the LAST 1216 bytes
    of the file (e_shoff + 19*64 == file size, byte-proven).
  - section 1 `.fwimage` (0x40, 0x0505b000 = 84,258,816 B) IS the GFW
    archive the campaign committed as `binaries/fwimage.bin` — byte-exact
    (containment full @0x40, sha256-cross-checked).
  - `.fwversion` = b"610.57.04\\0"; `.note.gnu.build-id` = GNU\\0 4f09703c…;
    TWELVE `.fwsignature_*` sections (gr10x, gb20x/y, gb10x/y, gh100,
    ad10x, ga10x + cc_/spdm_lite_ variants), 0x1000 each — the per-chip
    SEC2 signature blobs (the loader builds the names at runtime: the
    closed RM blob carries only the `fwsignature_`/`fwsignature_cc_`/
    `fwsignature_spdm_lite_` prefixes, plus the `.fwimage`/`.fwversion`
    literals).
  - `.symtab`/`.strtab`: the `_binary_..._start/_end/_size` symbols bound
    to `.fwimage`, whose names encode the NVIDIA build path
    (`…/resman/build/gsp/__out/Linux_amd64_release/LibOS/riscv64/release/
    firmware/ga10x/firmware.bin`, the r610_85 build).
  - NO compressed stream anywhere in the load path (zero LZ4-frame /
    zstd frame magics; the 12 `1f 8b 08` patterns inside the RM image
    inflate to 512 KiB of zeros each — data artifacts, not container
    compression). The LZ4 lane of findings-4.24-gsp-lz.md §4 is CLOSED
    with evidence: there is nothing compressed to re-encode.

WHAT THIS TOOL DOES:
  verify   — structural validation of a container (header, table, section
             sizes, version string).
  extract  — write `.fwimage` out (the campaign's fwimage.bin should be
             reproduced byte-exact).
  patch    — SAME-SIZE byte patch inside `.fwimage`, then rebuild the
             container. The rebuild guarantees: the output differs from
             the input EXACTLY on the patched byte range (nothing else —
             proven by tests), and re-parses structurally valid.
  rebuild  — from-parts reconstruction (header + section data + inert
             slivers + section table) — byte-exact on unchanged input.

HONEST LEDGER:
  - Same-size patches only (the u32-class patch the campaign needs).
    A size-changing rebuild would re-layout the section offsets after
    the modified section and re-emit e_shoff — DESIGNED, NOT EXERCISED.
  - The signature sections are COPIED verbatim. A patched .fwimage will
    (predictably) fail the SEC2 signature check on stock load paths.
    Building signatures is out of scope — the campaign's documented
    lane is driver-side. This tool is the byte-precise packaging half.
"""
import struct
import sys
from pathlib import Path

EHDR_FMT = "<16sHHIQQQIHHHHHH"
EHDR_SIZE = struct.calcsize(EHDR_FMT)          # 64
SHDR_FMT = "<IIQQQQIIQQ"
SHDR_SIZE = struct.calcsize(SHDR_FMT)          # 64

# ------------------------------------------------ RISC-V constant patching
# (pass 4.30, task 4). The mission's premise said the RM's 250000 constants
# sit as SIX u32 words (0x0003D090 LE) at six VAs — FALSIFIED on the bytes:
# the pattern 90 d0 03 00 occurs ZERO times in the whole 84,258,816-B
# fwimage. The REAL encoding (proven, exhaustive 2-byte-step scan): SIX
# lui+addi/addiw instruction PAIRS materializing 250000 as imm hi=0x3d /
# lo=0x090 (six in rm-full.elf at the mission's exact VAs — its VA list was
# computed on rm-full.elf, whose code LOAD has p_offset 0x40 — and six in
# gsp-rm-17MB.bin at a uniform -0x78 shift). A minimal same-size patch
# rewrites BOTH words (8 B per site); the bytes that actually DIFFER are
# only the immediate bytes (3 per site for these values — two in lui, one
# in addi — the rd/opcode bytes are shared), i.e. 18 bytes differ while
# 48 are rewritten. The mission's "exactly 24 bytes differ (6x4)" was
# itself a consequence of the falsified u32 premise.

def riscv_split(value: int):
    """The canonical lui+addi decomposition: value == (hi<<12) + lo with
    lo a SIGNED 12-bit integer. Returns (hi, lo) — the same split the
    compiler emits for `li`."""
    hi = (value + 0x800) >> 12
    lo = value - (hi << 12)
    assert -0x800 <= lo <= 0x7FF, hex(value)
    return hi, lo


def riscv_lui_addi_sites(blob: bytes, value: int):
    """Every lui+addi/addiw pair in `blob` that materializes `value`.

    Exhaustive at 2-byte steps (the C extension makes 2-byte instruction
    alignment legal; two of the six real 250000 sites sit at 2 mod 4).
    Each hit: (offset, rd, op) with op in {'addi','addiw'}; the pair is
    [lui rd, hi] @off ; [addi/addiw rd, rd, lo] @off+4.
    """
    hi, lo = riscv_split(value)
    lo_u = lo & 0xFFF
    sites = []
    for off in range(0, len(blob) - 8, 2):
        (w,) = struct.unpack_from("<I", blob, off)
        if (w & 0x7F) != 0x37 or (w >> 12) != hi:
            continue
        rd = (w >> 7) & 0x1F
        if rd == 0:
            continue                      # lui x0 = the canonical NOP
        (w2,) = struct.unpack_from("<I", blob, off + 4)
        opc = w2 & 0x7F
        if opc not in (0x13, 0x1B):
            continue
        if ((w2 >> 12) & 7) != 0:         # funct3 must be ADD
            continue
        if ((w2 >> 15) & 0x1F) != rd or ((w2 >> 7) & 0x1F) != rd:
            continue
        if (w2 >> 20) != lo_u:
            continue
        sites.append((off, rd, "addi" if opc == 0x13 else "addiw"))
    return sites


def patch_rm_constant(fw: "GspFw", rm_fw_off: int, rm_size: int,
                      old_value: int, new_value: int,
                      expected_sites: int = 6):
    """Replace every lui+addi materialization of old_value inside the rm
    component (fwimage-relative window [rm_fw_off, rm_fw_off+rm_size)) by
    new_value, then rebuild the container.

    Returns (blob, sites). Every site is re-decoded from the bytes and
    re-verified before writing; the rd register and the addi/addiw opcode
    are preserved; only the immediates change. Same-size by construction.
    """
    img = fw.fwimage()
    if rm_fw_off < 0 or rm_fw_off + rm_size > len(img):
        raise ValueError("rm window outside .fwimage")
    rm = img[rm_fw_off:rm_fw_off + rm_size]
    if rm[:4] != b"\x7fELF":
        raise ValueError("the rm window does not start with the ELF magic "
                         "(wrong offset?)")
    old_hi, old_lo = riscv_split(old_value)
    new_hi, new_lo = riscv_split(new_value)
    sites = riscv_lui_addi_sites(rm, old_value)
    if len(sites) != expected_sites:
        raise ValueError(f"expected {expected_sites} sites of {old_value:#x} "
                         f"in the rm window, found {len(sites)}")
    patched = bytearray(rm)
    for off, rd, op in sites:
        (w,) = struct.unpack_from("<I", rm, off)
        if (w >> 12) != old_hi:
            raise ValueError(f"site @0x{off:x}: lui imm {(w>>12):#x} != "
                             f"the canonical {old_hi:#x}")
        opc = 0x13 if op == "addi" else 0x1B
        new_lui = (new_hi << 12) | (rd << 7) | 0x37
        new_add = (new_lo & 0xFFF) << 20 | (rd << 15) | (rd << 7) | opc
        struct.pack_into("<II", patched, off, new_lui, new_add)
    new_img = img[:rm_fw_off] + bytes(patched) + img[rm_fw_off + rm_size:]
    blob = fw.rebuild({FW_IMAGE: new_img})
    return blob, sites


SHT_PROGBITS = 1
FW_IMAGE = ".fwimage"
FW_VERSION = ".fwversion"
FW_SIG_PREFIX = ".fwsignature_"


def _ehdr(data):
    (e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from(EHDR_FMT, data, 0)
    return dict(e_ident=e_ident, e_type=e_type, e_machine=e_machine,
                e_version=e_version, e_entry=e_entry, e_phoff=e_phoff,
                e_shoff=e_shoff, e_flags=e_flags, e_ehsize=e_ehsize,
                e_phentsize=e_phentsize, e_phnum=e_phnum,
                e_shentsize=e_shentsize, e_shnum=e_shnum,
                e_shstrndx=e_shstrndx)


def _shdrs(data, ehdr):
    out = []
    for i in range(ehdr["e_shnum"]):
        off = ehdr["e_shoff"] + i * ehdr["e_shentsize"]
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
            SHDR_FMT, data, off)
        out.append(dict(index=i, sh_name=sh_name, sh_type=sh_type,
                        sh_flags=sh_flags, sh_addr=sh_addr,
                        sh_offset=sh_offset, sh_size=sh_size,
                        sh_link=sh_link, sh_info=sh_info,
                        sh_addralign=sh_addralign, sh_entsize=sh_entsize))
    return out


def _names(data, ehdr, shdrs):
    st = shdrs[ehdr["e_shstrndx"]]
    strtab = data[st["sh_offset"]:st["sh_offset"] + st["sh_size"]]
    for s in shdrs:
        end = strtab.find(b"\x00", s["sh_name"])
        s["name"] = strtab[s["sh_name"]:end].decode("utf-8", "replace")
    return shdrs


class GspFw:
    """A parsed gsp_ga10x-style container."""

    def __init__(self, data: bytes):
        self.data = data
        self.ehdr = _ehdr(data)
        self.shdrs = _names(data, self.ehdr, _shdrs(data, self.ehdr))
        self.by_name = {s["name"]: s for s in self.shdrs if s["name"]}

    # -- accessors ----------------------------------------------------
    def section(self, name):
        s = self.by_name.get(name)
        if s is None:
            return None
        return self.data[s["sh_offset"]:s["sh_offset"] + s["sh_size"]]

    def fwimage(self):
        return self.section(FW_IMAGE)

    def fwversion(self):
        raw = self.section(FW_VERSION) or b""
        return raw.split(b"\x00")[0].decode("ascii", "replace")

    def signatures(self):
        return {s["name"][len(FW_SIG_PREFIX):]: self.section(s["name"])
                for s in self.shdrs
                if s["name"].startswith(FW_SIG_PREFIX)}

    # -- validation ---------------------------------------------------
    def verify(self):
        """Structural checks. Returns (ok, [issues]). Byte-derived only."""
        issues = []
        d, e = self.data, self.ehdr
        if d[:4] != b"\x7fELF":
            issues.append("no ELF magic")
        if e["e_phnum"] != 0:
            issues.append(f"unexpected program headers ({e['e_phnum']})")
        if e["e_shentsize"] != SHDR_SIZE:
            issues.append(f"shentsize {e['e_shentsize']} != 64")
        table_end = e["e_shoff"] + e["e_shnum"] * e["e_shentsize"]
        if table_end != len(d):
            issues.append(f"section table end {table_end:#x} != file size {len(d):#x}")
        if FW_IMAGE not in self.by_name:
            issues.append("missing .fwimage")
        if FW_VERSION not in self.by_name:
            issues.append("missing .fwversion")
        if not self.signatures():
            issues.append("no .fwsignature_* sections")
        # section ranges must stay in the data region (before the table)
        for s in self.shdrs:
            if s["sh_type"] == 8:      # NOBITS occupies no file space
                continue
            end = s["sh_offset"] + s["sh_size"]
            if end > e["e_shoff"]:
                issues.append(f"section {s['name']!r} crosses the table boundary")
        # overlapping sections (excluding the NULL section)
        spans = sorted((s["sh_offset"], s["sh_offset"] + s["sh_size"], s["name"])
                       for s in self.shdrs
                       if s["index"] != 0 and s["sh_type"] != 8 and s["sh_size"])
        for a, b in zip(spans, spans[1:]):
            if a[1] > b[0]:
                issues.append(f"sections {a[2]!r} and {b[2]!r} overlap")
        # .fwversion must be printable ASCII digits/dots/dashes + NUL
        raw = self.section(FW_VERSION) or b""
        if raw:
            txt = raw[:-1] if raw[-1:] == b"\x00" else raw
            ok_chars = all(48 <= c <= 57 or c in (46, 45) for c in txt)
            if raw[-1:] != b"\x00" or not ok_chars:
                issues.append(f".fwversion malformed: {raw!r}")
        return (not issues, issues)

    # -- rebuild ------------------------------------------------------
    def rebuild(self, section_data=None):
        """From-parts reconstruction.

        section_data: optional {name: bytes} overrides (same-size
        enforced). Inert bytes (the alignment slivers no section covers)
        are copied from the source container — the only honest from-parts
        policy, since their content carries no structural meaning.
        """
        e = self.ehdr
        out = bytearray(len(self.data))
        out[0:EHDR_SIZE] = self.data[0:EHDR_SIZE]
        covered = bytearray(len(self.data))     # coverage bitmap
        for s in self.shdrs:
            if s["index"] == 0 or s["sh_type"] == 8 or s["sh_size"] == 0:
                continue
            payload = self.data[s["sh_offset"]:s["sh_offset"] + s["sh_size"]]
            if section_data and s["name"] in section_data:
                payload = section_data[s["name"]]
                if len(payload) != s["sh_size"]:
                    raise ValueError(
                        f"size-changing rebuild not supported: {s['name']} "
                        f"{len(payload)} != {s['sh_size']} (designed, not exercised)")
            out[s["sh_offset"]:s["sh_offset"] + s["sh_size"]] = payload
            for i in range(s["sh_offset"], s["sh_offset"] + s["sh_size"]):
                covered[i] = 1
        # the section table itself
        table_end = e["e_shoff"] + e["e_shnum"] * e["e_shentsize"]
        out[e["e_shoff"]:table_end] = self.data[e["e_shoff"]:table_end]
        for i in range(e["e_shoff"], table_end):
            covered[i] = 1
        # inert slivers: copy from source
        for i in range(len(self.data)):
            if not covered[i]:
                out[i] = self.data[i]
        return bytes(out)

    def patch_fwimage(self, fw_offset: int, new_bytes: bytes):
        """Same-size patch inside .fwimage (fwimage-relative offset).

        Returns the rebuilt container bytes. Guarantees: the ONLY bytes
        that differ from the source are the patched range.
        """
        s = self.by_name[FW_IMAGE]
        if fw_offset < 0 or fw_offset + len(new_bytes) > s["sh_size"]:
            raise ValueError(f"patch range [0x{fw_offset:x}, 0x{fw_offset+len(new_bytes):x}) "
                             f"outside .fwimage (size 0x{s['sh_size']:x})")
        old = self.data[s["sh_offset"] + fw_offset:
                        s["sh_offset"] + fw_offset + len(new_bytes)]
        if old == new_bytes:
            raise ValueError("patch is a no-op (bytes already equal)")
        img = bytearray(self.fwimage())
        img[fw_offset:fw_offset + len(new_bytes)] = new_bytes
        return self.rebuild({FW_IMAGE: bytes(img)})


# ---------------------------------------------------------------- CLI
def _cli():
    if len(sys.argv) < 3:
        print(__doc__)
        print("usage: gspbuild.py verify <container>\n"
              "       gspbuild.py extract <container> <out.fwimage>\n"
              "       gspbuild.py patch <container> <fw_off_hex> <hexbytes> <out>\n"
              "       gspbuild.py patchrm <container> <rm_off_hex> <rm_size_hex> "
              "<old> <new> <out>  [sites=N]")
        return 2
    cmd, path = sys.argv[1], Path(sys.argv[2])
    fw = GspFw(path.read_bytes())
    print(f"container: {path} ({len(fw.data):,} B)  version={fw.fwversion()}  "
          f"sections={len(fw.shdrs)}  signatures={sorted(fw.signatures())}")
    if cmd == "verify":
        ok, issues = fw.verify()
        for i in issues:
            print("  ISSUE:", i)
        print("VERDICT:", "STRUCTURALLY VALID" if ok else "INVALID")
        return 0 if ok else 1
    if cmd == "extract":
        out = Path(sys.argv[3])
        out.write_bytes(fw.fwimage())
        print(f"wrote {out} ({len(fw.fwimage()):,} B)")
        return 0
    if cmd == "patchrm":
        # gspbuild.py patchrm <container> <rm_off_hex> <rm_size_hex> <old> <new> <out> [sites=N]
        rm_off = int(sys.argv[3], 16)
        rm_size = int(sys.argv[4], 16)
        old_v = int(sys.argv[5], 0)
        new_v = int(sys.argv[6], 0)
        out = Path(sys.argv[7])
        expect = int(sys.argv[8].split("=")[1]) if len(sys.argv) > 8 else 6
        blob, sites = patch_rm_constant(fw, rm_off, rm_size, old_v, new_v,
                                        expected_sites=expect)
        out.write_bytes(blob)
        diffs = [i for i in range(len(fw.data)) if fw.data[i] != blob[i]]
        # the differing bytes must sit inside the sites' rewritten windows
        fw_abs = fw.by_name[FW_IMAGE]["sh_offset"]
        windows = sorted(set(fw_abs + rm_off + o + k
                             for o, rd, op in sites for k in range(8)))
        inside = [i for i in diffs if i in set(windows)]
        ok_runs = len(inside) == len(diffs) and len(diffs) > 0
        ok, issues = GspFw(blob).verify()
        print(f"patchrm: {len(sites)} site(s) of {old_v} -> {new_v} "
              f"(lui+addi pairs, rm @fwimage+0x{rm_off:x})")
        for (off, rd, op) in sites:
            print(f"  site rm+0x{off:x} rd=x{rd} {op}")
        print(f"diff vs source: {len(diffs)} byte(s) differ "
              f"({len(windows)} rewritten), all inside the sites: {ok_runs}")
        print("re-parse:", "VALID" if ok else f"INVALID {issues}")
        return 0 if ok and ok_runs else 1
    if cmd == "patch":
        fw_off = int(sys.argv[3], 16)
        new = bytes.fromhex(sys.argv[4])
        out = Path(sys.argv[5])
        blob = fw.patch_fwimage(fw_off, new)
        # the minimal-diff proof, printed
        diffs = [i for i in range(len(fw.data)) if fw.data[i] != blob[i]]
        contig = diffs == list(range(diffs[0], diffs[0] + len(diffs))) if diffs else True
        out.write_bytes(blob)
        ok, issues = GspFw(blob).verify()
        print(f"patched {len(new)} B @fwimage+0x{fw_off:x} -> {out}")
        if diffs:
            print(f"diff vs source: {len(diffs)} byte(s), contiguous={contig}, "
                  f"first=0x{diffs[0]:x} last=0x{diffs[-1]:x}")
        else:
            print("diff vs source: none (unexpected)")
        print("re-parse:", "VALID" if ok else f"INVALID {issues}")
        return 0 if ok and contig and diffs else 1
    print("unknown command:", cmd)
    return 2


if __name__ == "__main__":
    sys.exit(_cli())
