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
              "       gspbuild.py patch <container> <fw_off_hex> <hexbytes> <out>")
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
