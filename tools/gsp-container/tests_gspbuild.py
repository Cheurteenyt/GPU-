#!/usr/bin/env python3
"""tests_gspbuild — the verification suite for the gsp container rebuilder.

Two lanes, both byte-derived:
  SYNTHETIC (always run): a mini container built in-test exercises every
  code path (round-trip, verify, tamper detection, patch, error cases)
  without needing the 84 MB artifact.
  REAL (gated on the artifact's presence): the official gsp_ga10x.bin —
  the byte-exact 84 MB round-trip, the fwimage.bin identity, the demo
  same-size patch with the minimal-diff proof.

Run:  python3 tests_gspbuild.py
Env:  GSP_GA10X=<path>   (default: the sandbox acquisition path)
"""
import hashlib
import os
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gspbuild import (EHDR_FMT, EHDR_SIZE, SHDR_FMT, SHDR_SIZE, GspFw,
                      patch_rm_constant, riscv_lui_addi_sites, riscv_split)

REAL = Path(os.environ.get(
    "GSP_GA10X",
    "/home/z/my-project/work/downloads/extracted/firmware/gsp_ga10x.bin"))
FWI = Path(__file__).resolve().parents[2] / "tools/analysis/gsp-extract/binaries/fwimage.bin"

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}" + (f"  [{detail}]" if detail else ""))
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


# ----------------------------------------------------------- synthetic
def mini_container(fwimage: bytes, sliver: bytes = b"\x00\x00") -> bytes:
    """A valid mini container: NULL + .fwimage + .fwversion +
    .fwsignature_test + .shstrtab, with a deliberate inert sliver."""
    fwversion = b"1.2.3\x00"
    sig = bytes(range(256))
    names = [b"", b".fwimage", b".fwversion", b".fwsignature_test", b".shstrtab"]
    shstrtab = b"\x00" + b"\x00".join(names[1:]) + b"\x00"
    name_off = {}
    cur = 0
    for n in names:
        name_off[n] = cur
        cur += len(n) + 1          # every name, including the empty one, owns a NUL
    # layout: ehdr | fwimage | fwversion | sig | shstrtab | sliver | shdrs
    off = EHDR_SIZE
    o_fw = off;            off += len(fwimage)
    o_ver = off;           off += len(fwversion)
    o_sig = off;           off += len(sig)
    o_str = off;           off += len(shstrtab)
    o_slv = off;           off += len(sliver)
    e_shoff = off
    e_shnum = 5
    data = bytearray(off + e_shnum * SHDR_SIZE)
    data[0:EHDR_SIZE] = b"\x7fELF" + b"\x00" * 60   # exact-size: no bytearray resize
    data[o_fw:o_fw + len(fwimage)] = fwimage
    data[o_ver:o_ver + len(fwversion)] = fwversion
    data[o_sig:o_sig + len(sig)] = sig
    data[o_str:o_str + len(shstrtab)] = shstrtab
    data[o_slv:o_slv + len(sliver)] = sliver
    shdrs = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_off[b".fwimage"], 1, 0, 0, o_fw, len(fwimage), 0, 0, 1, 0),
        (name_off[b".fwversion"], 1, 0, 0, o_ver, len(fwversion), 0, 0, 1, 0),
        (name_off[b".fwsignature_test"], 1, 0, 0, o_sig, len(sig), 0, 0, 1, 0),
        (name_off[b".shstrtab"], 3, 0, 0, o_str, len(shstrtab), 0, 0, 1, 0),
    ]
    for i, sh in enumerate(shdrs):
        struct.pack_into(SHDR_FMT, data, e_shoff + i * SHDR_SIZE, *sh)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    struct.pack_into(EHDR_FMT, data, 0, ident, 1, 0xF3, 1, 0, 0, e_shoff,
                     0, EHDR_SIZE, 0, 0, SHDR_SIZE, e_shnum, 4)
    return bytes(data)


def test_synthetic():
    print("== SYNTHETIC ==")
    fwimg = (b"FWIMG-MARKER-" + bytes(96) +
             (bytes(range(256)) * 16)[:4096 - 13 - 96])
    mini = mini_container(fwimg)

    # T1: parse + verify
    fw = GspFw(mini)
    ok, issues = fw.verify()
    check("T1 verify(mini)", ok, "; ".join(issues))
    check("T1 fwversion", fw.fwversion() == "1.2.3", fw.fwversion())
    check("T1 signatures", list(fw.signatures()) == ["test"])

    # T2: byte-exact from-parts round-trip (sliver exercised)
    rb = fw.rebuild()
    check("T2 rebuild == original", rb == mini,
          f"{len(rb)} vs {len(mini)}")

    # T3: same-size patch + minimal-diff proof
    tag = b"PATCHED!"
    blob = fw.patch_fwimage(0x10, tag)
    diffs = [i for i in range(len(mini)) if mini[i] != blob[i]]
    expect = {EHDR_SIZE + 0x10 + i for i in range(len(tag))}
    check("T3 patch diff set", set(diffs) == expect,
          f"{len(diffs)} bytes @0x{min(diffs):x}" if diffs else "none")
    fw2 = GspFw(blob)
    ok2, iss2 = fw2.verify()
    check("T3 patched re-parse valid", ok2, "; ".join(iss2))
    check("T3 fwimage reflects patch", fw2.fwimage()[0x10:0x18] == tag)
    check("T3 untouched bytes intact", fw2.fwimage()[0:0x10] == fwimg[0:0x10])

    # T4: error paths
    try:
        fw.patch_fwimage(0x10, fw.fwimage()[0x10:0x18])
        check("T4 no-op patch rejected", False)
    except ValueError:
        check("T4 no-op patch rejected", True)
    try:
        fw.patch_fwimage(0xFF0, b"\x00" * 32)   # runs past the section end
        check("T4 out-of-range rejected", False)
    except ValueError:
        check("T4 out-of-range rejected", True)
    try:
        fw.rebuild({".fwimage": fwimg + b"X"})
        check("T4 size-change rejected", False)
    except ValueError:
        check("T4 size-change rejected", True)

    # T5: tamper detection
    bad = bytearray(mini)
    bad[fw.by_name[".fwversion"]["sh_offset"]] = ord("Z")   # '1' -> 'Z'
    ok3, iss3 = GspFw(bytes(bad)).verify()
    check("T5 fwversion tamper detected", (not ok3) and
          any("fwversion" in i for i in iss3), "; ".join(iss3))
    bad2 = bytearray(mini)
    off = fw.ehdr["e_shoff"] + 1 * SHDR_SIZE
    sh = list(struct.unpack_from(SHDR_FMT, bad2, off))
    sh[5] += 64                                             # sh_size overlaps
    struct.pack_into(SHDR_FMT, bad2, off, *sh)
    ok4, iss4 = GspFw(bytes(bad2)).verify()
    check("T5 overlap detected", (not ok4) and
          any("overlap" in i for i in iss4), "; ".join(iss4))

    # T6: the RISC-V lui+addi constant patcher (synthetic, task 4)
    import struct as _s
    def lui(rd, hi):
        return _s.pack("<I", (hi << 12) | (rd << 7) | 0x37)
    def addi(rd, rs1, lo, w=False):
        return _s.pack("<I", ((lo & 0xFFF) << 20) | (rs1 << 15) |
                       (rd << 7) | (0x1B if w else 0x13))
    # exact-size assembly (no variable-length slice assignment: the fixture
    # must not resize — the 4.27 ledger's bytearray lesson)
    blob = b"".join([
        lui(15, 0x3D) + addi(15, 15, 0x090),        # +0:  site A (aligned)
        lui(0, 0x3D) + addi(0, 0, 0x090),           # +8:  lui x0 NOP decoy
        b"\x90\x12\x34\x56\x00\x00",                # +16: inert filler (6 B)
        lui(12, 0x3D) + addi(12, 12, 0x090, w=True),  # +22: site B (22%4==2)
        lui(15, 0x3D) + addi(15, 15, 0x091),        # +30: decoy: wrong lo
        lui(15, 0x3D) + addi(16, 15, 0x090),        # +38: decoy: rd2 != rd
    ])
    sites = riscv_lui_addi_sites(blob, 250000)
    check("T6 census = 2 sites (decoys rejected)",
          [(o, rd, op) for o, rd, op in sites] == [(0, 15, "addi"),
                                                   (22, 12, "addiw")],
          str([(hex(o), rd, op) for o, rd, op in sites]))
    patched = bytearray(blob)
    nh, nl = riscv_split(280000)
    for o, rd, op in sites:
        opc = 0x1B if op == "addiw" else 0x13
        _s.pack_into("<I", patched, o, (nh << 12) | (rd << 7) | 0x37)
        _s.pack_into("<I", patched, o + 4, ((nl & 0xFFF) << 20) |
                     (rd << 15) | (rd << 7) | opc)
    patched = bytes(patched)
    diffs = [i for i in range(len(blob)) if blob[i] != patched[i]]
    # the expected diff set is DERIVED from the word encodings (a rewrite
    # of 8 B per site changes only the immediate bytes — the rd/opcode
    # bytes are shared), not hand-counted:
    expect = set()
    for o, rd, op in sites:
        opc = 0x1B if op == "addiw" else 0x13
        old8 = lui(rd, 0x3D) + addi(rd, rd, 0x090, w=(op == "addiw"))
        new8 = lui(rd, 0x44) + addi(rd, rd, 0x5C0, w=(op == "addiw"))
        expect |= {o + k for k in range(8) if old8[k] != new8[k]}
    det6 = (f"{len(diffs)} B @0x{diffs[0]:x},0x{diffs[-1]:x} "
            f"(expected {len(expect)})" if diffs else "none")
    check("T6 synthetic patch diff set == encoding-derived",
          set(diffs) == expect, det6)
    check("T6 new immediates = 0x44 (both sites)",
          (_s.unpack_from("<I", patched, 0)[0] >> 12) == 0x44 and
          (_s.unpack_from("<I", patched, 22)[0] >> 12) == 0x44)
    check("T6 decoys byte-identical", patched[30:46] == blob[30:46])

    # T7: riscv_split sanity (the mission's two values)
    check("T7 split(250000) = (0x3d, 0x090)", riscv_split(250000) == (0x3D, 0x090))
    check("T7 split(280000) = (0x44, 0x5c0)", riscv_split(280000) == (0x44, 0x5C0))


# ----------------------------------------------------------- real
def test_real():
    print("== REAL (gated) ==")
    if not REAL.exists():
        print(f"  SKIP  {REAL} absent — real-file lane not exercised "
              f"(set GSP_GA10X=<path>)")
        return
    raw = REAL.read_bytes()
    fw = GspFw(raw)

    ok, issues = fw.verify()
    check("R1 verify(official)", ok, "; ".join(issues))
    check("R2 fwversion == 610.57.04", fw.fwversion() == "610.57.04",
          fw.fwversion())

    rb = fw.rebuild()
    check("R3 rebuild == original (84 MB byte-exact)", rb == raw,
          f"{len(rb):,} vs {len(raw):,}")

    img = fw.fwimage()
    check("R4 .fwimage size", len(img) == 0x505b000, f"{len(img):,}")
    h_img = hashlib.sha256(img).hexdigest()
    check("R5 .fwimage sha256", h_img ==
          "85213b87db131c17a0ebbb1b44abd18c4fcd58080dd43cde82c5c67a5b08eeec",
          h_img[:16])
    if FWI.exists():
        h_fwi = hashlib.sha256(FWI.read_bytes()).hexdigest()
        check("R6 == campaign fwimage.bin", h_img == h_fwi)

    sigs = fw.signatures()
    check("R7 12 signatures", len(sigs) == 12, str(sorted(sigs)))
    check("R8 each 0x1000", all(len(v) == 0x1000 for v in sigs.values()))
    check("R9 ga10x signature non-zero",
          "ga10x" in sigs and any(sigs["ga10x"]))

    # R10: the demo same-size patch — a zero window inside .fwimage
    probe_off = 0x126000                       # init.elf region-1 zeros
    window = img[probe_off:probe_off + 8]
    if window != bytes(8):
        print(f"  NOTE  fwimage+0x{probe_off:x} not zeros ({window.hex()}), "
              f"hunting the first zero window…")
        probe_off = None
        run = img.find(bytes(4096))
        if run >= 0:
            probe_off = run + 16
    if probe_off is None:
        check("R10 zero window found", False)
        return
    blob = fw.patch_fwimage(probe_off, b"GSP42701")
    diffs = [i for i in range(len(raw)) if raw[i] != blob[i]]
    abs0 = fw.by_name[".fwimage"]["sh_offset"] + probe_off
    contiguous = diffs == list(range(diffs[0], diffs[0] + len(diffs))) if diffs else False
    check("R10 demo patch minimal-diff", contiguous and len(diffs) == 8
          and diffs[0] == abs0,
          f"{len(diffs)} B @0x{diffs[0]:x}" if diffs else "none")
    fw3 = GspFw(blob)
    ok3, iss3 = fw3.verify()
    check("R11 patched container re-parse valid", ok3, "; ".join(iss3))
    check("R12 patched fwversion unchanged", fw3.fwversion() == "610.57.04")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "gsp_ga10x_patched_demo.bin"
        out.write_bytes(blob)
        check("R13 demo artifact written", out.exists()
              and out.stat().st_size == len(raw),
              f"{out} (temp, not committed)")

    # ---------------------------------------------------- task 4 (4.30)
    # the rm component's window inside .fwimage (v430_gfw_map.json):
    # rm.elf spans fwimage [0x19f000, 0x1210000) = 0x1071000 B, flat,
    # byte-exact == tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin.
    # The mission's "6 u32 sites of 250000" premise is FALSIFIED (the u32
    # pattern occurs 0 times in the whole image); the REAL encoding = six
    # lui+addi/addiw pairs at rm-relative offsets
    #   {0x190c6, 0x1a02a, 0x1f09a8, 0x7c467c, 0xb99bb4, 0xb99c90}
    # (the mission's VA list matches rm-full.elf, p_offset 0x40). The
    # minimal same-size patch therefore writes 6x8 = 48 bytes, not 6x4.
    RM_OFF = 0x19f000
    RM_SIZE = 0x1071000
    SITES = [0x190c6, 0x1a02a, 0x1f09a8, 0x7c467c, 0xb99bb4, 0xb99c90]

    # R14: the census on the real rm window
    img4 = fw.fwimage()
    rm_win = img4[RM_OFF:RM_OFF + RM_SIZE]
    check("R14 rm window starts with ELF magic", rm_win[:4] == b"\x7fELF")
    sites4 = riscv_lui_addi_sites(rm_win, 250000)
    check("R14 census == 6 sites at the exact offsets",
          [o for o, rd, op in sites4] == SITES,
          str([hex(o) for o, rd, op in sites4]))

    # R15: the patch — minimal-diff proof. The patch REWRITES 6x8 = 48 B
    # (both instruction words per site); the bytes that actually DIFFER
    # are only the immediate bytes (encoding-derived, 3 per site for
    # 250000->280000: two in lui, one in addi => 18). The mission's
    # "exactly 24 bytes (6x4)" rested on the falsified u32 premise.
    blob4, sites4b = patch_rm_constant(fw, RM_OFF, RM_SIZE, 250000, 280000)
    diffs4 = [i for i in range(len(raw)) if raw[i] != blob4[i]]
    fw_abs = fw.by_name[".fwimage"]["sh_offset"]
    expect48 = set(fw_abs + RM_OFF + s + k for s in SITES for k in range(8))
    expect_diff = set()
    for (s, (o, rd, op)) in zip(SITES, sites4):
        opc = 0x1B if op == "addiw" else 0x13
        old8 = struct.pack("<II", (0x3D << 12) | (rd << 7) | 0x37,
                           (0x090 << 20) | (rd << 15) | (rd << 7) | opc)
        new8 = struct.pack("<II", (0x44 << 12) | (rd << 7) | 0x37,
                           (0x5C0 << 20) | (rd << 15) | (rd << 7) | opc)
        expect_diff |= {fw_abs + RM_OFF + s + k
                        for k in range(8) if old8[k] != new8[k]}
    # the rewrite itself: all 8 bytes of every site window carry new8
    pbw = GspFw(blob4).fwimage()
    all_new = all(
        pbw[RM_OFF + s + k] == struct.pack(
            "<II", (0x44 << 12) | (rd << 7) | 0x37,
            (0x5C0 << 20) | (rd << 15) | (rd << 7) |
            (0x1B if op == "addiw" else 0x13))[k]
        for (s, (o, rd, op)) in zip(SITES, sites4) for k in range(8))
    check("R15 all 6x8 rewritten bytes carry the new encoding", all_new)
    check("R15 diff set == encoding-derived (18 B expected)",
          set(diffs4) == expect_diff,
          f"{len(diffs4)} B differ, {len(expect48)} B rewritten")
    check("R15 every differing byte inside the 6x8 rewrite window",
          set(diffs4) <= expect48 and len(diffs4) == len(expect_diff))

    # R16: the patched words decode to 280000; everything else identical
    pb = GspFw(blob4)
    ok5, iss5 = pb.verify()
    check("R16 patched container re-parse valid", ok5, "; ".join(iss5))
    check("R16 fwversion unchanged", pb.fwversion() == "610.57.04")
    pw = pb.fwimage()
    good = True
    for s, (o, rd, op) in zip(SITES, sites4):
        w, w2 = struct.unpack_from("<II", pw, RM_OFF + s)
        opc = 0x1B if op == "addiw" else 0x13
        good &= (w == (0x44 << 12) | (rd << 7) | 0x37)
        good &= (w2 == (0x5C0 << 20) | (rd << 15) | (rd << 7) | opc)
    check("R16 all 6 pairs now encode 280000 (rd/op preserved)", good)
    import hashlib as _h
    h6 = _h.sha256(blob4).hexdigest()
    print(f"  NOTE  patched container sha256 = {h6} "
          f"(produced in-memory; artifact NOT committed — >5 MB rule)")

    # R17: the negative — a wrong expected count is rejected
    try:
        patch_rm_constant(fw, RM_OFF, RM_SIZE, 250000, 280000,
                          expected_sites=7)
        check("R17 wrong-site-count rejected", False)
    except ValueError:
        check("R17 wrong-site-count rejected", True)
    try:
        patch_rm_constant(fw, RM_OFF + 0x1000, RM_SIZE, 250000, 280000)
        check("R17 non-ELF rm window rejected", False)
    except ValueError:
        check("R17 non-ELF rm window rejected", True)


if __name__ == "__main__":
    test_synthetic()
    test_real()
    print(f"\n==== {PASS} PASS / {FAIL} FAIL ====")
    sys.exit(1 if FAIL else 0)
