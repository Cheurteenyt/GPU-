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
from gspbuild import (EHDR_FMT, EHDR_SIZE, SHDR_FMT, SHDR_SIZE, GspFw)

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


if __name__ == "__main__":
    test_synthetic()
    test_real()
    print(f"\n==== {PASS} PASS / {FAIL} FAIL ====")
    sys.exit(1 if FAIL else 0)
