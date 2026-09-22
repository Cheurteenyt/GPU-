#!/usr/bin/env python3
"""tests_gsplz — the verification suite for tools/gsp-lz/lz4block.py.

The brief's standard: "decompressing your own stream with the documented
algorithm must reproduce the original byte-exactly." Applied in BOTH
directions, against the REFERENCE implementation (python-lz4, which wraps
lz4's official block codec):

  T1 round-trip:          ours.compress -> ours.decompress == original
  T2 reference-decodes-ours:
                          ours.compress -> lz4.block.decompress == original
                          (the compatibility property the gsp.bin path needs:
                           a stream WE produce must satisfy the standard
                           decoder the firmware shape implies)
  T3 ours-decodes-reference:
                          lz4.block.compress -> ours.decompress == original
  T4 adversarial inputs:  zeros / one byte / 3 bytes / overlap runs
                          (offset=1,2,3 RLE shapes) / random data / the real
                          campaign artifact (a 1 MiB slice of the flat RM
                          image) / all-byte-values ramp / length boundaries
                          (15, 255, 270, 65536+ runs).

Run: python3 tests_gsplz.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lz4block

try:
    import lz4.block
    HAVE_REF = True
except ImportError:
    HAVE_REF = False

RM_IMAGE = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/rm-full.elf"

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name} {detail}")
    if not cond:
        FAILURES.append(name)


def roundtrip(data):
    comp = lz4block.compress(data)
    back = lz4block.decompress(comp, len(data))
    return comp, back


def t1_roundtrip(data, name):
    comp, back = roundtrip(data)
    check(f"T1 {name}", back == data,
          f"({len(data):,} B -> {len(comp):,} B)")


def t2_ref_decodes_ours(data, name):
    if not HAVE_REF:
        return
    comp = lz4block.compress(data)
    ref = lz4.block.decompress(comp, uncompressed_size=len(data))
    check(f"T2 ref-decodes-ours {name}", ref == data,
          f"({len(data):,} B -> {len(comp):,} B)")


def t3_ours_decodes_ref(data, name):
    if not HAVE_REF:
        return
    ref_comp = lz4.block.compress(data, store_size=False)
    back = lz4block.decompress(ref_comp, len(data))
    check(f"T3 ours-decodes-ref {name}", back == data,
          f"({len(data):,} B -> {len(ref_comp):,} B)")


def t4_adversarial():
    rng = random.Random(0xC0FFEE)
    cases = [
        ("empty", b""),
        ("one byte", b"\x41"),
        ("three bytes", b"\x41\x42\x43"),
        ("4-byte run (min match)", b"ABCD" * 1000),
        ("RLE offset=1", b"A" * 70000),
        ("RLE offset=2", b"AB" * 40000),
        ("RLE offset=3", b"ABC" * 30000),
        ("all byte values ramp", bytes(range(256)) * 400),
        ("random incompressible 1 MiB", rng.randbytes(1 << 20)),
        ("random structured", bytes(rng.choice(b"ABCD") for _ in range(300000))),
        ("literal-length boundary 14/15/16/270",
         bytes(rng.randbytes(14) + b"MARK" + rng.randbytes(1) +
               b"MARK" + rng.randbytes(15) + b"MARK" + rng.randbytes(16) +
               b"MARK" + rng.randbytes(270) + b"MARK")),
        ("match-length boundary (14..19 + 255+)",
         (b"0123456789ABCDE" + b"F" * 1) * 50 + b"TAIL"),
    ]
    for name, data in cases:
        t1_roundtrip(data, name)
        t2_ref_decodes_ours(data, name)
        t3_ours_decodes_ref(data, name)

    # the literal-run boundary forcing multi-255 extensions: 1 MiB of unique
    # randoms (incompressible) then a 100 kB RLE tail
    data = rng.randbytes(1 << 20) + b"Z" * 100_000
    t1_roundtrip(data, "mixed random + 100kB RLE tail")
    t2_ref_decodes_ours(data, "mixed random + 100kB RLE tail")
    t3_ours_decodes_ref(data, "mixed random + 100kB RLE tail")


def t5_campaign_artifact():
    """a 1 MiB slice of the flat RM image — the real data shape this tool
    exists for"""
    if not os.path.exists(RM_IMAGE):
        print("  [skip] rm-full.elf not present")
        return
    with open(RM_IMAGE, "rb") as f:
        f.seek(0x267fc)                    # the code region around the 4.24 handler
        data = f.read(1 << 20)
    t1_roundtrip(data, "rm-full.elf code slice 1 MiB")
    t2_ref_decodes_ours(data, "rm-full.elf code slice 1 MiB")
    t3_ours_decodes_ref(data, "rm-full.elf code slice 1 MiB")
    with open(RM_IMAGE, "rb") as f:
        f.seek(0x1000000 - 0x1000000)      # the image head (zero-heavy)
        data = f.read(4 << 20)
    t1_roundtrip(data, "rm-full.elf image head 4 MiB")
    t2_ref_decodes_ours(data, "rm-full.elf image head 4 MiB")
    t3_ours_decodes_ref(data, "rm-full.elf image head 4 MiB")


def main():
    print(f"reference implementation: {'python-lz4 PRESENT' if HAVE_REF else 'ABSENT (T2/T3 skipped)'}")
    print("=== T4 adversarial battery ===")
    t4_adversarial()
    print("=== T5 the campaign artifact ===")
    t5_campaign_artifact()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURES: {FAILURES}")
        sys.exit(1)
    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
