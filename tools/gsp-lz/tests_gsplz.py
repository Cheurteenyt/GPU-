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
  T5 campaign artifact:   the 1 MiB code slice + the 4 MiB image head of
                          the flat rm-full.elf (when locally present).
  T6 (4.29) the REAL
      component round-trip:
                          EVERY component binary the campaign ships in
                          tools/analysis/gsp-extract/binaries/ — the
                          bootloader, comp-58KB (vgpu-class), comp-725KB
                          (= vgpu.elf), gsp-rm-17MB (= rm.elf), the PMU
                          WDT image — round-trips byte-exact in BOTH
                          directions, ours and reference-crossed. This is
                          the permanent test the 4.29 brief demands. HONEST
                          SCOPE (v429_lz_pair_forensics.json): these files
                          are the FLAT component ELFs — the test validates
                          the codec ON the real bytes; none of them is a
                          compressed stream (no NVIDIA LZ4 stream exists in
                          the artifact set, v429_lz_package_hunt.json).
                          Runtime note: the battery adds ~40 s (the
                          17,236,632-byte rm.elf compressed once, shared
                          across T1/T2).

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
REAL_BIN_DIR = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/"
REAL_FILES = ["bootloader.bin", "comp-58KB.bin", "comp-725KB.bin",
              "gsp-rm-17MB.bin", "pmu-wdt-41KB.bin"]

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


def t6_real_component_roundtrip():
    """4.29 — the round-trip on the REAL component binaries, permanent.

    Compress once per file, verify the three properties on the shared
    stream: ours round-trips (T1), the reference decodes ours (T2),
    ours decodes the reference (T3).
    """
    for name in REAL_FILES:
        path = REAL_BIN_DIR + name
        if not os.path.exists(path):
            print(f"  [skip] {name} not present")
            continue
        with open(path, "rb") as f:
            data = f.read()
        comp = lz4block.compress(data)             # once, shared
        back = lz4block.decompress(comp, len(data))
        check(f"T6 T1 round-trip {name}", back == data,
              f"({len(data):,} B -> {len(comp):,} B)")
        if HAVE_REF:
            ref = lz4.block.decompress(comp, uncompressed_size=len(data))
            check(f"T6 T2 ref-decodes-ours {name}", ref == data, "")
            ref_comp = lz4.block.compress(data, store_size=False)
            back2 = lz4block.decompress(ref_comp, len(data))
            check(f"T6 T3 ours-decodes-ref {name}", back2 == data,
                  f"(ref stream {len(ref_comp):,} B)")


def main():
    print(f"reference implementation: {'python-lz4 PRESENT' if HAVE_REF else 'ABSENT (T2/T3 skipped)'}")
    print("=== T4 adversarial battery ===")
    t4_adversarial()
    print("=== T5 the campaign artifact ===")
    t5_campaign_artifact()
    print("=== T6 the REAL component round-trip (4.29, permanent) ===")
    t6_real_component_roundtrip()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURES: {FAILURES}")
        sys.exit(1)
    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
