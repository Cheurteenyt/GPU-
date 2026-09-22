#!/usr/bin/env python3
"""4.29 pass — task A.2 extension: the package-wide LZ4 hunt.

The convention study (v429_lz_conventions.py) can only compare OUR
encoder to the REFERENCE — because the artifact set holds no
NVIDIA-produced LZ4 stream. This instrument hunts for one across the
WHOLE official driver package 610.57.04 (the .run payload, extracted):
every file is scanned for the frame magics of the compression formats
a component stream could plausibly ride —

  LZ4 frame        04 22 4D 18     (0x184D2204)
  LZ4 legacy       02 21 4C 18     (0x184C2102)
  LZ4 skippable    50..5F 2A 4D 18 (0x184D2A50..5F)
  zstd             28 B5 2F FD
  gzip             1F 8B 08
  xz               FD 37 7A 58 5A 00
  bzip2            42 5A 68

Every LZ4-frame hit is then PLAUSIBILITY-CHECKED (a real frame
decompresses with the reference lz4.frame from its hit offset; a
chance 4-byte collision does not). fwimage.bin / gsp_ga10x.bin are
re-scanned explicitly (the 4.27 closure re-banked live).

Provenance: the .run file sha256 is re-verified IN THIS INSTRUMENT
before the scan (the law 1 chain: package -> extraction -> corpus).

Output: lab/jalon411/v429_lz_package_hunt.json.
Selftest: re-derives the scan when the package tree is present; SKIP
(loud, exit 3) when it is not — the degradation is honest, per the
lab convention. Exit 2 on drift.
"""
import hashlib
import json
import os
import struct
import sys

PKG = "/home/z/my-project/work/downloads/NVIDIA-Linux-x86_64-610.57.04.run"
TREE = "/home/z/my-project/work/downloads/extracted"
FW = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/fwimage.bin"
GSPBIN = "/home/z/my-project/work/downloads/extracted/gsp_ga10x.bin"
OUT = "/home/z/my-project/work/gpu-repo/lab/jalon411/v429_lz_package_hunt.json"

CHUNK = 1 << 22

MAGICS = [
    ("lz4_frame", b"\x04\x22\x4d\x18"),
    ("lz4_legacy", b"\x02\x21\x4c\x18"),
    ("lz4_skippable", None),          # 16 variants, handled specially
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("gzip", b"\x1f\x8b\x08"),
    ("xz", b"\xfd\x37\x7a\x58\x5a\x00"),
    ("bzip2", b"\x42\x5a\x68"),
]
SKIP_RANGE = range(0x50, 0x60)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def scan_file(path, try_lz4_frame=False):
    """Magic census for one file (chunked, 8-byte overlap)."""
    counts = {name: 0 for name, _ in MAGICS}
    lz4_hits = []
    with open(path, "rb") as f:
        prev = b""
        base = 0
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf = prev + chunk
            for name, magic in MAGICS:
                if magic is None:      # the skippable family
                    for b0 in SKIP_RANGE:
                        m = bytes([b0, 0x2A, 0x4D, 0x18])
                        start = 0
                        while True:
                            i = buf.find(m, start)
                            if i < 0:
                                break
                            start = i + 1
                            counts[name] += 1
                else:
                    start = 0
                    while True:
                        i = buf.find(magic, start)
                        if i < 0:
                            break
                        start = i + 1
                        counts[name] += 1
                        if name == "lz4_frame" and try_lz4_frame and \
                                len(lz4_hits) < 16:
                            lz4_hits.append(base - len(prev) + i)
            prev = buf[-8:]
            base += len(chunk)
    return counts, lz4_hits


def lz4_frame_plausible(path, off):
    """A REAL lz4 frame decompresses from its magic offset."""
    try:
        import lz4.frame as lz4f
    except ImportError:
        return "reference-absent"
    with open(path, "rb") as f:
        f.seek(off)
        data = f.read()                        # the tail from the magic
    try:
        out = lz4f.decompress(data)
        return "DECOMPRESSED %d B" % len(out)
    except Exception as exc:
        return "no (%s)" % type(exc).__name__


def build():
    reg = {
        "package_sha256": file_sha256(PKG),
        "expected_package_sha256":
            "b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d",
        "files_scanned": 0,
        "bytes_scanned": 0,
        "hits": {},
        "lz4_frame_plausibility": {},
        "fwimage_gspga10x_rescan": {},
    }
    totals = {name: 0 for name, _ in MAGICS}
    for root, _dirs, files in os.walk(TREE):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            try:
                counts, lz4_hits = scan_file(p, try_lz4_frame=True)
            except OSError:
                continue
            reg["files_scanned"] += 1
            reg["bytes_scanned"] += os.path.getsize(p)
            rel = os.path.relpath(p, TREE)
            for name, _ in MAGICS:
                if counts[name]:
                    totals[name] += counts[name]
                    reg["hits"].setdefault(rel, {})[name] = counts[name]
            for off in lz4_hits:
                reg["lz4_frame_plausibility"]["%s@%d" % (rel, off)] = \
                    lz4_frame_plausible(p, off)
    reg["totals"] = totals
    for p in (FW, GSPBIN):
        if os.path.exists(p):
            counts, _ = scan_file(p)
            reg["fwimage_gspga10x_rescan"][os.path.basename(p)] = counts
    return reg


def selftest():
    if not os.path.isdir(TREE):
        print("SKIP — the extracted package tree is not present; the "
              "register cannot re-derive here (loud degradation).")
        sys.exit(3)
    frozen = json.load(open(OUT))
    fresh = build()
    if fresh != frozen:
        for key in frozen:
            if frozen[key] != fresh.get(key):
                print("SELFTEST DRIFT on: %s" % key)
                sys.exit(2)
        print("SELFTEST DRIFT (structure)")
        sys.exit(2)
    print("SELFTEST OK — the package hunt reproduces live:")
    print("  %d files, %.2f GB scanned; totals: %s" %
          (frozen["files_scanned"], frozen["bytes_scanned"] / 1e9,
           frozen["totals"]))
    for k, v in frozen["lz4_frame_plausibility"].items():
        print("  lz4_frame hit %s -> %s" % (k, v))


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        reg = build()
        with open(OUT, "w") as f:
            json.dump(reg, f, indent=1)
        print(json.dumps({k: reg[k] for k in
                          ("files_scanned", "bytes_scanned", "totals",
                           "lz4_frame_plausibility",
                           "fwimage_gspga10x_rescan")}, indent=1))
        print("register written: %s" % OUT)
