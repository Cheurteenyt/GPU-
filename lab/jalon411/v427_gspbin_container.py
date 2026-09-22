#!/usr/bin/env python3
"""v427 — the gsp_ga10x.bin container vs the campaign's fwimage.bin (pass 4.27).

Questions, in order:
  Q1. What does the OFFICIAL driver-package GSP firmware image look like
      (head bytes, structure)?
  Q2. Does the campaign's fwimage.bin live inside it byte-exact (or the
      reverse)? If not, WHERE do they diverge (first-diff map)?
  Q3. Are there compressed streams (LZ4-frame magic 0x184D2204, LZ4
      block plausibility, zlib/deflate 0x78, zstd 0x28B52FFD)?
  Q4. Where do the known components sit (ELF magics: the dev ELF
      gsp-rm-17MB.bin, the 725KB RISC-V ELF, init/vgpu)?

Every claim the script prints is byte-derived. No fabrication.
"""
import hashlib
import struct
import sys
from pathlib import Path

GSP = Path("/home/z/my-project/work/downloads/extracted/firmware/gsp_ga10x.bin")
FWI = Path("/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/fwimage.bin")

def sha256(p, n=None):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        if n is None:
            h.update(f.read())
        else:
            h.update(f.read(n))
    return h.hexdigest()

def head(p, n=256, width=16):
    data = p.read_bytes()[:n]
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:06x}  {hx:<{width*3}}  {asc}")

def find_all(hay: bytes, needle: bytes, limit=8):
    out = []
    start = 0
    while len(out) < limit:
        i = hay.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out

def u32le(b, off):
    return struct.unpack_from("<I", b, off)[0]

def main():
    gsp = GSP.read_bytes()
    fwi = FWI.read_bytes()
    print(f"gsp_ga10x.bin : {len(gsp):,} B  sha256 {sha256(GSP)}")
    print(f"fwimage.bin   : {len(fwi):,} B  sha256 {sha256(FWI)}")

    print("\n== Q1: gsp_ga10x.bin head 256 ==")
    head(GSP)

    print("\n== Q1b: fwimage.bin head 256 ==")
    head(FWI)

    print("\n== Q2: containment ==")
    # exact full containment either way
    print(f"  fwimage.bin inside gsp_ga10x.bin : {find_all(gsp, fwi) or 'NO (full)'}")
    print(f"  gsp_ga10x.bin inside fwimage.bin : {find_all(fwi, gsp) or 'NO (full)'}")
    # head containment (first 4096 B) — catches 'same content, shifted base'
    h_fwi = fwi[:4096]
    print(f"  fwimage head(4K) inside gsp      : {['0x%x' % i for i in find_all(gsp, h_fwi, 4)] or 'NO'}")
    h_gsp = gsp[:4096]
    print(f"  gsp head(4K) inside fwimage      : {['0x%x' % i for i in find_all(fwi, h_gsp, 4)] or 'NO'}")

    print("\n== Q2b: where do they agree? (matching-block scan, 4K stride) ==")
    common = 0
    first_div = None
    m = min(len(gsp), len(fwi))
    for off in range(0, m, 4096):
        if gsp[off:off+4096] == fwi[off:off+4096]:
            common += 1
        elif first_div is None:
            first_div = off
    total = (m + 4095) // 4096
    print(f"  4K-identical blocks: {common}/{total} ({100*common/total:.1f} %), first differing block @0x{first_div:x}" if first_div is not None else f"  4K-identical blocks: {common}/{total} (identical prefix)")

    print("\n== Q3: compressed-stream magics ==")
    for name, needle in [
        ("LZ4 frame", b"\x04\x22\x4d\x18"),
        ("zstd frame", b"\x28\xb5\x2f\xfd"),
        ("gzip", b"\x1f\x8b\x08"),
        ("zlib(78)", b"\x78\x9c"),
    ]:
        hits = find_all(gsp, needle, 12)
        print(f"  gsp {name:11s}: {len(hits)} hit(s) {['0x%x' % i for i in hits[:8]]}")
        hits2 = find_all(fwi, needle, 12)
        print(f"  fwi {name:11s}: {len(hits2)} hit(s) {['0x%x' % i for i in hits2[:8]]}")

    print("\n== Q4: ELF magics and known components ==")
    for name, path in [
        ("gsp-rm-17MB.bin", "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"),
        ("comp-725KB.bin", "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/comp-725KB.bin"),
        ("bootloader.bin", "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/bootloader.bin"),
    ]:
        p = Path(path)
        if p.exists():
            blob = p.read_bytes()
            hits = find_all(gsp, blob[:64], 4)
            full = find_all(gsp, blob, 2)
            print(f"  {name:16s} ({len(blob):,} B): head-hits in gsp {['0x%x' % i for i in hits]}  full-hits {['0x%x' % i for i in full]}")
    elf = find_all(gsp, b"\x7fELF", 16)
    print(f"  ELF magics in gsp_ga10x.bin: {['0x%x' % i for i in elf]}")

    print("\n== Q5: u32 census of the gsp head (first 128 B as LE u32) ==")
    for i in range(0, 128, 16):
        vals = [u32le(gsp, i + j) for j in range(0, 16, 4)]
        print(f"  +0x{i:02x}: " + "  ".join(f"{v:#010x}" for v in vals))

if __name__ == "__main__":
    sys.exit(main())
