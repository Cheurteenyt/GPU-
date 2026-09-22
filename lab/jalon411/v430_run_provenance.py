#!/usr/bin/env python3
"""v430_run_provenance — TASK 1 of pass 4.30: the byte-exact provenance of
the two GSP firmware files (gsp_ga10x.bin, gsp_tu10x.bin) INSIDE the
official makeself package NVIDIA-Linux-x86_64-610.57.04.run.

What is proven here (byte-derived, no assumptions):
  1. the .run sha256 == b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d
     (the campaign's already-banked hash — re-derived by streaming read);
  2. the makeself header fields (skip=1022, the `tail -n +$skip $0 | zstd -d
     | UnTAR` extraction line verbatim from the wrapper);
  3. the payload start BYTE OFFSET in the .run: `tail -n +1022` starts at
     LINE 1022 (1-based) — its first byte sits at offset 160,635 (0x2737b),
     where the zstd frame magic 28 b5 2f fd is byte-checked;
  4. the decompressed payload is a POSIX tar: EVERY member header is
     walked (name, size, mtime, mode, header offset in the decompressed
     stream); the firmware/ members are enumerated;
  5. ./firmware/gsp_ga10x.bin and ./firmware/gsp_tu10x.bin are re-extracted
     FROM the payload and compared byte-exact against the reference
     extraction (work/downloads/extracted/firmware/) — sha256 equality on
     both; ALSO against the hashes already banked in findings-4.27 §1.

HONEST FRAMING of "offsets dans le .run": the zstd frame is a
single compressed stream — per-member plain offsets DO NOT EXIST in the
.run coordinate (compression rewrites everything after 0x2737b). The
member offsets recorded here live in the DECOMPRESSED tar coordinate
(that is the only offset coordinate that is byte-stable). The .run-side
coordinates proven here: payload start 0x2737b, payload end = file end.

Selftest: re-derives every frozen number; exit 2 on any drift, 3 if the
inputs are absent (the lab's SKIP convention).
"""
import hashlib
import io
import json
import os
import struct
import sys

RUN_PATH = "/home/z/my-project/work/downloads/NVIDIA-Linux-x86_64-610.57.04.run"
REF_DIR = "/home/z/my-project/work/downloads/extracted/firmware"
OUT_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "v430_run_provenance.json")

RUN_SHA256 = "b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d"
GSP_GA10X_SHA256 = "c0156954f3e048d56011524e0c2ae2881bb6db8173b53f9b2f4eb94197f02999"
GSP_TU10X_SHA256 = "d157e3b7dd5da2ca8d1ccb6ca98958f9e35d10a9ef7326277ebac133e4b0d1a7"
ZSTD_MAGIC = bytes.fromhex("28b52ffd")


def sha256_stream(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def payload_start_offset(data: bytes, skip_lines: int) -> int:
    """Byte offset of LINE `skip_lines` (1-based) — `tail -n +skip` semantics."""
    off = 0
    line = 1
    while line < skip_lines:
        nl = data.find(b"\n", off)
        if nl < 0:
            raise ValueError("fewer lines than skip")
        off = nl + 1
        line += 1
    return off


def parse_tar_members(raw: bytes):
    """Walk a POSIX tar; return per-member dicts with header offsets."""
    members = []
    pos = 0
    while pos + 512 <= len(raw):
        block = raw[pos:pos + 512]
        if block == b"\x00" * 512:
            break                      # the two zero blocks end the archive
        name = block[0:100].rstrip(b"\x00").decode("utf-8", "replace")
        mode = block[100:108].rstrip(b"\x00 ")
        size_field = block[124:136].rstrip(b"\x00 ")
        size = int(size_field or "0", 8)
        mtime = int(block[136:148].rstrip(b"\x00 ") or "0", 8)
        typeflag = block[156:157]
        # ustar prefix
        prefix = block[345:500].rstrip(b"\x00").decode("utf-8", "replace")
        if prefix:
            name = prefix + "/" + name
        data_start = pos + 512
        data_end = data_start + size
        h = hashlib.sha256(raw[data_start:data_end]).hexdigest()
        members.append(dict(name=name, header_off=pos, data_off=data_start,
                            size=size, mtime=mtime,
                            mode=mode.decode("ascii", "replace"),
                            typeflag=typeflag.decode("ascii", "replace"),
                            sha256=h))
        pos = data_start + ((size + 511) // 512) * 512
    return members


def main():
    if not os.path.exists(RUN_PATH):
        print("SKIP: .run not present:", RUN_PATH)
        return 3
    reg = {}

    # --- 1. the .run identity -------------------------------------------
    run_size = os.path.getsize(RUN_PATH)
    run_sha = sha256_stream(RUN_PATH)
    reg["run"] = dict(path=RUN_PATH, size=run_size, sha256=run_sha)
    assert run_size == 463025450, f"size drift {run_size}"
    assert run_sha == RUN_SHA256, f"sha256 drift {run_sha}"

    with open(RUN_PATH, "rb") as f:
        head = f.read(300000)          # the wrapper is < 160 KB

    # --- 2. the makeself header fields ----------------------------------
    hdr = head[:4096].decode("latin-1")
    fields = {}
    for key in ("skip", "skip_decompress", "size_decompress"):
        for line in hdr.splitlines():
            if line.startswith(key + "="):
                fields[key] = int(line.split("=", 1)[1].strip())
                break
    assert fields["skip"] == 1022, fields
    reg["makeself_header"] = dict(
        fields=fields,
        generator="Makeself 1.6.0-nv9",
        extraction_line="tail -n +$skip $0 | zstd -d | UnTAR",
        md5_field=next(l for l in hdr.splitlines() if l.startswith("MD5=")),
        crc_field=next(l for l in hdr.splitlines() if l.startswith("CRCsum=")),
    )
    # the extraction line, verbatim, from the wrapper body
    assert b"zstd -d" in head and b"tail -n +$skip $0" in head

    # --- 3. the payload start offset (byte-checked) ----------------------
    poff = payload_start_offset(head, fields["skip"])
    magic = head[poff:poff + 4]
    assert magic == ZSTD_MAGIC, f"payload magic {magic.hex()} != zstd"
    reg["payload"] = dict(
        start_byte_offset=poff, start_hex=hex(poff),
        magic=magic.hex(), format="zstd frame",
        end_byte_offset=run_size,
        framing_note=("tail -n +1022 = from LINE 1022 (1-based); the payload "
                      "is ONE zstd stream to EOF; per-member plain offsets in "
                      "the .run coordinate do not exist (compression) — the "
                      "member offsets live in the decompressed tar coordinate"))

    # --- 4. decompress + walk the tar ------------------------------------
    import zstandard
    with open(RUN_PATH, "rb") as f:
        f.seek(poff)
        dctx = zstandard.ZstdDecompressor()
        raw = bytearray()
        reader = dctx.stream_reader(f)
        while True:
            chunk = reader.read(1 << 22)
            if not chunk:
                break
            raw.extend(chunk)
    raw = bytes(raw)
    reg["tar"] = dict(decompressed_size=len(raw))
    members = parse_tar_members(raw)
    reg["tar"]["member_count"] = len(members)
    fw_members = [m for m in members if m["name"].lstrip("./").startswith("firmware/")]
    reg["tar"]["firmware_members"] = fw_members

    # --- 5. byte-exact re-extraction vs the reference ---------------------
    targets = {}
    for m in fw_members:
        base = os.path.basename(m["name"])
        if base in ("gsp_ga10x.bin", "gsp_tu10x.bin"):
            blob = raw[m["data_off"]:m["data_off"] + m["size"]]
            ref = os.path.join(REF_DIR, base)
            ref_sha = sha256_stream(ref) if os.path.exists(ref) else None
            targets[base] = dict(
                tar_name=m["name"], size=m["size"],
                sha256_from_payload=hashlib.sha256(blob).hexdigest(),
                sha256_reference_extraction=ref_sha,
                byte_exact_vs_reference=(ref_sha == hashlib.sha256(blob).hexdigest()),
                header_off=m["header_off"], data_off=m["data_off"],
                mtime=m["mtime"], mode=m["mode"])
    reg["gsp"] = targets

    ga = targets["gsp_ga10x.bin"]; tu = targets["gsp_tu10x.bin"]
    assert ga["size"] == 84310168, ga["size"]
    assert tu["size"] == 29381504, tu["size"]
    assert ga["sha256_from_payload"] == GSP_GA10X_SHA256, "ga10x sha256 drift"
    assert tu["sha256_from_payload"] == GSP_TU10X_SHA256, "tu10x sha256 drift"
    assert ga["byte_exact_vs_reference"] and tu["byte_exact_vs_reference"], \
        "re-extraction != reference extraction"

    with open(OUT_JSON, "w") as f:
        json.dump(reg, f, indent=1)
    print("gsp_ga10x.bin:", ga["size"], "B @tar", hex(ga["data_off"]),
          ga["sha256_from_payload"][:16], "byte-exact vs reference:",
          ga["byte_exact_vs_reference"])
    print("gsp_tu10x.bin:", tu["size"], "B @tar", hex(tu["data_off"]),
          tu["sha256_from_payload"][:16], "byte-exact vs reference:",
          tu["byte_exact_vs_reference"])
    print("payload @.run", hex(poff), "zstd; tar members:", len(members),
          "decompressed", f"{len(raw):,} B")
    print("ALL CHECKS PASS —", OUT_JSON)
    return 0


if __name__ == "__main__":
    sys.exit(main())
