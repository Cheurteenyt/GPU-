#!/usr/bin/env python3
"""gx7-identity — the GPU ring-7 instrument (who the ROM says it is).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar, never transcribed from memory:
  * the 'i' info table: bytes b0..b4 at the table start give the full
    VBIOS version (b3.b2.b1.b0.b4) and the chip code (b3<<8|b2, with
    0x9404 = GA104 per nvidia-bios-reader's chip table). Imported from
    src/nvbios_reader.cpp parse_info.
  * BIOSDATA v2 (the 'B' token): field offsets 0x00 version u32, 0x04
    OEM version u8, 0x05 checksum u8, 0x06 INT15 POST u16, 0x08 INT15
    system u16, 0x0A frame count u16, 0x0C reserved u32, 0x10 max heads
    u8, 0x11 memory-size-report u8, 0x12/0x13 h/v scale u8, 0x14 data
    range table pointer u16, 0x16 ROMpacks ptr u16, 0x18 applied
    ROMpacks ptr u16, 0x1A applied max u8, 0x1B applied count u8, 0x1C
    module-map-external-0 u8, 0x1D compression info ptr u32 — from the
    NVIDIA BIOS Information Table Specification (cloned open-gpu-doc),
    BIT_BIOSDATA (Version 2). The Data Range Table entries are
    spec-named too: image start, BIT end, data resident start/end,
    data discard start/end, end of list.
  * the timing-record census logic and the map grammar come from the
    ring-5 instrument (imported there from the reader).

Modes:
  identity <rom>...      info + BIOSDATA + data range + timing spares
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

CHIP_CODES = {
    0x9002: "TU102", 0x9004: "TU104", 0x9006: "TU106", 0x9016: "TU116",
    0x9017: "TU117", 0x9402: "GA102", 0x9403: "GA103", 0x9404: "GA104",
    0x9406: "GA106", 0x9407: "GA107", 0x9502: "AD102", 0x9503: "AD103",
    0x9504: "AD104", 0x9506: "AD106", 0x9507: "AD107",
}


def u8(d: bytes, off: int) -> int:
    return d[off]


def u16(d: bytes, off: int) -> int:
    return int.from_bytes(d[off : off + 2], "little")


def u32(d: bytes, off: int) -> int:
    return int.from_bytes(d[off : off + 4], "little")


def find_legacy(data: bytes) -> dict:
    for base in range(0, len(data) - 0x20, 0x200):
        if data[base] == 0x55 and data[base + 1] == 0xAA:
            pcir = base + u16(data, base + 0x18)
            if data[pcir : pcir + 4] == b"PCIR" and data[pcir + 0x14] == 0:
                return {"base": base, "length": u16(data, pcir + 0x10) * 512}
    raise SystemExit("no legacy image")


def find_token_abs(data: bytes, legacy: dict, token_type: str) -> dict:
    base = legacy["base"]
    bit_off = data.find(b"\xff\xb8BIT\x00", base, base + legacy["length"])
    hlen, rlen, count = u8(data, bit_off + 8), u8(data, bit_off + 9), u8(data, bit_off + 10)
    for i in range(count):
        off = bit_off + hlen + i * rlen
        if chr(u8(data, off)) == token_type:
            return {
                "version": u8(data, off + 1),
                "table_length": u16(data, off + 2),
                "offset": base + u16(data, off + 4),
            }
    return {}


def decode_biosdata(data: bytes, off: int, length: int) -> dict:
    out = {
        "offset": off,
        "token_length": length,
        "bios_version_u32": f"{u32(data, off):08x}",
        "oem_version": u8(data, off + 0x04),
        "checksum_field": u8(data, off + 0x05),
        "int15_post_callbacks": u16(data, off + 0x06),
        "int15_system_callbacks": u16(data, off + 0x08),
        "frame_count": u16(data, off + 0x0A),
        "max_heads_at_post": u8(data, off + 0x10),
        "memory_size_report": u8(data, off + 0x11),
        "h_scale": u8(data, off + 0x12),
        "v_scale": u8(data, off + 0x13),
        "module_map_external_0": u8(data, off + 0x1C),
    }
    drt = u16(data, off + 0x14)
    legacy = find_legacy(data)
    drt_abs = legacy["base"] + drt
    out["data_range_table"] = {
        "pointer_rel": drt,
        "offset": drt_abs,
        "image_start": u16(data, drt_abs),
        "bit_end": u16(data, drt_abs + 2),
        "data_resident_start": u16(data, drt_abs + 4),
        "data_resident_end": u16(data, drt_abs + 6),
        "data_discard_start": u16(data, drt_abs + 8),
        "data_discard_end": u16(data, drt_abs + 10),
        "end_of_list": u32(data, drt_abs + 12),
    }
    out["token_tail_raw"] = data[off + 0x21 : off + length].hex()
    return out


def decode_info(data: bytes, tok: dict) -> dict:
    off = tok["offset"]
    b0, b1, b2, b3, b4 = (u8(data, off + i) for i in range(5))
    code = (b3 << 8) | b2
    return {
        "offset": off,
        "version_from_info": f"{b3:02X}.{b2:02X}.{b1:02X}.{b0:02X}.{b4:02X}",
        "chip_code": f"{code:04x}",
        "chip": CHIP_CODES.get(code, f"unknown-{code:04x}"),
        "raw_first_0x20": data[off : off + 0x20].hex(),
    }


def timing_spares(data: bytes, ring3: dict, spec3: dict) -> dict:
    ptrs = {p["name"]: p["offset"] for p in spec3["pointers"] if p.get("offset")}
    toff = ptrs["MEMORY TIMINGS"]
    tver, thlen, tbase, text_len, text_cnt, tcnt = (u8(data, toff + i) for i in range(6))
    tstride = tbase + text_len * text_cnt
    reg5 = None
    referenced = set()
    moff = ptrs["MEMORY TIMINGS MAPPING"]
    mcnt = u8(data, moff + 5)
    mhlen, mbase, mext_len, mext_cnt = u8(data, moff + 1), u8(data, moff + 2), u8(data, moff + 3), u8(data, moff + 4)
    mstride = mbase + mext_len * mext_cnt
    for i in range(mcnt):
        ro = moff + mhlen + i * mstride
        for g in range(mext_cnt):
            i_d = u8(data, ro + mbase + g * mext_len)
            if i_d != 0xFF:
                referenced.add(i_d)
    spares = []
    for i in range(tcnt):
        if i in referenced:
            continue
        ro = toff + thlen + i * tstride
        rec = data[ro : ro + tstride]
        spares.append(
            {
                "id": i,
                "is_zero": all(b == 0 for b in rec),
                "is_ff": all(b == 0xFF for b in rec),
            }
        )
    return {
        "table_record_count": tcnt,
        "referenced_count": len(referenced),
        "spare_count": tcnt - len(referenced),
        "spares_zero": sum(1 for s in spares if s["is_zero"]),
        "spares_ff": sum(1 for s in spares if s["is_ff"]),
        "spares_data": tcnt - len(referenced) - sum(1 for s in spares if s["is_zero"] or s["is_ff"]),
    }


def anatomy(path: Path, ring3: dict) -> dict:
    data = path.read_bytes()
    legacy = find_legacy(data)
    out = {
        "file": path.name,
        "size": len(data),
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }
    info_tok = find_token_abs(data, legacy, "i")
    if info_tok:
        out["info"] = decode_info(data, info_tok)
    bios_tok = find_token_abs(data, legacy, "B")
    if bios_tok:
        out["biosdata"] = decode_biosdata(data, bios_tok["offset"], bios_tok["table_length"])
        # the legacy image's own byte-sum vs the declared checksum field
        img = data[legacy["base"] : legacy["base"] + legacy["length"]]
        out["biosdata"]["legacy_image_byte_sum"] = sum(img) & 0xFF
    spec3 = next((s for s in ring3["specimens"] if s["file"] == path.name), None)
    if spec3:
        out["timing_spares"] = timing_spares(data, ring3, spec3)
    return out


def selftest(register_path: Path, corpus_dir: Path) -> int:
    reg = json.loads(register_path.read_text())
    ring3 = json.loads(register_path.with_name("gx3-perf-register.json").read_text())
    failures = []
    for spec in reg["specimens"]:
        name = spec["file"]
        p = corpus_dir / name
        if not p.exists():
            failures.append(f"tier-I: corpus file missing: {name}")
            continue
        live = anatomy(p, ring3)
        if live["sha256_16"] != spec["sha256_16"]:
            failures.append(f"G-hash {name}: drift")
            continue
        if live["info"]["chip"] != spec["info"]["chip"]:
            failures.append(f"G-chip {name}: {live['info']['chip']} != {spec['info']['chip']}")
        if live["info"]["version_from_info"] != spec["info"]["version_from_info"]:
            failures.append(f"G-version {name}: info version drifted")
        rb, lb = spec["biosdata"], live["biosdata"]
        for k in ("bios_version_u32", "oem_version", "checksum_field", "module_map_external_0"):
            if rb[k] != lb[k]:
                failures.append(f"G-biosdata {name}: {k} drifted")
        if rb["data_range_table"] != lb["data_range_table"]:
            failures.append(f"G-drt {name}: data range table drifted")
        rs, ls = spec["timing_spares"], live["timing_spares"]
        for k in ("spare_count", "spares_zero", "spares_ff", "spares_data"):
            if rs[k] != ls[k]:
                failures.append(f"G-spares {name}: {k} drifted")
    print(f"gx7-identity selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["identity", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx7-identity-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "identity":
        ring3 = json.loads((Path(__file__).parent / "gx3-perf-register.json").read_text())
        specs = [anatomy(Path(p), ring3) for p in args.roms]
        out = {"instrument": "gx7-identity", "ring": 7, "specimens": specs}
        text = json.dumps(out, indent=2)
        if args.out:
            args.out.write_text(text + "\n")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    return selftest(args.register, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
