#!/usr/bin/env python3
"""gx2-bit — the GPU ring-2 instrument (the BIT lens + the memory grammar).

Tracked in gpu-lab/lab/ (the fw33/fw37 precedent). Stdlib-only. Zero
hardware writes; filesystem writes are the JSON registers named on the
command line.

Imported grammar, never transcribed from memory:
  * BIT header: signature `FF B8 'B' 'I' 'T' 00`; version u16@+6 (0x0100);
    hlen u8@+8 (expect 12); rlen u8@+9 (expect 6); entry count u8@+10;
    the hlen header bytes must sum to 0 mod 256. Token record: type u8@0,
    version u8@1, table length u16@2, table offset u16@4 — offsets are
    RELATIVE TO THE LEGACY IMAGE BASE. Imported file-by-file from
    envytools nvbios/bit.c:70-133 and cross-checked against
    nvidia-bios-reader src/nvbios_reader.cpp:256-275 (they agree).
  * the BIT token-type nameplate: envytools bit.c:35-68 ('M' mem v1/v2,
    'P' power v1/v2, 'C' clock, 'u' UEFI, 'p' PMU/Falcon, 'i' info, ...).
  * the memory grammar: token 'M' v2, group count u8@0, translation
    pointer u16@+1, memory-info pointer u16@+3; info table header
    version/hlen/rlen/count u8@0..3; descriptor u32 per record with the
    fields below. Imported from nvidia-bios-reader
    src/nvbios_reader.cpp:420-478 and its field() decoder.

Modes:
  bit <rom>...          BIT header + token census + 'M' memory decode
  pair <a> <b>          the first GPU pair law: token sets + memory tables
  selftest              two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

BIT_SIGNATURE = b"\xff\xb8BIT\x00"

# envytools bit.c:35-68 — the nameplate only; parsing stays measured.
BIT_TYPE_NAMES = {
    "2": "i2c", "A": "analog", "B": "biosdata", "C": "clock",
    "c": "32bit", "D": "dfp-panel", "d": "dp", "I": "nvinit",
    "i": "info", "L": "lvds", "M": "memory", "N": "nop",
    "P": "power", "p": "pmu-falcon", "R": "bridge-fw", "S": "string",
    "T": "tmds", "U": "display", "u": "uefi", "V": "virtual-strap",
    "x": "mxm",
}

# nvidia-bios-reader decoders, imported VERBATIM from
# src/nvbios_reader.cpp:330-341 (memory_type) and :344-356 (memory_vendor).
# First transcription attempt was written from memory and WRONG (it called
# code 9 "GDDR5"); the source decided — this table is the corrected import.
MEMORY_TYPES = {0: "DDR2", 1: "DDR3", 2: "GDDR3", 3: "GDDR5", 6: "HBM2",
                9: "GDDR6", 10: "GDDR6X", 15: "Skip"}
MEMORY_VENDORS = {1: "Samsung", 2: "Qimonda/Infineon", 3: "Elpida",
                  4: "Etron", 5: "Nanya", 6: "Hynix", 7: "ProMOS/Mosel",
                  8: "Winbond", 9: "ESMT", 15: "Micron"}


def u8(data: bytes, off: int) -> int:
    return data[off]


def u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "little")


def field(value: int, low: int, high: int) -> int:
    width = high - low + 1
    return (value >> low) & ((1 << width) - 1)


def find_legacy(data: bytes) -> dict | None:
    for base in range(0, len(data) - 0x20, 0x200):
        if data[base] == 0x55 and data[base + 1] == 0xAA:
            pcir = base + u16(data, base + 0x18)
            if data[pcir : pcir + 4] == b"PCIR" and data[pcir + 0x14] == 0:
                return {"base": base, "length": u16(data, pcir + 0x10) * 512}
    return None


def parse_bit(data: bytes, legacy: dict) -> dict:
    base = legacy["base"]
    bit_off = data.find(BIT_SIGNATURE, base, base + legacy["length"])
    if bit_off < 0:
        return {"error": "BIT signature not found in legacy image"}
    version = u16(data, bit_off + 6)
    hlen = u8(data, bit_off + 8)
    rlen = u8(data, bit_off + 9)
    count = u8(data, bit_off + 10)
    checksum = sum(data[bit_off + i] for i in range(hlen)) & 0xFF
    tokens = []
    for i in range(count):
        off = bit_off + hlen + i * rlen
        t_type = chr(u8(data, off))
        tokens.append(
            {
                "type": t_type,
                "name": BIT_TYPE_NAMES.get(t_type, "UNKNOWN"),
                "version": u8(data, off + 1),
                "table_length": u16(data, off + 2),
                "table_offset_rel": u16(data, off + 4),
                "table_offset_abs": base + u16(data, off + 4),
                "record_offset": off,
            }
        )
    return {
        "signature_offset": bit_off,
        "image_rel": bit_off - base,
        "version": f"{version >> 8}.{version & 0xFF}",
        "hlen": hlen,
        "rlen": rlen,
        "entry_count": count,
        "checksum_zero": checksum == 0,
        "tokens": tokens,
    }


def decode_memory(data: bytes, legacy: dict, bit: dict) -> dict | None:
    tok = next((t for t in bit.get("tokens", []) if t["type"] == "M"), None)
    if tok is None:
        return None
    base = legacy["base"]
    tok_off = base + tok["table_offset_rel"]
    group_count = u8(data, tok_off)
    translation_ptr = u16(data, tok_off + 1)
    info_ptr = u16(data, tok_off + 3)
    translation = [u8(data, base + translation_ptr + i) for i in range(group_count)]
    table = base + info_ptr
    mt_version = u8(data, table)
    hlen = u8(data, table + 1)
    rlen = u8(data, table + 2)
    count = u8(data, table + 3)
    entries = []
    for i in range(count):
        off = table + hlen + i * rlen
        d = u32(data, off)
        mtype = field(d, 0, 3)
        entry = {
            "index": i,
            "offset": off,
            "descriptor": f"{d:08x}",
            "memory_type_code": mtype,
            "memory_type": MEMORY_TYPES.get(mtype, f"code-{mtype}"),
            "strap_code": field(d, 4, 7),
            "variant_index": field(d, 8, 11),
            "vendor_code": field(d, 12, 15),
            "vendor": (MEMORY_VENDORS.get(field(d, 12, 15), f"code-{field(d, 12, 15)}") if mtype != 0xF else None),
            "revision_code": field(d, 16, 19),
            "density_code": field(d, 20, 23),
            "organization_code": field(d, 24, 26),
            "feature_code": field(d, 27, 31),
            "physical_straps": [p for p, v in enumerate(translation) if v == i],
        }
        entries.append(entry)
    return {
        "token_offset": tok_off,
        "group_count": group_count,
        "translation": translation,
        "info_table_offset": table,
        "info_table_version": mt_version,
        "info_header_length": hlen,
        "info_record_length": rlen,
        "info_record_count": count,
        "entries": entries,
    }


def anatomy(path: Path) -> dict:
    data = path.read_bytes()
    legacy = find_legacy(data)
    if legacy is None:
        return {"file": path.name, "error": "no legacy x86 image"}
    bit = parse_bit(data, legacy)
    mem = decode_memory(data, legacy, bit)
    return {
        "file": path.name,
        "size": len(data),
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        "legacy_image": legacy,
        "bit": bit,
        "memory": mem,
    }


def pair(a: dict, b: dict) -> dict:
    def tokset(x):
        return sorted((t["type"], t["version"], t["table_length"], t["table_offset_rel"]) for t in x["bit"]["tokens"])

    sa, sb = tokset(a), tokset(b)
    ma, mb = a.get("memory"), b.get("memory")
    mem_delta = None
    if ma and mb:
        desca = [e["descriptor"] for e in ma["entries"]]
        descb = [e["descriptor"] for e in mb["entries"]]
        mem_delta = {
            "translation_equal": ma["translation"] == mb["translation"],
            "geometry_equal": (ma["info_record_length"], ma["info_record_count"]) == (mb["info_record_length"], mb["info_record_count"]),
            "descriptors_only_a": sorted(set(desca) - set(descb)),
            "descriptors_only_b": sorted(set(descb) - set(desca)),
        }
    return {
        "pair": [a["file"], b["file"]],
        "token_set_equal": sa == sb,
        "tokens_only_a": [t for t in sa if t not in sb],
        "tokens_only_b": [t for t in sb if t not in sa],
        "bit_table_length_deltas": {
            t[0]: (x["table_length"], y["table_length"])
            for x, y in zip(a["bit"]["tokens"], b["bit"]["tokens"])
            if x["table_length"] != y["table_length"]
        },
        "memory_delta": mem_delta,
    }


def selftest(register_path: Path, corpus_dir: Path) -> int:
    reg = json.loads(register_path.read_text())
    failures = []
    for spec in reg["specimens"]:
        name = spec["file"]
        p = corpus_dir / name
        if not p.exists():
            failures.append(f"tier-I: corpus file missing: {name}")
            continue
        live = anatomy(p)
        if live["sha256_16"] != spec["sha256_16"]:
            failures.append(f"G-hash {name}: live {live['sha256_16']} != register {spec['sha256_16']}")
            continue
        rbit, lbit = spec["bit"], live["bit"]
        if not lbit.get("checksum_zero"):
            failures.append(f"G-bit-checksum {name}: header checksum non-zero")
        if (lbit["hlen"], lbit["rlen"], lbit["version"]) != (rbit["hlen"], rbit["rlen"], rbit["version"]):
            failures.append(f"G-bit-geometry {name}: live {(lbit['hlen'], lbit['rlen'], lbit['version'])} != register")
        if [t["type"] for t in lbit["tokens"]] != [t["type"] for t in rbit["tokens"]]:
            failures.append(f"G-token-set {name}: token sequence changed")
        rm, lm = spec.get("memory"), live.get("memory")
        if rm and lm:
            if [e["descriptor"] for e in lm["entries"]] != [e["descriptor"] for e in rm["entries"]]:
                failures.append(f"G-memory-descriptors {name}: descriptor set drifted")
            if lm["translation"] != rm["translation"]:
                failures.append(f"G-memory-translation {name}: strap translation drifted")
    print(f"gx2-bit selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["bit", "pair", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx2-bit-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode in ("bit", "pair"):
        if len(args.roms) < (2 if args.mode == "pair" else 1):
            ap.error(f"{args.mode} needs the right number of ROMs")
        specs = [anatomy(Path(p)) for p in args.roms]
        if args.mode == "bit":
            out = {"instrument": "gx2-bit", "ring": 2, "specimens": specs}
        else:
            out = {"instrument": "gx2-bit", "ring": 2, "pairs": [pair(specs[0], specs[1])]}
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
