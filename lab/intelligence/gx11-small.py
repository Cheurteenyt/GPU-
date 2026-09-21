#!/usr/bin/env python3
"""gx11-small — the GPU ring-11 instrument (every remaining BIT token,
decoded against the vendor's own specification).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar, never transcribed from memory — the NVIDIA BIOS
Information Table Specification (cloned open-gpu-doc):
  * BIT_STRING_PTRS v2: SignOn/Version/Copyright/OEM-string/VendorName/
    ProductName/ProductRevision, each (u16 pointer, u8 max length),
    strings 0-terminated, pointers legacy-image-relative.
  * BIT_I2C_PTRS: I2CScripts u16, ExtHWMonInit u16.
  * BIT_TMDS_PTRS: TMDS info table pointer u16.
  * BIT_DISPLAY_PTRS: Display scripting table pointer u16 + flags u8
    (bit0 diagnostic overscan, bit1 no-display coprocessor, ...).
  * BIT_CLOCK_PTRS v2: PLL info table pointer u32, VBE mode PCLK table
    pointer u32.
  * BIT_DFP_PTRS / BIT_DP_PTRS / BIT_VIRTUAL_PTRS / BIT_MXM_DATA:
    pointer-table heads; fields beyond the first pointers stay raw.

Modes:
  small <rom>...         decode every remaining token
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


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


def find_bit_tokens(data: bytes, legacy: dict) -> dict:
    base = legacy["base"]
    bit_off = data.find(b"\xff\xb8BIT\x00", base, base + legacy["length"])
    hlen, rlen, count = u8(data, bit_off + 8), u8(data, bit_off + 9), u8(data, bit_off + 10)
    toks = {}
    for i in range(count):
        off = bit_off + hlen + i * rlen
        t = chr(u8(data, off))
        toks[t] = {
            "version": u8(data, off + 1),
            "table_length": u16(data, off + 2),
            "table_offset_abs": base + u16(data, off + 4),
        }
    return toks


def read_string(d: bytes, base: int, ptr: int, size: int) -> str:
    if not ptr:
        return ""
    s = d[base + ptr : base + ptr + size].split(b"\0")[0]
    return s.decode(errors="replace")


def decode_strings(d: bytes, base: int, t: dict) -> dict:
    off = t["table_offset_abs"]
    fields = [
        ("sign_on", 0), ("version", 3), ("copyright", 6), ("oem_string", 9),
        ("vendor_name", 12), ("product_name", 15), ("product_revision", 18),
    ]
    out = {"version": t["version"], "table_offset": off}
    for name, o in fields:
        ptr, size = u16(d, off + o), u8(d, off + o + 2)
        out[name] = {"pointer": ptr, "size": size, "value": read_string(d, base, ptr, size)}
    return out


def decode_i2c(d: bytes, base: int, t: dict) -> dict:
    off = t["table_offset_abs"]
    return {"version": t["version"], "i2c_scripts_ptr": u16(d, off),
            "ext_hwmon_init_ptr": u16(d, off + 2)}


def decode_tmds(d: bytes, base: int, t: dict) -> dict:
    off = t["table_offset_abs"]
    return {"version": t["version"], "tmds_info_ptr": u16(d, off)}


def decode_display(d: bytes, base: int, t: dict) -> dict:
    off = t["table_offset_abs"]
    flags = u8(d, off + 2)
    return {"version": t["version"], "display_scripting_ptr": u16(d, off),
            "flags": flags,
            "flags_bits": {"diagnostic_overscan": bool(flags & 1),
                            "no_display_coproc": bool(flags & 2),
                            "display_fpga": bool(flags & 4)}}


def decode_clock(d: bytes, base: int, t: dict) -> dict:
    off = t["table_offset_abs"]
    return {"version": t["version"], "pll_info_ptr": u32(d, off),
            "vbe_pclk_ptr": u32(d, off + 4),
            "raw": d[off : off + t["table_length"]].hex()}


def decode_small_raw(d: bytes, base: int, t: dict, names: list[str]) -> dict:
    off = t["table_offset_abs"]
    out = {"version": t["version"], "raw": d[off : off + t["table_length"]].hex()}
    for name, o in names:
        out[name] = u16(d, off + o)
    return out


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    legacy = find_legacy(data)
    base = legacy["base"]
    toks = find_bit_tokens(data, legacy)
    out = {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        "token_count": len(toks),
    }
    if "S" in toks:
        out["strings"] = decode_strings(data, base, toks["S"])
    if "2" in toks:
        out["i2c"] = decode_i2c(data, base, toks["2"])
    if "T" in toks:
        out["tmds"] = decode_tmds(data, base, toks["T"])
    if "U" in toks:
        out["display"] = decode_display(data, base, toks["U"])
    if "C" in toks:
        out["clock"] = decode_clock(data, base, toks["C"])
    if "D" in toks:
        out["dfp"] = decode_small_raw(data, base, toks["D"], [("dfp_ptr0", 0)])
    if "d" in toks:
        out["dp"] = decode_small_raw(data, base, toks["d"], [("dp_ptr0", 0)])
    if "V" in toks:
        out["virtual"] = decode_small_raw(data, base, toks["V"], [("virtual_ptr0", 0)])
    if "x" in toks:
        out["mxm"] = decode_small_raw(data, base, toks["x"], [("mxm_ptr0", 0)])
    if "u" in toks:
        t = toks["u"]
        off = t["table_offset_abs"]
        out["uefi"] = {
            "version": t["version"],
            "raw": data[off : off + t["table_length"]].hex(),
            "major_version": u8(data, off),
            "minor_version": u8(data, off + 1),
            "virtual_mem_addr": u32(data, off + 2),
            "virtual_mem_size": u32(data, off + 6),
        }
    return out


def selftest(register_path: Path, corpus_dir: Path) -> int:
    reg = json.loads(register_path.read_text())
    failures = []
    for spec in reg["specimens"]:
        name = spec["file"]
        p = corpus_dir / name
        if not p.exists():
            failures.append(f"tier-I: corpus file missing: {name}")
            continue
        live = analyze(p)
        if live["sha256_16"] != spec["sha256_16"]:
            failures.append(f"G-hash {name}: drift")
            continue
        s = spec["strings"]
        l = live["strings"]
        for k in ("sign_on", "version", "copyright", "vendor_name"):
            if s[k]["value"] != l[k]["value"]:
                failures.append(f"G-strings {name}:{k}: {l[k]['value']!r} != {s[k]['value']!r}")
        if live["display"]["flags"] != spec["display"]["flags"]:
            failures.append(f"G-display-flags {name}: drifted")
        if live["clock"]["pll_info_ptr"] != spec["clock"]["pll_info_ptr"]:
            failures.append(f"G-clock {name}: pll pointer drifted")
    print(f"gx11-small selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["small", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx11-small-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "small":
        specs = [analyze(Path(p)) for p in args.roms]
        out = {"instrument": "gx11-small", "ring": 11, "specimens": specs}
        text = json.dumps(out, indent=2)
        if args.out:
            args.out.write_text(text + "\n")
            print(f"wrote {args.out}")
        return 0

    return selftest(args.register, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
