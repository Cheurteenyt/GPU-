#!/usr/bin/env python3
"""gx4-clocks — the GPU ring-4 instrument (the clock ladder + the fan/raw map).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar:
  * the Memory Clock Table (P-table pointer 0x04 — envytools calls it
    "MEMORY TIMINGS MAPPING", the NVIDIA spec names it "Memory Clock
    Table"): header version 0x11, header size, base entry size, strap
    entry size, strap entry count, entry count; base entry begins with
    Min Frequency u16 and Max Frequency u16, each [15:14] reserved and
    [13:0] the frequency in MHz. Imported from open-gpu-doc
    MemoryClockTable.html (2018). MEASURED DELTA on Ampere: the 2018
    spec fixes base=20/strap=26 bytes; the GA104 ROMs carry base=86/
    strap=44 — the frequency fields still land where the spec puts
    them, the growth is in later/unknown fields.
  * the Virtual P-state table pointer is P-table offset 0x38 (the spec's
    sample code reads it from bit_P + 0x38); the spec documents ONLY
    version 0x10 (GF11X-GM20X) and warns "structure will change in
    Pascal and later GPUs" — the GA104 table reads version 0x20 and is
    therefore registered as RAW, honestly unknown.
  * the PERFORMANCE table (P 0x00, v0x60) and the FAN tables (P 0x58,
    0x5c) have no public spec and an envytools grammar written for a
    smaller pre-Pascal shape; their records are registered as RAW bytes
    with u16 candidate listings, never interpreted.

The pointer offsets come from the ring-3 register (anchors-before-marks).

Modes:
  clocks <rom>...        decode the ladder, register the raw territory
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

LIVE_MEMORY_CLOCK_MHZ = 6801  # day-0 runtime snapshot (day0/runtime-snapshot.txt)
LIVE_GRAPHICS_CLOCK_MHZ = 1890


def u8(d: bytes, off: int) -> int:
    return d[off]


def u16(d: bytes, off: int) -> int:
    return int.from_bytes(d[off : off + 2], "little")


def freq(raw: int) -> int:
    return raw & 0x3FFF


def decode_memclk(data: bytes, off: int) -> dict:
    ver, hlen, base_len, strap_len, strap_cnt, cnt = (u8(data, off + i) for i in range(6))
    out = {
        "version": f"0x{ver:02x}",
        "header_size": hlen,
        "base_entry_size": base_len,
        "strap_entry_size": strap_len,
        "strap_entry_count": strap_cnt,
        "entry_count": cnt,
        # the same bytes under the nvidia-bios-reader grammar (parse_timings):
        # base_length / extended_length / extended_count / record_count —
        # identical arithmetic, complementary semantics (freq range x
        # extended variants)
        "reader_fields": {
            "map_version": f"0x{ver:02x}",
            "map_header_length": hlen,
            "map_base_length": base_len,
            "map_extended_length": strap_len,
            "map_extended_count": strap_cnt,
            "map_record_count": cnt,
        },
        "spec_2018_delta": {
            "base_entry_size_spec": 20,
            "strap_entry_size_spec": 26,
            "grew": (base_len, strap_len) != (20, 26),
        },
        "entries": [],
    }
    entry_size = base_len + strap_len * strap_cnt
    out["computed_total"] = hlen + entry_size * cnt
    for e in range(cnt):
        eo = off + hlen + e * entry_size
        fmin = freq(u16(data, eo))
        fmax = freq(u16(data, eo + 2))
        out["entries"].append(
            {
                "index": e,
                "offset": eo,
                "min_mhz": fmin,
                "max_mhz": fmax,
                "config0_16": data[eo + 8 : eo + 16].hex(),
                "is_empty": fmin == 0 and fmax == 0,
            }
        )
    active = [e for e in out["entries"] if not e["is_empty"]]
    out["active_bins"] = len(active)
    out["monotone"] = all(
        a["max_mhz"] < b["min_mhz"] for a, b in zip(active, active[1:])
    )
    top = max(active, key=lambda e: e["min_mhz"])
    out["top_bin"] = top
    out["covers_live_memory_clock"] = top["min_mhz"] <= LIVE_MEMORY_CLOCK_MHZ <= top["max_mhz"]
    return out


def raw_records(data: bytes, off: int, hlen: int, rlen: int, count: int, limit: int = 4) -> list[dict]:
    recs = []
    for i in range(min(count, limit)):
        ro = off + hlen + i * rlen
        rec = data[ro : ro + rlen]
        recs.append(
            {
                "index": i,
                "offset": ro,
                "hex": rec.hex(),
                "u16_candidates": [u16(data, ro + j) for j in range(0, rlen - 1, 2)],
            }
        )
    return recs


def decode_geometry(data: bytes, off: int) -> dict:
    return {
        "version": f"0x{u8(data, off):02x}",
        "hlen": u8(data, off + 1),
        "rlen": u8(data, off + 2),
        "count": u8(data, off + 3),
    }


def anatomy(path: Path, ring3: dict) -> dict:
    data = path.read_bytes()
    spec3 = next(s for s in ring3["specimens"] if s["file"] == path.name)
    ptrs = {p["name"]: p["offset"] for p in spec3["pointers"] if p.get("offset")}
    out = {
        "file": path.name,
        "size": len(data),
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }
    if "MEMORY TIMINGS MAPPING" in ptrs:  # the Memory Clock Table
        out["memory_clock_table"] = decode_memclk(data, ptrs["MEMORY TIMINGS MAPPING"])
    if "PERFORMANCE" in ptrs:
        g = decode_geometry(data, ptrs["PERFORMANCE"])
        out["performance_raw"] = {
            **g,
            "records": raw_records(data, ptrs["PERFORMANCE"], g["hlen"], g["rlen"], g["count"]),
            "grammar": "UNKNOWN — v0x60 has no public spec; envytools predates it",
        }
    if "POWER BASE CLOCK" in ptrs or True:
        # the vP-state pointer (spec: bit_P + 0x38). Its header shape does
        # not match the hlen/rlen/count family, so the ring-3 sane_table
        # leaves it unresolved; the spec still NAMES the pointer, so the
        # raw header is captured at the spec-adjusted offset regardless.
        p38 = next((p for p in spec3["pointers"] if p["rel"] == 0x38), None)
        if p38:
            off = p38.get("offset")
            if off is None and p38.get("raw"):
                # re-derive the pointer domain locally (the ring-3 register
                # does not carry the image geometry)
                base = None
                for q in spec3["pointers"]:
                    if q.get("domain") == "image_rel" and q.get("offset") is not None and q.get("raw"):
                        base = q["offset"] - q["raw"]
                        break
                if base is None:
                    for b in range(0, len(data) - 0x20, 0x200):
                        if data[b] == 0x55 and data[b + 1] == 0xAA:
                            pcir = b + u16(data, b + 0x18)
                            if data[pcir : pcir + 4] == b"PCIR" and data[pcir + 0x14] == 0:
                                base = b
                                break
                if base is not None:
                    raw = p38["raw"]
                    efi_len = 0
                    legacy_len = 0
                    pcir = base + u16(data, base + 0x18)
                    legacy_len = u16(data, pcir + 0x10) * 512
                    for b2 in range(base + legacy_len, len(data) - 0x20, 0x200):
                        if data[b2] == 0x55 and data[b2 + 1] == 0xAA:
                            pcir2 = b2 + u16(data, b2 + 0x18)
                            if data[pcir2 : pcir2 + 4] == b"PCIR" and data[pcir2 + 0x14] == 3:
                                efi_len = u16(data, pcir2 + 0x10) * 512
                            break
                    off = base + raw + (efi_len if raw > legacy_len else 0)
            if off is not None and off + 6 <= len(data):
                out["virtual_pstate_raw"] = {
                    "offset": off,
                    "pointer_domain": p38.get("domain"),
                    "header_hex": data[off : off + 0x20].hex(),
                    "version": f"0x{u8(data, off):02x}",
                    "grammar": "UNKNOWN — spec documents v0x10 only (GF11X-GM20X); "
                    "Pascal+ changed the structure; this reads v0x20",
                }
    for name in ("FAN COOLERS", "POWER FAN_MGMT"):
        if name in ptrs:
            g = decode_geometry(data, ptrs[name])
            out[name.lower().replace(" ", "_") + "_raw"] = {
                **g,
                "records": raw_records(data, ptrs[name], g["hlen"], g["rlen"], g["count"]),
                "grammar": "UNKNOWN — envytools grammar predates multi-cooler records",
            }
    if "MEMORY TIMINGS" in ptrs:
        # the timing TABLE (P + 0x08) under the reader's TimingTable grammar:
        # version, header_length, base_length, extended_length,
        # extended_count, record_count; stride = base + ext_len*ext_count
        off = ptrs["MEMORY TIMINGS"]
        out["memory_timings"] = {
            "offset": off,
            "version": f"0x{u8(data, off):02x}",
            "header_length": u8(data, off + 1),
            "base_length": u8(data, off + 2),
            "extended_length": u8(data, off + 3),
            "extended_count": u8(data, off + 4),
            "record_count": u8(data, off + 5),
        }
        mt = out["memory_timings"]
        mt["stride"] = mt["base_length"] + mt["extended_length"] * mt["extended_count"]
    return out


def selftest(register_path: Path, corpus_dir: Path) -> int:
    reg = json.loads(register_path.read_text())
    ring3 = json.loads(register_path.with_name("gx3-perf-register.json").read_text())
    ring2 = json.loads(register_path.with_name("gx2-bit-register.json").read_text())
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
        rm, lm = spec["memory_clock_table"], live["memory_clock_table"]
        if [(e["min_mhz"], e["max_mhz"]) for e in rm["entries"]] != [
            (e["min_mhz"], e["max_mhz"]) for e in lm["entries"]
        ]:
            failures.append(f"G-memclk-bins {name}: ladder drifted")
        if not lm["monotone"]:
            failures.append(f"G-memclk-monotone {name}: active bins are not strictly increasing")
        if name == reg["primary_file"] and not lm["covers_live_memory_clock"]:
            failures.append(f"G-memclk-live {name}: top bin no longer covers the live {LIVE_MEMORY_CLOCK_MHZ} MHz")
        # cross-ring coherence: the memclk variant count must equal the
        # ring-2 memory translation length (14 straps on both sides)
        r2 = next(s for s in ring2["specimens"] if s["file"] == name)
        if rm["strap_entry_count"] != len(r2["memory"]["translation"]):
            failures.append(
                f"G-strap-coherence {name}: memclk variants {rm['strap_entry_count']} != ring-2 translation {len(r2['memory']['translation'])}"
            )
        for key in ("performance_raw", "fan_coolers_raw"):
            if spec.get(key, {}).get("records") != live.get(key, {}).get("records"):
                failures.append(f"G-raw {name}:{key}: record bytes drifted")
        if spec.get("virtual_pstate_raw", {}).get("header_hex") != live.get("virtual_pstate_raw", {}).get("header_hex"):
            failures.append(f"G-raw {name}:virtual_pstate: header bytes drifted")
        if spec.get("memory_timings", {}).get("record_count") != live.get("memory_timings", {}).get("record_count"):
            failures.append(f"G-timing-geometry {name}: record count drifted")
    print(f"gx4-clocks selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["clocks", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx4-clocks-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "clocks":
        ring3 = json.loads((Path(__file__).parent / "gx3-perf-register.json").read_text())
        specs = [anatomy(Path(p), ring3) for p in args.roms]
        out = {
            "instrument": "gx4-clocks",
            "ring": 4,
            "primary_file": Path(args.roms[0]).name,
            "live_cross": {"memory_clock_mhz": LIVE_MEMORY_CLOCK_MHZ, "graphics_clock_mhz": LIVE_GRAPHICS_CLOCK_MHZ},
            "specimens": specs,
        }
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
