#!/usr/bin/env python3
"""gx5-timings — the GPU ring-5 instrument (the timing layer, decoded).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar, never transcribed from memory:
  * the timing MAP (P-table pointer 0x04 — the same object the ring-4
    instrument decoded as the "Memory Clock Table"; the NVIDIA spec doc
    calls its variants "Strap Entries", nvidia-bios-reader calls the
    extended bytes "timing IDs" — one object, two grammars): version
    0x11, records = low u16 / high u16 frequency range + one timing-ID
    byte per strap, imported from src/nvbios_reader.cpp parse_timings.
  * the timing TABLE (P+0x08): version 0x20, records of stride
    base_length + extended_length*extended_count, referenced by ID.
  * the TimingFields decode: six u32 words c0..c5 at the record start,
    18 fields — rc/rfc/ras/rp/cl/wl/rd_rcd/wr_rcd/rpre/wpre/cdlr/wr/
    w2r_bus/r2w_bus/faw/refresh/rrd/wrcrc — imported verbatim from
    decode_timing_fields (c0:[0:7],[8:16],[17:23],[24:30]; c1:[0:6],
    [7:13],[14:19],[20:25]; c2:[0:3],[4:7],[8:14],[16:22],[24:27],
    [28:31]; c3:[9:16]; c4:[3:14],[15:20]; c5:[4:10]). Timing values
    are controller register fields / cycle counts, NOT nanoseconds
    (the reader's own note).
  * 0xFF timing ID = "no timing record referenced" — the reader's
    original research subject (the low-P-state instability class).

The pointer offsets come from the ring-3 register (anchors-before-marks).

Modes:
  timings <rom>...     the map, the referenced records, the coverage census
  selftest             two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

FIELD_NAMES = [
    "rc", "rfc", "ras", "rp", "cl", "wl", "rd_rcd", "wr_rcd",
    "rpre", "wpre", "cdlr", "wr", "w2r_bus", "r2w_bus", "faw",
    "refresh", "rrd", "wrcrc",
]


def u8(d: bytes, off: int) -> int:
    return d[off]


def u16(d: bytes, off: int) -> int:
    return int.from_bytes(d[off : off + 2], "little")


def u32(d: bytes, off: int) -> int:
    return int.from_bytes(d[off : off + 4], "little")


def bits(v: int, low: int, high: int) -> int:
    return (v >> low) & ((1 << (high - low + 1)) - 1)


def decode_timing_fields(data: bytes, off: int) -> dict:
    c = [u32(data, off + i * 4) for i in range(6)]
    raw = [
        bits(c[0], 0, 7), bits(c[0], 8, 16), bits(c[0], 17, 23), bits(c[0], 24, 30),
        bits(c[1], 0, 6), bits(c[1], 7, 13), bits(c[1], 14, 19), bits(c[1], 20, 25),
        bits(c[2], 0, 3), bits(c[2], 4, 7), bits(c[2], 8, 14), bits(c[2], 16, 22),
        bits(c[2], 24, 27), bits(c[2], 28, 31), bits(c[3], 9, 16),
        bits(c[4], 3, 14), bits(c[4], 15, 20), bits(c[5], 4, 10),
    ]
    return dict(zip(FIELD_NAMES, raw))


def anatomy(path: Path, ring3: dict) -> dict:
    data = path.read_bytes()
    spec3 = next(s for s in ring3["specimens"] if s["file"] == path.name)
    ptrs = {p["name"]: p["offset"] for p in spec3["pointers"] if p.get("offset")}
    out = {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }
    # --- the map (P+0x04) ---
    moff = ptrs["MEMORY TIMINGS MAPPING"]
    mver, mhlen, mbase, mext_len, mext_cnt, mcnt = (u8(data, moff + i) for i in range(6))
    mstride = mbase + mext_len * mext_cnt
    out["map"] = {
        "offset": moff,
        "version": f"0x{mver:02x}",
        "header_length": mhlen,
        "base_length": mbase,
        "extended_length": mext_len,
        "extended_count": mext_cnt,
        "record_count": mcnt,
        "records": [],
    }
    for i in range(mcnt):
        ro = moff + mhlen + i * mstride
        ids = [u8(data, ro + mbase + g * mext_len) for g in range(mext_cnt)]
        out["map"]["records"].append(
            {
                "index": i,
                "low_mhz": u16(data, ro) & 0x3FFF,
                "high_mhz": u16(data, ro + 2) & 0x3FFF,
                "timing_ids": ids,
            }
        )
    # --- the table (P+0x08) ---
    toff = ptrs["MEMORY TIMINGS"]
    tver, thlen, tbase, text_len, text_cnt, tcnt = (u8(data, toff + i) for i in range(6))
    tstride = tbase + text_len * text_cnt
    out["table"] = {
        "offset": toff,
        "version": f"0x{tver:02x}",
        "header_length": thlen,
        "base_length": tbase,
        "extended_length": text_len,
        "extended_count": text_cnt,
        "record_count": tcnt,
        "stride": tstride,
    }
    # --- coverage census + referenced records ---
    referenced = sorted({i for r in out["map"]["records"] for i in r["timing_ids"] if i != 0xFF})
    pairs = [(r["index"], s) for r in out["map"]["records"] for s, i in enumerate(r["timing_ids"])]
    ff_pairs = sum(1 for r in out["map"]["records"] for i in r["timing_ids"] if i == 0xFF)
    out["census"] = {
        "pairs_total": len(pairs),
        "pairs_with_ff": ff_pairs,
        "pairs_with_record": len(pairs) - ff_pairs,
        "referenced_ids": referenced,
        "referenced_count": len(referenced),
        "zero_records_referenced": sum(
            1 for i in referenced
            if all(b == 0 for b in data[toff + thlen + i * tstride : toff + thlen + i * tstride + tbase])
        ),
    }
    out["records"] = []
    for i in referenced:
        ro = toff + thlen + i * tstride
        rec = data[ro : ro + tstride]
        entry = {
            "id": i,
            "offset": ro,
            "is_zero": all(b == 0 for b in rec),
        }
        if tstride >= 24 and not entry["is_zero"]:
            entry["fields"] = decode_timing_fields(data, ro)
        out["records"].append(entry)
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
        if live["map"]["timing_ids_shape"] if False else False:
            pass
        if [r["timing_ids"] for r in live["map"]["records"]] != [r["timing_ids"] for r in spec["map"]["records"]]:
            failures.append(f"G-map-ids {name}: timing-id matrix drifted")
        if [r["id"] for r in live["records"]] != [r["id"] for r in spec["records"]]:
            failures.append(f"G-referenced-ids {name}: referenced record set drifted")
        for lr, rr in zip(live["records"], spec["records"]):
            if lr.get("fields") != rr.get("fields"):
                failures.append(f"G-fields {name}:id{lr['id']}: decoded fields drifted")
        c = live["census"]
        if c["pairs_with_ff"] != spec["census"]["pairs_with_ff"]:
            failures.append(f"G-census {name}: FF-pair count drifted")
        # the cross-ring law: extended_count must equal the ring-2 translation length
        ring2 = json.loads(register_path.with_name("gx2-bit-register.json").read_text())
        r2 = next(s for s in ring2["specimens"] if s["file"] == name)
        if live["map"]["extended_count"] != len(r2["memory"]["translation"]):
            failures.append(f"G-strap-coherence {name}: map straps != ring-2 translation")
    print(f"gx5-timings selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["timings", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx5-timings-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "timings":
        ring3 = json.loads((Path(__file__).parent / "gx3-perf-register.json").read_text())
        specs = [anatomy(Path(p), ring3) for p in args.roms]
        out = {"instrument": "gx5-timings", "ring": 5, "specimens": specs}
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
