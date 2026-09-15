#!/usr/bin/env python3
"""gx3-perf — the GPU ring-3 instrument (the 'P' Performance lens).

Tracked in gpu-lab/lab/ (the fw33/fw37 precedent). Stdlib-only. Zero
hardware writes; filesystem writes are the JSON registers named on the
command line.

Imported grammar, never transcribed from memory:
  * the 'P' token layout: 40 named u32 pointers at fixed offsets 0x00..0x98
    (PERFORMANCE, MEMORY TIMINGS MAPPING, MEMORY TIMINGS, VOLTAGE,
    THERMAL, THERMAL DEVICES, THERMAL COOLERS, PERF SETTINGS SCRIPT,
    VOLT MAPPING, VENTURA, POWER SENSE, POWER BUDGET, BOOST, CSTEP,
    POWER BASE CLOCK, POWER TOPOLOGY, POWER LEAKAGE, PERF TEST SPEC,
    THERMAL CHANNEL, THERMAL ADJUSTMENT, THERMAL POLICY, PSTATE MEMORY
    CLK FREQ, FAN COOLERS, POWER FAN_MGMT, DI/DT, FAN TEST,
    VOLTAGE RAIL, VOLTAGE DEVICE, VOLTAGE POLICY, LOW POWER x7,
    THERM MONITOR, OVERCLOCKING) — imported verbatim from envytools
    nvbios/power.c:104-140 (P2_tbls). The token's t_len carries MORE
    dwords than envytools names; the unnamed tail is recorded as unk.
  * the POWER BUDGET table: version u8@0x0 (0x10/0x20/0x30), hlen u8@0x1,
    rlen u8@0x2, count u8@0x3, cap_entry u8@0x9 (v2) / u8@0xA (v3);
    records rlen>=8: min u32@+0x2, avg u32@+0x6, peak u32@+0xA,
    unkn12 u32@+0x12 — imported from envytools power.c
    envy_bios_parse_power_budget.
  * the pointer-domain question is NOT assumed: every pointer is read
    both as a raw file offset and as legacy-image-relative; the
    interpretation that lands on a sane table header wins and is
    recorded.

Modes:
  perf <rom>...          the 'P' pointer map + the budget/fan/oc tables
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

# envytools power.c:104-140 — the P2 nameplate, verbatim.
P2_TABLES = {
    0x00: "PERFORMANCE",
    0x04: "MEMORY TIMINGS MAPPING",
    0x08: "MEMORY TIMINGS",
    0x0C: "VOLTAGE",
    0x10: "THERMAL",
    0x14: "THERMAL DEVICES",
    0x18: "THERMAL COOLERS",
    0x1C: "PERF SETTINGS SCRIPT",
    0x20: "VOLT MAPPING",
    0x24: "VENTURA",
    0x28: "POWER SENSE",
    0x2C: "POWER BUDGET",
    0x30: "BOOST",
    0x34: "CSTEP",
    0x38: "POWER BASE CLOCK",
    0x3C: "POWER TOPOLOGY",
    0x40: "POWER LEAKAGE",
    0x44: "PERF TEST SPEC",
    0x48: "THERMAL CHANNEL",
    0x4C: "THERMAL ADJUSTMENT",
    0x50: "THERMAL POLICY",
    0x54: "PSTATE MEMORY CLK FREQ",
    0x58: "FAN COOLERS",
    0x5C: "POWER FAN_MGMT",
    0x60: "DI/DT",
    0x64: "FAN TEST",
    0x68: "VOLTAGE RAIL",
    0x6C: "VOLTAGE DEVICE",
    0x70: "VOLTAGE POLICY",
    0x74: "LOW POWER",
    0x78: "LOW POWER PCIe",
    0x7C: "LOW POWER PCIe-PLATFORM",
    0x80: "LOW POWER GR",
    0x84: "LOW POWER MS",
    0x88: "LOW POWER DI",
    0x8C: "LOW POWER GC6",
    0x90: "LOW POWER PSI",
    0x94: "THERM MONITOR",
    0x98: "OVERCLOCKING",
}

BUDGET_CAP_OFFSET = {0x20: 0x9, 0x30: 0xA}


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
                length = u16(data, pcir + 0x10) * 512
                # the UEFI image that follows, for the spec's pointer rule
                efi_next = base + length
                efi_length = 0
                for b2 in range(efi_next, len(data) - 0x20, 0x200):
                    if data[b2] == 0x55 and data[b2 + 1] == 0xAA:
                        pcir2 = b2 + u16(data, b2 + 0x18)
                        if data[pcir2 : pcir2 + 4] == b"PCIR" and data[pcir2 + 0x14] == 3:
                            efi_length = u16(data, pcir2 + 0x10) * 512
                        break
                return {"base": base, "length": length, "efi_length": efi_length}
    raise SystemExit("no legacy image")


def find_bit_token(data: bytes, legacy: dict, token_type: str) -> dict | None:
    base = legacy["base"]
    bit_off = data.find(b"\xff\xb8BIT\x00", base, base + legacy["length"])
    if bit_off < 0:
        return None
    hlen, rlen, count = u8(data, bit_off + 8), u8(data, bit_off + 9), u8(data, bit_off + 10)
    for i in range(count):
        off = bit_off + hlen + i * rlen
        if chr(u8(data, off)) == token_type:
            return {
                "version": u8(data, off + 1),
                "table_length": u16(data, off + 2),
                "table_offset_rel": u16(data, off + 4),
                "table_offset_abs": base + u16(data, off + 4),
            }
    return None


def sane_table(data: bytes, off: int) -> bool:
    """A table header is sane if version/hlen/rlen/count are byte-shaped."""
    if off + 4 > len(data):
        return False
    hlen, rlen, count = u8(data, off + 1), u8(data, off + 2), u8(data, off + 3)
    return 4 <= hlen <= 0x40 and 4 <= rlen <= 0x80 and 1 <= count <= 0x40 and off + hlen + rlen * count <= len(data)


def resolve_pointer(data: bytes, legacy: dict, raw: int) -> dict:
    """The NVIDIA spec's own rule (BIOS-Information-Table): pointers are
    legacy-image-relative; if pointer > legacy image length, the adjusted
    pointer adds the UEFI image length. Domains are named by how they were
    computed; sanity is judged by the decoded header shape."""
    base = legacy["base"]
    if raw <= legacy["length"]:
        off = base + raw
        kind = "image_rel"
    else:
        off = base + raw + legacy["efi_length"]
        kind = "spec_adjusted"
    if off + 4 <= len(data) and sane_table(data, off):
        return {"raw": raw, "domain": kind, "offset": off}
    return {"raw": raw, "domain": "unresolved", "offset": None}


def decode_budget(data: bytes, off: int) -> dict:
    version = u8(data, off)
    hlen, rlen, count = u8(data, off + 1), u8(data, off + 2), u8(data, off + 3)
    out = {"version": f"0x{version:02x}", "hlen": hlen, "rlen": rlen, "count": count}
    if version in BUDGET_CAP_OFFSET:
        out["cap_entry"] = u8(data, off + BUDGET_CAP_OFFSET[version])
    entries = []
    for i in range(count):
        rec = off + hlen + i * rlen
        e = {"index": i, "offset": rec}
        if rlen >= 0x14:
            e["min"] = u32(data, rec + 0x2)
            e["avg"] = u32(data, rec + 0x6)
            e["peak"] = u32(data, rec + 0xA)
            e["unkn12"] = u32(data, rec + 0x12)
        elif rlen >= 0x6:
            e["avg"] = u32(data, rec + 0x2)
        entries.append(e)
    out["entries"] = entries
    cap = out.get("cap_entry")
    if cap is not None and cap < len(entries):
        out["cap_entry_values"] = {k: v for k, v in entries[cap].items() if k in ("min", "avg", "peak")}
    return out


def decode_geometry(data: bytes, off: int) -> dict:
    return {
        "version": f"0x{u8(data, off):02x}",
        "hlen": u8(data, off + 1),
        "rlen": u8(data, off + 2),
        "count": u8(data, off + 3),
    }


def anatomy(path: Path) -> dict:
    data = path.read_bytes()
    legacy = find_legacy(data)
    perf_tok = find_bit_token(data, legacy, "P")
    if perf_tok is None:
        return {"file": path.name, "error": "no 'P' token"}
    t_off = perf_tok["table_offset_abs"]
    t_len = perf_tok["table_length"]
    pointers = []
    for rel in range(0, t_len - 3, 4):
        raw = u32(data, t_off + rel)
        if raw == 0:
            pointers.append({"rel": rel, "name": P2_TABLES.get(rel, f"unk-{rel:02x}"), "null": True})
            continue
        r = resolve_pointer(data, legacy, raw)
        pointers.append(
            {
                "rel": rel,
                "name": P2_TABLES.get(rel, f"unk-{rel:02x}"),
                "raw": raw,
                "domain": r["domain"],
                "offset": r["offset"],
            }
        )
    out = {
        "file": path.name,
        "size": len(data),
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        "p_token": perf_tok,
        "pointer_count": len(pointers),
        "named_count": sum(1 for p in pointers if p["rel"] in P2_TABLES),
        "pointers": pointers,
    }
    by_name = {p["name"]: p for p in pointers if p.get("offset")}
    if "POWER BUDGET" in by_name:
        out["power_budget"] = decode_budget(data, by_name["POWER BUDGET"]["offset"])
    for name in ("PERFORMANCE", "POWER SENSE", "FAN COOLERS", "POWER FAN_MGMT", "OVERCLOCKING", "VOLTAGE", "THERMAL", "BOOST"):
        if name in by_name:
            out.setdefault("geometries", {})[name] = decode_geometry(data, by_name[name]["offset"])
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
        live = anatomy(p)
        if live["sha256_16"] != spec["sha256_16"]:
            failures.append(f"G-hash {name}: drift")
            continue
        if live["pointer_count"] != spec["pointer_count"]:
            failures.append(f"G-pointer-count {name}: live {live['pointer_count']} != register {spec['pointer_count']}")
        # anchor re-derivation: every named pointer must land on the same
        # domain/offset as the register, or refuse loudly
        for rp, lp in zip(spec["pointers"], live["pointers"]):
            if rp.get("domain") != lp.get("domain") or rp.get("offset") != lp.get("offset"):
                failures.append(f"G-pointer {name}@{rp['rel']:#04x} ({rp['name']}): live {lp.get('domain')}@{lp.get('offset')} != register {rp.get('domain')}@{rp.get('offset')}")
        rb, lb = spec.get("power_budget"), live.get("power_budget")
        if rb and lb:
            if (rb["version"], rb["count"], rb["rlen"]) != (lb["version"], lb["count"], lb["rlen"]):
                failures.append(f"G-budget-geometry {name}: drifted")
            if [e.get("avg") for e in rb["entries"]] != [e.get("avg") for e in lb["entries"]]:
                failures.append(f"G-budget-entries {name}: avg values drifted")
    print(f"gx3-perf selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["perf", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx3-perf-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "perf":
        specs = [anatomy(Path(p)) for p in args.roms]
        out = {"instrument": "gx3-perf", "ring": 3, "specimens": specs}
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
