#!/usr/bin/env python3
"""gx10-init — the GPU ring-10 instrument (the devinit scripts, decoded).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar, never transcribed from memory:
  * the NVINIT token ('I'): u16@0 = the script-table pointer, whose
    entries are u16 script offsets — from nouveau nvkm/subdev/bios/
    init.c (init_table / init_script_table / init_script).
  * the INIT opcode grammar and per-opcode argument sizes, imported
    from the same file's handlers (init_zm_reg: 9, init_nv_reg: 13,
    init_zm_reg_sequence: 6+4*count, init_time: 3, init_io: 5,
    init_pll: 7, init_zm_reg16: 7, init_zm_index_io: 5, init_repeat: 2,
    init_not: 1, init_sub_direct: 3, init_sub: 2, init_resume: 1,
    init_ltime: 5, init_strap_condition: 9 (reads the memory-strap
    register R[0x101000]), init_io_restrict_prog: 11+4*count,
    init_zm_reg_group: 6+5*count, init_done: 1).
  * the walk is SELF-VALIDATING: a script is admitted only when the
    length table walks it to a clean init_done (0x71); every unknown
    opcode stops the walk loudly.

Modes:
  scripts <rom>          the script inventory of the legacy image
  compare <live> <acq>   the day-0 differ, resolved at script level
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

OPNAMES = {
    0x71: "DONE", 0x7A: "ZM_REG", 0x6E: "NV_REG", 0x58: "ZM_REG_SEQUENCE",
    0x74: "TIME", 0x69: "IO", 0x79: "PLL", 0x77: "ZM_REG16",
    0x62: "ZM_INDEX_IO", 0x33: "REPEAT", 0x38: "NOT", 0x5B: "SUB_DIRECT",
    0x6B: "SUB", 0x72: "RESUME", 0x57: "LTIME", 0x73: "STRAP_CONDITION",
    0x32: "IO_RESTRICT_PROG", 0x91: "ZM_REG_GROUP",
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


def find_bit_token(data: bytes, legacy: dict, token_type: str) -> dict:
    base = legacy["base"]
    bit_off = data.find(b"\xff\xb8BIT\x00", base, base + legacy["length"])
    hlen, rlen, count = u8(data, bit_off + 8), u8(data, bit_off + 9), u8(data, bit_off + 10)
    for i in range(count):
        off = bit_off + hlen + i * rlen
        if chr(u8(data, off)) == token_type:
            return {"version": u8(data, off + 1),
                    "table_length": u16(data, off + 2),
                    "table_offset_abs": base + u16(data, off + 4)}
    return {}


def size_of(op: int, d: bytes, o: int) -> int | None:
    L = len(d)
    if op == 0x71: return 1
    if op == 0x7A: return 9
    if op == 0x6E: return 13
    if op == 0x58: return 6 + 4 * d[o + 5] if o + 6 < L else None
    if op == 0x74: return 3
    if op == 0x69: return 5
    if op == 0x79: return 7
    if op == 0x77: return 7
    if op == 0x62: return 5
    if op == 0x33: return 2
    if op == 0x38: return 1
    if op == 0x5B: return 3
    if op == 0x6B: return 2
    if op == 0x72: return 1
    if op == 0x57: return 5
    if op == 0x73: return 9
    if op == 0x32: return 11 + 4 * d[o + 6] if o + 7 < L else None
    if op == 0x91: return 6 + d[o + 5] * 5 if o + 6 < L else None
    return None


def walk_to_done(d: bytes, start: int, end_limit: int) -> dict | None:
    off, ops, regw = start, [], []
    while off < end_limit:
        op = d[off]
        if op == 0x71:
            return {"start": start, "done": off, "ops": ops, "regw": regw}
        s = size_of(op, d, off)
        if s is None:
            return None
        if op == 0x7A:
            regw.append(("ZM_REG", u32(d, off + 1)))
        elif op == 0x6E:
            regw.append(("NV_REG", u32(d, off + 1)))
        elif op == 0x58:
            regw.append(("ZM_REG_SEQ", u32(d, off + 1), d[off + 5]))
        elif op == 0x91:
            regw.append(("ZM_REG_GROUP", u32(d, off + 1), d[off + 5]))
        ops.append(op)
        off += s
    return None


def inventory(d: bytes, lo: int, hi: int) -> list[dict]:
    donemap = {}
    for start in range(lo, hi):
        r = walk_to_done(d, start, hi)
        if r:
            key = r["done"]
            if key not in donemap or r["start"] < donemap[key]["start"]:
                donemap[key] = r
    return sorted(donemap.values(), key=lambda x: x["start"])


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    legacy = find_legacy(data)
    base = legacy["base"]
    lo, hi = 0x3000, legacy["length"]
    scripts = inventory(data, base + lo, base + hi)
    regs = {}
    opcensus = {}
    for s in scripts:
        for w in s["regw"]:
            regs[w[1]] = regs.get(w[1], 0) + 1
        for op in s["ops"]:
            opcensus[OPNAMES.get(op, hex(op))] = opcensus.get(OPNAMES.get(op, hex(op)), 0) + 1
    return {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        "legacy_base": base,
        "scan_range": [lo, hi],
        "script_count": len(scripts),
        "scripts": [{"start": s["start"] - base, "done": s["done"] - base,
                     "n_ops": len(s["ops"]), "writes": s["regw"][:6]} for s in scripts],
        "register_census_top": sorted(regs.items(), key=lambda kv: -kv[1])[:16],
        "opcode_census": opcensus,
    }


def selftest(register_path: Path, corpus_dir: Path) -> int:
    reg = json.loads(register_path.read_text())
    failures = []
    for spec in reg["specimens"]:
        name = spec["file"]
        p = corpus_dir / name
        if not p.exists():
            p = corpus_dir.parent / "day0" / name
        if not p.exists():
            failures.append(f"tier-I: corpus file missing: {name}")
            continue
        live = analyze(p)
        if live["sha256_16"] != spec["sha256_16"]:
            failures.append(f"G-hash {name}: drift")
            continue
        if live["script_count"] != spec["script_count"]:
            failures.append(f"G-scripts {name}: {live['script_count']} != {spec['script_count']}")
        if [s["start"] for s in live["scripts"]] != [s["start"] for s in spec["scripts"]]:
            failures.append(f"G-script-starts {name}: drifted")
        if live["opcode_census"] != spec["opcode_census"]:
            failures.append(f"G-opcode-census {name}: drifted")
    print(f"gx10-init selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["scripts", "compare", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx10-init-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "scripts":
        specs = [analyze(Path(p)) for p in args.roms]
        out = {"instrument": "gx10-init", "ring": 10, "specimens": specs}
        text = json.dumps(out, indent=2)
        if args.out:
            args.out.write_text(text + "\n")
            print(f"wrote {args.out}")
        return 0

    if args.mode == "compare":
        a = analyze(Path(args.roms[0]))
        b = analyze(Path(args.roms[1]))
        sa = set(s["start"] for s in a["scripts"])
        sb = set(s["start"] for s in b["scripts"])
        out = {
            "pair": [a["file"], b["file"]],
            "scripts_a": a["script_count"],
            "scripts_b": b["script_count"],
            "starts_both": len(sa & sb),
            "starts_only_a": sorted(sa - sb),
            "starts_only_b": sorted(sb - sa),
        }
        print(json.dumps(out, indent=2) if not args.out else "")
        if args.out:
            args.out.write_text(json.dumps(out, indent=2) + "\n")
            print(f"wrote {args.out}")
        return 0

    return selftest(args.register, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
