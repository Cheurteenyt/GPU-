#!/usr/bin/env python3
"""gx6-fan — the GPU ring-6 instrument (the fan coolers, named by the kernel).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar, never transcribed from memory:
  * the FAN COOLERS table (P-table pointer 0x58, exactly what nouveau's
    nvkm_bios fan.c reads): header version 0x10 with hdr@+1, len@+2,
    cnt@+3; per-record fields — type u8@0x00 (0=toggle, 1/2=PWM),
    min_duty u8@0x02, max_duty u8@0x03, pwm_freq u32@0x0b & 0xffffff.
    Imported from torvalds/linux drivers/gpu/drm/nouveau/nvkm/subdev/
    bios/fan.c (nvbios_fan_parse), fetched 2026-09-15 to
    imports/nouveau/fan.c.
  * the PERFORMANCE table version check: nouveau perf.c handles up to
    v0x40 — our v0x60 is beyond every open parser (consumed by
    GSP-RM); it stays registered RAW.
  * POWER TOPOLOGY (P+0x3c) and POWER FAN_MGMT (P+0x5c): no open
    grammar; registered as geometry + raw records with u16 candidates.

Modes:
  fan <rom>...           the coolers decoded, the raw territory mapped
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

FAN_TYPE = {0: "toggle", 1: "pwm", 2: "pwm", 3: "unknown"}


def u8(d: bytes, off: int) -> int:
    return d[off]


def u16(d: bytes, off: int) -> int:
    return int.from_bytes(d[off : off + 2], "little")


def u32(d: bytes, off: int) -> int:
    return int.from_bytes(d[off : off + 4], "little")


def decode_fan(data: bytes, off: int) -> dict:
    ver, hlen, rlen, cnt = (u8(data, off + i) for i in range(4))
    coolers = []
    for i in range(cnt):
        ro = off + hlen + i * rlen
        t = u8(data, ro)
        coolers.append(
            {
                "index": i,
                "offset": ro,
                "type_code": t,
                "type": FAN_TYPE.get(t, f"unknown-{t}"),
                "min_duty_pct": u8(data, ro + 0x02),
                "max_duty_pct": u8(data, ro + 0x03),
                "pwm_freq": u32(data, ro + 0x0B) & 0xFFFFFF,
                "raw": data[ro : ro + rlen].hex(),
            }
        )
    return {
        "offset": off,
        "version": f"0x{ver:02x}",
        "header_length": hlen,
        "record_length": rlen,
        "count": cnt,
        "coolers": coolers,
    }


def raw_records(data: bytes, off: int, hlen: int, rlen: int, count: int, limit: int = 3) -> list[dict]:
    recs = []
    for i in range(min(count, limit)):
        ro = off + hlen + i * rlen
        recs.append(
            {
                "index": i,
                "offset": ro,
                "hex": data[ro : ro + rlen].hex(),
                "u16_candidates": [u16(data, ro + j) for j in range(0, rlen - 1, 2)],
            }
        )
    return recs


def anatomy(path: Path, ring3: dict) -> dict:
    data = path.read_bytes()
    spec3 = next(s for s in ring3["specimens"] if s["file"] == path.name)
    ptrs = {p["name"]: p["offset"] for p in spec3["pointers"] if p.get("offset")}
    out = {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }
    if "FAN COOLERS" in ptrs:
        out["fan_coolers"] = decode_fan(data, ptrs["FAN COOLERS"])
    if "POWER TOPOLOGY" in ptrs:
        off = ptrs["POWER TOPOLOGY"]
        out["power_topology_raw"] = {
            "offset": off,
            "version": f"0x{u8(data, off):02x}",
            "hlen": u8(data, off + 1),
            "rlen": u8(data, off + 2),
            "count": u8(data, off + 3),
            "records": raw_records(data, off, u8(data, off + 1), u8(data, off + 2), u8(data, off + 3), limit=6),
            "grammar": "UNKNOWN — no open parser (nouveau/envytools predate the Ampere shape)",
        }
    if "POWER FAN_MGMT" in ptrs:
        off = ptrs["POWER FAN_MGMT"]
        out["fan_mgmt_raw"] = {
            "offset": off,
            "version": f"0x{u8(data, off):02x}",
            "hlen": u8(data, off + 1),
            "rlen": u8(data, off + 2),
            "count": u8(data, off + 3),
            "records": raw_records(data, off, u8(data, off + 1), u8(data, off + 2), u8(data, off + 3), limit=2),
            "grammar": "UNKNOWN — RPM-class u16 candidates only (honest)",
        }
    if "PERFORMANCE" in ptrs:
        off = ptrs["PERFORMANCE"]
        out["performance_status"] = {
            "offset": off,
            "version": f"0x{u8(data, off):02x}",
            "note": "v0x60 — beyond nouveau perf.c (max 0x40) and every open parser; RAW since ring 4",
        }
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
        rf, lf = spec["fan_coolers"], live["fan_coolers"]
        for rl, ll in zip(rf["coolers"], lf["coolers"]):
            for k in ("type_code", "min_duty_pct", "max_duty_pct", "pwm_freq"):
                if rl[k] != ll[k]:
                    failures.append(f"G-fan {name}:cooler{rl['index']}: {k} drifted ({rl[k]} vs {ll[k]})")
        if spec.get("power_topology_raw", {}).get("records") != live.get("power_topology_raw", {}).get("records"):
            failures.append(f"G-raw {name}:power_topology: record bytes drifted")
        if spec.get("fan_mgmt_raw", {}).get("records") != live.get("fan_mgmt_raw", {}).get("records"):
            failures.append(f"G-raw {name}:fan_mgmt: record bytes drifted")
    print(f"gx6-fan selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["fan", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx6-fan-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "fan":
        ring3 = json.loads((Path(__file__).parent / "gx3-perf-register.json").read_text())
        specs = [anatomy(Path(p), ring3) for p in args.roms]
        out = {"instrument": "gx6-fan", "ring": 6, "specimens": specs}
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
