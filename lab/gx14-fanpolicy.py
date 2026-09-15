#!/usr/bin/env python3
"""gx14-fanpolicy — the GPU ring-14 instrument (the fan curves, decoded).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar, never transcribed from memory — from the community
parser shengyuewangshuai-del/NVIDIA-VBIOS-Info-Reader (vbios_fan_policy.py,
fetched to imports/), which targets exactly our tables:
  * FAN POLICY (P+0x5C, version 0x20, records 0x33 = 51 B): per record,
    three duty bytes @+14, three temperature u16s @+18/+22/+26 each
    /32.0 (°C), three target-RPM u16s @+20/+24/+28; a record is plausible
    when duties are 0-100 sorted, rpms 0-20000 sorted, any nonzero.
  * FAN COOLER (P+0x58, version 0x10): type u8@0, min_duty u8@2,
    max_duty u8@3, pwm_freq u32@0x0b & 0xffffff (nouveau, ring 6), plus
    rpm-candidate u16s @0x0E/@0x10 (the parser labels them candidates
    needing the fan-policy cross-check).
  * the power budget (P+0x2C) and its cap entry are the ring-3 anchors.

Modes:
  fanpolicy <rom>...     the curves of every specimen
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

FIELD_PTRS = {"power_budget": 0x2C, "fan_cooler": 0x58, "fan_policy": 0x5C}


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


def find_p_table(data: bytes, legacy: dict) -> tuple[int, int, dict]:
    """The 'P' token table with the spec-adjusted pointer resolution,
    imported from the ring-3 instrument."""
    base = legacy["base"]
    bit_off = data.find(b"\xff\xb8BIT\x00", base, base + legacy["length"])
    hlen, rlen, count = u8(data, bit_off + 8), u8(data, bit_off + 9), u8(data, bit_off + 10)
    for i in range(count):
        off = bit_off + hlen + i * rlen
        if chr(u8(data, off)) == "P":
            t_off = base + u16(data, off + 4)
            t_len = u16(data, off + 2)
            efi_len = 0
            for b2 in range(base + legacy["length"], len(data) - 0x20, 0x200):
                if data[b2] == 0x55 and data[b2 + 1] == 0xAA:
                    pcir2 = b2 + u16(data, b2 + 0x18)
                    if data[pcir2 : pcir2 + 4] == b"PCIR" and data[pcir2 + 0x14] == 3:
                        efi_len = u16(data, pcir2 + 0x10) * 512
                    break

            def resolve(raw: int) -> int:
                if raw <= legacy["length"]:
                    return base + raw
                return base + raw + efi_len

            return t_off, t_len, resolve
    raise SystemExit("no 'P' token")


def decode_fan_policy_record(d: bytes, off: int, index: int) -> dict:
    duties = [u8(d, off + 14), u8(d, off + 15), u8(d, off + 16)]
    temps = [round(u16(d, off + o) / 32.0, 2) for o in (18, 22, 26)]
    rpms = [u16(d, off + o) for o in (20, 24, 28)]
    plausible = (
        all(0 <= v <= 100 for v in duties)
        and duties == sorted(duties)
        and all(0 <= v <= 20000 for v in rpms)
        and rpms == sorted(rpms)
        and any(rpms)
    )
    return {
        "index": index,
        "duty_percent": duties,
        "temperature_c": temps,
        "target_rpm": rpms,
        "plausible": plausible,
        "raw": d[off : off + 0x33].hex(),
    }


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    legacy = find_legacy(data)
    t_off, t_len, resolve = find_p_table(data, legacy)
    out = {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }
    # fan cooler (0x58) — nouveau fields + the parser's RPM candidates
    cooler_raw = u32(data, t_off + FIELD_PTRS["fan_cooler"])
    if cooler_raw:
        coff = resolve(cooler_raw)
        ver, hlen, rlen, cnt = (u8(data, coff + i) for i in range(4))
        coolers = []
        for i in range(cnt):
            ro = coff + hlen + i * rlen
            coolers.append(
                {
                    "index": i,
                    "type_code": u8(data, ro),
                    "min_duty_pct": u8(data, ro + 2),
                    "max_duty_pct": u8(data, ro + 3),
                    "pwm_freq": u32(data, ro + 0x0B) & 0xFFFFFF,
                    "rpm_candidate_min": u16(data, ro + 0x0E),
                    "rpm_candidate_max": u16(data, ro + 0x10),
                }
            )
        out["fan_coolers"] = {"offset": coff, "version": f"0x{ver:02x}", "count": cnt, "coolers": coolers}
    # fan policy (0x5C) — the curve records
    policy_raw = u32(data, t_off + FIELD_PTRS["fan_policy"])
    if policy_raw:
        poff = resolve(policy_raw)
        ver, hlen, rlen, cnt = (u8(data, poff + i) for i in range(4))
        records = [decode_fan_policy_record(data, poff + hlen + i * rlen, i) for i in range(cnt)]
        out["fan_policy"] = {
            "offset": poff,
            "version": f"0x{ver:02x}",
            "record_size": rlen,
            "record_count": cnt,
            "plausible_records": sum(1 for r in records if r["plausible"]),
            "records": records,
        }
    # power budget cap (0x2C) — the ring-3 anchor re-derived for the cross
    budget_raw = u32(data, t_off + FIELD_PTRS["power_budget"])
    if budget_raw:
        boff = resolve(budget_raw)
        ver, hlen, rlen, cnt = (u8(data, boff + i) for i in range(4))
        cap = u8(data, boff + 0xA) if ver >= 0x30 else u8(data, boff + 0x9)
        croff = boff + hlen + cap * rlen
        out["power_budget_cap"] = {
            "offset": boff,
            "version": f"0x{ver:02x}",
            "cap_entry": cap,
            "min_mw": u32(data, croff + 2),
            "avg_mw": u32(data, croff + 6),
            "peak_mw": u32(data, croff + 0xA),
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
        lp = spec["fan_policy"]["records"]
        ll = live["fan_policy"]["records"]
        if [(r["duty_percent"], r["temperature_c"], r["target_rpm"]) for r in ll] != [
            (r["duty_percent"], r["temperature_c"], r["target_rpm"]) for r in lp
        ]:
            failures.append(f"G-curve {name}: fan curve drifted")
        if live["fan_coolers"]["coolers"] != spec["fan_coolers"]["coolers"]:
            failures.append(f"G-coolers {name}: drifted")
        if live["power_budget_cap"] != spec["power_budget_cap"]:
            failures.append(f"G-cap {name}: drifted")
    print(f"gx14-fanpolicy selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["fanpolicy", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx14-fanpolicy-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "fanpolicy":
        specs = [analyze(Path(p)) for p in args.roms]
        out = {"instrument": "gx14-fanpolicy", "ring": 14, "specimens": specs}
        text = json.dumps(out, indent=2)
        if args.out:
            args.out.write_text(text + "\n")
            print(f"wrote {args.out}")
        return 0

    return selftest(args.register, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
