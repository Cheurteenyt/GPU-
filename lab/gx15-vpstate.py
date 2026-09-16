#!/usr/bin/env python3
"""gx15-vpstate — the GPU ring-15 instrument (the vP-state v0x20, decoded).

Tracked in gpu-lab/lab/. Stdlib-only for the register; the imported
community parser (imports/CPR_calculator.py, from
JadeRover/Nvidia-vBIOS-Clock-Power-Tweaker) does the table walk.

Imported grammar, never transcribed from memory:
  * the vP-state v0x20 (Ampere) header is `20 15 01` (header length 21,
    +1 denominator byte = 22), entries are 65-byte profiles whose clock
    fields are fixed-point /2^15 (the 0x0F denominator byte precedes the
    first clock); profile ID 0x07 opens the list (the tool's own
    convention, coherence-checked: the first clock must decode to
    100-2000 MHz).
  * per-profile fields (u16, x2 for MHz): first_limit_clock @+9,
    second_limit_clock @+15, mem_clock_short @+17, mem_clock_long @+21
    (with the tool's own correction), third_limit_clock @+39.
  * clocks are the vP-state CAPS: they must cover the live machine's
    clocks (the live cross, ring-4 style).

Modes:
  vpstate <rom>...     the decoded vP-state profiles
  selftest             two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import importlib.util
_spec = importlib.util.spec_from_file_location("cpr", Path(__file__).parent.parent / "imports" / "CPR_calculator.py")
cpr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cpr)

LIVE_MEMORY_CLOCK_MHZ = 6801
LIVE_GRAPHICS_CLOCK_MHZ = 1890


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    out = {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }
    try:
        pd = cpr.parsed_data(data)
    except IndexError:
        # the eager constructor indexes an empty profile list when the
        # container holds no VP table — the case for the day-0 sysfs
        # window (the legacy image alone; the vP-state lives in the tail)
        out.update({
            "generation": None,
            "note": "no VP table inside this container (sysfs window = legacy image only)",
            "table_count": 0,
            "tables": [],
        })
        return out
    offsets = pd.find_v_p_table_offsets()
    out.update({
        "generation": pd.VP_generation,
        "header_length": pd.VP_header_length,
        "table_count": len(offsets),
        "tables": [],
    })
    try:
        pd.get_VP_profiles_list()
    except Exception as e:
        out["error"] = f"profiles walk: {e}"
        return out
    for i, sub in enumerate(pd.VP_profile_list):
        profiles = []
        for prof in sub:
            first = prof.get("first_limit_clock", [0, 0])
            if not isinstance(first, list) or first[0] == 0:
                continue
            mem_s = prof["mem_clock_short"][0]
            profiles.append(
                {
                    "id": prof["ID"],
                    "first_limit_mhz": first[0],
                    "second_limit_mhz": prof["second_limit_clock"][0],
                    "mem_clock_short_mhz": mem_s,
                    "mem_clock_long_mhz": prof["mem_clock_long"][0],
                    "third_limit_mhz": prof["third_limit_clock"][0],
                }
            )
        out["tables"].append({"offset": hex(offsets[i]) if i < len(offsets) else None, "profiles": profiles})
    # the live cross: the max mem_clock_short across profiles must cover
    # the live memory clock, and the max graphics limit the live graphics
    mems = [p["mem_clock_short_mhz"] for t in out["tables"] for p in t["profiles"]]
    gfx = [p["first_limit_mhz"] for t in out["tables"] for p in t["profiles"]]
    out["live_cross"] = {
        "covers_live_memory_clock": LIVE_MEMORY_CLOCK_MHZ in mems,
        "live_memory_clock_in_profiles": LIVE_MEMORY_CLOCK_MHZ in mems,
        "live_graphics_under_max_limit": max(gfx) >= LIVE_GRAPHICS_CLOCK_MHZ if gfx else False,
        "max_graphics_limit": max(gfx) if gfx else None,
        "mem_clocks_seen": sorted(set(mems)),
    }
    return out


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
        for i, (lt, rt) in enumerate(zip(live["tables"], spec["tables"])):
            if [(p["id"], p["first_limit_mhz"], p["mem_clock_short_mhz"]) for p in lt["profiles"]] != [
                (p["id"], p["first_limit_mhz"], p["mem_clock_short_mhz"]) for p in rt["profiles"]
            ]:
                failures.append(f"G-vpstate {name}:table{i}: profiles drifted")
    print(f"gx15-vpstate selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["vpstate", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx15-vpstate-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "vpstate":
        specs = [analyze(Path(p)) for p in args.roms]
        out = {"instrument": "gx15-vpstate", "ring": 15, "specimens": specs}
        text = json.dumps(out, indent=2)
        if args.out:
            args.out.write_text(text + "\n")
            print(f"wrote {args.out}")
        return 0

    return selftest(args.register, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
