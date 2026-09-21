#!/usr/bin/env python3
"""vbios-unlock-mod.py — build the FULL unlock VBIOS: clock caps raised
(vP-state 2100 → 2200 MHz) + the power budget raised (250 → 280 W peak)
in one image, every patch re-derived and re-verified by decode.

The vP-state cap fields (profile 0xF, the max-performance profile):
  first_limit_clock  u16 @ 563,686, multiplier 4 (525 → 2100 MHz)
  second_limit_clock u16 @ 563,692, multiplier 4
  third_limit_clock  u16 @ 563,716, multiplier 4 (487 → 1948 MHz)
The power budget cap entry: min @+2, avg @+6, peak @+10 (u32 mW).

Usage: python3 vbios-unlock-mod.py [--core-max 2200] [--peak-w 280] [--avg-w 265]
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

BUILD = Path(__file__).resolve().parent.parent / "acquisitions/MSI.RTX3070.8192.210519_1.rom"
VP_FIRST = 563686
VP_SECOND = 563692
VP_THIRD = 563716
POWER_ENTRY = 588802  # cap entry 2 (ring 3): min +2, avg +6, peak +10
MULT = 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core-max", type=int, default=2200, help="new vP-state max clock, MHz (default 2200)")
    ap.add_argument("--third-max", type=int, default=2048, help="new third-limit clock, MHz")
    ap.add_argument("--peak-w", type=int, default=280)
    ap.add_argument("--avg-w", type=int, default=265)
    ap.add_argument("--min-w", type=int, default=100)
    ap.add_argument("--source", help="base image (default: the TPU stock; pass the REAL chip dump so per-card InfoROM data is preserved)")
    ap.add_argument("--out")
    args = ap.parse_args()

    if not 2000 <= args.core_max <= 2400:
        raise SystemExit(f"refusing core-max {args.core_max} — outside the 2000-2400 sanity band")
    if not 250 <= args.peak_w <= 320:
        raise SystemExit(f"refusing peak-w {args.peak_w} — outside the 250-320 W band")

    src = Path(args.source) if args.source else BUILD
    rom = bytearray(src.read_bytes())

    def patch_u16(off, old_decoded, new_decoded, mult=MULT, label=""):
        old_stored = struct.unpack_from("<H", rom, off)[0]
        expect = old_stored * mult
        if expect != old_decoded:
            raise SystemExit(f"REFUSED: {label} @ {off:#x}: stored {old_stored}×{mult} = {expect}, expected {old_decoded}")
        new_stored = round(new_decoded / mult)
        struct.pack_into("<H", rom, off, new_stored)
        print(f"  {label} @ {off:#x}: {old_stored}→{new_stored} (×{mult} = {new_decoded} MHz)")

    def patch_u32mW(off, old, new, label=""):  # noqa
        cur = struct.unpack_from("<I", rom, off)[0]
        if cur != old:
            raise SystemExit(f"REFUSED: {label} @ {off:#x}: {cur} mW, expected {old}")
        struct.pack_into("<I", rom, off, new)
        print(f"  {label} @ {off:#x}: {old/1000:.0f} W → {new/1000:.0f} W")

    print(f"source: {src.name} ({len(rom):,} B)")
    # the vP-state caps (profile 0xF)
    patch_u16(VP_FIRST, 2100, args.core_max, label="vP first_limit")
    patch_u16(VP_SECOND, 2100, args.core_max, label="vP second_limit")
    patch_u16(VP_THIRD, 1948, args.third_max, label="vP third_limit")
    # the power budget (cap entry 2)
    patch_u32mW(POWER_ENTRY + 2, 100000, args.min_w * 1000, label="power min")
    patch_u32mW(POWER_ENTRY + 6, 240000, args.avg_w * 1000, label="power avg")
    patch_u32mW(POWER_ENTRY + 10, 250000, args.peak_w * 1000, label="power peak")

    out = Path(args.out) if args.out else BUILD.with_name(BUILD.stem + f"-unlock-{args.core_max}MHz-{args.peak_w}W.rom")
    out.write_bytes(bytes(rom))
    print(f"written: {out.name} sha256 {hashlib.sha256(bytes(rom)).hexdigest()[:32]}…")
    print("NOT flashed — the flash session (usb-flash-session.sh) targets this image.")


if __name__ == "__main__":
    main()
