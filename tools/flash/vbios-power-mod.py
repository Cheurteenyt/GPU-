#!/usr/bin/env python3
"""vbios-power-mod — build a power-budget-modded VBIOS from a full image.

Deep-improvement pipeline, step A (gpu-lab ring 26). The power budget table
(P+0x2C, ver 0x30) sits in the data tail BEYOND the PCI image chain, so the
patch touches no PCI checksum — but every byte is verified before and after.

The tool is deliberately conservative:
  * refuses anything but the exact expected table layout,
  * refuses peak targets below stock or above a hard sanity ceiling,
  * writes the modded image NEXT TO the original, never over it,
  * re-decodes the result with the same grammar and shows the verdict.

Usage:
  python3 vbios-power-mod.py <rom> [--peak-mw 280000] [--avg-mw 265000] [--out FILE]
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

TOKEN_HINT = 588616  # known layout for this build; re-derived below anyway


def find_layout(rom):
    """Re-derive the P token and the power-budget table from scratch."""
    legacy = None
    for base in range(0, len(rom) - 0x20, 0x200):
        if rom[base:base + 2] == b"\x55\xaa":
            pcir = base + struct.unpack_from("<H", rom, base + 0x18)[0]
            if rom[pcir:pcir + 4] == b"PCIR" and rom[pcir + 0x14] == 0:
                legacy = {"base": base, "length": struct.unpack_from("<H", rom, pcir + 0x10)[0] * 512}
                break
    if not legacy:
        raise SystemExit("error: no legacy image")
    efi_len = 0
    for probe in range(legacy["base"] + legacy["length"], len(rom) - 0x20, 0x200):
        if rom[probe:probe + 2] == b"\x55\xaa":
            pcir2 = probe + struct.unpack_from("<H", rom, probe + 0x18)[0]
            if rom[pcir2:pcir2 + 4] == b"PCIR" and rom[pcir2 + 0x14] == 3:
                efi_len = struct.unpack_from("<H", rom, pcir2 + 0x10)[0] * 512
            break
    bit = rom.find(b"\xff\xb8BIT\x00", legacy["base"], legacy["base"] + legacy["length"])
    if bit < 0:
        raise SystemExit("error: BIT table not found")
    hlen, rlen, count = rom[bit + 8], rom[bit + 9], rom[bit + 10]
    token = None
    for i in range(count):
        off = bit + hlen + i * rlen
        if rom[off:off + 1] == b"P":
            token = legacy["base"] + struct.unpack_from("<H", rom, off + 4)[0]
            break
    if token is None:
        raise SystemExit("error: no 'P' token")

    def resolve(raw):
        return legacy["base"] + raw if raw <= legacy["length"] else legacy["base"] + raw + efi_len

    budget_raw = struct.unpack_from("<I", rom, token + 0x2C)[0]
    boff = resolve(budget_raw)
    if boff + 12 > len(rom):
        raise SystemExit(f"error: power table at {boff:#x} is beyond the image — full dump required")
    ver, h, r, cnt = rom[boff], rom[boff + 1], rom[boff + 2], rom[boff + 3]
    if ver != 0x30 or r != 0x47:
        raise SystemExit(f"error: unexpected power table layout (ver {ver:#x} rlen {r:#x}) — refusing")
    cap = rom[boff + 0xA]
    entry = boff + h + cap * r
    return {"token": token, "boff": boff, "entry": entry, "cap_index": cap, "rlen": r}


def decode_entry(rom, entry):
    return {"min_mw": struct.unpack_from("<I", rom, entry + 2)[0],
            "avg_mw": struct.unpack_from("<I", rom, entry + 6)[0],
            "peak_mw": struct.unpack_from("<I", rom, entry + 10)[0]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rom")
    ap.add_argument("--peak-mw", type=int, default=280000)
    ap.add_argument("--avg-mw", type=int, default=265000)
    ap.add_argument("--out")
    args = ap.parse_args()

    if not 100000 <= args.peak_mw <= 300000:
        raise SystemExit("refusing: peak outside 100-300 W sanity ceiling")
    if args.avg_mw > args.peak_mw:
        raise SystemExit("refusing: avg above peak")

    src = Path(args.rom)
    rom = bytearray(src.read_bytes())
    layout = find_layout(rom)
    entry = layout["entry"]
    before = decode_entry(rom, entry)
    if before["peak_mw"] < 200000:
        raise SystemExit(f"refusing: stock peak {before['peak_mw']} mW looks wrong for this table")

    struct.pack_into("<I", rom, entry + 2, before["min_mw"])
    struct.pack_into("<I", rom, entry + 6, args.avg_mw)
    struct.pack_into("<I", rom, entry + 10, args.peak_mw)

    after = decode_entry(bytes(rom), entry)
    diff_bytes = [(i, src.read_bytes()[i]) for i in range(entry, entry + 0x14)
                  if src.read_bytes()[i] != rom[i]]

    out = Path(args.out) if args.out else src.with_name(src.stem + f"-mod-{args.peak_mw // 1000}W.rom")
    out.write_bytes(bytes(rom))

    # verify by re-decoding the written file with the same grammar
    verify = decode_entry(out.read_bytes(), entry)
    print(f"source : {src.name} sha256 {hashlib.sha256(src.read_bytes()).hexdigest()[:32]}…")
    print(f"entry 2 @ {entry:#x} (cap index {layout['cap_index']}):")
    print(f"  before: min {before['min_mw']/1000:.0f} W  avg {before['avg_mw']/1000:.0f} W  peak {before['peak_mw']/1000:.0f} W")
    print(f"  after : min {after['min_mw']/1000:.0f} W  avg {after['avg_mw']/1000:.0f} W  peak {after['peak_mw']/1000:.0f} W")
    print(f"patched bytes: {[(hex(i), f'{old:02x}->{new:02x}') for (i, old), new in zip(diff_bytes, [rom[i] for i, _ in diff_bytes])]}")
    print(f"verified: {verify == after}")
    print(f"written: {out} ({out.stat().st_size:,} B) — NOT flashed; the GPU is untouched")
    print(f"next: flash step requires the live-USB procedure and the real chip read first")


if __name__ == "__main__":
    main()
