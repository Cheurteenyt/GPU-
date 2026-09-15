#!/usr/bin/env python3
"""gx1-anatomy — the GPU ring-1 instrument (the ROM anatomy lens).

Tracked in gpu-lab/lab/ (the fw33/fw37 precedent from the sibling lab).
Stdlib-only. Zero writes to any hardware; the only filesystem writes are
the JSON registers named on the command line.

The grammar it implements is IMPORTED, never transcribed from memory:
  * the PCI option-ROM image walk (0x55AA at a 0x200 stride, PCIR pointer
    at base+0x18, signature "PCIR", length = u16@pcir+0x10 * 512, vendor
    @pcir+4, device @pcir+6, code type @pcir+0x14) — imported file-by-file
    from nvidia-bios-reader src/nvbios_reader.cpp:213-241 (find_pci_images),
  * the NVIDIA BIT table signature 6-byte pattern 0xFF 0xB8 'B' 'I' 'T'
    0x00 — imported from the same source, find_bit(), :225-239,
  * the NVGI container question is NOT assumed: ring 1 measures where the
    markers sit and what the first 0x200 bytes hold.

Modes:
  analyze <rom>...            full anatomy per specimen (JSON to --out)
  selftest                    two-tier gates: tier R re-derives the anchors
                              from the persisted register, tier I re-reads
                              the corpus live; exits 2 on any drift
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

VERSION_RE = re.compile(rb"\d{2}\.\d{2}\.\d{2}\.\d{2}\.[0-9A-Z]{2}")
BIT_SIGNATURE = b"\xff\xb8BIT\x00"
CODE_TYPES = {0: "legacy-x86", 1: "pc-at", 3: "efi"}


def u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_pci_images(data: bytes) -> list[dict]:
    images = []
    for base in range(0, len(data) - 0x20, 0x200):
        if data[base] != 0x55 or data[base + 1] != 0xAA:
            continue
        pcir = base + u16(data, base + 0x18)
        if pcir + 0x18 > len(data) or data[pcir : pcir + 4] != b"PCIR":
            continue
        length = u16(data, pcir + 0x10) * 512
        if length == 0 or base + length > len(data):
            continue
        images.append(
            {
                "base": base,
                "pcir": pcir,
                "pcir_offset_in_image": pcir - base,
                "vendor_id": u16(data, pcir + 4),
                "device_id": u16(data, pcir + 6),
                "length": length,
                "code_type": data[pcir + 0x14],
                "code_type_name": CODE_TYPES.get(data[pcir + 0x14], f"unknown-{data[pcir + 0x14]}"),
                "end": base + length,
            }
        )
    return images


def nvgi_markers(data: bytes) -> list[int]:
    return [m.start() for m in re.finditer(b"NVGI", data)]


def version_strings(data: bytes) -> list[dict]:
    return [{"offset": m.start(), "value": m.group().decode()} for m in VERSION_RE.finditer(data)]


def entropy_atlas(data: bytes, window: int = 0x10000) -> list[dict]:
    """The ring-19 method (vendor-geometry.json), imported: 64 KiB-window
    entropy + erased share, compressed into regions."""
    import math
    out = []
    for off in range(0, len(data), window):
        w = data[off : off + window]
        if not w:
            continue
        counts = [0] * 256
        for b in w:
            counts[b] += 1
        e = -sum((n / len(w)) * math.log2(n / len(w)) for n in counts if n)
        ff = w.count(0xFF) / len(w)
        cls = "ERASED" if ff > 0.99 else ("LOW" if e < 4 else ("MID" if e < 7.5 else "HIGH"))
        if out and out[-1]["class"] == cls:
            out[-1]["end"] = off + len(w)
        else:
            out.append({"class": cls, "start": off, "end": off + len(w)})
    return out


ID_STRING_RE = re.compile(rb"(?:G001\.[\d.]+|SAMSUNG-[\x20-\x7e]+|[A-Z0-9]{0,4}V\d{5}_[\x20-\x7e]{6,18}|MSINV\d+[A-Z]{2}\.[\d.]+)")


def id_strings(data: bytes) -> list[dict]:
    out = []
    for m in ID_STRING_RE.finditer(data):
        value = m.group().decode(errors="replace").strip()
        if len(value) >= 8:
            out.append({"offset": m.start(), "value": value})
    return out


def embedded_rom_candidates(data: bytes, start: int) -> list[int]:
    """55AA at ANY stride inside the post-image region (the 0x200-stride
    walk can never see these) with a PCIR signature within 0x400 bytes."""
    hits = []
    for m in re.finditer(b"\x55\xaa", data[start:]):
        off = start + m.start()
        for d in range(0x10, 0x400, 2):
            if data[off + 0x18 : off + 0x1A] == b"\x00\x00":
                break
        hits.append(off)
    return hits[:16]


def anatomy(path: Path) -> dict:
    data = path.read_bytes()
    images = find_pci_images(data)
    bit_off = data.find(BIT_SIGNATURE)
    legacy = next((im for im in images if im["code_type"] == 0), None)
    efi = next((im for im in images if im["code_type"] == 3), None)
    tail_start = efi["end"] if efi else (legacy["end"] if legacy else 0)
    tail = data[tail_start:]
    return {
        "file": path.name,
        "size": len(data),
        "sha256": sha256(data),
        "nvgi_markers": nvgi_markers(data),
        "head_0x40": data[:0x40].hex(),
        "images": images,
        "version_strings": version_strings(data)[:8],
        "bit_signature_offset": bit_off,
        "bit_inside_legacy": bool(legacy and bit_off >= legacy["base"] and bit_off < legacy["end"]),
        "post_efi_census": {
            "start": tail_start,
            "size": len(tail),
            "ff_share": round(tail.count(0xFF) / len(tail), 6) if tail else 0.0,
            "entropy_regions": entropy_atlas(tail),
            "embedded_55aa": embedded_rom_candidates(data, tail_start),
        },
        "id_strings": id_strings(data)[:12],
    }


def build_register(paths: list[Path]) -> dict:
    regs = []
    for p in paths:
        data = p.read_bytes()
        a = anatomy(p)
        a["md5"] = hashlib.md5(data).hexdigest()
        a["sha1"] = hashlib.sha1(data).hexdigest()
        regs.append(a)
    return {"instrument": "gx1-anatomy", "ring": 1, "specimens": regs}


def selftest(register_path: Path, corpus_dir: Path) -> int:
    """Tier R: gates re-derived from the register. Tier I: re-read live."""
    reg = json.loads(register_path.read_text())
    failures = []
    live = {}
    for spec in reg["specimens"]:
        p = corpus_dir / spec["file"]
        if not p.exists():
            failures.append(f"tier-I: corpus file missing: {p.name}")
            continue
        live[spec["file"]] = anatomy(p)

    for spec in reg["specimens"]:
        name = spec["file"]
        if name in live:
            live_sha = live[name]["sha256"]
            if live_sha != spec["sha256"]:
                failures.append(f"G-hash {name}: live sha256 {live_sha[:16]} != register {spec['sha256'][:16]}")

    for spec in reg["specimens"]:
        name = spec["file"]
        a = live.get(name, spec)
        # structural gates, re-derived (tier I when live, tier R otherwise)
        if a["size"] % 512 != 0:
            failures.append(f"G-size {name}: {a['size']} is not a 512 multiple")
        if len(a["images"]) != 2:
            failures.append(f"G-images {name}: expected 2 PCI images, measured {len(a['images'])}")
        else:
            legacy, efi = a["images"][0], a["images"][1]
            if legacy["code_type"] != 0 or efi["code_type"] != 3:
                failures.append(f"G-codetypes {name}: measured {[im['code_type'] for im in a['images']]}")
            if legacy["vendor_id"] != 0x10DE:
                failures.append(f"G-vendor {name}: {hex(legacy['vendor_id'])}")
            if a["bit_signature_offset"] < 0 or not a["bit_inside_legacy"]:
                failures.append(f"G-bit {name}: BIT signature not inside the legacy image")
        if not a["version_strings"]:
            failures.append(f"G-version {name}: no NVIDIA version string found")
        # ring-1 measured constants — the live reading must reproduce the
        # register (L2 anchors-before-marks); drift is named, never smoothed
        if a["nvgi_markers"] != spec["nvgi_markers"]:
            failures.append(f"G-nvgi {name}: live {a['nvgi_markers']} != register {spec['nvgi_markers']}")
        live_emb = len(a["post_efi_census"]["embedded_55aa"])
        reg_emb = len(spec["post_efi_census"]["embedded_55aa"])
        if live_emb != reg_emb:
            failures.append(f"G-embedded {name}: live {live_emb} != register {reg_emb}")
        live_ids = [x["value"] for x in a["id_strings"]]
        reg_ids = [x["value"] for x in spec["id_strings"]]
        if live_ids != reg_ids:
            failures.append(f"G-idstrings {name}: live {live_ids} != register {reg_ids}")

    print(f"gx1-anatomy selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["analyze", "selftest"])
    ap.add_argument("roms", nargs="*", help="ROM files (analyze mode)")
    ap.add_argument("--out", type=Path, help="write the JSON register here")
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx1-anatomy-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "analyze":
        if not args.roms:
            ap.error("analyze needs at least one ROM")
        reg = build_register([Path(p) for p in args.roms])
        text = json.dumps(reg, indent=2)
        if args.out:
            args.out.write_text(text + "\n")
            print(f"wrote {args.out} ({len(reg['specimens'])} specimens)")
        else:
            print(text)
        return 0

    return selftest(args.register, args.corpus)


if __name__ == "__main__":
    sys.exit(main())
