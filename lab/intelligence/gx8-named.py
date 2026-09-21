#!/usr/bin/env python3
"""gx8-named — the GPU ring-8 instrument (the nameplate completed, the
memory-clock header named, the Falcon ucode inventoried).

Tracked in gpu-lab/lab/. Stdlib-only. Zero hardware writes.

Imported grammar, never transcribed from memory:
  * the FULL 58-dword P-pointer nameplate with the modern RM names —
    envytools stopped at offset 0x98 (39 names); the open-source ImHex
    pattern "kepler-ada-nvidia-vbios-visualizer" (TechPowerUp forums
    thread 322299, fetched to imports/) names every pointer up to 232
    bytes, including the >=224 block (PerfCf*, Nne*, Illum*, Lpwr*,
    FanArbiter) and FanAcousticsQual @0xE4.
  * the Memory Clock Table (P+0x04) Ampere header fields: Flags,
    FBVDDSettleTime, CfgPwrdVal, FBVDDQHigh/Low, ScriptListPtr/Count,
    CmdScriptListPtr/Count — from the same pattern's
    MEMORY_CLOCK_HEADER_1X.
  * the Falcon ucode inventory via the 'p' token (FALCON_DATA, v2, 4 B):
    a u32 falcon_table_ptr to FALCON_UCODE_TABLE_HDR_V1 (Version,
    HeaderSize, EntrySize, EntryCount, DescVersion, DescSize) whose
    entries carry UCodeApplicationID / UCodeTargetID enums and a
    DescPtr to FALCON_UCODE_DESC_V1 (StoredSize, UncompressedSize,
    VirtualEntry, IMEM/DMEM bases and sizes...). From the pattern.

Modes:
  named <rom>...         the nameplate completed + memclk header + falcon
  selftest               two-tier gates over the persisted register
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

# offsets 0x00..0x40 (17) from the pattern's unconditional block,
# 0x44..0x98 (22) from its >=156 block, 0x9C..0xE0 (17) from >=224,
# 0xE4 from >=232 — 58 names for the 58 dwords our table carries.
EXTENDED_P2_NAMES = {
    0x00: "PerfTable", 0x04: "MemClockTable", 0x08: "MemTweakTable",
    0x0C: "PowerControl", 0x10: "ThermalControl", 0x14: "ThermalDevice",
    0x18: "ThermalCooler", 0x1C: "SettingsScript", 0x20: "VoltageDesc-CVB",
    0x24: "SpbSensorParam", 0x28: "PowerSensors", 0x2C: "PowerCapping",
    0x30: "PstateClkRange", 0x34: "VoltageFreq", 0x38: "VirtualPState",
    0x3C: "PowerTopology", 0x40: "PowerEquation",
    0x44: "PerfTestSpec", 0x48: "ThermalChannel", 0x4C: "ThermalAdjustment",
    0x50: "ThermalPolicy", 0x54: "PstateMclkFreq", 0x58: "FanCooler",
    0x5C: "FanPolicy", 0x60: "DIDT", 0x64: "FanTest", 0x68: "VoltageRail",
    0x6C: "VoltageDevice", 0x70: "VoltagePolicy", 0x74: "LpwrIdx",
    0x78: "LpwrPcie", 0x7C: "LpwrPciePlatform", 0x80: "LpwrGr",
    0x84: "LpwrMs", 0x88: "LpwrDi", 0x8C: "LpwrGc6", 0x90: "LpwrPsi",
    0x94: "ThermalMonitor", 0x98: "Overclocking",
    0x9C: "LpwrNvlink", 0xA0: "PerfCfSensor", 0xA4: "PerfCfTopology",
    0xA8: "PerfCfController", 0xAC: "PerfCfPolicy", 0xB0: "IllumDevice",
    0xB4: "IllumZone", 0xB8: "PerfCfPwrModel", 0xBC: "LpwrAp",
    0xC0: "LpwrGcOff", 0xC4: "NneVars", 0xC8: "NneLayers", 0xCC: "NneDescs",
    0xD0: "PerfCfPmSensor", 0xD4: "LpwrGrRg", 0xD8: "LpwrEi",
    0xDC: "FanArbiter", 0xE0: "FanAcousticsQual", 0xE4: "ThermalPolicyOvrd",
}


def spec_adjust(data: bytes, legacy: dict, raw: int) -> int:
    """The NVIDIA spec's pointer rule: legacy-image-relative; if the raw
    pointer exceeds the legacy image length, add the UEFI image length."""
    if raw <= legacy["length"]:
        return legacy["base"] + raw
    efi_next = legacy["base"] + legacy["length"]
    for b2 in range(efi_next, len(data) - 0x20, 0x200):
        if data[b2] == 0x55 and data[b2 + 1] == 0xAA:
            pcir2 = b2 + u16(data, b2 + 0x18)
            if data[pcir2 : pcir2 + 4] == b"PCIR" and data[pcir2 + 0x14] == 3:
                return legacy["base"] + raw + u16(data, pcir2 + 0x10) * 512
            break
    return legacy["base"] + raw

UCODE_APP = {0: "NO", 1: "PRE_OS", 2: "GC6_DEVINIT_ENGINE",
             3: "GC6_DEVINIT_COMPACTION", 4: "PRIMARY_DEVINIT_ENGINE",
             5: "FIRMWARE_SEC_LIC", 6: "DEVINIT_RESERVED", 8: "LS_UDE",
             9: "HULK", 0x13: "DEVINIT_FMC", 0x14: "POSTLTSSM"}
UCODE_TARGET = {0: "NO", 1: "PMU", 2: "DPU", 3: "FECS", 4: "RESERVED"}


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
            return {
                "version": u8(data, off + 1),
                "table_length": u16(data, off + 2),
                "table_offset_abs": base + u16(data, off + 4),
            }
    return {}


def nameplate(data: bytes, p_token: dict) -> list[dict]:
    t_off, t_len = p_token["table_offset_abs"], p_token["table_length"]
    out = []
    for rel in range(0, t_len - 3, 4):
        raw = u32(data, t_off + rel)
        out.append(
            {
                "rel": rel,
                "name": EXTENDED_P2_NAMES.get(rel, f"unk-{rel:02x}"),
                "null": raw == 0,
                "raw": None if raw == 0 else raw,
            }
        )
    return out


def named_memclk_header(data: bytes, off: int) -> dict:
    return {
        "offset": off,
        "version": f"0x{u8(data, off):02x}",
        "header_size": u8(data, off + 1),
        "flags": u8(data, off + 6),
        "fbvdd_settle_time_us": u8(data, off + 7),
        "cfg_pwrd_val": u32(data, off + 8),
        "fbvddq_high": u16(data, off + 12),
        "fbvddq_low": u16(data, off + 14),
        "script_list_ptr": u32(data, off + 16),
        "script_list_count": u8(data, off + 20),
        "cmd_script_list_ptr": u32(data, off + 21),
        "cmd_script_list_count": u8(data, off + 25),
    }


def falcon_inventory(data: bytes, legacy: dict) -> dict | None:
    tok = find_bit_token(data, legacy, "p")
    if not tok or tok["table_length"] < 4:
        return None
    ptr_off = tok["table_offset_abs"]
    falcon_ptr = u32(data, ptr_off)
    if falcon_ptr == 0:
        return {"error": "falcon_table_ptr is null"}
    foff = spec_adjust(data, legacy, falcon_ptr)
    ver, hlen, esize, ecount, dver, dsize = (u8(data, foff + i) for i in range(6))
    entries = []
    for i in range(ecount):
        eo = foff + hlen + i * esize
        app, target = u8(data, eo), u8(data, eo + 1)
        desc_rel = u32(data, eo + 2)
        entry = {
            "index": i,
            "application": UCODE_APP.get(app, f"unk-{app:02x}"),
            "target": UCODE_TARGET.get(target, f"unk-{target:02x}"),
            "desc_rel": desc_rel,
        }
        if desc_rel:
            # the spec's pointer rule applies recursively to the desc pointer
            doff = spec_adjust(data, legacy, desc_rel)
            stored, unc = u32(data, doff), u32(data, doff + 4)
            entry["desc"] = {
                "offset": doff,
                "stored_size": stored,
                "uncompressed_size": unc,
                "virtual_entry": u32(data, doff + 8),
                "sane": 0 < stored < 0x40000 and unc != 0xFFFFFFFF,
            }
        entries.append(entry)
    return {
        "token_offset": ptr_off,
        "falcon_table_offset": foff,
        "version": f"0x{ver:02x}",
        "header_size": hlen,
        "entry_size": esize,
        "entry_count": ecount,
        "desc_version": f"0x{dver:02x}",
        "desc_size": dsize,
        "entries": entries,
    }


def anatomy(path: Path) -> dict:
    data = path.read_bytes()
    legacy = find_legacy(data)
    p_token = find_bit_token(data, legacy, "P")
    out = {
        "file": path.name,
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
    }
    if p_token:
        pl = nameplate(data, p_token)
        out["nameplate"] = {
            "dword_count": len(pl),
            "null_count": sum(1 for p in pl if p["null"]),
            "pointers": pl,
        }
        memclk_ptr = next((p["raw"] for p in pl if p["name"] == "MemClockTable" and not p["null"]), None)
        if memclk_ptr is not None:
            out["memclk_header_named"] = named_memclk_header(data, spec_adjust(data, legacy, memclk_ptr))
    out["falcon"] = falcon_inventory(data, legacy)
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
        if live["nameplate"]["dword_count"] != spec["nameplate"]["dword_count"]:
            failures.append(f"G-nameplate {name}: dword count drifted")
        key = [(x["name"], x["null"]) for x in live["nameplate"]["pointers"]]
        if key != [(x["name"], x["null"]) for x in spec["nameplate"]["pointers"]]:
            failures.append(f"G-nameplate {name}: null pattern drifted")
        if live.get("memclk_header_named") != spec.get("memclk_header_named"):
            failures.append(f"G-memclk-header {name}: named fields drifted")
        lf = live.get("falcon") or {}
        rf = spec.get("falcon") or {}
        if [(e["application"], e["target"]) for e in lf.get("entries", [])] != [
            (e["application"], e["target"]) for e in rf.get("entries", [])
        ]:
            failures.append(f"G-falcon {name}: ucode inventory drifted")
    print(f"gx8-named selftest: {len(failures)} failure(s)")
    for f in failures:
        print("  " + f)
    return 2 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["named", "selftest"])
    ap.add_argument("roms", nargs="*")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--register", type=Path, default=Path(__file__).parent / "gx8-named-register.json")
    ap.add_argument("--corpus", type=Path, default=Path(__file__).parent.parent.parent / "acquisitions")
    args = ap.parse_args()

    if args.mode == "named":
        specs = [anatomy(Path(p)) for p in args.roms]
        out = {"instrument": "gx8-named", "ring": 8, "specimens": specs}
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
