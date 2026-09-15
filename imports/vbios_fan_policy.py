#!/usr/bin/env python3
"""Read NVIDIA RTX 30/40/50 VBIOS metadata and fan policy, without modifying it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any, Iterable

BIT_SIGNATURE = b"\xff\xb8BIT\x00"
PERF_POWER_BUDGET_PTR_OFFSET = 0x2C
PERF_FAN_COOLER_PTR_OFFSET = 0x58
PERF_FAN_POLICY_PTR_OFFSET = 0x5C
FAN_POLICY_VERSION = 0x20
FAN_POLICY_RECORD_SIZE = 0x33
FAN_COOLER_VERSION = 0x10

# Exact PCI IDs only.  Unknown IDs remain unknown instead of being guessed from a range.
DEVICE_DATABASE: dict[int, dict[str, str]] = {
    0x2203: {"model": "GeForce RTX 3090 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA102"},
    0x2204: {"model": "GeForce RTX 3090", "generation": "RTX 30", "architecture": "Ampere", "die": "GA102"},
    0x2206: {"model": "GeForce RTX 3080", "generation": "RTX 30", "architecture": "Ampere", "die": "GA102"},
    0x2207: {"model": "GeForce RTX 3070 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA102"},
    0x2208: {"model": "GeForce RTX 3080 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA102"},
    0x220A: {"model": "GeForce RTX 3080", "generation": "RTX 30", "architecture": "Ampere", "die": "GA102"},
    0x2216: {"model": "GeForce RTX 3080", "generation": "RTX 30", "architecture": "Ampere", "die": "GA102"},
    0x2414: {"model": "GeForce RTX 3060 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x2482: {"model": "GeForce RTX 3070 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x2484: {"model": "GeForce RTX 3070", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x2486: {"model": "GeForce RTX 3060 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x2487: {"model": "GeForce RTX 3060", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x2488: {"model": "GeForce RTX 3070", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x2489: {"model": "GeForce RTX 3060 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x24C7: {"model": "GeForce RTX 3060", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x24C9: {"model": "GeForce RTX 3060 Ti", "generation": "RTX 30", "architecture": "Ampere", "die": "GA104"},
    0x2503: {"model": "GeForce RTX 3060", "generation": "RTX 30", "architecture": "Ampere", "die": "GA106"},
    0x2504: {"model": "GeForce RTX 3060", "generation": "RTX 30", "architecture": "Ampere", "die": "GA106"},
    0x2507: {"model": "GeForce RTX 3050", "generation": "RTX 30", "architecture": "Ampere", "die": "GA106"},
    0x2508: {"model": "GeForce RTX 3050 OEM", "generation": "RTX 30", "architecture": "Ampere", "die": "GA106"},
    0x2544: {"model": "GeForce RTX 3060", "generation": "RTX 30", "architecture": "Ampere", "die": "GA106"},
    0x2582: {"model": "GeForce RTX 3050", "generation": "RTX 30", "architecture": "Ampere", "die": "GA107"},
    0x2584: {"model": "GeForce RTX 3050", "generation": "RTX 30", "architecture": "Ampere", "die": "GA107"},
    0x2684: {"model": "GeForce RTX 4090", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD102"},
    0x2685: {"model": "GeForce RTX 4090 D", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD102"},
    0x2689: {"model": "GeForce RTX 4070 Ti SUPER", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD102"},
    0x2702: {"model": "GeForce RTX 4080 SUPER", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD103"},
    0x2704: {"model": "GeForce RTX 4080", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD103"},
    0x2705: {"model": "GeForce RTX 4070 Ti SUPER", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD103"},
    0x2709: {"model": "GeForce RTX 4070", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD103"},
    0x2782: {"model": "GeForce RTX 4070 Ti", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD104"},
    0x2783: {"model": "GeForce RTX 4070 SUPER", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD104"},
    0x2785: {"model": "GeForce RTX 4070（特殊/工程 ID）", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD104"},
    0x2786: {"model": "GeForce RTX 4070", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD104"},
    0x2788: {"model": "GeForce RTX 4060 Ti", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD104"},
    0x2803: {"model": "GeForce RTX 4060 Ti", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD106"},
    0x2805: {"model": "GeForce RTX 4060 Ti", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD106"},
    0x2808: {"model": "GeForce RTX 4060", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD106"},
    0x2882: {"model": "GeForce RTX 4060", "generation": "RTX 40", "architecture": "Ada Lovelace", "die": "AD107"},
    0x2B85: {"model": "GeForce RTX 5090", "generation": "RTX 50", "architecture": "Blackwell", "die": "GB202"},
    0x2B87: {"model": "GeForce RTX 5090 D", "generation": "RTX 50", "architecture": "Blackwell", "die": "GB202"},
    0x2B8C: {"model": "GeForce RTX 5090 D V2", "generation": "RTX 50", "architecture": "Blackwell", "die": "GB202"},
    0x2C02: {"model": "GeForce RTX 5080", "generation": "RTX 50", "architecture": "Blackwell", "die": "GB203"},
    0x2C05: {"model": "GeForce RTX 5070 Ti", "generation": "RTX 50", "architecture": "Blackwell", "die": "GB203"},
    0x2D04: {"model": "GeForce RTX 5060 Ti", "generation": "RTX 50", "architecture": "Blackwell", "die": "未确认"},
    0x2D05: {"model": "GeForce RTX 5060", "generation": "RTX 50", "architecture": "Blackwell", "die": "未确认"},
    0x2D83: {"model": "GeForce RTX 5050", "generation": "RTX 50", "architecture": "Blackwell", "die": "未确认"},
}

SUBSYSTEM_VENDOR_NAMES = {
    0x10DE: "NVIDIA（子系统厂商 ID；不等同于必然是 FE 公版）",
    0x196E: "PNY",
    0x19DA: "ZOTAC",
    0x107D: "Leadtek 丽台",
    0x1028: "Dell",
    0x1043: "ASUS",
    0x1458: "Gigabyte / AORUS",
    0x1462: "MSI",
    0x1569: "Palit",
    0x10B0: "Gainward / CardExpert",
    0x1B4C: "GALAX / KFA2",
    0x3842: "EVGA",
    0x7377: "Colorful",
    0x1849: "ASRock",
}

MEMORY_TYPE_NAMES = {
    0x0: "DDR2", 0x1: "DDR3", 0x2: "GDDR3", 0x3: "GDDR5",
    0x6: "HBM2", 0x8: "GDDR5X", 0x9: "GDDR6", 0xA: "GDDR6X", 0xD: "GDDR7",
}


def find_all(blob: bytes, needle: bytes) -> list[int]:
    result: list[int] = []
    pos = 0
    while True:
        pos = blob.find(needle, pos)
        if pos < 0:
            return result
        result.append(pos)
        pos += 1


def u16(blob: bytes, pos: int) -> int:
    return struct.unpack_from("<H", blob, pos)[0]


def u32(blob: bytes, pos: int) -> int:
    return struct.unpack_from("<I", blob, pos)[0]


def _hex_offset(value: int | None) -> str | None:
    return f"0x{value:x}" if value is not None else None


def _npde_offset(blob: bytes, pcir: int, image_end: int) -> int | None:
    if pcir + 12 > image_end:
        return None
    pcir_length = u16(blob, pcir + 0x0A)
    pos = (pcir + pcir_length + 15) & ~15
    if pos + 12 <= image_end and blob[pos:pos + 4] == b"NPDE":
        return pos
    return None


def parse_pci_images(blob: bytes) -> list[dict[str, Any]]:
    """Return valid PCI option-ROM images and their standard/NPDE metadata."""
    images: list[dict[str, Any]] = []
    seen: set[int] = set()
    for pos in find_all(blob, b"\x55\xaa"):
        if pos in seen or pos % 512 or pos + 0x1A > len(blob):
            continue
        pcir = pos + u16(blob, pos + 0x18)
        if pcir + 0x18 > len(blob) or blob[pcir:pcir + 4] != b"PCIR":
            continue
        length = u16(blob, pcir + 0x10) * 512
        if not length or pos + length > len(blob):
            continue
        seen.add(pos)
        code_type = blob[pcir + 0x14]
        image_end = pos + length
        item: dict[str, Any] = {
            "offset_int": pos,
            "offset": _hex_offset(pos),
            "pcir_offset_int": pcir,
            "pcir_offset": _hex_offset(pcir),
            "pcir_structure_length": u16(blob, pcir + 0x0A),
            "length": length,
            "code_type": code_type,
            "indicator": blob[pcir + 0x15],
            "checksum_mod256": sum(blob[pos:image_end]) % 256,
            "vendor_id_int": u16(blob, pcir + 4),
            "device_id_int": u16(blob, pcir + 6),
            "vendor_id": f"0x{u16(blob, pcir + 4):04x}",
            "device_id": f"0x{u16(blob, pcir + 6):04x}",
        }
        if code_type == 0 and pos + 3 <= len(blob):
            init_length = blob[pos + 2] * 512
            item["initialization_length"] = init_length
            item["initialization_checksum_mod256"] = (
                sum(blob[pos:pos + init_length]) % 256 if init_length and pos + init_length <= len(blob) else None
            )
        if code_type == 3 and pos + 0x0E <= image_end:
            efi_signature = u32(blob, pos + 4)
            item["efi_format_signature_valid"] = efi_signature == 0x00000EF1
            item["efi_subsystem"] = u16(blob, pos + 8)
            item["efi_machine"] = u16(blob, pos + 0x0A)
            item["efi_compression"] = u16(blob, pos + 0x0C)
        npde = _npde_offset(blob, pcir, image_end)
        item["npde_offset_int"] = npde
        item["npde_offset"] = _hex_offset(npde)
        if npde is not None:
            item["npde_revision"] = f"0x{u16(blob, npde + 4):04x}"
            item["npde_structure_length"] = u16(blob, npde + 6)
            if code_type == 0 and item["npde_structure_length"] >= 20 and npde + 20 <= image_end:
                item["subsystem_vendor_id_int"] = u16(blob, npde + 0x10)
                item["subsystem_device_id_int"] = u16(blob, npde + 0x12)
            if code_type == 3 and item["npde_structure_length"] >= 16 and npde + 16 <= image_end:
                raw = blob[npde + 0x0C:npde + 0x10]
                item["gop_version_hint"] = ".".join(f"{byte:02X}" for byte in reversed(raw))
        images.append(item)
    images.sort(key=lambda item: item["offset_int"])
    return images


def _adjacent_uefi(images: list[dict[str, Any]], legacy: dict[str, Any]) -> dict[str, Any] | None:
    legacy_end = legacy["offset_int"] + legacy["length"]
    return next(
        (image for image in images if image["code_type"] == 3 and image["offset_int"] == legacy_end),
        None,
    )


def pointer_file_offset(pointer: int, legacy: dict[str, Any], uefi: dict[str, Any] | None) -> int:
    adjusted = pointer
    if pointer > legacy["length"] and uefi is not None:
        adjusted += uefi["length"]
    return legacy["offset_int"] + adjusted


def locate_bit_context(blob: bytes, images: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Locate a checksum-valid BIT table and retain its validated token directory."""
    for legacy in (image for image in images if image["code_type"] == 0):
        legacy_start = legacy["offset_int"]
        legacy_end = legacy_start + legacy["length"]
        bit = blob.find(BIT_SIGNATURE, legacy_start, legacy_end)
        while bit >= 0:
            if bit + 12 <= legacy_end:
                header_size, token_size, token_count = blob[bit + 8:bit + 11]
                directory_end = bit + header_size + token_size * token_count
                if (
                    header_size >= 12 and token_size >= 6 and directory_end <= legacy_end
                    and sum(blob[bit:bit + header_size]) % 256 == 0
                ):
                    tokens: dict[str, dict[str, Any]] = {}
                    valid = True
                    for index in range(token_count):
                        token_pos = bit + header_size + index * token_size
                        token_id = blob[token_pos]
                        data_size = u16(blob, token_pos + 2)
                        data_pointer = u16(blob, token_pos + 4)
                        data_pos = legacy_start + data_pointer
                        if data_size and not (legacy_start <= data_pos <= legacy_end and data_pos + data_size <= legacy_end):
                            valid = False
                            break
                        key = chr(token_id) if 32 <= token_id < 127 else f"0x{token_id:02x}"
                        tokens[key] = {
                            "id": token_id, "version": blob[token_pos + 1], "size": data_size,
                            "pointer": data_pointer, "offset_int": data_pos, "offset": _hex_offset(data_pos),
                            "directory_offset": _hex_offset(token_pos),
                        }
                    if valid:
                        return {
                            "bit_offset_int": bit, "bit_offset": _hex_offset(bit),
                            "header_size": header_size, "token_size": token_size,
                            "token_count": token_count, "header_checksum_valid": True,
                            "tokens": tokens, "legacy": legacy, "uefi": _adjacent_uefi(images, legacy),
                        }
            bit = blob.find(BIT_SIGNATURE, bit + 1, legacy_end)
    return None


def locate_bit_perf(blob: bytes, images: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Compatibility wrapper for the previous public helper."""
    context = locate_bit_context(blob, images)
    if context is None:
        return None
    perf = context["tokens"].get("P")
    if not perf or perf["version"] != 2 or perf["size"] < 0x60:
        return None
    return {
        "bit_offset_int": context["bit_offset_int"], "bit_offset": context["bit_offset"],
        "perf_offset_int": perf["offset_int"], "perf_offset": perf["offset"],
        "perf_size": perf["size"], "legacy": context["legacy"], "uefi": context["uefi"],
    }


def _token_data(context: dict[str, Any] | None, token_id: str, version: int | None = None) -> dict[str, Any] | None:
    if not context:
        return None
    token = context["tokens"].get(token_id)
    if not token or (version is not None and token["version"] != version):
        return None
    return token


def _version_from_bytes(raw: bytes) -> str | None:
    if len(raw) < 5:
        return None
    return ".".join(f"{byte:02X}" for byte in (raw[3], raw[2], raw[1], raw[0], raw[4]))


def _read_ascii_string(blob: bytes, pos: int, max_length: int) -> str | None:
    if pos < 0 or pos >= len(blob) or not max_length:
        return None
    raw = blob[pos:min(len(blob), pos + max_length)].split(b"\0", 1)[0]
    try:
        text = raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        return None
    if not text or any(ord(char) < 9 or (13 < ord(char) < 32) for char in text):
        return None
    return text


def parse_bit_metadata(blob: bytes, context: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": None, "build_date_bit_i": None, "option_rom_header_date": None,
        "board_id": None, "strings": {}, "version_consistent": None,
    }
    if context is None:
        return result
    versions: list[str] = []
    token_b = _token_data(context, "B", 2)
    if token_b and token_b["size"] >= 6:
        raw = blob[token_b["offset_int"]:token_b["offset_int"] + token_b["size"]]
        result["version"] = _version_from_bytes(raw)
        result["build_checksum_field"] = f"0x{raw[5]:02X}"
        result["version_source"] = "BIT B v2"
        if result["version"]:
            versions.append(result["version"])
    token_i = _token_data(context, "i", 2)
    if token_i and token_i["size"] >= 0x17:
        pos = token_i["offset_int"]
        i_version = _version_from_bytes(blob[pos:pos + 5])
        result["info_version"] = i_version
        if i_version:
            versions.append(i_version)
        date_raw = blob[pos + 0x0F:pos + 0x17]
        try:
            date = date_raw.decode("ascii")
        except UnicodeDecodeError:
            date = ""
        if re.fullmatch(r"\d{2}/\d{2}/\d{2}", date):
            result["build_date_bit_i"] = date
    token_s = _token_data(context, "S", 2)
    if token_s and token_s["size"] >= 21:
        labels = ("sign_on", "version", "copyright", "oem", "oem_vendor", "product", "revision")
        pos = token_s["offset_int"]
        for index, label in enumerate(labels):
            pointer = u16(blob, pos + index * 3)
            max_length = blob[pos + index * 3 + 2]
            file_pos = pointer_file_offset(pointer, context["legacy"], context["uefi"])
            result["strings"][label] = _read_ascii_string(blob, file_pos, max_length)
        version_string = result["strings"].get("version") or ""
        match = re.search(r"([0-9A-F]{2}(?:\.[0-9A-F]{2}){4})", version_string, re.I)
        if match:
            result["string_version"] = match.group(1).upper()
            versions.append(result["string_version"])
        sign_on = result["strings"].get("sign_on") or ""
        board = re.search(r"PG\d+\s+SKU\s+\d+", sign_on, re.I)
        if board:
            result["board_id"] = board.group(0).upper()
    header = blob[context["legacy"]["offset_int"]:context["legacy"]["offset_int"] + 0x100]
    match = re.search(rb"\d{2}/\d{2}/\d{2}", header)
    if match:
        result["option_rom_header_date"] = match.group(0).decode("ascii")
    if versions:
        result["version_consistent"] = len(set(versions)) == 1
    return result


def parse_hardware(images: list[dict[str, Any]]) -> dict[str, Any]:
    legacy = next((image for image in images if image["code_type"] == 0), None)
    if not legacy:
        return {"vendor_id": None, "device_id": None, "model": None, "generation": None, "architecture": None, "die": None}
    device_id = legacy["device_id_int"]
    known = DEVICE_DATABASE.get(device_id, {})
    return {
        "vendor_id": f"{legacy['vendor_id_int']:04X}", "device_id": f"{device_id:04X}",
        "pci_id": f"{legacy['vendor_id_int']:04X}:{device_id:04X}",
        "model": known.get("model"), "generation": known.get("generation"),
        "architecture": known.get("architecture"), "die": known.get("die"),
        "identity_source": "精确 PCI Device ID 映射" if known else "ROM legacy PCIR；型号未映射",
    }


def parse_subsystem(images: list[dict[str, Any]]) -> dict[str, Any]:
    legacy = next((image for image in images if image["code_type"] == 0), None)
    if not legacy or "subsystem_vendor_id_int" not in legacy:
        return {"vendor_id": None, "device_id": None, "brand": None, "source": None}
    vendor = legacy["subsystem_vendor_id_int"]
    device = legacy["subsystem_device_id_int"]
    return {
        "vendor_id": f"{vendor:04X}", "device_id": f"{device:04X}", "id": f"{vendor:04X}:{device:04X}",
        "brand": SUBSYSTEM_VENDOR_NAMES.get(vendor, "未知品牌（保留原始 ID）"),
        "source": "legacy PCI image 的 NVIDIA NPDE 扩展字段",
    }


def parse_uefi(images: list[dict[str, Any]]) -> dict[str, Any]:
    legacy = next((image for image in images if image["code_type"] == 0), None)
    uefi = _adjacent_uefi(images, legacy) if legacy else None
    if not uefi:
        return {"present": False}
    subsystem_names = {0x0B: "Boot Service Driver", 0x0C: "Runtime Driver"}
    machine_names = {0x014C: "IA32", 0x8664: "x64", 0xAA64: "ARM64"}
    compression_names = {0: "未压缩", 1: "UEFI 压缩"}
    return {
        "present": True, "offset": uefi["offset"], "length": uefi["length"],
        "efi_format_signature_valid": uefi.get("efi_format_signature_valid", False),
        "subsystem": subsystem_names.get(uefi.get("efi_subsystem"), f"0x{uefi.get('efi_subsystem', 0):04X}"),
        "machine": machine_names.get(uefi.get("efi_machine"), f"0x{uefi.get('efi_machine', 0):04X}"),
        "compression": compression_names.get(uefi.get("efi_compression"), str(uefi.get("efi_compression"))),
        "gop_version_hint": uefi.get("gop_version_hint"),
        "gop_confidence": "中（来自 UEFI NPDE 扩展字段）" if uefi.get("gop_version_hint") else None,
    }


def parse_memory_info(blob: bytes, context: dict[str, Any] | None) -> dict[str, Any]:
    unavailable = {
        "table_found": False, "memory_types": [], "vendor_codes": [], "vendor_candidates": [],
        "actual_capacity": "离线 VBIOS 无法可靠确定；需结合运行中 GPU/硬件 RAMCFG strap",
        "actual_chips": "ROM 表示支持配置，不代表 PCB 实际焊接颗粒",
    }
    token = _token_data(context, "M", 2)
    if not token or token["size"] < 5 or context is None:
        return unavailable
    mpos = token["offset_int"]
    pointer = u16(blob, mpos + 3)
    table = pointer_file_offset(pointer, context["legacy"], context["uefi"])
    if table + 4 > len(blob):
        return unavailable
    version, header_size, record_size, count = blob[table:table + 4]
    end = table + header_size + record_size * count
    if version != 0x10 or header_size < 4 or record_size < 2 or not count or end > len(blob):
        return unavailable
    entries: list[dict[str, Any]] = []
    type_ids: list[int] = []
    vendor_codes: list[int] = []
    for index in range(count):
        pos = table + header_size + index * record_size
        raw = blob[pos:pos + record_size]
        type_id = raw[0] & 0x0F
        if type_id == 0x0F:
            continue
        vendor_code = raw[1] >> 4
        type_ids.append(type_id)
        vendor_codes.append(vendor_code)
        entries.append({
            "index": index, "ramcfg_index": raw[0] >> 4, "memory_type_id": f"0x{type_id:X}",
            "memory_type": MEMORY_TYPE_NAMES.get(type_id, f"未知类型 0x{type_id:X}"),
            "vendor_code_high_nibble": f"0x{vendor_code:X}", "raw": raw.hex(" "),
        })
    unique_types = list(dict.fromkeys(MEMORY_TYPE_NAMES.get(value, f"未知类型 0x{value:X}") for value in type_ids))
    unique_codes = list(dict.fromkeys(vendor_codes))
    candidates: list[str] = []
    for code in unique_codes:
        if code == 1:
            candidates.append("Samsung（候选编码，高置信）")
        elif code == 6:
            candidates.append("SK hynix（候选编码，高置信）")
        elif code == 0xF:
            candidates.append("未指定/通配编码 0xF（不能据此直接认作 Micron）")
        else:
            candidates.append(f"厂商编码 0x{code:X}（公开映射不足）")
    return {
        **unavailable, "table_found": True, "offset": _hex_offset(table), "pointer": _hex_offset(pointer),
        "version": f"0x{version:02X}", "header_size": header_size, "record_size": record_size,
        "record_count": count, "active_config_count": len(entries), "memory_types": unique_types,
        "vendor_codes": [f"0x{code:X}" for code in unique_codes], "vendor_candidates": candidates,
        "entries": entries, "type_confidence": "高（BIT M v2 Memory Information Table）",
        "vendor_confidence": "部分可识别；厂商编码未完全公开，不能视为实际焊接颗粒",
    }


def parse_power_budget(blob: bytes, context: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {"table_found": False, "decoded": False}
    perf = _token_data(context, "P", 2)
    if not perf or perf["size"] < PERF_POWER_BUDGET_PTR_OFFSET + 4 or context is None:
        return result
    raw_pointer = u32(blob, perf["offset_int"] + PERF_POWER_BUDGET_PTR_OFFSET)
    if not raw_pointer:
        return result
    table = pointer_file_offset(raw_pointer, context["legacy"], context["uefi"])
    if table + 4 > len(blob):
        return result
    version, header_size, record_size, count = blob[table:table + 4]
    end = table + header_size + record_size * count
    result.update({
        "table_found": True, "offset": _hex_offset(table), "pointer": _hex_offset(raw_pointer),
        "version": f"0x{version:02X}", "header_size": header_size,
        "record_size": record_size, "record_count": count,
    })
    if header_size < 4 or not record_size or not count or end > len(blob):
        result["error"] = "Power Budget 表边界无效"
        return result
    if version == 0x30 and count > 2 and record_size >= 0x0E:
        record_index, offsets = 2, (0x02, 0x06, 0x0A)
    elif version == 0x40 and count > 8 and record_size >= 0x19:
        record_index, offsets = 8, (0x0D, 0x11, 0x15)
    else:
        result["error"] = "已发现表，但该版本尚无可靠的板卡主功耗记录映射"
        return result
    record = table + header_size + record_index * record_size
    values = [u32(blob, record + offset) for offset in offsets]
    if not (10_000 <= values[0] <= values[1] <= values[2] <= 1_500_000):
        result["error"] = "主功耗记录未通过数值/单调性校验"
        result["raw_candidate_mw"] = values
        return result
    result.update({
        "decoded": True, "record_index": record_index, "minimum_w": values[0] / 1000,
        "default_w": values[1] / 1000, "maximum_w": values[2] / 1000,
        "source": f"BIT P v2 +0x2C Power Budget v{version:02X}，板卡主记录 #{record_index}",
        "confidence": "高（结构、范围和单调性已验证）",
    })
    return result


def decode_fan_policy_record(blob: bytes, pos: int, index: int, table_pos: int, record_size: int) -> dict[str, Any]:
    duty = list(blob[pos + 14:pos + 17])
    temperatures = [round(u16(blob, pos + off) / 32.0, 4) for off in (18, 22, 26)]
    rpms = [u16(blob, pos + off) for off in (20, 24, 28)]
    stop = round(u16(blob, pos + 30) / 32.0, 4)
    start = round(u16(blob, pos + 32) / 32.0, 4)
    return {
        "index": index, "offset": _hex_offset(pos), "table_offset": _hex_offset(table_pos),
        "controller_index": blob[pos], "policy_index": blob[pos + 1],
        "duty_percent": duty, "temperature_c": temperatures, "target_rpm": rpms,
        "flag": f"0x{blob[pos + 50]:02x}",
        "possible_stop_start_c": {"stop": stop, "start": start},
        "stop_start_hint_plausible": 0 < stop < start <= 120,
        # Retained for compatibility; this is a hint, not proof that the physical fan stops.
        "zero_rpm_possible": 0 < stop < start <= 120,
        "raw": blob[pos:pos + record_size].hex(" "),
    }


def _fan_record_plausible(record: dict[str, Any]) -> bool:
    duty = record["duty_percent"]
    temps = record["temperature_c"]
    rpms = record["target_rpm"]
    return (
        all(0 <= value <= 100 for value in duty) and duty == sorted(duty)
        and all(0 <= value <= 130 for value in temps) and temps == sorted(temps)
        and all(0 <= value <= 20_000 for value in rpms) and rpms == sorted(rpms)
        and any(rpms)
    )


def parse_pointed_fan_policy(blob: bytes, table_pos: int) -> dict[str, Any] | None:
    if table_pos < 0 or table_pos + 4 > len(blob):
        return None
    version, header_size, record_size, record_count = blob[table_pos:table_pos + 4]
    if version != FAN_POLICY_VERSION or header_size < 4 or record_size < FAN_POLICY_RECORD_SIZE or not record_count:
        return None
    end = table_pos + header_size + record_size * record_count
    if end > len(blob):
        return None
    records = [
        decode_fan_policy_record(blob, table_pos + header_size + index * record_size, index, table_pos, record_size)
        for index in range(record_count)
    ]
    if not records or not all(_fan_record_plausible(record) for record in records):
        return None
    main = records[0]
    return {
        "offset": _hex_offset(table_pos), "source": "BIT P v2 Fan Policy pointer",
        "version": f"0x{version:02x}", "header_size": header_size,
        "record_size": record_size, "record_count": record_count,
        "active_record_count": sum(any(record["target_rpm"]) for record in records),
        "max_target_rpm": max(max(record["target_rpm"]) for record in records),
        "fan_stop_possible": main["stop_start_hint_plausible"],
        "fan_stop_note": "仅由主策略记录的原始 stop/start 字段推断，需在实际显卡上验证",
        "records": records,
    }


def parse_pointed_fan_cooler(blob: bytes, table_pos: int) -> dict[str, Any] | None:
    if table_pos < 0 or table_pos + 4 > len(blob):
        return None
    version, header_size, record_size, record_count = blob[table_pos:table_pos + 4]
    if version != FAN_COOLER_VERSION or header_size < 4 or not record_size or not record_count:
        return None
    end = table_pos + header_size + record_size * record_count
    if end > len(blob):
        return None
    entries = []
    for index in range(record_count):
        pos = table_pos + header_size + index * record_size
        raw = blob[pos:pos + record_size]
        entry: dict[str, Any] = {"index": index, "offset": _hex_offset(pos), "raw": raw.hex(" ")}
        if record_size >= 0x12:
            entry.update({
                "duty_min_percent": raw[2], "duty_max_percent": raw[3],
                "pwm_frequency": int.from_bytes(raw[0x0B:0x0E], "little"),
                "rpm_candidate_min": u16(raw, 0x0E), "rpm_candidate_max": u16(raw, 0x10),
                "minimum_rpm": u16(raw, 0x0E), "maximum_rpm": u16(raw, 0x10),
            })
        entries.append(entry)
    return {
        "offset": _hex_offset(table_pos), "source": "BIT P v2 Fan Cooler pointer",
        "version": f"0x{version:02x}", "header_size": header_size, "record_size": record_size,
        "record_count": record_count, "rpm_field_note": "RPM 值需由 Fan Policy 表交叉确认", "entries": entries,
    }


def parse_bit_fan_tables(blob: bytes, images: list[dict[str, Any]], context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or locate_bit_context(blob, images)
    perf = _token_data(context, "P", 2)
    if not perf or perf["size"] < 0x60 or context is None:
        return {"bit": None, "fan_policy": None, "fan_cooler": None}
    perf_pos = perf["offset_int"]
    policy_pointer = u32(blob, perf_pos + PERF_FAN_POLICY_PTR_OFFSET)
    cooler_pointer = u32(blob, perf_pos + PERF_FAN_COOLER_PTR_OFFSET)
    policy_offset = pointer_file_offset(policy_pointer, context["legacy"], context["uefi"]) if policy_pointer else None
    cooler_offset = pointer_file_offset(cooler_pointer, context["legacy"], context["uefi"]) if cooler_pointer else None
    return {
        "bit": {
            "bit_offset": context["bit_offset"], "bit_header_checksum_valid": context["header_checksum_valid"],
            "perf_offset": perf["offset"], "perf_size": perf["size"],
            "legacy_offset": context["legacy"]["offset"], "legacy_length": context["legacy"]["length"],
            "uefi_offset": context["uefi"]["offset"] if context["uefi"] else None,
            "uefi_length": context["uefi"]["length"] if context["uefi"] else 0,
            "fan_cooler_pointer": _hex_offset(cooler_pointer) if cooler_pointer else None,
            "fan_policy_pointer": _hex_offset(policy_pointer) if policy_pointer else None,
            "fan_cooler_file_offset": _hex_offset(cooler_offset), "fan_policy_file_offset": _hex_offset(policy_offset),
        },
        "fan_policy": parse_pointed_fan_policy(blob, policy_offset) if policy_offset is not None else None,
        "fan_cooler": parse_pointed_fan_cooler(blob, cooler_offset) if cooler_offset is not None else None,
    }


def scan_fan_policies(blob: bytes) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    for pos in find_all(blob, bytes([FAN_POLICY_VERSION, 4, FAN_POLICY_RECORD_SIZE])):
        table = parse_pointed_fan_policy(blob, pos)
        if table is not None:
            table["source"] = "validated fallback scan"
            tables.append(table)
    return tables


def parse_integrity(images: list[dict[str, Any]], context: dict[str, Any] | None) -> dict[str, Any]:
    legacy = next((image for image in images if image["code_type"] == 0), None)
    return {
        "bit_header_checksum_valid": context["header_checksum_valid"] if context else None,
        "legacy_initialization_checksum_valid": (
            legacy.get("initialization_checksum_mod256") == 0
            if legacy and legacy.get("initialization_checksum_mod256") is not None else None
        ),
        "pci_image_checksum_results": [
            {"offset": image["offset"], "code_type": f"0x{image['code_type']:02X}", "mod256": image["checksum_mod256"]}
            for image in images
        ],
        "digital_signature": "未验证（未知）",
        "digital_signature_note": "本工具没有 NVIDIA 信任根、签名算法和签名区域定义；EFI 格式签名/BIT 校验均不等于数字签名验证",
    }


def analyze(path: Path) -> dict[str, Any]:
    blob = path.read_bytes()
    images = parse_pci_images(blob)
    context = locate_bit_context(blob, images)
    pointed = parse_bit_fan_tables(blob, images, context)
    policies = [pointed["fan_policy"]] if pointed["fan_policy"] else scan_fan_policies(blob)
    hardware = parse_hardware(images)
    metadata = parse_bit_metadata(blob, context)
    return {
        "file": str(path), "size_bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest(),
        "hardware": hardware, "vbios": metadata, "subsystem": parse_subsystem(images),
        "uefi": parse_uefi(images), "memory": parse_memory_info(blob, context),
        "power": parse_power_budget(blob, context), "integrity": parse_integrity(images, context),
        "device_id_hint": f"0x{hardware['device_id'].lower()}" if hardware.get("device_id") else None,
        "series_hint": " / ".join(filter(None, (hardware.get("generation"), hardware.get("architecture")))),
        "pci_images": images, "bit_pointer_info": pointed["bit"], "fan_cooler_table": pointed["fan_cooler"],
        "fan_tables": policies,
        "notes": [
            "只读分析：不会修改或刷写 VBIOS。",
            "容量、实际焊接显存颗粒和数字签名不能仅凭离线 ROM 可靠确定。",
            "智能启停与部分未公开字段只作提示，需在实际显卡上验证。",
        ],
    }


def fmt_number(value: float) -> str:
    return f"{value:g}"


def fmt_record(record: dict[str, Any]) -> str:
    temperatures = "/".join(f"{fmt_number(x)}°C" for x in record["temperature_c"])
    duty = "/".join(f"{x}%" for x in record["duty_percent"])
    rpms = "/".join(str(x) for x in record["target_rpm"])
    stop_start = record["possible_stop_start_c"]
    hint = "可能" if record["stop_start_hint_plausible"] else "未发现"
    return (
        f"    策略记录 #{record['index']} | 温度 {temperatures} | PWM {duty} | 目标RPM {rpms} | "
        f"原始停/启提示 {fmt_number(stop_start['stop'])}/{fmt_number(stop_start['start'])}°C（{hint}，语义待实卡验证） | "
        f"flag {record['flag']}"
    )


def _yes_no_unknown(value: bool | None) -> str:
    if value is None:
        return "未检测"
    return "通过" if value else "未通过"


def print_report(data: dict[str, Any]) -> None:
    hardware, vbios = data["hardware"], data["vbios"]
    subsystem, uefi = data["subsystem"], data["uefi"]
    print(f"文件: {data['file']}")
    print(f"大小: {data['size_bytes']:,} bytes")
    print(f"SHA-256: {data['sha256']}")
    print("\n=== GPU / VBIOS 基本信息 ===")
    print(f"GPU: {hardware.get('model') or '型号未映射'}")
    print(f"系列 / 架构代目 / 核心: {hardware.get('generation') or '未知'} / {hardware.get('architecture') or '未知'} / {hardware.get('die') or '未知'}")
    print(f"PCI ID: {hardware.get('pci_id') or '未识别'}（{hardware.get('identity_source') or '无'}）")
    print(f"VBIOS 版本: {vbios.get('version') or '未解析'}（{vbios.get('version_source') or '无'}）")
    print(f"VBIOS 构建日期: {vbios.get('build_date_bit_i') or '未解析'}（BIT i）")
    print(f"Option-ROM 镜像/封装日期: {vbios.get('option_rom_header_date') or '未解析'}")
    print(f"板号线索: {vbios.get('board_id') or '未解析'}（工程 PG/SKU，不是零售型号）")
    if vbios.get("version_consistent") is False:
        print("警告: BIT B / i / 字符串中的 VBIOS 版本不一致")
    print(f"子系统 ID: {subsystem.get('id') or '未解析'}")
    print(f"子 ID 品牌: {subsystem.get('brand') or '未解析'}（来源: {subsystem.get('source') or '无'}）")
    if uefi.get("present"):
        print(f"UEFI GOP: 有 | {uefi.get('machine')} | {uefi.get('subsystem')} | {uefi.get('compression')}")
        print(f"GOP 版本线索: {uefi.get('gop_version_hint') or '未解析'}（{uefi.get('gop_confidence') or '无'}）")
    else:
        print("UEFI GOP: 未找到相邻有效 UEFI 镜像")
    strings = vbios.get("strings", {})
    if strings.get("sign_on"):
        print(f"Sign-on: {strings['sign_on'].replace(chr(13), ' ').replace(chr(10), ' | ')}")

    memory = data["memory"]
    print("\n=== 显存信息 ===")
    if memory["table_found"]:
        print(f"支持类型（ROM 配置表）: {', '.join(memory['memory_types']) or '未识别'}")
        print(f"有效 RAMCFG 配置: {memory['active_config_count']} / {memory['record_count']} 条 | 表 {memory['offset']}")
        print(f"颗粒厂商候选: {', '.join(memory['vendor_candidates']) or '未识别'}")
        print(f"厂商结论限制: {memory['vendor_confidence']}")
    else:
        print("未找到可验证的 BIT M v2 Memory Information Table")
    print(f"实际显存容量: {memory['actual_capacity']}")
    print(f"实际显存颗粒: {memory['actual_chips']}")

    power = data["power"]
    print("\n=== 板卡功耗 ===")
    if power.get("decoded"):
        print(
            f"最低 / 默认 / 最大功耗: {fmt_number(power['minimum_w'])} / {fmt_number(power['default_w'])} / "
            f"{fmt_number(power['maximum_w'])} W"
        )
        print(f"来源: {power['source']} | {power['confidence']} | 表 {power['offset']}")
    elif power.get("table_found"):
        print(f"发现 Power Budget 表 {power['offset']}（版本 {power['version']}），但未可靠解出板卡最大功耗")
        if power.get("error"):
            print(f"原因: {power['error']}")
    else:
        print("未找到可验证的 Power Budget 表")

    print("\n=== 风扇温控策略 ===")
    bit = data.get("bit_pointer_info")
    if bit:
        print(
            f"BIT P v2: BIT {bit['bit_offset']} | P表 {bit['perf_offset']} | "
            f"Fan Cooler {bit['fan_cooler_file_offset']} | Fan Policy {bit['fan_policy_file_offset']}"
        )
    cooler = data.get("fan_cooler_table")
    if cooler:
        print(f"Fan Cooler 表 {cooler['offset']}：{cooler['record_count']} 条，记录长度 {cooler['record_size']} bytes")
        for entry in cooler["entries"]:
            if "rpm_candidate_max" in entry:
                print(
                    f"  冷却器配置 #{entry['index']} | PWM {entry['duty_min_percent']}–{entry['duty_max_percent']}% | "
                    f"转速候选 {entry['rpm_candidate_min']}–{entry['rpm_candidate_max']} RPM | PWM频率 {entry['pwm_frequency']}"
                )
    if not data["fan_tables"]:
        print("未找到可信的 BIT 指针风扇策略表或经过结构验证的备用表。")
    for table in data["fan_tables"]:
        print(
            f"策略表 {table['offset']}（{table['source']}）：{table['record_count']} 条，"
            f"最高目标 {table['max_target_rpm']} RPM，智能启停提示={'可能' if table['fan_stop_possible'] else '未发现'}"
        )
        print(f"  注: {table['fan_stop_note']}")
        for record in table["records"]:
            print(fmt_record(record))

    integrity = data["integrity"]
    print("\n=== 完整性 / 镜像 ===")
    print(f"BIT 头校验: {_yes_no_unknown(integrity['bit_header_checksum_valid'])}")
    print(f"Legacy 初始化区校验: {_yes_no_unknown(integrity['legacy_initialization_checksum_valid'])}")
    print(f"数字签名/证书: {integrity['digital_signature']}（不能由普通 checksum 推断）")
    print(f"PCI option-ROM 镜像: {len(data['pci_images'])}")
    for image in data["pci_images"]:
        print(
            f"  {image['offset']} device {image['device_id']} 长度 {image['length']} | "
            f"类型 0x{image['code_type']:02X} | image checksum mod256={image['checksum_mod256']}"
        )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="只读分析 NVIDIA RTX 30/40/50 VBIOS 综合信息与风扇策略")
    parser.add_argument("rom", nargs="+", type=Path, help="一个或多个 .rom/.bin 文件")
    parser.add_argument("--json", action="store_true", help="输出完整 JSON")
    parser.add_argument("--out", type=Path, help="JSON 模式下写入文件")
    args = parser.parse_args(list(argv) if argv is not None else None)
    results = []
    for path in args.rom:
        try:
            results.append(analyze(path))
        except (OSError, ValueError, struct.error) as exc:
            print(f"读取失败: {path}: {exc}", file=sys.stderr)
            return 2
    if args.json:
        payload: Any = results[0] if len(results) == 1 else results
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.out:
            args.out.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
    else:
        for index, result in enumerate(results):
            if index:
                print("\n" + "=" * 88 + "\n")
            print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
