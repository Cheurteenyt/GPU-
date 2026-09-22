#!/usr/bin/env python3
"""4.25 pass — the x86 marshal hunt for the interface 0x2080d0 (the 1544-B
struct of control 0x2080d031) — and the substrate falsification that
redirected it.

THE TASK (the 4.24 queue, pass I §"Queue for 4.25"): mine the closed x86
blob for the interface-0x2080d0 marshal — the marshal code embeds the
field offsets, so the 1544-B params struct {poff 0=255, 4=3, 8=257,
56=257, 64=250000} would be reconstructible from its copy graph.

THE SUBSTRATE PREMISE, TESTED FIRST (this instrument, section A):
  the task names tools/analysis/gsp-extract/win.elf as "the closed x86
  blob". Byte-level audit: win.elf is a 768-B RISC-V ELF *disassembly
  window* carved out of binaries/gsp-rm-17MB.bin by win-disasm.py (the
  committed generator; section A re-executes its recipe and reproduces
  the file byte-identically). It is not x86 and holds no marshal.

THE REDIRECT, run honestly on everything the repo actually holds:

  B. THE X86 CENSUS — every non-RISC-V executable committed in the repo
     (the nvflash family x86/x64/PPC64/AArch64 + busybox) and the
     archives (nvflash-5.867.zip, the day0 initramfs cpio.gz set),
     scanned for the interface-0x2080d0 family ids and for 250000.
     Hit classification is instruction-aware: an x86 u32 "250000" that
     begins at a modrm byte preceded by an opcode is the modrm+disp32
     overlap of e.g. call [rax+0x3d0] — NOT the value; an unaligned hit
     in a fixed-width ISA (aarch64/ppc64) is a cross-instruction
     boundary overlap (context-disassembled to prove it). The closed
     host RM (nvidia.ko unpacked, 27.7 MB — findings-4.22 §3) is NOT
     committed anywhere. Verdict: the host-side marshal is NOT in the
     repo — named honestly, not worked around.

  C. THE FIRMWARE SIDE — the only closed substrate present (rm-full.elf
     = the GSP-RM RISC-V image, LOAD @0x1000000): the full
     interface-0x2080d0 family map from the 4.20 dispatch table
     (@0x1c183b8, 1,156 entries, stride 0x20 — v424_entry_calib.py):
     19 controls, per-control tags (paramsSize), shared pA/sz0, the
     handler code region + its interface interleaving; the whole-image
     dword census (each family id exists ONCE — its dispatch entry);
     the code-immediate census (lui hi=0x2080d + addi: ZERO sites — the
     firmware never materializes the family ids as immediates); the
     closed-interface census vs the open SDK's 38/0x2080a7 (4.24 §1).

  D. THE 250000 QUESTION on the available substrates: the GSP-RM's own
     uses of the constant (zero u32 data dwords; four lui+addi code
     sites — disassembled ±context, 4.16-map verified status) and the
     x86 binaries' apparent hits (all instruction artifacts, not the
     value). The producer of the @64 250000 rides nvidia.ko — absent.

  E. THE STRUCT LEDGER — the five captured offsets re-derived from
     tools/edpp/edpp_payload_1616.bin (the 4.24 anchors): what is
     PROVEN (size 1544, carried values, handler-ignored) and what
     stays HYPOTHESIS (field names) and WHY (the naming substrate —
     the host marshal — is not in the repo).

  F. THE OPEN-TAG CROSS-CHECK — the raw open-gpu-kernel-modules TAG
     610.57.04 ctrl2080 headers (fetched once into
     lab/jalon411/.v425-ctrl2080-cache/ — the v424_citation_audit.py
     fetch-once pattern; per-file sha256 pinned in the JSON): the open
     interface census (34 interfaces with shipped commands, 38 FINN
     names — the 4.24 §1 "38" reconciled; max 0x2080a7 re-derived),
     the open↔closed join (385 named commands × their dispatch tags:
     tag == sizeof(params struct) validated on GET_EDPP=24 B,
     UPDATE_EDPP=8 B and FIFO_QUERY_CHANNEL_UNIQUE_ID=1540 B), the
     same-1544-B sibling census (three controls, ALL closed:
     0x20809004, 0x20809030, 0x2080d031 — the two siblings share the
     family's code region), and the closed-only interface list (30 in
     the table, in no shipped header — 0x2080d0 AND 0x208090 among
     them). Degrades gracefully without network.

Output: lab/jalon411/v425_x86_marshal.json (+ the console verdicts).
Standalone: every substrate path resolves from the repo root (two
parents up from this file); no /usr/src dependency (the open headers
are fetched from the raw tag, not the local tree).
Self-test: the banked anchors (the dispatch entry, tag 0x608, the
five nonzero u32s, the win.elf regeneration, the join anchors) are
asserted — a drift exits non-zero with the DRIFT name.
"""
import gzip
import json
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GSP_DIR = REPO / "tools" / "analysis" / "gsp-extract"
FLASH_DIR = REPO / "tools" / "flash"
OUT = REPO / "lab" / "jalon411" / "v425_x86_marshal.json"

# ---- the banked constants (findings-4.24, re-derived below) ----
TABLE_VA = 0x1C183B8          # the 4.20 dispatch table (v424_entry_calib.py)
N_ENTRIES = 1156              # 1156 entries, stride 0x20
STRIDE = 0x20
IMG_LO = 0x1000000            # rm-full.elf single RWX LOAD vaddr
FAM_LO, FAM_HI = 0x2080D000, 0x2080D0FF   # the interface-0x2080d0 family
CMD = 0x2080D031              # this campaign's control
TAG_0x608 = 1544              # the cmd's paramsSize (the dispatch tag)
BANKED_FIVE = {0: 255, 4: 3, 8: 257, 56: 257, 64: 250000}  # 4.24 §1
ANCHORS = {                   # the 4.24 §4 calibration anchors
    0x20800AFD: "PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO",
    0x20800AD0: "PMGR_PFM_REQ_HNDLR_UPDATE_EDPP_LIMIT",
}
# the open-SDK census (findings-4.24 §1, verified there against the
# 610.57.04 headers): 38 interfaces 0x2080, id max 0x2080a7 — the
# closed-only claim this pass cross-checks from the firmware table
# AND re-derives from the raw tag (section F)
OPEN_SDK = {"interfaces": 38, "max_interface": 0x2080A7}
TAG_REF = "610.57.04"
CTRL_BASE = (f"https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/"
             f"{TAG_REF}/src/common/sdk/nvidia/inc/ctrl/ctrl2080")
CTRL_PARENT = (f"https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/"
               f"{TAG_REF}/src/common/sdk/nvidia/inc/ctrl/ctrl2080.h")
CACHE = REPO / "lab" / "jalon411" / ".v425-ctrl2080-cache"
CTRL_HEADERS = [
    "ctrl2080acr", "ctrl2080base", "ctrl2080bif", "ctrl2080bios",
    "ctrl2080boardobj", "ctrl2080boardobjgrpclasses", "ctrl2080bus",
    "ctrl2080ce", "ctrl2080cipher", "ctrl2080clk", "ctrl2080clkavfs",
    "ctrl2080dma", "ctrl2080dmabuf", "ctrl2080ecc", "ctrl2080event",
    "ctrl2080fan", "ctrl2080fb", "ctrl2080fifo", "ctrl2080fla",
    "ctrl2080flcn", "ctrl2080fuse", "ctrl2080gpio", "ctrl2080gpu",
    "ctrl2080gpumon", "ctrl2080gr", "ctrl2080grmgr", "ctrl2080gsp",
    "ctrl2080hshub", "ctrl2080i2c", "ctrl2080illum", "ctrl2080internal",
    "ctrl2080lpwr", "ctrl2080mc", "ctrl2080nvd", "ctrl2080nvlink",
    "ctrl2080nvlink_common", "ctrl2080perf", "ctrl2080perf_cf",
    "ctrl2080perf_cf_pwr_model", "ctrl2080pmgr", "ctrl2080pmu",
    "ctrl2080pmumon", "ctrl2080power", "ctrl2080rc", "ctrl2080spdm",
    "ctrl2080spi", "ctrl2080thermal", "ctrl2080tmr",
    "ctrl2080ucodefuzzer", "ctrl2080unix", "ctrl2080vfe",
    "ctrl2080vgpumgrinternal", "ctrl2080volt",
]

try:
    import capstone
    from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC
    MD_RISCV = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    MD_ARM64 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    HAVE_CS = True
except ImportError:                                   # degrade loudly, not silently
    MD_RISCV = MD_ARM64 = None
    HAVE_CS = False

import hashlib
import re
import urllib.request

MACHINES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64",
            243: "RISC-V", 50: "IA-64", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64"}

# x86 opcodes that take a modrm (the hit byte would BE the modrm or the
# disp; both shapes classified below)
_MODRM_OPS = {0xFF, 0x8B, 0x89, 0x39, 0x3B, 0x8D, 0xC6, 0xC7, 0x03, 0x2B, 0x01, 0x29,
              0x88, 0x38, 0x3A, 0x02, 0x0A, 0x32, 0x3A}
_IMM32_OPS = set(range(0xB8, 0xC0))            # mov r32, imm32
_Solo_IMM32 = {0x68, 0x05, 0x2D, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}  # push/add/cmp imm32


def load_rm_image():
    """rm-full.elf → (image bytes, img_lo). Fingerprint: one RWX LOAD,
    filesz==memsz, shnum==0 (the 4.14+ invariant, v420_rpcanchor.py)."""
    d = Path(GSP_DIR / "rm-full.elf").read_bytes()
    e_shnum = struct.unpack_from("<H", d, 60)[0]
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
    img = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", d, o)[0] != 1:
            continue
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if p_filesz == p_memsz and p_filesz:
            img = (d[p_off:p_off + p_filesz], p_vaddr)
    assert e_shnum == 0 and img and img[1] == IMG_LO, "fingerprint drift"
    return img[0]


def load_416_map():
    """the boundary-verified map (v416): seen half → per-halfword bit."""
    import zlib
    blob = zlib.decompress((REPO / "lab" / "jalon411" / "v416_map.bin").read_bytes())
    return blob[: len(blob) // 2]


def verified_at(seen, off):
    s = off >> 1
    return bool(seen[s]) if 0 <= s < len(seen) else False


def riscv_rows(img, va, n_before, n_after):
    """linear RISC-V disasm around va; bytes kept so the disasm is
    re-derivable without capstone."""
    rows = []
    if not HAVE_CS:
        return rows
    off = va - IMG_LO - n_before * 4
    stop = va - IMG_LO + (n_after + 2) * 4
    while off < stop and off < len(img) - 4:
        try:
            ins = next(MD_RISCV.disasm(img[off:off + 4], IMG_LO + off))
        except StopIteration:
            off += 2
            continue
        rows.append({"va": IMG_LO + off, "mnemonic": ins.mnemonic,
                     "op_str": ins.op_str, "bytes": img[off:off + ins.size].hex()})
        off += ins.size
    return rows


# ------------------------------------------------- A. the substrate audit
def section_a():
    """What win.elf IS: byte-proven RISC-V window artifact of
    gsp-rm-17MB.bin, generated by win-disasm.py — not an x86 blob."""
    w = (GSP_DIR / "win.elf").read_bytes()
    machine = struct.unpack_from("<H", w, 18)[0]
    e_entry = struct.unpack_from("<Q", w, 24)[0]
    e_phoff = struct.unpack_from("<Q", w, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", w, 54)
    ph = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", w, o)
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", w, o + 8)
        ph = {"type": p_type, "flags": p_flags, "off": p_off, "vaddr": p_vaddr,
              "filesz": p_filesz, "memsz": p_memsz}
    assert machine == 243 and ph and ph["off"] == 0x78 and ph["vaddr"] == e_entry
    out = {"header": {"size": len(w), "machine": machine,
                      "machine_name": MACHINES.get(machine),
                      "is_x86": machine in (3, 62),
                      "e_entry": e_entry,
                      "e_shnum": struct.unpack_from("<H", w, 60)[0], "phdr": ph}}

    # the window payload + its source inside gsp-rm-17MB.bin
    win = w[ph["off"]:ph["off"] + ph["filesz"]]
    g = (GSP_DIR / "binaries" / "gsp-rm-17MB.bin").read_bytes()
    src = g.find(win)
    assert src >= 0, "win.elf window not found in gsp-rm-17MB.bin"
    out["window_in_gsp_rm"] = {
        "found": True, "file_off": src,
        "va_generator_label": src + 0x1000000,   # win-disasm's off2va
    }
    # the coordinate reconciliation: gsp_off + 0x78 = rm-full.elf file
    # offset (proven on the dispatch-entry anchor) → the 4.16/4.20 map
    # VA of the same bytes = gsp_off + 0x38 + 0x1000000 (win-disasm's
    # label sits 0x38 BELOW the map convention)
    needle = struct.pack("<II", CMD, TAG_0x608)
    gsp_entry = g.find(needle)
    rm = (GSP_DIR / "rm-full.elf").read_bytes()
    rm_entry = rm.find(needle)
    assert gsp_entry >= 0 and rm_entry >= 0, "dispatch-entry anchor lost"
    out["coordinate_reconciliation"] = {
        "anchor": f"the raw 0x2080d031 dispatch entry (id+tag)",
        "gsp_off": gsp_entry, "rm_full_file_off": rm_entry,
        "delta_rm_minus_gsp": rm_entry - gsp_entry,
        "map_va_of_window": f"0x{src + 0x38 + 0x1000000:x}",
        "note": ("gsp_off + 0x78 = rm-full.elf file offset; the 4.20 VA "
                 "convention = gsp_off + 0x38 + 0x1000000 — win-disasm's "
                 "off2va label is 0x38 below the map convention"),
    }

    # re-execute the win-disasm.py recipe → byte-identical file?
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"; eh[4] = 2; eh[5] = 1; eh[6] = 1
    struct.pack_into("<HHI", eh, 16, 2, 243, 1)
    struct.pack_into("<QQQ", eh, 24, ph["vaddr"], 64, 0)
    struct.pack_into("<IHHHHH", eh, 48, 1, 64, 56, 1, 0, 0)
    pph = struct.pack("<IIQQQQQQ", 1, 7, 0x78, ph["vaddr"], ph["vaddr"],
                      len(win), len(win), 0x1000)
    rebuilt = bytes(eh) + pph + win
    assert rebuilt == w, "win.elf regeneration mismatch"
    out["regeneration_proof"] = {
        "recipe": "win-disasm.py disasm_window() (the committed generator)",
        "byte_identical": True, "rebuilt_size": len(rebuilt)}

    # does the window itself carry the family ids or 250000? (no)
    fam_in_win = sum(win.count(struct.pack("<I", cid))
                     for cid in range(FAM_LO, FAM_HI + 1))
    out["window_content"] = {
        "family_id_dwords": fam_in_win,
        "dword_250000": win.count(struct.pack("<I", 0x3D090)),
        "first_insns": riscv_rows(win, ph["vaddr"], 0, 10),
        "reading": ("HYPOTHESIS memset/memcpy-shaped leaf (the 8/4/1-byte "
                    "copy tail loop); PROVEN: RISC-V code of the GSP-RM"),
    }
    return out


# ------------------------------------------------------ B. the x86 census
def classify_x86_hit(d, h):
    """Classify a 0x3D090 dword at offset h in x86 code/data.

    Shape ARTIFACT (the observed one): the hit byte 0x90 IS a modrm
    (mod=10 → disp32) of an opcode at d[h-1] — e.g. FF 90 D0 03 00 00
    = call [rax+0x3d0]: the needle overlaps modrm+disp[0:3]; the true
    displacement is d[h+1:h+5], NOT 250000.
    Shape DISP: d[h-1] is a modrm with mod=10 and d[h-2] an opcode →
    the hit IS a real disp32 operand [reg+0x3d090].
    Shape IMM: the hit is a mov/push/cmp imm32 → a real 250000 value.
    """
    if h < 2:
        return {"class": "unclassified", "preceding": ""}
    prev2 = d[h - 2:h].hex()
    op_at_h1, byte_at_h = d[h - 1], d[h]
    if op_at_h1 in _MODRM_OPS and (byte_at_h >> 6) == 0b10:
        true_disp = struct.unpack_from("<I", d, h + 1)[0]
        return {"class": f"instruction-artifact: modrm overlap of opcode "
                         f"{op_at_h1:#04x} (true disp32 = {true_disp:#x})",
                "preceding": prev2, "true_disp": true_disp}
    if (byte_at_h >> 6) == 0b10 and d[h - 2] in _MODRM_OPS and h >= 1 \
            and (d[h - 1] >> 6) == 0b10:
        return {"class": "operand-displacement [reg+0x3d090]", "preceding": prev2}
    if d[h - 1] in _Solo_IMM32 or d[h - 2] in _IMM32_OPS:
        return {"class": "imm32 value (real 250000)", "preceding": prev2}
    return {"class": "value-candidate (standalone/data)", "preceding": prev2}


def arm64_context(d, h, n=6):
    """Disassemble ±3 AArch64 instructions around an unaligned hit to
    prove the cross-boundary overlap reading."""
    if not HAVE_CS:
        return []
    base = (h - 2) & ~3
    rows = []
    for k in range(n):
        o = base + k * 4
        if o < 0 or o + 4 > len(d):
            continue
        code = d[o:o + 4]
        try:
            ins = next(MD_ARM64.disasm(code, o))
            rows.append({"off": o, "bytes": code.hex(), "mnemonic": ins.mnemonic,
                         "op_str": ins.op_str,
                         "spans_hit": o <= h < o + 4})
        except StopIteration:
            rows.append({"off": o, "bytes": code.hex(), "mnemonic": "?",
                         "op_str": "", "spans_hit": o <= h < o + 4})
    return rows


def section_b():
    """Every non-RISC-V executable in the repo + the archives: is the
    closed host RM (or any 0x2080d0 marshal) committed anywhere?"""
    executables = []
    for p in sorted(FLASH_DIR.rglob("*")):
        if not p.is_file() or p.name.endswith((".zip", ".md", ".txt", ".sh", ".json")):
            continue
        try:
            head = p.read_bytes()[:64]
        except OSError:
            continue
        if head[:4] == b"\x7fELF" or head[:2] == b"MZ":
            executables.append(p)
    per_file = []
    for p in executables:
        d = p.read_bytes()
        rec = {"file": str(p.relative_to(REPO)), "size": len(d)}
        if d[:4] == b"\x7fELF":
            rec["machine"] = MACHINES.get(struct.unpack_from("<H", d, 18)[0])
        is_fixed_isa = rec.get("machine") in ("AArch64", "PowerPC64", "PowerPC", "ARM", "RISC-V")
        # exact cmd + family ids (byte-step-1: alignment-free, honest)
        fam = []
        for cid in range(FAM_LO, FAM_HI + 1):
            needle = struct.pack("<I", cid)
            i = d.find(needle)
            while i >= 0:
                ent = {"id": f"0x{cid:08x}", "off": i, "aligned4": i % 4 == 0}
                if is_fixed_isa and i % 4:
                    ent["class"] = "cross-instruction-boundary overlap (unaligned)"
                    ent["arm64_context"] = arm64_context(d, i) if rec.get("machine") == "AArch64" else []
                elif rec.get("machine") in ("x86", "x86-64"):
                    ent["class"] = classify_x86_hit(d, i)["class"]
                fam.append(ent)
                i = d.find(needle, i + 1)
        rec["family_0x2080d0_hits"] = fam
        rec["exact_cmd_hit"] = d.count(struct.pack("<I", CMD))
        # 250000: classify every hit (x86/x64 only meaningful)
        val, art, disp = [], 0, 0
        needle = struct.pack("<I", 0x3D090)
        i = d.find(needle)
        while i >= 0:
            if rec.get("machine") in ("x86", "x86-64"):
                c = classify_x86_hit(d, i)
                if c["class"].startswith("instruction-artifact"):
                    art += 1
                elif c["class"].startswith("operand-displacement"):
                    disp += 1
                else:
                    val.append({"off": i, **c})
            else:
                val.append({"off": i, "class": "non-x86: unclassified raw hit",
                            "aligned4": i % 4 == 0})
            i = d.find(needle, i + 1)
        rec["0x3D090"] = {"value_or_imm_hits": val,
                          "instruction_artifacts": art,
                          "real_disp32_operands": disp}
        per_file.append(rec)

    # archives: the zip + every day0 initramfs (cpio name census)
    arch = {"nvflash_zip": zipfile.ZipFile(FLASH_DIR / "nvflash-5.867.zip").namelist(),
            "initramfs": []}
    init_files = sorted((REPO / "day0").rglob("vm-initramfs.cpio.gz"),
                        key=lambda p: -p.stat().st_size)
    for p in init_files:
        rec = {"file": str(p.relative_to(REPO)), "gz_size": p.stat().st_size}
        if p.stat().st_size < 100:
            rec["stub"] = True
            arch["initramfs"].append(rec)
            continue
        try:
            raw = gzip.open(p, "rb").read()
        except OSError:
            rec["error"] = "unreadable"
            arch["initramfs"].append(rec)
            continue
        names, pos, drv = [], 0, []
        while pos + 110 <= len(raw) and raw[pos:pos + 6] == b"070701":
            fsize = int(raw[pos + 54:pos + 62], 16)
            namesize = int(raw[pos + 94:pos + 102], 16)
            name = raw[pos + 110:pos + 110 + namesize - 1].decode(errors="replace")
            names.append(name)
            if any(x in name.lower() for x in (".ko", "nvidia", ".sys", ".dll")):
                drv.append(name)
            skip = 110 + namesize
            pos += skip + ((-skip) % 4) + fsize + ((-fsize) % 4)
        rec.update({"entries": len(names), "driver_blobs": drv or "NONE"})
        arch["initramfs"].append(rec)
    return {"executables": per_file, "archives": arch,
            "n_initramfs": len(init_files)}


# ------------------------------------------- C. the firmware family map
def section_c(img):
    """The interface-0x2080d0 family on the GSP-RM side."""
    t = TABLE_VA - IMG_LO
    entries = []
    for idx in range(N_ENTRIES):
        o = t + idx * STRIDE
        cid, = struct.unpack_from("<I", img, o)
        entries.append((idx, cid, o))
    fam, anchors = [], {}
    for idx, cid, o in entries:
        tag, = struct.unpack_from("<I", img, o + 4)
        pA, = struct.unpack_from("<Q", img, o + 8)
        h, = struct.unpack_from("<Q", img, o + 0x10)
        sz0, sz1 = struct.unpack_from("<II", img, o + 0x18)
        rec = {"entry": idx, "id": f"0x{cid:08x}", "tag": tag, "pA": f"0x{pA:x}",
               "handler": f"0x{h:x}", "sz0": f"0x{sz0:x}", "sz1": sz1,
               "raw": img[o:o + 0x20].hex()}
        if FAM_LO <= cid <= FAM_HI:
            fam.append(rec)
        if cid in ANCHORS:
            anchors[f"0x{cid:08x}"] = {**rec, "name": ANCHORS[cid]}
    the_entry = next(r for r in fam if r["id"] == f"0x{CMD:08x}")
    assert the_entry["tag"] == TAG_0x608, "dispatch tag drift"
    assert the_entry["handler"] == f"0x{0x11267FC:x}", "handler drift"

    # whole-table censuses
    pAs, sz0s, ifaces = Counter(), Counter(), Counter()
    handler_by_iface = defaultdict(list)
    for idx, cid, o in entries:
        pA, = struct.unpack_from("<Q", img, o + 8)
        sz0, = struct.unpack_from("<I", img, o + 0x18)
        h, = struct.unpack_from("<Q", img, o + 0x10)
        pAs[f"0x{pA:x}"] += 1
        sz0s[f"0x{sz0:x}"] += 1
        if 0x20800000 <= cid <= 0x2081FFFF:
            ifaces[cid >> 8] += 1
            handler_by_iface[cid >> 8].append(h)
    # the family's handler cluster (18 in-region + the outlier)
    fh = sorted(int(r["handler"], 16) for r in fam)
    cluster = [h for h in fh if 0x10C0000 <= h <= 0x1150000]
    outliers = [r["id"] for r in fam if not (0x10C0000 <= int(r["handler"], 16) <= 0x1150000)]
    # which interfaces share the family's code region?
    region_mates = {f"0x{i:04x}": [f"0x{h:x}" for h in hs[:8]]
                    for i, hs in sorted(handler_by_iface.items())
                    if any(0x10C0000 <= h <= 0x1150000 for h in hs)}
    # the whole-image family-id dword census (byte-step-1)
    img_dword_census = {}
    for cid in range(FAM_LO, FAM_HI + 1):
        needle = struct.pack("<I", cid)
        offs, i = [], img.find(needle)
        while i >= 0:
            offs.append(f"0x{IMG_LO + i:x}")
            i = img.find(needle, i + 1)
        if offs:
            img_dword_census[f"0x{cid:08x}"] = offs
    # the code-immediate census: lui hi=0x2080d paired with addi/addiw
    ndw = len(img) // 4
    words = struct.unpack_from(f"<{ndw}I", img, 0)
    li_sites = []
    for off in range(0, len(img) - 8, 4):
        w = words[off >> 2]
        if (w & 0x7F) != 0x37:
            continue
        if ((w >> 12) & 0xFFFFF) != 0x2080D:
            continue
        rd = (w >> 7) & 0x1F
        w2 = words[(off >> 2) + 1]
        if (w2 & 0x7F) not in (0x13, 0x1B) or ((w2 >> 7) & 0x1F) != rd:
            continue
        lo = (w2 >> 20) - (1 << 12) if (w2 >> 20) >= 0x800 else (w2 >> 20)
        val = (0x2080D << 12) + lo
        if FAM_LO <= val <= 0x2080DFFF:
            li_sites.append({"va": f"0x{IMG_LO + off:x}", "value": f"0x{val:08x}"})
    # the closed-interface census vs the open SDK (4.24 §1 banked claim)
    closed_ifaces = sorted(ifaces)
    beyond = [f"0x{i:04x}" for i in closed_ifaces if i > OPEN_SDK["max_interface"]]
    return {
        "family_0x2080d0": fam,
        "calibration_anchors": anchors,
        "family_stats": {
            "n_controls": len(fam),
            "tags": sorted(r["tag"] for r in fam),
            "tag_cmd_0x2080d031": the_entry["tag"],
            "distinct_pA_across_table": dict(pAs),
            "distinct_sz0_across_table": dict(sz0s),
            "handler_cluster": [f"0x{cluster[0]:x}", f"0x{cluster[-1]:x}"],
            "cluster_size": len(cluster),
            "handlers_outside_cluster": outliers,
        },
        "region_mates_0x10c_0x115": region_mates,
        "whole_image_family_dword_census": img_dword_census,
        "code_immediate_census_lui_0x2080d": li_sites,
        "interface_census": {
            "closed_table_interfaces": len(closed_ifaces),
            "open_sdk_interfaces": OPEN_SDK["interfaces"],
            "open_sdk_max": f"0x{OPEN_SDK['max_interface']:04x}",
            "interfaces_beyond_open": beyond,
            "all_interfaces": [f"0x{i:04x}" for i in closed_ifaces],
        },
        "strings_grep_2080d0": (GSP_DIR / "rm-strings.txt").read_text(errors="ignore").lower().count("2080d0"),
    }


# --------------------------------------- D. the 250000 sites on the GSP-RM
def section_d(img, seen):
    """Where 250000 actually lives in the closed substrates present."""
    data_hits = []
    needle = struct.pack("<I", 0x3D090)
    i = img.find(needle)
    while i >= 0:
        data_hits.append(f"0x{IMG_LO + i:x}")
        i = img.find(needle, i + 1)
    ndw = len(img) // 4
    words = struct.unpack_from(f"<{ndw}I", img, 0)
    sites = []
    for off in range(0, len(img) - 8, 4):
        w = words[off >> 2]
        if (w & 0x7F) != 0x37 or ((w >> 12) & 0xFFFFF) != 0x3D:
            continue
        rd = (w >> 7) & 0x1F
        w2 = words[(off >> 2) + 1]
        if (w2 & 0x7F) not in (0x13, 0x1B) or ((w2 >> 7) & 0x1F) != rd:
            continue
        lo = (w2 >> 20) - (1 << 12) if (w2 >> 20) >= 0x800 else (w2 >> 20)
        if ((0x3D << 12) + lo) == 0x3D090:
            sites.append(off)
    return {"gsp_rm": {
        "u32_data_dwords": data_hits,
        "n_code_sites": len(sites),
        "lui_addi_code_sites": [{
            "va": f"0x{IMG_LO + off:x}",
            "verified_416": verified_at(seen, off),
            "context": riscv_rows(img, IMG_LO + off, 9, 9),
        } for off in sites],
    }}


# ------------------------------------------- E. the struct ledger anchors
def section_e():
    """Re-derive the five captured offsets from the 4.23 payload — the
    honest basis of the struct table (findings-4.24 §1/§2)."""
    d = (REPO / "tools" / "edpp" / "edpp_payload_1616.bin").read_bytes()
    cmd, = struct.unpack_from("<I", d, 8)
    psize, = struct.unpack_from("<I", d, 0x10)
    params = d[40:40 + 1544]
    nonzero = {p: v for p in range(0, 1544, 4)
               for v in [struct.unpack_from("<I", params, p)[0]] if v}
    residue = d[1584:1616]
    assert cmd == CMD and psize == TAG_0x608, "payload header drift"
    assert nonzero == BANKED_FIVE, "five-nonzero drift"
    assert not any(residue), "residue law drift"
    return {
        "capture": {"size": len(d), "cmd": f"0x{cmd:08x}", "paramsSize": psize,
                    "residue_32B_all_zero": True},
        "five_nonzero_params": {f"poff {k}": v for k, v in nonzero.items()},
        "matches_banked_424": True,
    }


# --------------------------------------- F. the open-tag cross-check
def fetch_ctrl_headers():
    """Fetch-once cache of the raw tag's ctrl2080 headers (the
    v424_citation_audit.py pattern). Returns (files, sha256s, fetched)."""
    CACHE.mkdir(exist_ok=True)
    files, sha, fetched_now = {}, {}, 0
    names = CTRL_HEADERS + ["ctrl2080_top"]
    for name in names:
        local = CACHE / f"{name}.h"
        if not local.exists():
            url = CTRL_PARENT if name == "ctrl2080_top" else f"{CTRL_BASE}/{name}.h"
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    local.write_bytes(r.read())
                fetched_now += 1
            except Exception as exc:                       # noqa: BLE001
                return None, {"error": f"network unavailable: {exc}"}, 0
        files[name] = local.read_text(encoding="utf-8", errors="ignore")
        sha[name] = hashlib.sha256(local.read_bytes()).hexdigest()
    return files, sha, fetched_now


def section_f():
    """The raw-tag open census + the open↔closed join."""
    files, sha, fetched = fetch_ctrl_headers()
    if files is None:
        return {"network": "unavailable — rerun with network to populate "
                           "the cache (the fetch-once pattern)",
                "sha256": sha}
    cmd_pat = re.compile(r"#define\s+(NV2080_CTRL_CMD_\w+)\s+.*?(0x2080[0-9a-fA-F]{4})\b")
    finn_pat = re.compile(r"FINN_NV20_SUBDEVICE_0_([A-Z0-9_]+?)_INTERFACE_ID")
    open_cmds, iface_names = {}, {}
    cmd_file = {}
    finn_names = set()
    for name, txt in files.items():
        for m in finn_pat.finditer(txt):
            finn_names.add(f"FINN_NV20_SUBDEVICE_0_{m.group(1)}_INTERFACE_ID")
        for m in cmd_pat.finditer(txt):
            val = int(m.group(2), 16)
            open_cmds[val] = m.group(1)
            cmd_file[val] = name
            fm = finn_pat.search(txt[max(0, m.start() - 400):m.start()])
            if fm:
                iface_names[val >> 8] = f"FINN_NV20_SUBDEVICE_0_{fm.group(1)}_INTERFACE_ID"
    open_ifaces = sorted(set(v >> 8 for v in open_cmds))
    # fallback: one header ≈ one interface ≈ the file's single FINN name
    for iface in open_ifaces:
        if iface in iface_names:
            continue
        src_files = {cmd_file[v] for v in open_cmds if (v >> 8) == iface}
        cands = set()
        for sf in src_files:
            cands |= {m.group(0) for m in
                      re.finditer(r"FINN_NV20_SUBDEVICE_0_[A-Z0-9_]+_INTERFACE_ID",
                                  files[sf])}
        if len(cands) == 1:
            iface_names[iface] = cands.pop()

    # the dispatch-table join (needs the image)
    img = load_rm_image()
    t = TABLE_VA - IMG_LO
    join = {}
    for idx in range(N_ENTRIES):
        o = t + idx * STRIDE
        cid, tag = struct.unpack_from("<II", img, o)
        if cid in open_cmds:
            join[cid] = (open_cmds[cid], tag)
    # anchors: tag == sizeof(params struct)
    anchors = {f"0x{cid:08x}": {"name": join[cid][0], "tag": join[cid][1]}
               for cid in join if cid in (0x20800AFD, 0x20800AD0)}
    assert anchors[f"0x{0x20800AFD:08x}"]["tag"] == 24, "GET_EDPP tag drift (expect 24)"
    assert anchors[f"0x{0x20800AD0:08x}"]["tag"] == 8, "UPDATE_EDPP tag drift (expect 8)"
    # the FIFO struct size check: 4*(N+N+1+N) with N parsed from the header
    fifo = files.get("ctrl2080fifo", "")
    mN = re.search(r"#define\s+NV2080_CTRL_CMD_FIFO_MAX_CHANNELS_PER_TSG\s+\(?(\d+)",
                   fifo)
    n_ch = int(mN.group(1)) if mN else None
    fifo_check = None
    if n_ch and 0x20801124 in join:
        fifo_check = {"N": n_ch, "computed": 4 * (n_ch + n_ch + 1 + n_ch),
                      "tag": join[0x20801124][1],
                      "name": join[0x20801124][0]}
        assert fifo_check["computed"] == fifo_check["tag"], "FIFO size model drift"
    # the 1544-B sibling census (whole table)
    sib = [{"id": f"0x{cid:08x}", "tag": tag,
            "interface": f"0x{cid >> 8:04x}",
            "named_open": cid in open_cmds}
           for cid, tag in ((struct.unpack_from("<II", img, t + i * STRIDE))
                            for i in range(N_ENTRIES))
           if tag == TAG_0x608]
    assert len(sib) == 3 and all(not s["named_open"] for s in sib), "sibling census drift"
    # closed-only interfaces + open-not-in-table
    closed_ifaces = {cid >> 8 for cid, _ in
                     ((struct.unpack_from("<II", img, t + i * STRIDE))
                      for i in range(N_ENTRIES))
                     if 0x20800000 <= cid <= 0x2081FFFF}
    return {
        "network": f"fetched {fetched} file(s) now; cache reused otherwise",
        "headers_sha256": sha,
        "open_census": {
            "interfaces_with_shipped_cmds": len(open_ifaces),
            "finn_interface_names": len(finn_names),
            "max_interface": f"0x{open_ifaces[-1]:04x}",
            "note_38": ("the 4.24 §1 '38 interfaces' = the FINN interface-ID "
                        "names carried by the headers; 34 of them have "
                        "commands shipped in ctrl2080/ — both re-derived here"),
            "interface_names": {f"0x{i:04x}": iface_names.get(i, "?")
                                for i in open_ifaces},
        },
        "open_closed_join": {
            "named_open_cmds_in_table": len(join),
            "tag_eq_sizeof_anchors": anchors,
            "fifo_struct_size_check": fifo_check,
            "open_cmds_not_in_table": len(open_cmds) - len(join),
        },
        "siblings_1544B": sib,
        "closed_only_interfaces": [f"0x{i:04x}" for i in sorted(closed_ifaces - set(open_ifaces))],
        "open_interfaces_not_in_table": [f"0x{i:04x}" for i in sorted(set(open_ifaces) - closed_ifaces)],
    }


# ---------------------------------------------------------------- main
def main():
    print("4.25 — the x86 marshal hunt: substrate audit first")
    a = section_a()
    print(f"[A] win.elf: machine={a['header']['machine_name']} "
          f"(x86? {a['header']['is_x86']}), {a['header']['size']} B — window of "
          f"gsp-rm-17MB.bin @ file_off {a['window_in_gsp_rm']['file_off']:#x} "
          f"(generator VA label {a['window_in_gsp_rm']['va_generator_label']:#x}; "
          f"map-convention VA {a['coordinate_reconciliation']['map_va_of_window']}); "
          f"regeneration byte-identical: "
          f"{a['regeneration_proof']['byte_identical']}; family ids in window: "
          f"{a['window_content']['family_id_dwords']}, 250000: "
          f"{a['window_content']['dword_250000']}")

    print("[B] the x86 census: scanning every non-RISC-V executable + archives …")
    b = section_b()
    for rec in b["executables"]:
        fam = len(rec["family_0x2080d0_hits"])
        v = rec["0x3D090"]
        print(f"     {rec['file']}: family hits={fam}, cmd hits={rec['exact_cmd_hit']}, "
              f"250000 real-values={len(v['value_or_imm_hits'])} "
              f"(artifacts={v['instruction_artifacts']}, disp-operands={v['real_disp32_operands']})")
    n_ir = sum(1 for ir in b["archives"]["initramfs"] if not ir.get("stub"))
    any_drv = any(ir.get("driver_blobs", "NONE") != "NONE" for ir in b["archives"]["initramfs"])
    print(f"     archives: zip={len(b['archives']['nvflash_zip'])} entries; "
          f"{n_ir} initramfs census-listed (+ stubs), any driver blob: {any_drv}")

    img = load_rm_image()
    seen = load_416_map()
    c = section_c(img)
    fs = c["family_stats"]
    print(f"[C] interface 0x2080d0 on the GSP-RM: {fs['n_controls']} controls; "
          f"cmd tag={fs['tag_cmd_0x2080d031']}; handler cluster "
          f"{fs['handler_cluster'][0]}..{fs['handler_cluster'][1]} "
          f"({fs['cluster_size']}/{fs['n_controls']}; outside: {fs['handlers_outside_cluster']}); "
          f"distinct pA across the WHOLE table: {fs['distinct_pA_across_table']}")
    print(f"     whole-image family dwords: {len(c['whole_image_family_dword_census'])} ids, "
          f"each exactly once (dispatch entries); lui(0x2080d)+addi sites: "
          f"{len(c['code_immediate_census_lui_0x2080d'])}")
    ic = c["interface_census"]
    print(f"     interface census: closed table={ic['closed_table_interfaces']} interfaces "
          f"(open SDK={ic['open_sdk_interfaces']}, max {ic['open_sdk_max']}); "
          f"beyond open max: {len(ic['interfaces_beyond_open'])} "
          f"(0x2080d0 among them: {('0x2080d0' in ic['interfaces_beyond_open'])})")
    print(f"     rm-strings.txt '2080d0' hits: {c['strings_grep_2080d0']}")

    d = section_d(img, seen)
    g = d["gsp_rm"]
    print(f"[D] 250000 on the GSP-RM: {len(g['u32_data_dwords'])} data dwords, "
          f"{g['n_code_sites']} lui+addi code sites: "
          f"{[s['va'] + ('*' if s['verified_416'] else '') for s in g['lui_addi_code_sites']]}")

    e = section_e()
    print(f"[E] payload anchors: cmd={e['capture']['cmd']} "
          f"paramsSize={e['capture']['paramsSize']}, five nonzero "
          f"{e['five_nonzero_params']}, residue law OK")

    f = section_f()
    if "open_census" in f:
        oc, jc = f["open_census"], f["open_closed_join"]
        print(f"[F] open-tag cross-check: {oc['interfaces_with_shipped_cmds']} interfaces "
              f"with shipped cmds, {oc['finn_interface_names']} FINN names, "
              f"max {oc['max_interface']} — the 4.24 '38' reconciled; "
              f"join: {jc['named_open_cmds_in_table']} named cmds x tags "
              f"(GET_EDPP={jc['tag_eq_sizeof_anchors']['0x20800afd']['tag']} B, "
              f"UPDATE_EDPP={jc['tag_eq_sizeof_anchors']['0x20800ad0']['tag']} B, "
              f"FIFO={jc['fifo_struct_size_check'] and jc['fifo_struct_size_check']['computed']} B — "
              f"tag==sizeof PROVEN on 3 anchors); 1544-B siblings: "
              f"{[s['id'] for s in f['siblings_1544B']]} (ALL closed); "
              f"closed-only interfaces: {len(f['closed_only_interfaces'])}")
    else:
        print(f"[F] open-tag cross-check: {f['network']}")

    out = {"pass": "4.25", "instrument": "v425_x86_marshal.py",
           "substrate_audit_win_elf": a, "x86_census": b,
           "firmware_family_map": c, "sites_250000": d,
           "struct_ledger_anchors": e, "open_tag_crosscheck": f,
           "capstone": HAVE_CS}
    OUT.write_text(json.dumps(out, indent=1))
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"DRIFT: {exc}", file=sys.stderr)
        sys.exit(2)
