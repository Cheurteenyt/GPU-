#!/usr/bin/env python3
"""v462a_wpr2_read.py — PASS 4.62 T1 — ROUTE W, PROBE B1: the WPR2
meta decoder + the BAR1/ReBAR FB read (the READ-ONLY gesture).

THE MISSION (the founder, verbatim anchors): « le 4.61 a prouvé que les
bases = dans le heap FB (le plan gate = MISS sur toutes les surfaces
hôtes). La mission = LIRE le heap FB/WPR2 ». THIS pass executes the
4.52 §5 design (read first — « the read decides the route-W verdict »):

  T1  probe B1 = the BAR1/ReBAR read (8192 MiB standing — banked ring
      18; ZERO driver patch; the v454b PROT_READ pattern: mmap the
      sysfs resource, ONE u32 LE per offset, NO polling, NO repeat,
      NO write path — the code IS the guarantee, the selftest asserts
      the source stays write-free). The FB addresses = OUR data: the
      S8 wpr2meta.bin captured on the 4.51 verdict day carries the
      FB layout (the mission's captured pair 0x1f2d000/0x1ffee00 —
      the FIELD NAMING of that pair = THIS decoder's structural
      decision at run time; the message quoted no field names, and
      the bytes decide, never the narrative).
  T2  probe MD = the memdesc-over-phys two-sided instrument
      (gsp_wpr2_read.c + patch_nv_462.py + the plan header THIS tool
      emits: memdescCreateExisting @g_mem_desc_nvoc.h:943 +
      memdescDescribe(ADDR_FBMEM) @:1009 + memdescMap READABLE @:990
      + memdescUnmap @:994 — the 4.52 anchors RE-ASSERTED on the
      exact 610.57.04 tree this pass).
  T3  the scan = v462c (the v451a floor + the v454a markers + the
      v461a object fingerprint — the 0x0EE6B280 shape-match).

THE DECODER (the committed grammar — imports/
open-gpu-kernel-modules-610.57.04/gsp/gsp_fw_wpr_meta.h, gcc-asserted):
  GspFwWprMeta = 256 B (the header's own "exactly 256 bytes" law):
  magic@0 (0xdc3aae21371a60b3), revision@8 (=1), gspFwRsvdStart@88,
  nonWprHeapOffset@96, nonWprHeapSize@104, gspFwWprStart@112 (128K
  aligned), gspFwHeapOffset@120, gspFwHeapSize@128, gspFwOffset@136,
  bootBinOffset@144, frtsOffset@152, frtsSize@160, gspFwWprEnd@168
  (128K aligned), fbSize@176, bootCount@200, verified@248
  (0xa0a0a0a0a0a0a0a0 = the booter locked it in WPR2).
  The tree guard re-asserts EVERY offset through gcc offsetof against
  the COMMITTED header (the machine law — never the memory).

THE WINDOW MATH (the honest core — the bytes decide):
  gspFwHeapOffset semantics = ABS-vs-REL INDECIDABLE from the header
  alone (the diagram draws the FB-layout fields as absolute; the ONLY
  field the tree NAMES relative = gspFwHeapFreeListWprOffset — the
  resume-path comment @gsp_fw_wpr_meta.h:95-96; the host expression
  fbSize - gspFwRsvdStart @kernel_gsp.c:4449 proves gspFwRsvdStart
  absolute). THIS tool emits BOTH candidate readings and scores each
  against the structural invariants:
    W_ABS  = [gspFwHeapOffset, +gspFwHeapSize)         (the raw-field
           reading — the header diagram's absolute form)
    W_REL  = [gspFwWprStart + gspFwHeapOffset, +size)  (the 4.52 §5
           formula, verbatim)
  scored by: the WPR2 containment ([gspFwWprStart, gspFwWprEnd]),
  the FB bound (<= fbSize), the page alignment, and the diagram-order
  corroboration (WprStart <= HeapOffset <= FwOffset <= BootBin <=
  FrtsOffset <= WprEnd in the reading's own frame). The survivors =
  the windows the probe reads (read-only — reading both = free);
  the scan (v462c) decides which held the data. ZERO survivors =
  INDECIDABLE — the table printed, the day stops (never a guess).

  THIRD SOURCE (the cross-input): the S4 libosinit.bin (captured on
  the 4.51 day) = the GSP's OWN boot map — the loc=FB regions name
  the heap as GSP-RM booted with it (v452a.walk_s4 imported — the
  committed 27/27 parser, zero re-transcription). An S4 FB region
  overlapping an S8 window = the corroboration named; an S4 FB
  region matching NO S8 window = a window candidate ITSELF.

THE PLAUSIBILITY GUARDS (the mission law — the named negatives; the
  shared integer semantics live in classify_bytes and are mirrored
  VERBATIM in gsp_wpr2_read.c — the v462b battery proves the two
  implementations agree on every fixture):
    SEAL-ZERO       all bytes 0x00 — the seal answered (the negative)
    SEAL-FF         all bytes 0xFF — the seal answered (the negative)
    SEAL-CONSTANT   one byte value >= 255/256 of the window
    WPRMETA-MAGIC   the first u64 == the meta magic (the window =
                    the META struct — the math off by one window)
    ELF-MAGIC       the first 4 B == 7f 45 4c 46 (the window = the
                    ELF — the math off by one window)
    HEAP-FREELIST   the first u64 == 0x4845415046524545 (the
                    GspFwHeapFreeList magic — the HEAP signature, a
                    POSITIVE)
    DEGENERATE      <= 4 distinct byte values (the seal's constant
                    patterns; the float-free form — identical in C)
    LIVE-UNKNOWN    non-degenerate, no known magic — the content is
                    live; the sha16 + the v462c scan decide

THE ACK (the 4.54 discipline — even the reads are gated):
  ROUTE_W_462_ACK=1 required for the REAL read (exit 2 without).
  The synthetic mode (--resource <file>) = the selftest path — the
  SAME read code path against a regular file, the real device never
  needed.

ZÉRO BOOT BY CONSTRUCTION: this instrument never patches, never
  boots, never writes. §1 of runbook-462.sh = THIS tool hot (the
  zero-patch zero-boot gesture). The outputs land OUTSIDE /tmp (the
  copy-out law: the default = ~/route-w-462/).
"""
import argparse
import hashlib
import json
import mmap
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import v452a_libos_walk as v452a          # noqa: E402 — the S4 grammar

ROOT = HERE.parents[1]
WPR_META_HDR = ROOT / ("imports/open-gpu-kernel-modules-610.57.04/gsp/"
                       "gsp_fw_wpr_meta.h")

# ---- the decode model (gcc-asserted against the COMMITTED header —
#      the tree guard re-derives every number below, the drift = FAIL)
META_MODEL = {
    "sizeof_GspFwWprMeta": 256,
    "off_magic": 0,
    "off_revision": 8,
    "off_gspFwRsvdStart": 88,
    "off_nonWprHeapOffset": 96,
    "off_nonWprHeapSize": 104,
    "off_gspFwWprStart": 112,
    "off_gspFwHeapOffset": 120,
    "off_gspFwHeapSize": 128,
    "off_gspFwOffset": 136,
    "off_bootBinOffset": 144,
    "off_frtsOffset": 152,
    "off_frtsSize": 160,
    "off_gspFwWprEnd": 168,
    "off_fbSize": 176,
    "off_bootCount": 200,
    "off_verified": 248,
}

META_MAGIC = 0xDC3AAE21371A60B3
META_VERIFIED = 0xA0A0A0A0A0A0A0A0
HEAP_FREELIST_MAGIC = 0x4845415046524545
META_REVISION = 1
ALIGN_128K = 0x20000
ALIGN_PAGE = 0x1000

# the banked card standing (ring 18): the ReBAR BAR1 = the whole FB
BAR1_EXPECT_BYTES = 8192 * 1024 * 1024

READ_LEN_DEFAULT = 65536
READ_LEN_MAX = 1 << 20

WIN_ABS = 1     # [gspFwHeapOffset, +gspFwHeapSize)
WIN_REL = 2     # [gspFwWprStart + gspFwHeapOffset, +gspFwHeapSize)
WIN_S4 = 3      # the S4 loc=FB region (the GSP's own boot map)

# the plausibility classes (the integer semantics mirrored in C)
C_SEAL_ZERO = 0
C_SEAL_FF = 1
C_SEAL_CONSTANT = 2
C_WPRMETA_MAGIC = 3
C_ELF_MAGIC = 4
C_HEAP_FREELIST = 5
C_DEGENERATE = 6
C_LIVE_UNKNOWN = 7
C_NAMES = {
    C_SEAL_ZERO: "SEAL-ZERO",
    C_SEAL_FF: "SEAL-FF",
    C_SEAL_CONSTANT: "SEAL-CONSTANT",
    C_WPRMETA_MAGIC: "WPRMETA-MAGIC",
    C_ELF_MAGIC: "ELF-MAGIC",
    C_HEAP_FREELIST: "HEAP-FREELIST",
    C_DEGENERATE: "DEGENERATE",
    C_LIVE_UNKNOWN: "LIVE-UNKNOWN",
}


# ---- the tree guard (the v461a pattern: gcc judges, never memory) ----

def tree_guard():
    """gcc offsetof probe against the COMMITTED gsp_fw_wpr_meta.h."""
    if not WPR_META_HDR.exists():
        return "SKIP (the header absent)"
    with tempfile.TemporaryDirectory() as td:
        shim = Path(td) / "nvtypes.h"
        shim.write_text(
            "#ifndef NVTYPES_SHIM_H\n"
            "#define NVTYPES_SHIM_H\n"
            "typedef unsigned long long NvU64;\n"
            "typedef unsigned int NvU32;\n"
            "typedef unsigned short NvU16;\n"
            "typedef unsigned char NvU8;\n"
            "typedef unsigned char NvBool;\n"
            "#endif\n")
        probe = Path(td) / "probe.c"
        fields = ["magic", "revision", "gspFwRsvdStart", "nonWprHeapOffset",
                  "nonWprHeapSize", "gspFwWprStart", "gspFwHeapOffset",
                  "gspFwHeapSize", "gspFwOffset", "bootBinOffset",
                  "frtsOffset", "frtsSize", "gspFwWprEnd", "fbSize",
                  "bootCount", "gspFwHeapVfPartitionCount", "flags",
                  "pmuReservedSize", "verified"]
        probe.write_text(
            '#include <stdio.h>\n#include <stddef.h>\n'
            '#include "nvtypes.h"\n'
            '#include "gsp_fw_wpr_meta.h"\n'
            "int main(void) {\n"
            '  printf("%zu ' + " ".join(["%zu"] * len(fields)) + '\\n",\n'
            "    sizeof(GspFwWprMeta),\n" +
            "".join("    offsetof(GspFwWprMeta, %s)%s\n"
                    % (f, "," if i < len(fields) - 1 else ");")
                    for i, f in enumerate(fields)) +
            '  printf("0x%llx 0x%llx 0x%llx %llu\\n",\n'
            "    (unsigned long long)GSP_FW_WPR_META_MAGIC,\n"
            "    (unsigned long long)GSP_FW_WPR_META_VERIFIED,\n"
            "    (unsigned long long)GSP_FW_HEAP_FREE_LIST_MAGIC,\n"
            "    (unsigned long long)GSP_FW_WPR_META_REVISION);\n"
            "  return 0;\n}\n")
        r = subprocess.run(
            ["gcc", "-I", td, "-I", str(WPR_META_HDR.parent), "-o",
             str(Path(td) / "probe"), str(probe)],
            capture_output=True, text=True)
        if r.returncode != 0:
            return f"gcc FAIL: {r.stderr[:200]}"
        r = subprocess.run([str(Path(td) / "probe")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return f"run FAIL: {r.stderr[:200]}"
        l1, l2 = r.stdout.strip().splitlines()
        nums = [int(x) for x in l1.split()]
        got = dict(zip(["sizeof"] + fields, nums))
        m2 = l2.split()
        magics = (int(m2[0], 16), int(m2[1], 16), int(m2[2], 16),
                  int(m2[3]))
        want_off = (META_MODEL["sizeof_GspFwWprMeta"],
                    META_MODEL["off_magic"], META_MODEL["off_revision"],
                    META_MODEL["off_gspFwRsvdStart"],
                    META_MODEL["off_nonWprHeapOffset"],
                    META_MODEL["off_nonWprHeapSize"],
                    META_MODEL["off_gspFwWprStart"],
                    META_MODEL["off_gspFwHeapOffset"],
                    META_MODEL["off_gspFwHeapSize"],
                    META_MODEL["off_gspFwOffset"],
                    META_MODEL["off_bootBinOffset"],
                    META_MODEL["off_frtsOffset"],
                    META_MODEL["off_frtsSize"],
                    META_MODEL["off_gspFwWprEnd"],
                    META_MODEL["off_fbSize"],
                    META_MODEL["off_bootCount"],
                    240,  # gspFwHeapVfPartitionCount
                    241,  # flags
                    244,  # pmuReservedSize
                    META_MODEL["off_verified"])
        got_off = (got["sizeof"], got["magic"], got["revision"],
                   got["gspFwRsvdStart"], got["nonWprHeapOffset"],
                   got["nonWprHeapSize"], got["gspFwWprStart"],
                   got["gspFwHeapOffset"], got["gspFwHeapSize"],
                   got["gspFwOffset"], got["bootBinOffset"],
                   got["frtsOffset"], got["frtsSize"], got["gspFwWprEnd"],
                   got["fbSize"], got["bootCount"],
                   got["gspFwHeapVfPartitionCount"], got["flags"],
                   got["pmuReservedSize"], got["verified"])
        if got_off != want_off:
            return f"DRIFT got={got_off} want={want_off}"
        want_mag = (META_MAGIC, META_VERIFIED, HEAP_FREELIST_MAGIC,
                    META_REVISION)
        if magics != want_mag:
            return f"MAGIC DRIFT got={magics} want={want_mag}"
    return "OK"


# ---- the decoder ------------------------------------------------------

def decode_wpr2meta(data: bytes):
    """Decode the S8 dump per the committed grammar + the invariants.

    Returns {fields, invariants, ok, reason}. The hard refusals: the
    magic, the revision, the 128K alignments, fbSize >= wprEnd, the
    heap size 0. The verified field = RECORDED (the expected
    0xa0a0... post-lock; a 0 = the UNVERIFIED-META warning, never a
    refusal — the bytes decide).
    """
    n = META_MODEL["sizeof_GspFwWprMeta"]
    if len(data) < n:
        return {"ok": False,
                "reason": f"wpr2meta too small: {len(data)} < {n}"}
    u64 = lambda off: struct.unpack_from("<Q", data, off)[0]  # noqa: E731
    u32 = lambda off: struct.unpack_from("<I", data, off)[0]  # noqa: E731
    f = {
        "magic": u64(META_MODEL["off_magic"]),
        "revision": u64(META_MODEL["off_revision"]),
        "gspFwRsvdStart": u64(META_MODEL["off_gspFwRsvdStart"]),
        "nonWprHeapOffset": u64(META_MODEL["off_nonWprHeapOffset"]),
        "nonWprHeapSize": u64(META_MODEL["off_nonWprHeapSize"]),
        "gspFwWprStart": u64(META_MODEL["off_gspFwWprStart"]),
        "gspFwHeapOffset": u64(META_MODEL["off_gspFwHeapOffset"]),
        "gspFwHeapSize": u64(META_MODEL["off_gspFwHeapSize"]),
        "gspFwOffset": u64(META_MODEL["off_gspFwOffset"]),
        "bootBinOffset": u64(META_MODEL["off_bootBinOffset"]),
        "frtsOffset": u64(META_MODEL["off_frtsOffset"]),
        "frtsSize": u64(META_MODEL["off_frtsSize"]),
        "gspFwWprEnd": u64(META_MODEL["off_gspFwWprEnd"]),
        "fbSize": u64(META_MODEL["off_fbSize"]),
        "bootCount": u64(META_MODEL["off_bootCount"]),
        "gspFwHeapFreeListWprOffset":
            u32(META_MODEL["off_gspFwRsvdStart"] - 16),
        "verified": u64(META_MODEL["off_verified"]),
    }
    inv = []
    ok = True
    if f["magic"] != META_MAGIC:
        inv.append(f"magic {f['magic']:#x} != {META_MAGIC:#x}")
        ok = False
    if f["revision"] != META_REVISION:
        inv.append(f"revision {f['revision']} != {META_REVISION}")
        ok = False
    if f["gspFwWprStart"] % ALIGN_128K:
        inv.append(f"gspFwWprStart {f['gspFwWprStart']:#x} not 128K-aligned")
        ok = False
    if f["gspFwWprEnd"] % ALIGN_128K:
        inv.append(f"gspFwWprEnd {f['gspFwWprEnd']:#x} not 128K-aligned")
        ok = False
    if f["fbSize"] < f["gspFwWprEnd"]:
        inv.append(f"fbSize {f['fbSize']:#x} < gspFwWprEnd "
                   f"{f['gspFwWprEnd']:#x}")
        ok = False
    if f["gspFwHeapSize"] == 0:
        inv.append("gspFwHeapSize == 0 — no window to read")
        ok = False
    verified_ok = f["verified"] == META_VERIFIED
    return {"ok": ok, "reason": "; ".join(inv) if inv else "all green",
            "verified_locked": verified_ok, "fields": f,
            "invariants": inv}


# ---- the window math (the honest core) --------------------------------

def _chain_ok(f, shift):
    """The header diagram order in the reading's own frame.

    ABS (shift=0): WprStart <= HeapOffset <= FwOffset <= BootBin
                   <= FrtsOffset <= WprEnd  (the raw absolute form)
    REL (shift=WprStart): the layout offsets relative to WprStart —
                   HeapOffset <= FwOffset <= BootBin <= FrtsOffset
                   AND WprStart + FrtsOffset + FrtsSize <= WprEnd
                   (the FRTS below the WPR end in the shifted frame).
    """
    ws = f["gspFwWprStart"]
    if shift == 0:
        return (ws <= f["gspFwHeapOffset"] <= f["gspFwOffset"] <=
                f["bootBinOffset"] <= f["frtsOffset"] <=
                f["gspFwWprEnd"])
    return (f["gspFwHeapOffset"] <= f["gspFwOffset"] <=
            f["bootBinOffset"] <= f["frtsOffset"] and
            ws + f["frtsOffset"] + f["frtsSize"] <=
            f["gspFwWprEnd"] + f["frtsSize"])


def compute_windows(f, s4_regions=None):
    """The candidate FB-heap windows, scored; the bytes decide.

    Returns {survivors: [...], indecidable: bool}. Every survivor =
    {win_class (WIN_ABS/WIN_REL/WIN_S4), base, size, chain_ok, note}.
    The S4 loc=FB regions enter as WIN_S4 candidates (the GSP's own
    boot map); an S4 region CONTAINED in an S8 survivor = the
    corroboration recorded on that survivor.
    """
    ws = f["gspFwWprStart"]
    we = f["gspFwWprEnd"]
    fb = f["fbSize"]
    sz = f["gspFwHeapSize"]
    cands = []
    if sz:
        for cls, base, shift in ((WIN_ABS, f["gspFwHeapOffset"], 0),
                                 (WIN_REL, ws + f["gspFwHeapOffset"], ws)):
            end = base + sz
            contain_wpr = base >= ws and end <= we
            contain_fb = end <= fb
            aligned = base % ALIGN_PAGE == 0
            chain = _chain_ok(f, shift)
            cands.append({
                "win_class": cls, "base": base, "size": sz,
                "contain_wpr": contain_wpr, "contain_fb": contain_fb,
                "aligned": aligned, "chain_ok": chain,
                "survives": bool(contain_wpr and contain_fb and aligned),
            })
    s4 = []
    if s4_regions:
        for r in s4_regions:
            if r.get("loc_raw") != 2 or r.get("kind_raw") != 1:
                continue   # only the CONTIGUOUS FB regions (the v452a
                           # record shape: loc_raw/kind_raw)
            base, rsz = r["pa"], r["size"]
            if rsz == 0:
                continue
            cands.append({
                "win_class": WIN_S4, "base": base, "size": rsz,
                "contain_wpr": base >= ws and base + rsz <= we,
                "contain_fb": base + rsz <= fb,
                "aligned": base % ALIGN_PAGE == 0,
                "chain_ok": None,
                "survives": bool(base >= ws and base + rsz <= we and
                                 base + rsz <= fb and
                                 base % ALIGN_PAGE == 0),
                "name": r.get("name", ""),
            })
    # the S4 corroboration on the S8 survivors (the overlap = named)
    s4_spans = [(c["base"], c["base"] + c["size"])
                for c in cands if c["win_class"] == WIN_S4]
    for c in cands:
        if c["win_class"] in (WIN_ABS, WIN_REL) and c["survives"]:
            hits = [s for s in s4_spans
                    if s[0] < c["base"] + c["size"] and
                    c["base"] < s[1]]
            c["s4_corroborated"] = bool(hits)
    survivors = [c for c in cands if c["survives"]]
    return {"candidates": cands, "survivors": survivors,
            "indecidable": not survivors}


# ---- the plausibility classifier (the integer semantics — mirrored
#      VERBATIM in gsp_wpr2_read.c; the v462b battery proves the two
#      implementations agree on every fixture, the float-free form) ----

def byte_primitives(data: bytes):
    """The shared primitives: the 256-bin histogram + the first u64.

    THE C MIRROR CONTRACT: gsp_wpr2_read.c computes EXACTLY these
    (the histogram, the first-u64, distinct = the nonzero bins, the
    top count) — never a float, never an entropy — so the two sides
    classify identically on every input.
    """
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    first_u64 = struct.unpack_from("<Q", data, 0)[0] if len(data) >= 8 \
        else 0
    top_val = max(range(256), key=lambda v: hist[v])
    top_cnt = hist[top_val]
    distinct = sum(1 for v in hist if v)
    return {"hist": hist, "first_u64": first_u64,
            "top_val": top_val, "top_cnt": top_cnt, "distinct": distinct,
            "len": len(data)}


def classify_bytes(data: bytes):
    """The verdict per the shared integer semantics (the docstring
    table; the precedence: the seals FIRST, then the magics, then the
    degeneracy, then live-unknown)."""
    if not data:
        return C_DEGENERATE, byte_primitives(data)
    p = byte_primitives(data)
    n = p["len"]
    if p["hist"][0x00] == n:
        return C_SEAL_ZERO, p
    if p["hist"][0xFF] == n:
        return C_SEAL_FF, p
    if p["top_cnt"] * 256 >= n * 255:
        return C_SEAL_CONSTANT, p
    if p["first_u64"] == META_MAGIC:
        return C_WPRMETA_MAGIC, p
    if data[:4] == b"\x7fELF":
        return C_ELF_MAGIC, p
    if p["first_u64"] == HEAP_FREELIST_MAGIC:
        return C_HEAP_FREELIST, p
    if p["distinct"] <= 4:
        return C_DEGENERATE, p
    return C_LIVE_UNKNOWN, p


# ---- the read loop (the v454b pattern — the ONE code path, real and
#      synthetic; NO write path exists in this file) ---------------------

class ProbeRefused(Exception):
    pass


def read_window(resource_path, base, length, expect_full_bar1=False):
    """mmap PROT_READ, ONE u32 LE per 4-B step, the bytes assembled in
    order. NO polling, NO repeat, NO read-modify-anything."""
    f = open(resource_path, "rb")
    try:
        size = os.fstat(f.fileno()).st_size
        if expect_full_bar1 and size != BAR1_EXPECT_BYTES:
            raise ProbeRefused(
                f"the BAR1 size {size:#x} != the banked ReBAR standing "
                f"{BAR1_EXPECT_BYTES:#x} — the linear-window assumption "
                f"needs the full-FB aperture (ring 18); REFUSED")
        if base + length > size:
            raise ProbeRefused(
                f"the window [{base:#x}, {base + length:#x}) beyond the "
                f"resource size {size:#x}")
        view = mmap.mmap(f.fileno(), size, prot=mmap.PROT_READ,
                         flags=mmap.MAP_SHARED)
    finally:
        f.close()   # the mapping stays valid after close (POSIX)

    out = bytearray(length)
    try:
        step = 4
        for off in range(0, length - (length % step), step):
            val = struct.unpack_from("<I", view, base + off)[0]
            struct.pack_into("<I", out, off, val)
        tail = length % step
        if tail:
            out[length - tail:length] = \
                view[base + length - tail:base + length]
    finally:
        view.close()
    return bytes(out)


# ---- the MD plan emission (the v452c/v461a law: the reviewed plan,
#      plan-sha'd, gcc-tested byte-exact; the NULL plan = the refusal) --

def emit_md_plan_header(windows, meta_sha16):
    """The wpr2_read_plan.h emission for gsp_wpr2_read.c.

    The plan = the SURVIVING windows only (the structural proof); the
    GATED NULL plan (N=0 + the one zero sentinel) = no window
    survived — the probe refuses cleanly (never a guessed address).
    readLen = min(the plan read len, GSP_WPR2_READ_MAX_LEN).
    """
    ws = list(windows)
    null_plan = not ws
    lines = [
        "/* GENERATED by v462a_wpr2_read.py — the reviewed WPR2 READ",
        "   plan (the RM header for gsp_wpr2_read.c). meta_sha16 = %s",
        "   — the S8 dump identity. The windows = the structural",
        "   survivors (the v462a compute_windows: the WPR2 containment,",
        "   the FB bound, the page alignment). The probe reads, never",
        "   writes. READ-ONLY BY CONSTRUCTION. */",
        "#define GSP_WPR2_READ_PLAN_N %d" % len(ws),
        '#define GSP_WPR2_READ_PLAN_META_SHA16 "%s"' % meta_sha16,
        "#define GSP_WPR2_READ_MAX_LEN %d" % READ_LEN_MAX,
        "",
        "typedef struct {",
        "    NvU32 winClass;  /* 1=ABS 2=REL 3=S4 (the v462a classes) */",
        "    NvU32 readLen;   /* the probe length, <= MAX_LEN */",
        "    NvU64 base;      /* the FB PA of the window start */",
        "    NvU64 size;      /* the window size */",
        "    NvU32 chainOk;   /* the diagram-order corroboration */",
        "    NvU32 s4Hit;     /* the S4 boot-map corroboration */",
        "} GSP_WPR2_READ_WINDOW;",
        "",
    ]
    if null_plan:
        lines += [
            "/* the GATED NULL plan: nothing reads (the honest close) */",
            "static const GSP_WPR2_READ_WINDOW gspWpr2ReadWindows[1] =",
            "{",
            "    { 0, 0, 0x0ULL, 0x0ULL, 0, 0 },",
            "};",
            "",
        ]
        return "\n".join(lines)
    lines += ["static const GSP_WPR2_READ_WINDOW "
              "gspWpr2ReadWindows[GSP_WPR2_READ_PLAN_N] =",
              "{"]
    for w in ws:
        rl = min(w.get("read_len", READ_LEN_DEFAULT), READ_LEN_MAX)
        lines.append(
            "    { %d, %d, 0x%xULL, 0x%xULL, %d, %d }," %
            (w["win_class"], rl, w["base"], w["size"],
             1 if w.get("chain_ok") else 0,
             1 if w.get("s4_corroborated") else 0))
    lines += ["};", ""]
    return "\n".join(lines)


def plan_sha16_of(windows, meta_sha16):
    """The v452c signature law: sha256(canonical plan JSON)[:16] — the
    C table embeds the META identity; the boot ledger prints it."""
    canon = json.dumps(
        [{"c": w["win_class"], "b": w["base"], "s": w["size"]}
         for w in windows], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(
        (canon + "|" + meta_sha16).encode()).hexdigest()[:16]


# ---- the selftest (the v451a/v461a pattern: MANDATORY, every path
#      executed before the founder runs anything) ------------------------

def _meta_fixture(**over):
    """A structurally-green GspFwWprMeta fixture (256 B)."""
    f = {
        "magic": META_MAGIC, "revision": META_REVISION,
        "sysmemAddrOfRadix3Elf": 0x1000, "sizeOfRadix3Elf": 0x4000000,
        "gspFwRsvdStart": 0x1FFE00000, "nonWprHeapOffset": 0x1FFE00000,
        "nonWprHeapSize": 0x200000,
        "gspFwWprStart": 0x1F0000000, "gspFwHeapOffset": 0x1F1000000,
        "gspFwHeapSize": 0x2000000, "gspFwOffset": 0x1F3000000,
        "bootBinOffset": 0x1F9000000, "frtsOffset": 0x1F9E00000,
        "frtsSize": 0x100000, "gspFwWprEnd": 0x1FAE00000,
        "fbSize": 0x200000000, "bootCount": 1,
        "gspFwHeapFreeListWprOffset": 0x1000,
        "verified": META_VERIFIED,
    }
    f.update(over)
    buf = bytearray(META_MODEL["sizeof_GspFwWprMeta"])
    for name, off in (("magic", "off_magic"),
                      ("revision", "off_revision"),
                      ("gspFwRsvdStart", "off_gspFwRsvdStart"),
                      ("nonWprHeapOffset", "off_nonWprHeapOffset"),
                      ("nonWprHeapSize", "off_nonWprHeapSize"),
                      ("gspFwWprStart", "off_gspFwWprStart"),
                      ("gspFwHeapOffset", "off_gspFwHeapOffset"),
                      ("gspFwHeapSize", "off_gspFwHeapSize"),
                      ("gspFwOffset", "off_gspFwOffset"),
                      ("bootBinOffset", "off_bootBinOffset"),
                      ("frtsOffset", "off_frtsOffset"),
                      ("frtsSize", "off_frtsSize"),
                      ("gspFwWprEnd", "off_gspFwWprEnd"),
                      ("fbSize", "off_fbSize"),
                      ("bootCount", "off_bootCount"),
                      ("verified", "off_verified")):
        struct.pack_into("<Q", buf, META_MODEL[off], f[name] & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<I", buf, META_MODEL["off_gspFwRsvdStart"] - 16,
                     f["gspFwHeapFreeListWprOffset"])
    return bytes(buf), f


def _s4_fixture(pa, size, name="HEAP1"):
    """One CONTIGUOUS FB record in the S4 table grammar (32 B)."""
    rec = struct.pack("<QQQBB6x", v452a.encode_id8(name), pa, size, 1, 2)
    return rec + b"\x00" * (4096 - len(rec))


def selftest():
    import random
    ok = 0
    tot = 0

    def check(name, cond, detail=""):
        nonlocal ok, tot
        tot += 1
        ok += int(bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {name}"
              + (f" — {detail}" if detail else ""))

    rng = random.Random(0x4621)

    # ---- 1. the tree guard: the committed header through gcc ----
    tg = tree_guard()
    check("tree-guard: the meta offsets re-asserted", tg == "OK", tg)

    # ---- 2. the green fixture: the decode + the invariants ----
    raw, f = _meta_fixture()
    dec = decode_wpr2meta(raw)
    check("decode: the green fixture decodes", dec["ok"], dec["reason"])
    check("decode: the meta locked (0xa0a0...)",
          dec["verified_locked"])
    check("decode: the heap fields named",
          f["gspFwHeapOffset"] == 0x1F1000000 and
          f["gspFwHeapSize"] == 0x2000000)

    # ---- 3. the windows: the ABS-consistent fixture ----
    wins = compute_windows(f)
    cls_surv = {w["win_class"] for w in wins["survivors"]}
    check("windows: ABS survives on the green fixture",
          WIN_ABS in cls_surv, str([hex(w["base"])
                                    for w in wins["survivors"]]))
    check("windows: ABS chain corroborated",
          any(w["win_class"] == WIN_ABS and w["chain_ok"]
              for w in wins["candidates"]))
    # REL on this fixture = 0x1F0000000 + 0x1F1000000 = beyond WPR end:
    check("windows: REL refused by the containment",
          all(w["win_class"] != WIN_REL or not w["survives"]
              for w in wins["candidates"]))

    # ---- 4. the REL-consistent fixture (the small offsets) ----
    raw2, f2 = _meta_fixture(
        gspFwHeapOffset=0x2000000, gspFwHeapSize=0x1ffee00,
        gspFwOffset=0x4000000, bootBinOffset=0xA00000,
        frtsOffset=0xF00000, frtsSize=0x100000)
    # force the REL world: the raw heap offset (0x2000000) sits below
    # the WPR start (0x1F0000000) so ABS fails the containment; the
    # shifted window [0x1F2000000, +0x1ffee00) = inside. NOTE the heap
    # size = the mission's captured pair 0x1ffee00 = ~32 MiB as the
    # plausible gspFwHeapSize form — the REAL dump names the fields at
    # run time (the narrative never decides).
    wins2 = compute_windows(f2)
    cls_surv2 = {w["win_class"] for w in wins2["survivors"]}
    check("windows: REL survives on the small-offset fixture",
          WIN_REL in cls_surv2,
          str([(w["win_class"], hex(w["base"]))
               for w in wins2["candidates"]]))

    # ---- 5. the S4 cross-source: the FB region = a window ----
    s4data = _s4_fixture(0x1F1000000, 0x2000000)
    walked = v452a.walk_s4(s4data)
    regs = walked.get("fb_regions", [])
    wins3 = compute_windows(f, s4_regions=regs)
    check("windows: the S4 FB region survives as a window",
          any(w["win_class"] == WIN_S4 and w["survives"]
              for w in wins3["candidates"]),
          str([r.get("name") for r in regs]))
    check("windows: the ABS window = S4-corroborated",
          any(w["win_class"] == WIN_ABS and w.get("s4_corroborated")
              for w in wins3["candidates"]))

    # ---- 6. the invariant refusals ----
    bad, _ = _meta_fixture(magic=0xDEADBEEF)
    check("refusal: the bad magic", not decode_wpr2meta(bad)["ok"])
    bad, _ = _meta_fixture(gspFwWprStart=0x1F0000123)
    check("refusal: the non-128K WprStart",
          not decode_wpr2meta(bad)["ok"])
    bad, _ = _meta_fixture(gspFwHeapSize=0)
    check("refusal: the zero heap size",
          not decode_wpr2meta(bad)["ok"])
    unv, _ = _meta_fixture(verified=0)
    dec_unv = decode_wpr2meta(unv)
    check("warn: the unverified meta = recorded, not refused",
          dec_unv["ok"] and not dec_unv["verified_locked"])

    # ---- 7. the classifier: every named verdict ----
    n = 4096
    fixtures = [
        (b"\x00" * n, C_SEAL_ZERO),
        (b"\xFF" * n, C_SEAL_FF),
        (b"\x5A" * n, C_SEAL_CONSTANT),
        # the 255/256 bar: 8 stray bytes over 4096 = 4088/4096 >= 255/256
        (b"\x00" * (n - 8) + bytes([0x5A]) * 8, C_SEAL_CONSTANT),
        # the same shape but the stray mass above the bar = DEGENERATE
        (b"\x00" * (n - 64) + bytes([0x5A]) * 64, C_DEGENERATE),
        (struct.pack("<Q", META_MAGIC) + rng.randbytes(n - 8),
         C_WPRMETA_MAGIC),
        (b"\x7fELF" + rng.randbytes(n - 4), C_ELF_MAGIC),
        (struct.pack("<Q", HEAP_FREELIST_MAGIC) + rng.randbytes(n - 8),
         C_HEAP_FREELIST),
        (bytes([0xAA, 0xBB, 0xCC, 0xDD]) * (n // 4), C_DEGENERATE),
        (rng.randbytes(n), C_LIVE_UNKNOWN),
    ]
    for data, want in fixtures:
        got, _p = classify_bytes(data)
        check(f"classifier: {C_NAMES[want]}", got == want, C_NAMES[got])

    # ---- 8. the synthetic read (the SAME code path, a regular file) --
    with tempfile.TemporaryDirectory() as td:
        win_base = 0x100000
        win_len = 4096
        blob = bytearray(rng.randbytes(win_base + win_len))  # the live
        # entropy first — the zero-filled blob would read SEAL-CONSTANT
        blob[win_base:win_base + 4] = struct.pack("<I", 0xDEADBEEF)
        marker_off = win_base + 0x800
        blob[marker_off:marker_off + 4] = struct.pack("<I", 0x0EE6B280)
        res = Path(td) / "resource1"
        res.write_bytes(bytes(blob))
        data = read_window(str(res), win_base, win_len)
        check("read: the synthetic window read back",
              data[:4] == struct.pack("<I", 0xDEADBEEF) and
              data[0x800:0x804] == struct.pack("<I", 0x0EE6B280))
        cls, _ = classify_bytes(data)
        check("read: the synthetic window = LIVE-UNKNOWN",
              cls == C_LIVE_UNKNOWN, C_NAMES[cls])
        try:
            read_window(str(res), win_base + win_len, 64)
            check("read: the OOR window refused", False, "no exception")
        except ProbeRefused:
            check("read: the OOR window refused", True)
        try:
            read_window(str(res), 0, win_len, expect_full_bar1=True)
            check("read: the BAR1-size guard refused the small file",
                  False, "no exception")
        except ProbeRefused:
            check("read: the BAR1-size guard refused the small file",
                  True)

    # ---- 9. the write-free source law (the v454b guarantee) ----
    # (the needles assembled by concat — the check must not carry the
    # literal it greps for, the self-referential trap, caught live)
    src = Path(__file__).read_text()
    has_write_lit = ("mmap.PROT_" + "WRITE") in src
    has_read_lit = ("mmap.PROT_" + "READ") in src
    check("law: the source carries NO write protection literal",
          (not has_write_lit) and has_read_lit)

    # ---- 10. the C emission byte-exact (gcc, the 4.44 law) ----
    ce = c_emission_test(wins["survivors"], "0123456789abcdef")
    check("c-emission: gcc dump == python", ce == "OK", str(ce))
    ce_null = c_emission_test([], "0123456789abcdef")
    check("c-emission: the null plan skips (no bytes to compare)",
          ce_null == "SKIP (the null plan — no bytes to compare)",
          str(ce_null))

    print(f"selftest v462a: {ok}/{tot} "
          f"{'PASS' if ok == tot else 'FAIL'}")
    return ok == tot


def c_emission_test(windows, meta_sha16):
    """gcc compiles the emitted header, dumps the window structs; the
    dump == the python emission (the 4.44 byte-exact law)."""
    hdr = emit_md_plan_header(windows, meta_sha16)
    ws = list(windows)
    if not ws:
        return "SKIP (the null plan — no bytes to compare)"
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "wpr2_read_plan.h"
        h.write_text(hdr)
        # the nvtypes shim (the RM TU gets the types from its includes;
        # the standalone test = the v461a shim law)
        (Path(td) / "nvtypes.h").write_text(
            "#ifndef NVTYPES_SHIM_H\n"
            "#define NVTYPES_SHIM_H\n"
            "typedef unsigned long long NvU64;\n"
            "typedef unsigned int NvU32;\n"
            "typedef unsigned short NvU16;\n"
            "typedef unsigned char NvU8;\n"
            "typedef unsigned char NvBool;\n"
            "#endif\n")
        probe = Path(td) / "dump.c"
        probe.write_text(
            '#include <stdio.h>\n#include <string.h>\n'
            '#include "nvtypes.h"\n'
            '#include "wpr2_read_plan.h"\n'
            "int main(void) {\n"
            "  unsigned int i;\n"
            "  for (i = 0; i < GSP_WPR2_READ_PLAN_N; i++) {\n"
            "    unsigned char out[32]; unsigned int j;\n"
            "    memcpy(out, &gspWpr2ReadWindows[i], 32);\n"
            "    for (j = 0; j < 32; j++) printf(\"%02x\", out[j]);\n"
            "    printf(\"\\n\");\n"
            "  }\n"
            '  printf("%s\\n", GSP_WPR2_READ_PLAN_META_SHA16);\n'
            "  return 0;\n}\n")
        r = subprocess.run(
            ["gcc", "-I", td, "-o", str(Path(td) / "dump"), str(probe)],
            capture_output=True, text=True)
        if r.returncode != 0:
            return f"gcc FAIL: {r.stderr[:200]}"
        r = subprocess.run([str(Path(td) / "dump")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return f"run FAIL: {r.stderr[:200]}"
        lines = r.stdout.strip().splitlines()
        if len(lines) != len(ws) + 1:
            return f"line count {len(lines)} != {len(ws) + 1}"
        for w, line in zip(ws, lines):
            want = struct.pack("<IIQQII", w["win_class"],
                               min(w.get("read_len", READ_LEN_DEFAULT),
                                   READ_LEN_MAX),
                               w["base"], w["size"],
                               1 if w.get("chain_ok") else 0,
                               1 if w.get("s4_corroborated") else 0).hex()
            if line[:64] != want:
                return f"drift: {line[:64]} != {want}"
        if lines[-1] != meta_sha16:
            return f"sha drift: {lines[-1]} != {meta_sha16}"
    return "OK"


# ---- main --------------------------------------------------------------

def discover_gpus(sysfs="/sys/bus/pci/devices"):
    """The NVIDIA display controllers (the v454b discovery law)."""
    found = []
    base = Path(sysfs)
    if not base.is_dir():
        return found
    for dev in sorted(base.iterdir()):
        try:
            vendor = int((dev / "vendor").read_text().strip(), 16)
            cls = int((dev / "class").read_text().strip(), 16)
        except (OSError, ValueError):
            continue
        if vendor == 0x10DE and (cls >> 16) == 0x03:
            found.append(dev.name)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--decode", default="",
                    help="decode a wpr2meta.bin (S8) and print the table")
    ap.add_argument("--wpr2meta", default="",
                    help="the S8 dump — the window-math input")
    ap.add_argument("--libosinit", default="",
                    help="the S4 dump — the GSP's own boot map (the "
                         "loc=FB regions = the cross-source)")
    ap.add_argument("--pci", default="", help="the PCI address (0000:01:00.0)")
    ap.add_argument("--resource", default="",
                    help="the BAR1 file override (the synthetic mode — "
                         "a regular file emulates the aperture)")
    ap.add_argument("--bar", type=int, default=1,
                    help="the BAR index (1 = the aperture, the default)")
    ap.add_argument("--read-len", type=lambda x: int(x, 0),
                    default=READ_LEN_DEFAULT)
    ap.add_argument("--out", default=str(Path.home() / "route-w-462"))
    ap.add_argument("--emit-plan", default="",
                    help="write the wpr2_read_plan.h emission here")
    ap.add_argument("--plan-out", default="",
                    help="write the plan JSON here")
    ap.add_argument("nothing", nargs="*", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1

    if a.decode:
        d = decode_wpr2meta(Path(a.decode).read_bytes())
        print(json.dumps(d, indent=1))
        return 0 if d["ok"] else 1

    if not a.wpr2meta:
        print("no --wpr2meta — run --selftest or pass the S8 dump",
              file=sys.stderr)
        return 2

    # ---- the plan gate: the decode + the windows ----
    meta_bytes = Path(a.wpr2meta).read_bytes()
    meta_sha16 = hashlib.sha256(meta_bytes).hexdigest()[:16]
    dec = decode_wpr2meta(meta_bytes)
    print(f"[wpr2meta] sha16={meta_sha16} ok={dec['ok']} "
          f"locked={dec.get('verified_locked')} — {dec['reason']}")
    if not dec["ok"]:
        print(json.dumps(dec["fields"], indent=1))
        print("REFUSÉ: the meta invariants failed — the day stops "
              "(the bytes decide, never the narrative)", file=sys.stderr)
        return 1
    f = dec["fields"]
    print(f"[wpr2meta] WprStart={f['gspFwWprStart']:#x} "
          f"WprEnd={f['gspFwWprEnd']:#x} fbSize={f['fbSize']:#x} "
          f"HeapOff={f['gspFwHeapOffset']:#x} "
          f"HeapSize={f['gspFwHeapSize']:#x} "
          f"FwOff={f['gspFwOffset']:#x} bootCount={f['bootCount']}")

    s4_regions = None
    if a.libosinit:
        s4d = v452a.walk_s4(Path(a.libosinit).read_bytes())
        s4_regions = s4d.get("fb_regions", [])
        print(f"[libosinit] {s4d.get('active')} active region(s), "
              f"{len(s4_regions)} FB (the walk = the committed v452a)")

    wins = compute_windows(f, s4_regions=s4_regions)
    for c in wins["candidates"]:
        print(f"  window cls={c['win_class']} base={c['base']:#x} "
              f"size={c['size']:#x} survives={c['survives']} "
              f"chain={c['chain_ok']} s4={c.get('s4_corroborated')}")
    if wins["indecidable"]:
        print("REFUSÉ: NO window survives the structural invariants — "
              "INDECIDABLE (the table above = the evidence; the day "
              "stops, the re-decode or the fresh dump decides)",
              file=sys.stderr)
        return 1
    survivors = wins["survivors"]
    plan_sha16 = plan_sha16_of(survivors, meta_sha16)
    print(f"[plan] {len(survivors)} window(s), plan_sha16={plan_sha16}")

    if a.emit_plan:
        Path(a.emit_plan).write_text(
            emit_md_plan_header(survivors, meta_sha16))
        print(f"plan header: {a.emit_plan}")
    if a.plan_out:
        Path(a.plan_out).write_text(json.dumps(
            {"meta_sha16": meta_sha16, "plan_sha16": plan_sha16,
             "windows": survivors, "fields": f}, indent=1))

    if not a.resource and not a.pci:
        print("no --pci/--resource — the windows + the plan are the "
              "deliverable (the read = the runbook §1 gesture)",
              file=sys.stderr)
        return 0

    # ---- the READ (the ACK law: even the reads are gated) ----
    if a.resource:
        res_path = a.resource          # the synthetic mode
        expect_full = False
    else:
        if os.environ.get("ROUTE_W_462_ACK") != "1":
            print("REFUSÉ: ROUTE_W_462_ACK=1 absent — the sonde ne lit "
                  "rien (the 4.54 discipline: even the reads are gated)",
                  file=sys.stderr)
            return 2
        pci = a.pci or (discover_gpus() or [None])[0]
        if not pci:
            print("REFUSÉ: no NVIDIA display controller found",
                  file=sys.stderr)
            return 2
        res_path = f"/sys/bus/pci/devices/{pci}/resource{a.bar}"
        expect_full = True
        print(f"[probe] PCI={pci} resource={res_path}")

    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    results = []
    for i, w in enumerate(survivors):
        rl = min(a.read_len, w["size"], READ_LEN_MAX)
        try:
            data = read_window(res_path, w["base"], rl,
                               expect_full_bar1=expect_full)
        except ProbeRefused as e:
            print(f"  [{i}] REFUSÉ: {e}", file=sys.stderr)
            results.append({"window": i, "verdict": "REFUSED",
                            "reason": str(e)})
            continue
        cls, p = classify_bytes(data)
        dump = outdir / f"v462a_b1_win{i}.bin"
        dump.write_bytes(data)
        row = {
            "window": i, "win_class": w["win_class"],
            "base": w["base"], "base_hex": hex(w["base"]),
            "size": w["size"], "read_len": rl,
            "verdict": C_NAMES[cls], "first_u64_hex":
                hex(p["first_u64"]), "distinct": p["distinct"],
            "top_byte": (p["top_val"], p["top_cnt"]),
            "sha256_16": hashlib.sha256(data).hexdigest()[:16],
            "dump": str(dump),
        }
        results.append(row)
        print(f"  [{i}] base={w['base']:#x} len={rl} "
              f"verdict={row['verdict']} first_u64={row['first_u64_hex']} "
              f"distinct={p['distinct']} sha16={row['sha256_16']}")
        out = outdir / f"v462a_b1_read.json"
        out.write_text(json.dumps(
            {"meta_sha16": meta_sha16, "plan_sha16": plan_sha16,
             "reads": results}, indent=1))
    neg = {r["verdict"] for r in results
           if r.get("verdict") in ("SEAL-ZERO", "SEAL-FF",
                                   "SEAL-CONSTANT", "DEGENERATE")}
    if len(neg) == len(results) and results:
        print("THE SEAL ANSWERED (the named negative): every window "
              "read back degenerate — the WPR2 CPU-read question = "
              "the negative, the runbook §5 decision table decides",
              file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
