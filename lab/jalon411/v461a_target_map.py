#!/usr/bin/env python3
"""v461a_target_map.py — PASS 4.61 T1 — LE CIBLAGE: the µW-base target map.

THE OBJECT MODEL (all banked, zero invention):
  the power object = 0x6d0 B, allocated by the RM init (the allocator
  0x18C373C, the descriptor 0x4190DE8, memset-zero, 4.43 §2.2). The
  recompute (0x143FDBC) fills it from the internal events 0x20809009
  (the mask -> obj+0x65c) and 0x20809064 (the lookup clé->ligne: the
  rows live at (a0)+0x32BC8, 4.46 §1.3); the base quad lands at
  obj+0x618+k*0x10 (k = 0..3, the group keys {1,4,8,2} @0x1C7B320)
  and the records at obj+0x18+k*0x30 (f18 @+0x18, f14 @+0x14).
  THE FORMULA (4.43 §2.4, the evaluator 0x1446D98):
      limite_mW = base_uW * f18 / 100 / 1000
  THE PERSISTENCE SPLIT (4.44 §payload table, the campaign's most
  load-bearing fact for this pass):
      f18  = PERSISTENT  (the recompute NEVER rewrites f14/f18)
      base = VOLATILE    (the recompute rewrites A/B/C/D each pass)
  THE PAYLOAD LAW (4.44, the emulated+TF-tested shape): the base write
  = the u64 pair {base_uW, 0} at obj+0x618+k*0x10 (the u64
  zero-extension side effect = DOCUMENTED, not accidental).

THE MARKER FAMILY (imported from v454a — zero re-transcription):
  0x0EE6B280 = 250000000 µW = 250 W stock base  (the 4.53 shape)
  0x0E4E1C00 = 240000000 µW = 240 W sibling base (the v454a shape)
  0x10B07600 = 280000000 µW = 280 W target       (the v454a shape)
  A 0x10B07600 hit in a base slot = ALREADY-280: named, NEVER a write
  target (the no-op refusal — the honest plan entry).

THE SCAN (per dump surface, the v451a floor discipline imported):
  1. the base-form u32le EXACT hits (3 shapes above);
  2. the u64le pair {base, 0} (the 4.44 payload law);
  3. THE OBJECT FINGERPRINT — the stride-0x10 co-location: a base hit
     is a CANDIDATE only with >=1 sibling base-form at +-0x10/0x20/
     0x30; the FULL quad (4 slots) + the f18 quad (the values {100,
     112, 0xffffffff} at obj+0x18+k*0x30) = THE OBJECT FOUND;
  4. the object-base inference: obj_base = hit_off - 0x618 - k*0x10 —
     ALL co-located hits must infer the SAME obj_base (the consistency
     gate; a lone hit = a LEAD, never plan-eligible — the k ambiguity).

THE TARGET MAP (the mission's deliverable):
  {adresse absolue (the surface-relative offset = the host-reachable
   address the dump proves), offset objet (obj+0x618+k*0x10), rôle
   (base[k], the group key), valeur actuelle attendue (the shape)}.

THE PLAN (the v452c law, the same defense order):
  sel = k+1 in {1..4}; ONE entry per sel (the collision = REFUSED);
  old = THE BYTES FOUND (the runtime truth); new = the u64 pair
  {0x10B07600, 0}; verify_after on EVERY entry; plan_sha16 =
  sha256(canonical entries JSON)[:16]; the GATED NULL plan (0 entries,
  the stable sha) when the bytes do not speak.

THE SELFTEST (the v451a pattern, mandatory — the scan refuses without
  it): the full-object fixture (both quads planted), the partial
  fixture (1 hit = LEAD, no plan), the control (random = MISS), the
  already-280 fixture (the no-op), the tree guard (the committed
  610.57.04 header re-read through gcc offsetof — the machine law),
  the C emission byte-exact (gcc, the 4.44 law).

ZÉRO BOOT BY CONSTRUCTION: this instrument reads FILES and emits
  TABLES. It cannot touch hardware. The machine day = runbook-461.sh,
  ACK-gated, and only a plan built from REAL dump bytes can boot.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import v451a_dmem_scan as v451a          # noqa: E402 — the floor discipline
import v454a_probe_table as v454a        # noqa: E402 — the SHAPE constants

ROOT = HERE.parents[1]
GSP_HDR = ROOT / ("imports/open-gpu-kernel-modules-610.57.04/gsp/"
                  "gsp_init_args.h")

# ---- the object model (banked 4.43/4.44/4.46 — the constants are the
#      single source; the findings cite the instruction windows) -------
OBJ_SIZE = 0x6D0
BASE_OFF = 0x618             # base[k] = obj + 0x618 + k*0x10 (lwu @0x1446f0c)
GROUP_STRIDE = 0x10
N_GROUPS = 4                 # k = 0..3 (the evaluator: a4 = 0..3, 4.44 §1)
GROUP_KEYS = (1, 4, 8, 2)    # @0x1C7B320 (the recompute pre-places, 4.46 §1.3)
REC_STRIDE = 0x30            # record[k] = obj + k*0x30
F18_OFF = 0x18               # record[k].f18 (c.lw @0x1446efe, SIGNED, -1 = unlimited)
F14_OFF = 0x14               # record[k].f14 (c.lw @0x1446f24)
F18_SENTINEL = 0xFFFFFFFF    # -1 = illimité (the normalized u32 form)
F18_STOCK = 100              # percent (the 250 W reading)
F18_280 = 112                # percent (the 280 W alternative — the f18 route)
MASK_OFF = 0x65C             # the policy mask (sw @0x143fe3e)
EV_MASK = 0x20809009         # the mask event (lui/c.addi @0x143fe1c)
EV_FILL = 0x20809064         # the fill event (the lookup clé->ligne)
SOURCE_TABLE_OFF = 0x32BC8   # (a0)+0x32BC8 = the row source (4.46 §1.3)
FORMULA = "limite_mW = base_uW * f18 / 100 / 1000"

# the surface IDs (the writer's resolver — the KernelGsp members the
# 4.51 dump instrument itself read; the write = the same pointers)
SURFACES = {
    1: ("args", "pGspArgumentsCached"),
    2: ("libosinit", "pLibosInitArgumentsCached"),
    3: ("statemonitor", "pRmStateMonitorBuffer"),
    4: ("wprmeta", "pWprMeta"),
    5: ("sysmemheap", "pSysmemHeapDescriptor(map)"),
}

# the shapes (imported — the assert here re-arms the v454a law)
SHAPE_250 = v454a.SHAPE_250_UW
SHAPE_240 = v454a.SHAPE_240_UW
SHAPE_280 = v454a.SHAPE_280_UW
assert SHAPE_250 == 0x0EE6B280, hex(SHAPE_250)
assert SHAPE_240 == 0x0E4E1C00, hex(SHAPE_240)
assert SHAPE_280 == 0x10B07600, hex(SHAPE_280)
SHAPE_NAMES = {SHAPE_250: "250W-stock", SHAPE_240: "240W-sibling",
               SHAPE_280: "280W-target"}
BASE_FORMS = sorted(SHAPE_NAMES)
BASE_FORM_BYTES = {v: struct.pack("<I", v) for v in BASE_FORMS}

# the args decode model (the committed gsp_init_args.h @610.57.04,
# NvLength = NvUPtr = 8 on LP64 — the 4.51 machine decode coherence:
# rmStateMonitorBufferArgs {0xC7FE0000, 4096} matched the blob)
ARGS_MODEL = {
    "sizeof_MESSAGE_QUEUE_INIT_ARGUMENTS": 64,
    "sizeof_GSP_SR_INIT_ARGUMENTS": 16,
    "off_gpuInstance": 80,
    "off_bDmemStack": 84,
    "off_profilerArgs": 88,
    "off_sysmemHeapArgs": 104,
    "off_rmStateMonitorBufferArgs": 120,
    "off_bindataArgs": 136,
    "sizeof_GSP_ARGUMENTS_CACHED": 152,
}


def find_base_hits(data: bytes):
    """All base-form u32le hits with the shape name + the u64-pair flag."""
    hits = []
    for val in BASE_FORMS:
        pat = BASE_FORM_BYTES[val]
        start = 0
        while True:
            i = data.find(pat, start)
            if i < 0:
                break
            # the u64-pair law: the upper half must be the zero half
            pair = (i + 8 <= len(data) and data[i + 4:i + 8] == b"\x00" * 4)
            hits.append({"off": i, "val": val, "name": SHAPE_NAMES[val],
                         "u64pair": pair})
            start = i + 1
    hits.sort(key=lambda h: h["off"])
    return hits


def siblings_at(data: bytes, off: int, hits_by_off: dict):
    """The base-form siblings at the +-0x10/0x20/0x30 object strides."""
    sib = []
    for d in (0x10, 0x20, 0x30, -0x10, -0x20, -0x30):
        o = off + d
        if 0 <= o < len(data) and o in hits_by_off:
            sib.append({"delta": d, "off": o,
                        "name": hits_by_off[o]["name"]})
    return sib


def f18_quad_shape(data: bytes, obj_base: int):
    """The record quad check: u32 @obj+0x18+k*0x30 in the plausible set.

    The set = the BANKED f18 domain: {100 (stock), 112 (the 280 W
    alternative), 0xffffffff (the -1 sentinel, the 4.44 normalized
    form)} — anything else = the shape broken (not our object).
    """
    ok = 0
    seen = []
    for k in range(N_GROUPS):
        o = obj_base + REC_STRIDE * k + F18_OFF
        if o + 4 > len(data):
            seen.append(None)
            continue
        v = struct.unpack("<I", data[o:o + 4])[0]
        seen.append(v)
        if v in (F18_STOCK, F18_280, F18_SENTINEL):
            ok += 1
    return ok, seen


def infer_object(data: bytes, hits: list):
    """The object-base inference: the consistency gate.

    For every (hit, k) pair the candidate obj_base = off - 0x618 -
    k*0x10; the score = how many base-form hits sit at the inferred
    obj_base + 0x618 + j*0x10 (j = 0..3). The best-scoring candidate
    with score >= 2 = the inferred object (the k ambiguity resolved by
    the co-location). The f18 quad = the structural corroboration
    (reported, required only for the FULL verdict).
    """
    by_off = {h["off"]: h for h in hits}
    cands = {}
    for h in hits:
        for k in range(N_GROUPS):
            ob = h["off"] - BASE_OFF - k * GROUP_STRIDE
            if ob < 0:
                continue
            score = 0
            ks = []
            for j in range(N_GROUPS):
                o = ob + BASE_OFF + j * GROUP_STRIDE
                if o in by_off:
                    score += 1
                    ks.append(j)
            if score >= 2 and (score > cands.get(ob, (0, None, None))[0]):
                cands[ob] = (score, tuple(sorted(ks)), h["off"])
    if not cands:
        return None
    ob = max(cands, key=lambda b: (cands[b][0], -b))
    score, ks, _ = cands[ob]
    f18ok, f18seen = f18_quad_shape(data, ob)
    return {"obj_base": ob, "hits": score, "groups": list(ks),
            "f18_quad_ok": f18ok, "f18_quad_seen": f18seen}


def scan_surface(label: str, data: bytes):
    """The per-surface scan: the hits, the inference, the verdict."""
    hits = find_base_hits(data)
    by_off = {h["off"]: h for h in hits}
    rows = []
    for h in hits:
        sib = siblings_at(data, h["off"], by_off)
        raw8 = data[h["off"]:h["off"] + 8]
        if len(raw8) < 8:                       # the end-of-surface guard
            raw8 = raw8 + b"\x00" * (8 - len(raw8))
        rows.append({
            "off": h["off"], "hex_off": hex(h["off"]), "shape": h["name"],
            "val": h["val"], "raw8_hex": raw8.hex(),
            "u64pair": h["u64pair"], "siblings": sib,
            "stride_class": ("CANDIDATE" if sib else
                             "LEAD"),  # a lone hit = never plan-eligible
        })
    obj = infer_object(data, hits) if hits else None
    if obj:
        full = obj["hits"] == N_GROUPS
        obj["verdict"] = ("OBJECT-FOUND" if (full and obj["f18_quad_ok"] >= 3)
                          else ("OBJECT-CANDIDATE" if obj["hits"] >= 2
                                else "LEAD"))
    elif hits:
        obj = {"obj_base": None, "hits": 0, "groups": [],
               "f18_quad_ok": 0, "f18_quad_seen": [],
               "verdict": "LEAD"}   # the lone hits — the k ambiguity
    else:
        obj = {"obj_base": None, "hits": 0, "groups": [],
               "f18_quad_ok": 0, "f18_quad_seen": [],
               "verdict": "NO-OBJECT"}
    # the floor discipline on the base-form family (the v451a law): a
    # 4-byte exact form over N bytes: floor = N / 2^32 — any realistic
    # dump floor << 1, so 1 hit clears the noise bar STRUCTURALLY; the
    # object gate above is what separates the real estate from the echo.
    fl = v451a.floor_for(4, len(data))
    return {"surface": label, "size": len(data),
            "sha256_16": hashlib.sha256(data).hexdigest()[:16],
            "floor_u32": round(fl, 9),
            "hits": rows, "object": obj,
            "verdict": ("MISS" if not rows else obj["verdict"])}


def build_plan(scans: dict, surface_ids: dict):
    """The signed write plan (the v452c law) from the OBJECT-FOUND /
    OBJECT-CANDIDATE surfaces. The null plan when the bytes are silent."""
    entries = []
    nulls = []
    refused = []
    by_sel = {}
    for label, sc in scans.items():
        obj = sc["object"]
        if obj["verdict"] not in ("OBJECT-FOUND", "OBJECT-CANDIDATE"):
            continue
        sid = surface_ids.get(label)
        if sid is None:
            refused.append({"surface": label,
                            "reason": "no surface id — name it with "
                                      "--surface label=id before the plan"})
            continue
        for h in sc["hits"]:
            k = (h["off"] - obj["obj_base"] - BASE_OFF) // GROUP_STRIDE
            if h["off"] != obj["obj_base"] + BASE_OFF + k * GROUP_STRIDE:
                continue  # a sibling echo outside the quad — never write
            sel = k + 1
            old8 = b"\x00" * 8
            # the runtime truth: the 8 bytes as found (the base u32 +
            # the neighbor u32 — the u64 write lane covers both)
            entry = {
                "sel": sel, "group": k, "surface": sid,
                "surface_label": label,
                "offset": h["off"], "addr_hex": hex(h["off"]),
                "obj_offset": f"obj+{hex(BASE_OFF + k * GROUP_STRIDE)}",
                "role": f"base[{k}] (group key {GROUP_KEYS[k]})",
                "len": 8,
                "old_hex": h["raw8_hex"],
                "new_hex": struct.pack("<Q", SHAPE_280).hex(),
                "verify_after": True,
            }
            if h["val"] == SHAPE_280:
                nulls.append({"sel": sel, "surface": label,
                              "addr_hex": h["hex_off"],
                              "reason": "ALREADY-280 (the 0x10B07600 form) "
                                        "— the no-op refusal, never a "
                                        "write target"})
                continue
            col = by_sel.setdefault(sel, [])
            col.append(entry)
    for sel in sorted(by_sel):
        col = by_sel[sel]
        if len(col) > 1:
            refused.append({"reason": f"selector {sel} carries "
                                      f"{len(col)} entries — AMBIGUOUS "
                                      "(one group, one surface, one "
                                      "boot)", "candidates":
                            sorted({e["surface_label"] for e in col})})
            continue
        entries.append(col[0])
    entries.sort(key=lambda e: e["sel"])
    canon = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    sha16 = hashlib.sha256(canon.encode()).hexdigest()[:16]
    return {"entries": entries, "null_targets": nulls, "refused": refused,
            "plan_sha16": sha16, "formula": FORMULA}


def emit_c_header(plan: dict) -> str:
    """The gsp_dmem_write_plan.h emission (the v452c law: byte-exact,
    gcc-tested vs the python emission — the 4.44 lesson). The GATED
    NULL plan = the N=0 macro + the ONE all-zero sentinel entry (the
    writer reads plan[0].sel == 0 -> the NULL_PLAN verdict; the scan
    loop `i < PLAN_N` never reads it)."""
    es = list(plan["entries"])
    null_plan = not es
    lines = [
        "/* GENERATED by v461a_target_map.py — the reviewed DMEM write",
        "   plan (the RM header). plan_sha16 = %s — the writer prints it",
        "   NEXT TO the pre/post verify: any drift between the reviewed",
        "   plan and the compiled table = visible in the boot ledger.",
        "   The formula: %s. The payload = the u64 pair {base, 0}",
        "   (the 4.44 law). ONE write per boot, sel = the group k+1. */",
        "#define GSP_DMEM_WRITE_PLAN_N %d" % len(es),
        '#define GSP_DMEM_WRITE_PLAN_SHA16 "%s"' % plan["plan_sha16"],
        "",
        "typedef struct {",
        "    NvU32 sel;         /* 1..4 = the group k+1 (RmGspDMemWrite) */",
        "    NvU32 group;       /* k (0-based) */",
        "    NvU32 surface;     /* 1=args 2=libosinit 3=statemonitor",
        "                          4=wprmeta 5=sysmemheap(map) */",
        "    NvU32 groupKey;    /* the expected group key {1,4,8,2} */",
        "    NvU64 offset;      /* the surface-relative byte offset */",
        "    NvU32 len;         /* 8 = the u64 pair lane */",
        "    NvU32 verifyAfter; /* always 1 */",
        "    NvU8  old[8];      /* the runtime truth (the pre-verify) */",
        "    NvU8  nw[8];       /* 0x10B07600 + the zero half */",
        "} GSP_DMEM_WRITE_ENTRY;",
        "",
    ]
    if null_plan:
        lines += [
            "/* the GATED NULL plan: nothing writes (the honest close) */",
            "static const GSP_DMEM_WRITE_ENTRY gspDmemWritePlan[1] =",
            "{",
            "    { 0, 0, 0, 0, 0x0ULL, 0, 0, { 0 }, { 0 } },",
            "};",
            "",
        ]
        return "\n".join(lines)
    lines += ["static const GSP_DMEM_WRITE_ENTRY "
              "gspDmemWritePlan[GSP_DMEM_WRITE_PLAN_N] =",
              "{"]
    for e in es:
        old = ",".join("0x%02x" % b for b in bytes.fromhex(e["old_hex"]))
        new = ",".join("0x%02x" % b for b in bytes.fromhex(e["new_hex"]))
        lines.append(
            "    { %d, %d, %d, %d, 0x%xULL, %d, %d, "
            "{ %s }, { %s } }," %
            (e["sel"], e["group"], e["surface"], GROUP_KEYS[e["group"]],
             e["offset"], e["len"], 1 if e["verify_after"] else 0,
             old, new))
    lines += ["};", ""]
    return "\n".join(lines)


def decode_args(data: bytes):
    """The S3 decode per the committed gsp_init_args.h @610.57.04."""
    m = ARGS_MODEL
    if len(data) < m["sizeof_GSP_ARGUMENTS_CACHED"]:
        return {"error": f"args too small ({len(data)} < "
                         f"{m['sizeof_GSP_ARGUMENTS_CACHED']})"}
    def u64(o):
        return struct.unpack("<Q", data[o:o + 8])[0]
    return {
        "gpuInstance": struct.unpack("<I", data[80:84])[0],
        "bDmemStack": data[84],
        "profilerArgs": {"pa": u64(88), "size": u64(96)},
        "sysmemHeapArgs": {"pa": u64(104), "size": u64(112)},
        "rmStateMonitorBufferArgs": {"pa": u64(120), "size": u64(128)},
        "bindataArgs": {"radix3": u64(136), "size": u64(144)},
        "model": m,
    }


def selftest():
    """The mandatory pre-scan proof (the v451a pattern, expanded)."""
    import random
    ok = 0
    tot = 0

    def check(name, cond, detail=""):
        nonlocal ok, tot
        tot += 1
        ok += int(bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {name}"
              + (f" — {detail}" if detail else ""))

    rng = random.Random(0x4611)

    def plant(base_val, f18_val, k, obj_base, buf):
        off = obj_base + BASE_OFF + k * GROUP_STRIDE
        buf[off:off + 4] = struct.pack("<I", base_val)
        # the neighbor u32 = the zero half (the u64-pair law as found)
        buf[off + 4:off + 8] = b"\x00" * 4
        ro = obj_base + REC_STRIDE * k + F18_OFF
        buf[ro:ro + 4] = struct.pack("<I", f18_val)

    # ---- 1. the FULL fixture: the object planted, both quads ----
    OB = 0x20000
    buf = bytearray(rng.randbytes(1 << 18))
    for k in range(N_GROUPS):
        plant(SHAPE_250 if k != 2 else SHAPE_240, F18_STOCK, k, OB, buf)
    data = bytes(buf)
    sc = scan_surface("fixture-full", data)
    check("full: the object inferred", sc["object"]["obj_base"] == OB,
          f"obj_base={hex(sc['object']['obj_base'])}")
    check("full: the verdict OBJECT-FOUND",
          sc["object"]["verdict"] == "OBJECT-FOUND",
          sc["object"]["verdict"])
    check("full: 4 base hits", len(sc["hits"]) == 4)
    check("full: the u64 pairs all true",
          all(h["u64pair"] for h in sc["hits"]))
    plan = build_plan({"fixture-full": sc}, {"fixture-full": 3})
    check("full: the plan = 4 entries", len(plan["entries"]) == 4,
          str(len(plan["entries"])))
    check("full: every new = the 280 u64 pair",
          all(e["new_hex"] == struct.pack("<Q", SHAPE_280).hex()
              for e in plan["entries"]))
    check("full: the sels = 1..4",
          [e["sel"] for e in plan["entries"]] == [1, 2, 3, 4])
    check("full: the k=2 entry old = the 240 form",
          plan["entries"][2]["old_hex"] == struct.pack(
              "<II", SHAPE_240, 0).hex())
    # the sha stability (deterministic)
    plan2 = build_plan({"fixture-full": sc}, {"fixture-full": 3})
    check("full: the sha stable", plan["plan_sha16"] == plan2["plan_sha16"])

    # ---- 2. the PARTIAL fixture: 1 hit = LEAD, no plan ----
    buf = bytearray(rng.randbytes(1 << 18))
    plant(SHAPE_250, F18_STOCK, 0, 0x30000, buf)
    sc1 = scan_surface("fixture-partial", bytes(buf))
    check("partial: the verdict = LEAD",
          sc1["object"]["verdict"] == "LEAD", sc1["object"]["verdict"])
    plan1 = build_plan({"fixture-partial": sc1}, {"fixture-partial": 3})
    check("partial: the plan refuses (0 entries)",
          len(plan1["entries"]) == 0)

    # ---- 3. the control: random = MISS, no plan ----
    rnd = bytes(rng.randbytes(1 << 18))
    scc = scan_surface("fixture-control", rnd)
    check("control: MISS", scc["verdict"] == "MISS", scc["verdict"])

    # ---- 4. the ALREADY-280 fixture: the no-op refusal ----
    buf = bytearray(rng.randbytes(1 << 18))
    for k in range(N_GROUPS):
        plant(SHAPE_280, F18_STOCK, k, 0x18000, buf)
    sc2 = scan_surface("fixture-already", bytes(buf))
    check("already: the object found",
          sc2["object"]["verdict"] == "OBJECT-FOUND")
    plan3 = build_plan({"fixture-already": sc2}, {"fixture-already": 3})
    check("already: 0 write entries", len(plan3["entries"]) == 0)
    check("already: the no-ops named",
          len(plan3["null_targets"]) == 4)

    # ---- 5. the tree guard: the committed header through gcc ----
    tg = tree_guard()
    check("tree-guard: the args offsets re-asserted", tg, tg)

    # ---- 6. the C emission byte-exact (gcc, the 4.44 law) ----
    ce = c_emission_test(plan)
    check("c-emission: gcc dump == python", ce, "")

    print(f"selftest v461a: {ok}/{tot} "
          f"{'PASS' if ok == tot else 'FAIL'}")
    return ok == tot


def tree_guard():
    """gcc offsetof probe against the COMMITTED 610.57.04 header — the
    ARGS_MODEL constants re-asserted from the tree itself (the v452a
    G-law: the machine gcc judges, never the memory)."""
    if not GSP_HDR.exists():
        return "SKIP (the header absent)"
    with tempfile.TemporaryDirectory() as td:
        shim = Path(td) / "nvtypes.h"
        shim.write_text(
            "#ifndef NVTYPES_SHIM_H\n"
            "#define NVTYPES_SHIM_H\n"
            "typedef unsigned long long NvU64;\n"
            "typedef unsigned int NvU32;\n"
            "typedef unsigned char NvU8;\n"
            "typedef unsigned char NvBool;\n"
            "typedef unsigned long NvUPtr;\n"
            "typedef NvUPtr NvLength;\n"
            "#endif\n")
        (Path(td) / "gpu" / "mem_mgr").mkdir(parents=True, exist_ok=True)
        ps = Path(td) / "gpu" / "mem_mgr" / "rm_page_size.h"
        ps.write_text("#define RM_PAGE_SIZE_128K 0x20000\n")
        probe = Path(td) / "probe.c"
        probe.write_text(
            '#include <stdio.h>\n#include <stddef.h>\n'
            '#include "gsp_init_args.h"\n'
            "int main(void) {\n"
            "  printf(\"%zu %zu %zu %zu %zu\\n\",\n"
            "    offsetof(GSP_ARGUMENTS_CACHED, profilerArgs),\n"
            "    offsetof(GSP_ARGUMENTS_CACHED, sysmemHeapArgs),\n"
            "    offsetof(GSP_ARGUMENTS_CACHED, rmStateMonitorBufferArgs),\n"
            "    offsetof(GSP_ARGUMENTS_CACHED, bindataArgs),\n"
            "    sizeof(GSP_ARGUMENTS_CACHED));\n"
            "  return 0;\n}\n")
        r = subprocess.run(
            ["gcc", "-I", td, "-I", str(GSP_HDR.parent), "-o",
             str(Path(td) / "probe"), str(probe)],
            capture_output=True, text=True)
        if r.returncode != 0:
            return f"gcc FAIL: {r.stderr[:200]}"
        r = subprocess.run([str(Path(td) / "probe")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return f"run FAIL: {r.stderr[:200]}"
        got = tuple(int(x) for x in r.stdout.split())
        want = (ARGS_MODEL["off_profilerArgs"],
                ARGS_MODEL["off_sysmemHeapArgs"],
                ARGS_MODEL["off_rmStateMonitorBufferArgs"],
                ARGS_MODEL["off_bindataArgs"],
                ARGS_MODEL["sizeof_GSP_ARGUMENTS_CACHED"])
        return ("OK" if got == want else
                f"DRIFT got={got} want={want}")


def c_emission_test(plan: dict):
    """gcc compiles the emitted header, dumps the entries' bytes; the
    dump == the python emission (the 4.44 byte-exact law)."""
    hdr = emit_c_header(plan)
    es = plan["entries"]
    if not es:
        return "SKIP (the null plan — no bytes to compare)"
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "gsp_dmem_write_plan.h"
        h.write_text(hdr)
        probe = Path(td) / "dump.c"
        probe.write_text(
            '#include <stdio.h>\n#include <string.h>\n'
            '#include "gsp_dmem_write_plan.h"\n'
            "int main(void) {\n"
            "  unsigned int i;\n"
            "  for (i = 0; i < GSP_DMEM_WRITE_PLAN_N; i++) {\n"
            "    unsigned char out[16]; unsigned int j;\n"
            "    memcpy(out, &gspDmemWritePlan[i], 16);\n"
            "    for (j = 0; j < 16; j++) printf(\"%02x\", out[j]);\n"
            "    printf(\"\\n\");\n"
            "  }\n"
            "  printf(\"%s\\n\", GSP_DMEM_WRITE_PLAN_SHA16);\n"
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
        if len(lines) != len(es) + 1:
            return f"line count {len(lines)} != {len(es) + 1}"
        for e, line in zip(es, lines):
            # the dump = the first 16 B of the struct = sel,group,surface,
            # groupKey,offset(8) — compare FIELD-WISE (the struct layout
            # vs the python emission, the byte-exact contract)
            want = struct.pack("<IIIIQ", e["sel"], e["group"], e["surface"],
                               GROUP_KEYS[e["group"]], e["offset"]).hex()
            if line[:32] != want[:32]:
                return (f"drift sel={e['sel']}: {line[:32]} != {want[:32]}")
        if lines[-1] != plan["plan_sha16"]:
            return f"sha drift: {lines[-1]} != {plan['plan_sha16']}"
    return "OK"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default="lab/jalon411/v461a_target_map.json")
    ap.add_argument("--plan-out", default="lab/jalon411/v461a_plan.json")
    ap.add_argument("--emit-c", default="",
                    help="write the gsp_dmem_write_plan.h emission here")
    ap.add_argument("--decode-args", default="",
                    help="decode an args.bin (S3) per the committed header")
    ap.add_argument("--surface", action="append", default=[],
                    help="label=id (the writer's surface resolver id)")
    ap.add_argument("regions", nargs="*",
                    help="the dump blobs, path[:label]")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1

    if a.decode_args:
        d = decode_args(Path(a.decode_args).read_bytes())
        print(json.dumps(d, indent=1))
        return 0

    if not a.regions:
        print("no regions — run --selftest or pass the dump blobs",
              file=sys.stderr)
        return 2
    if not selftest():
        print("SELFTEST FAILED — the scan refuses to run", file=sys.stderr)
        return 1

    surface_ids = {}
    for spec in a.surface:
        label, _, sid = spec.partition("=")
        surface_ids[label] = int(sid)
    # the default naming (the 4.51 blob stems -> the SURFACES ids)
    defaults = {"args": 1, "libosinit": 2, "statemonitor": 3,
                "wpr2meta": 4, "sysmemheap": 5}
    for lbl, sid in defaults.items():
        surface_ids.setdefault(lbl, sid)

    scans = {}
    for spec in a.regions:
        path, _, label = spec.partition(":")
        p = Path(path)
        label = label or p.stem
        scans[label] = scan_surface(label, p.read_bytes())
        sc = scans[label]
        obj = sc["object"]
        print(f"[{label}] {sc['size']} B — {sc['verdict']}"
              + (f" obj_base={hex(obj['obj_base'])} hits={obj['hits']} "
                 f"groups={obj['groups']} "
                 f"f18quad={obj['f18_quad_ok']}/4"
                 if obj["obj_base"] is not None else ""))

    plan = build_plan(scans, surface_ids)
    out = {"pass": "4.61", "instrument": "v461a_target_map",
           "source_tag": "610.57.04",
           "object_model": {
               "obj_size": OBJ_SIZE, "base_off": BASE_OFF,
               "group_stride": GROUP_STRIDE, "n_groups": N_GROUPS,
               "group_keys": list(GROUP_KEYS),
               "rec_stride": REC_STRIDE, "f18_off": F18_OFF,
               "formula": FORMULA,
               "events": {"mask": hex(EV_MASK), "fill": hex(EV_FILL)},
               "source_table_off": hex(SOURCE_TABLE_OFF),
               "persistence": {"f18": "PERSISTENT (never rewritten)",
                               "base": "VOLATILE (rewritten each pass)"}},
           "surfaces": {label: {"size": sc["size"],
                                "sha256_16": sc["sha256_16"],
                                "verdict": sc["verdict"],
                                "object": sc["object"],
                                "hits": sc["hits"]}
                        for label, sc in scans.items()},
           "plan": plan,
           "verdict": (
               "HIT — the µW bases are host-reachable; the plan = the "
               "write day (runbook-461 §2+)"
               if plan["entries"] else
               "MISS — the bases are NOT in any supplied surface (the "
               "banked model: the FB/WPR2 heap, route-W / the DMEM seal "
               "question) — the honest close, the plan = the GATED NULL"),
           }
    Path(a.out).write_text(json.dumps(out, indent=1))
    Path(a.plan_out).write_text(json.dumps(plan, indent=1))
    if a.emit_c and plan["entries"]:
        Path(a.emit_c).write_text(emit_c_header(plan))
        print(f"C header: {a.emit_c}")
    n = len(plan["entries"])
    print(f"verdict: {out['verdict']}")
    print(f"plan: {n} entrée(s), plan_sha16={plan['plan_sha16']}"
          + (" — the GATED NULL (nothing writes)" if n == 0 else ""))
    print(f"written {a.out} + {a.plan_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
