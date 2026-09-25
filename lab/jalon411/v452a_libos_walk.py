#!/usr/bin/env python3
"""v452a_libos_walk.py — PASS 4.52 T1 — the Libos region-inventory walker.

Decodes the S4 dump (libosinit.bin = pKernelGsp->pLibosInitArgumentsCached)
into the map of the memory regions GSP-RM booted with — the sysmem-heap
segments NAMED (the id8 tag IS the name), with offsets (pa) and sizes.
The output feeds v452b (the heap walker): the heap region = the SYSMEM
CONTIGUOUS region whose size matches the S5 dump size.

GROUNDING (the EXACT tree, open-gpu-kernel-modules @ 610.57.04, e4a5faa):
  - src/common/uproc/os/common/include/libos_init_args.h (the grammar):
      typedef struct {
          LibosAddress id8;   // NvU64 — Id tag (ASCII big-endian, 8 chars)
          LibosAddress pa;    // NvU64 — Physical address
          LibosAddress size;  // NvU64 — Size of memory area
          NvU8 kind;          // LibosMemoryRegionKind
          NvU8 loc;           // LibosMemoryRegionLoc
      } LibosMemoryRegionInitArgument;          // = 32 B (6 B pad)
      LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX = 4096  // BYTES (= 128 slots)
      kind: NONE=0 CONTIGUOUS=1 RADIX3=2
      loc : NONE=0 SYSMEM=1 FB=2
  - src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c 6201-6233
    (kgspSetupLibosInitArgs_IMPL): the host writes the log entries
    (kind=CONTIGUOUS, loc=SYSMEM, pa = pTaskLogBuffer[1] — the GPA the
    driver stored INSIDE the log buffer, size = memdescGetSize) then
    "RMARGS" (pa = memdescGetPhysAddr(pGspArgumentsDescriptor)).
  - src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c 3219-3233
    (_kgspGenerateInitArgId): id8 = up to 8 ASCII chars packed
    big-endian, NUL-stopped → the INVERSE decode: struct.pack('>Q', id8)
    left-stripped of NULs. "RMARGS" -> 0x00524D41524753.
  - src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_tu102.c
    152-175: the S4 storage = LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX
    bytes, contiguous UNCACHED SYSMEM, zeroed at setup.

THE HONESTY RULES (unchanged):
  - a zeroed slot (id8=0, kind=0, loc=0) = EMPTY, not an error (the
    table is zero-filled to 4096);
  - a slot with a name but kind/loc out of the enum = FLAGGED, decoded
    anyway, never guessed into a valid value;
  - the heap pick with no exact S5-size match = UNRESOLVED (never the
    "largest region" guess);
  - GATED by default: no S4 dump -> the selftest only, targets null
    (the v451b pattern).

THE SELFTEST (mandatory, the v451a lesson: every path executed before
the founder runs it): synthesizes a 4096-byte S4 per the EXACT header
layout and walks every branch — the 9-entry table + zero tail, the
full 128-slot table, an invalid-kind record, an 8-char non-NUL id, the
empty id, the heap pick (match + miss), the S5-size cross-check. When
the .ogkm-610-cache tree is present the selftest ALSO re-reads the
header live and asserts the grammar constants against it (the tree
guard — the exact members, not plausible names); absent tree = the
guard reports SKIPPED and the byte logic still validates.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TREE = ROOT / ".ogkm-610-cache"
HEADER = TREE / "src/common/uproc/os/common/include/libos_init_args.h"

# ---- the grammar (the header constants, re-asserted by the selftest) ----
RECORD_FMT = "<QQQBB6x"           # id8, pa, size, kind, loc, pad — 32 B
RECORD_SIZE = struct.calcsize(RECORD_FMT)
TABLE_BYTES = 4096                # LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX
SLOTS = TABLE_BYTES // RECORD_SIZE

KIND = {0: "NONE", 1: "CONTIGUOUS", 2: "RADIX3"}
LOC = {0: "NONE", 1: "SYSMEM", 2: "FB"}


def decode_id8(id8: int) -> str:
    """The _kgspGenerateInitArgId inverse (kernel_gsp.c:3219): the u64
    read as big-endian ASCII, NUL-stopped. 0 = the empty tag."""
    if id8 == 0:
        return ""
    return struct.pack(">Q", id8).lstrip(b"\x00").decode("ascii", "replace")


def encode_id8(name: str) -> int:
    """The generator itself (for the selftest synthesis)."""
    ident = 0
    for ch in name.encode("ascii")[:8]:
        ident = (ident << 8) | ch
    return ident


def parse_record(buf: bytes, off: int) -> dict:
    id8, pa, size, kind, loc = struct.unpack_from(RECORD_FMT, buf, off)
    return {
        "slot": off // RECORD_SIZE,
        "id8": id8,
        "id8_hex": f"0x{id8:016x}",
        "name": decode_id8(id8),
        "pa": pa,
        "pa_hex": f"0x{pa:x}",
        "size": size,
        "size_hex": f"0x{size:x}",
        "kind_raw": kind,
        "loc_raw": loc,
        "kind": KIND.get(kind, f"INVALID({kind})"),
        "loc": LOC.get(loc, f"INVALID({loc})"),
        "state": ("EMPTY" if (id8 == 0 and pa == 0 and size == 0
                              and kind == 0 and loc == 0)
                  else "VALID" if kind in KIND and loc in LOC and size > 0
                  else "FLAGGED"),
    }


def walk_s4(data: bytes, s5_size: int = None) -> dict:
    """The full walk: every 32-B slot, the flags, the heap pick."""
    if len(data) < TABLE_BYTES:
        return {"error": f"S4 too small: {len(data)} B < {TABLE_BYTES} B "
                         "(the descriptor is LIBOS_MEMORY_REGION_INIT_"
                         "ARGUMENTS_MAX bytes — a truncated dump is not "
                         "parsed, never guessed)"}
    data = data[:TABLE_BYTES]
    recs = [parse_record(data, i * RECORD_SIZE) for i in range(SLOTS)]
    active = [r for r in recs if r["state"] != "EMPTY"]
    flagged = [r for r in active if r["state"] == "FLAGGED"]
    sysmem = [r for r in active if r["loc_raw"] == 1]

    out = {
        "table_bytes": len(data),
        "slots": SLOTS,
        "active": len(active),
        "zero_tail_from_slot": (min(r["slot"] for r in recs
                                    if r["state"] == "EMPTY")
                                if len(active) < SLOTS else None),
        "records": active,
        "flagged": flagged,
        "sysmem_regions": sysmem,
        "fb_regions": [r for r in active if r["loc_raw"] == 2],
    }

    # ---- the heap pick (the v452b input): the SYSMEM CONTIGUOUS region
    # whose size == the S5 dump size. No match = UNRESOLVED, never the
    # largest-region guess.
    if s5_size:
        cands = [r for r in sysmem if r["size"] == s5_size
                 and r["kind_raw"] == 1]
        out["heap_ref"] = (
            {"verdict": "RESOLVED", "s5_size": s5_size,
             "matches": cands}
            if len(cands) == 1
            else {"verdict": "AMBIGUOUS", "s5_size": s5_size,
                  "matches": cands} if len(cands) > 1
            else {"verdict": "UNRESOLVED", "s5_size": s5_size,
                  "note": "no SYSMEM CONTIGUOUS region matches the S5 "
                          "dump size — the heap may be RADIX3-kind or "
                          "the dump truncated; v452b runs offset-relative"})
    else:
        out["heap_ref"] = {"verdict": "NO-S5-SIZE-GIVEN",
                           "note": "pass --s5 sysmemheap.bin to resolve "
                                   "the heap region"}
    return out


# -----------------------------------------------------------------------
# the selftest — every branch executed (the v451a lesson)
# -----------------------------------------------------------------------

def _synth_table(entries, slots=SLOTS):
    buf = bytearray(TABLE_BYTES)
    for i, (name, pa, size, kind, loc) in enumerate(entries[:slots]):
        struct.pack_into(RECORD_FMT, buf, i * RECORD_SIZE,
                         encode_id8(name), pa, size, kind, loc)
    return bytes(buf)


def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    # -- 0. the tree guard: the grammar re-read from the EXACT header ----
    guard = "SKIPPED (no .ogkm-610-cache — the byte logic still validates)"
    if HEADER.is_file():
        txt = HEADER.read_text(errors="replace")
        checks = [("LibosMemoryRegionInitArgument" in txt, "struct name"),
                  ("LibosAddress          id8" in txt, "member id8"),
                  ("LibosAddress          pa" in txt, "member pa"),
                  ("LibosAddress          size" in txt, "member size"),
                  ("NvU8                  kind" in txt, "member kind"),
                  ("NvU8                  loc" in txt, "member loc"),
                  ("#define LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX 4096"
                   in txt, "MAX = 4096 BYTES"),
                  ("LIBOS_MEMORY_REGION_CONTIGUOUS" in txt, "kind enum"),
                  ("LIBOS_MEMORY_REGION_LOC_SYSMEM" in txt, "loc enum")]
        guard_ok = all(c for c, _ in checks)
        for c, what in checks:
            check(f"tree-guard: {what}", c)
        guard = "PASS" if guard_ok else "FAIL"
    print(f"[{'INFO' if guard != 'FAIL' else 'FAIL'}] tree-guard: {guard}")

    # -- 1. the id8 codec round-trip (the exact generator semantics) -----
    check("id8: 'RMARGS' -> 0x524d41524753",
          encode_id8("RMARGS") == 0x524D41524753)
    check("id8: decode(0x524D41524753) == 'RMARGS'",
          decode_id8(0x524D41524753) == "RMARGS")
    eight = "LOGINIT0"
    check("id8: 8-char name round-trips", decode_id8(encode_id8(eight)) == eight)
    check("id8: 0 -> '' (the EMPTY tag)", decode_id8(0) == "")
    check("id8: >8 chars truncated by the generator",
          encode_id8("TOOLONGNAME") == encode_id8("TOOLONGNA"))

    # -- 2. the record codec: sizes and field order ----------------------
    check("record size == 32 B (3x u64 + 2x u8 + 6 pad)",
          RECORD_SIZE == 32)
    buf = _synth_table([("RMARGS", 0x1234, 0x1000, 1, 1)])
    id8, pa, size, kind, loc = struct.unpack_from(RECORD_FMT, buf, 0)
    check("record: LE layout {id8,pa,size,kind,loc}",
          id8 == 0x524D41524753 and pa == 0x1234 and size == 0x1000
          and kind == 1 and loc == 1)

    # -- 3. the 9-entry table + zero tail (the REAL-shape case) ----------
    entries = [("LOGINIT", 0x100000000, 1 << 20, 1, 1)]
    entries += [(f"LOG{i}", 0x100000000 + (i + 1) * (1 << 20), 1 << 20, 1, 1)
                for i in range(1, 8)]
    entries += [("RMARGS", 0x108000000, 0x1000, 1, 1)]
    t9 = _synth_table(entries)
    w = walk_s4(t9, s5_size=None)
    check("9-entry table: active=9", w["active"] == 9)
    check("9-entry table: zero tail from slot 9",
          w["zero_tail_from_slot"] == 9)
    check("9-entry table: all SYSMEM", len(w["sysmem_regions"]) == 9)
    check("9-entry table: RMARGS named",
          w["records"][-1]["name"] == "RMARGS")

    # -- 4. the heap pick: exact S5-size match ---------------------------
    heap_size = 64 << 20
    t_heap = _synth_table(entries + [("SYSMEMHP", 0x200000000,
                                      heap_size, 1, 1)])
    w2 = walk_s4(t_heap, s5_size=heap_size)
    check("heap pick: RESOLVED on the size match",
          w2["heap_ref"]["verdict"] == "RESOLVED"
          and w2["heap_ref"]["matches"][0]["name"] == "SYSMEMHP")

    # -- 5. the heap pick: no match = UNRESOLVED (never a guess) ---------
    w3 = walk_s4(t_heap, s5_size=heap_size + 1)
    check("heap pick: UNRESOLVED on a size miss",
          w3["heap_ref"]["verdict"] == "UNRESOLVED")

    # -- 6. the heap pick: two matches = AMBIGUOUS -----------------------
    t_amb = _synth_table(entries + [("SYSMEMA", 0x200000000, heap_size, 1, 1),
                                    ("SYSMEMB", 0x300000000, heap_size, 1, 1)])
    check("heap pick: AMBIGUOUS on two matches",
          walk_s4(t_amb, s5_size=heap_size)["heap_ref"]["verdict"]
          == "AMBIGUOUS")

    # -- 7. the full 128-slot table (no zero tail — never crash) ---------
    t_full = _synth_table([(f"R{i:05d}", 0x1000 * (i + 1), 0x1000, 1, 1)
                           for i in range(SLOTS)])
    w4 = walk_s4(t_full)
    check("128-slot table: active=128, tail=None",
          w4["active"] == 128 and w4["zero_tail_from_slot"] is None)

    # -- 8. the FLAGGED record (kind/loc out of enum — decoded anyway) ---
    t_flag = _synth_table([("WEIRD", 0x4000, 0x1000, 7, 9)])
    w5 = walk_s4(t_flag)
    check("invalid kind/loc: FLAGGED, not crash, not guessed",
          w5["flagged"] and w5["flagged"][0]["kind"] == "INVALID(7)"
          and w5["flagged"][0]["loc"] == "INVALID(9)")

    # -- 9. a truncated dump refuses (never guessed) ---------------------
    check("truncated S4: error, not parsed",
          "error" in walk_s4(t9[:TABLE_BYTES - 1]))

    # -- 10. the name with an interior high NUL (id8 < 8 chars used) -----
    check("id8: 'L0' short name decodes",
          decode_id8(encode_id8("L0")) == "L0")

    print(f"selftest v452a: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--s4", default=None, help="the S4 dump (libosinit.bin)")
    ap.add_argument("--s5", default=None,
                    help="the S5 dump (sysmemheap.bin) — its size resolves "
                         "the heap region")
    ap.add_argument("--out", default="lab/jalon411/v452a_libos_walk.json")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1

    if not a.s4:
        print("GATED — no S4 dump given. The instrument runs its selftest "
              "only; the region map assembles on the 451-day dump "
              "(the v451b pattern: targets stay null until the bytes "
              "decide).", file=sys.stderr)
        return 2
    if not selftest():
        print("SELFTEST FAILED — the walk refuses to run", file=sys.stderr)
        return 1

    s4 = Path(a.s4)
    data = s4.read_bytes()
    s5_size = Path(a.s5).stat().st_size if a.s5 else None
    out = {
        "pass": "4.52", "instrument": "v452a_libos_walk",
        "grammar": "libos_init_args.h @610.57.04 (LibosMemoryRegion"
                   "InitArgument, 32 B records, 4096 B table)",
        "s4": {"path": str(s4), "size": len(data),
               "sha256_16": hashlib.sha256(data).hexdigest()[:16]},
        "s5_size": s5_size,
        "walk": walk_s4(data, s5_size),
    }
    Path(a.out).write_text(json.dumps(out, indent=1))
    walk = out["walk"]
    if "error" in walk:
        print(f"walk error: {walk['error']}")
        return 1
    print(f"[S4] active={walk['active']}/{walk['slots']} slots, "
          f"flagged={len(walk['flagged'])}, "
          f"sysmem={len(walk['sysmem_regions'])}, "
          f"fb={len(walk['fb_regions'])}")
    for r in walk["records"][:16]:
        print(f"  slot {r['slot']:3d}  {r['name']:<8s} pa={r['pa_hex']:<14s} "
              f"size={r['size_hex']:<12s} {r['kind']:<10s} {r['loc']}")
    hr = walk["heap_ref"]
    print(f"heap_ref: {hr['verdict']}"
          + (f" -> {hr['matches'][0]['name']}"
             if hr.get("matches") else ""))
    print(f"written {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
