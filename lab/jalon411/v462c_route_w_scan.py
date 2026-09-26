#!/usr/bin/env python3
"""v462c_route_w_scan.py — PASS 4.62 T3 — THE SCAN of the route-W data:
the marker hunt over the FB-heap reads (the v451a floor discipline +
the v461a object scan + the v454a marker family — ALL IMPORTED, zero
re-transcription; the pattern set stays the single source).

THE INPUT: the route-W dumps — the v462a B1 windows (the BAR1/ReBAR
reads) and/or the MD blobs (the debugfs window<sel>.bin from the
gsp_wpr2_read boot). ANY degenerate surface (SEAL-ZERO / SEAL-FF /
SEAL-CONSTANT / DEGENERATE per the v462a integer classifier) = THE
SEAL ANSWERED — the scan refuses it with the named negative (the
mission law: the plausibility guards name the negative; the scan
never parses the seal's constant as data).

THE SCAN (per surface — the v461a machinery, imported):
  1. the base-form u32le EXACT hits: 0x0EE6B280 (250 W stock),
     0x0E4E1C00 (240 W sibling), 0x10B07600 (280 W target) —
     the v454a family, the POWER-BASE-MATCH rows (the v454c
     EXACT-FIRST precedence: every exact hit = a row, the plausible-
     range fuzzy forms stay LEADS and are never emitted here);
  2. the u64-pair law {base, 0} (the 4.44 payload shape, as found);
  3. THE OBJECT FINGERPRINT: the 0x10-stride co-location quad +
     the f18 quad ({100, 112, 0xffffffff} at obj+0x18+k*0x30);
  4. the object-base inference with the consistency gate (a lone hit
     = a LEAD, never plan-eligible — the k ambiguity).

THE OUTPUT (the target map — the mission's deliverable):
  {surface, adresse (the surface-relative offset), offset objet
  (obj+0x618+k*0x10), rôle (base[k], the group key), valeur actuelle
  (the shape as found)} — plus the verdict:
    OBJECT-FOUND  the bases ARE in the FB heap — the targeting = DONE
                  (the write-lane input NAMED; this pass WRITES
                  NOTHING — naming ≠ writing, the v454c law)
    LEAD/CANDIDATE  the bigger window or the fresh dump decides
    MISS          the honest close (the falcon-internal negative or
                  the window math — the re-decode day)

ZÉRO BOOT BY CONSTRUCTION: this instrument reads FILES and emits
TABLES. The selftest = mandatory (the scan refuses without it) — the
v451a rehearsal pattern: the synthetic heap with the planted quad
hits every family, the control stays MISS, the degenerate input
refuses.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import v451a_dmem_scan as v451a          # noqa: E402 — the floor law
import v461a_target_map as v461a         # noqa: E402 — the object scan
import v462a_wpr2_read as v462a          # noqa: E402 — the classifier

# the shapes re-asserted (the import chain: v461a imported them from
# v454a — the assert here re-arms the family, zero re-transcription)
assert v461a.SHAPE_250 == 0x0EE6B280
assert v461a.SHAPE_240 == 0x0E4E1C00
assert v461a.SHAPE_280 == 0x10B07600

# the MD blob stems (the debugfs layout the patch_nv_462 publisher
# creates: /sys/kernel/debug/gsp_wpr2_read/win/window<sel>.bin)
MD_STEMS = {"window1", "window2", "window3", "window4"}


def scan_surface_route_w(label: str, data: bytes):
    """The route-W surface scan: the seal gate FIRST (the named
    negative), then the v461a scan (imported — the hits, the object
    inference, the floor), then the POWER-BASE-MATCH rows."""
    cls, prim = v462a.classify_bytes(data)
    seal = cls in (v462a.C_SEAL_ZERO, v462a.C_SEAL_FF,
                   v462a.C_SEAL_CONSTANT, v462a.C_DEGENERATE)
    if seal:
        return {"surface": label, "size": len(data),
                "sha256_16": hashlib.sha256(data).hexdigest()[:16],
                "class": v462a.C_NAMES[cls],
                "verdict": "SEAL-NEGATIVE (" + v462a.C_NAMES[cls] + ")",
                "note": "the seal answered — the scan refuses this "
                        "surface (the named negative, never parsed "
                        "as data)",
                "hits": [], "object": {"verdict": "NO-OBJECT"},
                "rows": []}
    sc = v461a.scan_surface(label, data)
    # the POWER-BASE-MATCH rows (the v454c precedence: the exact
    # markers FIRST — v461a's hits = the exact family by construction)
    rows = []
    for h in sc["hits"]:
        rows.append({
            "off": h["off"], "hex_off": h["hex_off"],
            "shape": h["shape"], "val": h["val"],
            "u64pair": h["u64pair"],
            "stride_class": h["stride_class"],
            "verdict": "POWER-BASE-MATCH",
            "note": f"the exact marker {h['shape']}"
                    + (" — ALREADY-280: the no-op refusal, never a "
                       "write target" if h["val"] == v461a.SHAPE_280
                       else ""),
        })
    sc["class"] = v462a.C_NAMES[cls]
    sc["rows"] = rows
    sc["primitives"] = {"first_u64": hex(prim["first_u64"]),
                        "distinct": prim["distinct"]}
    return sc


def build_target_map(scans: dict):
    """The target map from the OBJECT-FOUND / OBJECT-CANDIDATE
    surfaces (the v461a build_plan input law — but this pass emits
    the MAP, never a write plan: naming ≠ writing)."""
    entries = []
    leads = []
    for label, sc in scans.items():
        obj = sc.get("object", {})
        if obj.get("verdict") not in ("OBJECT-FOUND", "OBJECT-CANDIDATE"):
            for r in sc.get("rows", []):
                leads.append({"surface": label, **r})
            continue
        for h in sc["hits"]:
            k = (h["off"] - obj["obj_base"] - v461a.BASE_OFF) \
                // v461a.GROUP_STRIDE
            if h["off"] != obj["obj_base"] + v461a.BASE_OFF \
                    + k * v461a.GROUP_STRIDE:
                continue   # a sibling echo outside the quad
            entries.append({
                "surface": label,
                "addr": h["off"], "addr_hex": h["hex_off"],
                "obj_offset": f"obj+{hex(v461a.BASE_OFF + k * v461a.GROUP_STRIDE)}",
                "role": f"base[{k}] (group key {v461a.GROUP_KEYS[k]})",
                "value_found": h["shape"],
                "u64pair": h["u64pair"],
                "note": ("ALREADY-280 — the no-op refusal"
                         if h["val"] == v461a.SHAPE_280 else
                         "the write-lane input (the next pass NAMED; "
                         "this pass writes nothing)"),
            })
    return {"targets": entries, "leads": leads}


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

    rng = random.Random(0x4624)

    # ---- 1. the rehearsal: the FULL object planted (the v451a
    #         rehearsal pattern — the quad + the f18 quad) ----
    OB = 0x20000
    buf = bytearray(rng.randbytes(1 << 18))
    for k in range(v461a.N_GROUPS):
        off = OB + v461a.BASE_OFF + k * v461a.GROUP_STRIDE
        val = v461a.SHAPE_250 if k != 2 else v461a.SHAPE_240
        buf[off:off + 4] = struct.pack("<I", val)
        buf[off + 4:off + 8] = b"\x00" * 4
        ro = OB + v461a.REC_STRIDE * k + v461a.F18_OFF
        buf[ro:ro + 4] = struct.pack("<I", v461a.F18_STOCK)
    data = bytes(buf)
    sc = scan_surface_route_w("rehearsal-full", data)
    check("rehearsal: the object inferred",
          sc["object"]["obj_base"] == OB, hex(sc["object"]["obj_base"]))
    check("rehearsal: OBJECT-FOUND",
          sc["object"]["verdict"] == "OBJECT-FOUND",
          sc["object"]["verdict"])
    check("rehearsal: 4 POWER-BASE-MATCH rows",
          len(sc["rows"]) == 4 and
          all(r["verdict"] == "POWER-BASE-MATCH" for r in sc["rows"]))
    tm = build_target_map({"rehearsal-full": sc})
    check("rehearsal: 4 targets, 0 leads",
          len(tm["targets"]) == 4 and len(tm["leads"]) == 0)
    check("rehearsal: the roles named with the group keys",
          [t["role"].startswith(f"base[{k}]")
           for k, t in zip(range(4), tm["targets"])].count(True) == 4)

    # ---- 2. the LONE hit = LEAD (the consistency gate) ----
    buf = bytearray(rng.randbytes(1 << 18))
    off = 0x30000 + v461a.BASE_OFF
    buf[off:off + 4] = struct.pack("<I", v461a.SHAPE_250)
    sc1 = scan_surface_route_w("rehearsal-lone", bytes(buf))
    check("lone: the verdict LEAD",
          sc1["object"]["verdict"] == "LEAD", sc1["object"]["verdict"])
    tm1 = build_target_map({"rehearsal-lone": sc1})
    check("lone: 0 targets, 1 lead", len(tm1["targets"]) == 0 and
          len(tm1["leads"]) == 1)

    # ---- 3. the control: random = MISS ----
    scc = scan_surface_route_w("rehearsal-control",
                               bytes(rng.randbytes(1 << 18)))
    check("control: MISS", scc["verdict"] == "MISS", scc["verdict"])

    # ---- 4. the ALREADY-280 = the no-op naming ----
    buf = bytearray(rng.randbytes(1 << 18))
    for k in range(v461a.N_GROUPS):
        off = 0x18000 + v461a.BASE_OFF + k * v461a.GROUP_STRIDE
        buf[off:off + 4] = struct.pack("<I", v461a.SHAPE_280)
        buf[off + 4:off + 8] = b"\x00" * 4
        ro = 0x18000 + v461a.REC_STRIDE * k + v461a.F18_OFF
        buf[ro:ro + 4] = struct.pack("<I", v461a.F18_STOCK)
    sc2 = scan_surface_route_w("rehearsal-280", bytes(buf))
    tm2 = build_target_map({"rehearsal-280": sc2})
    check("already: the object found",
          sc2["object"]["verdict"] == "OBJECT-FOUND")
    check("already: every target = the no-op note",
          len(tm2["targets"]) == 4 and
          all("ALREADY-280" in t["note"] for t in tm2["targets"]))

    # ---- 5. THE SEAL GATE: the degenerate inputs refuse ----
    for blob, name in ((b"\x00" * 4096, "SEAL-ZERO"),
                       (b"\xFF" * 4096, "SEAL-FF"),
                       (b"\x5A" * 4096, "SEAL-CONSTANT"),
                       (bytes([1, 2, 3, 4]) * 1024, "DEGENERATE")):
        scx = scan_surface_route_w(f"seal-{name}", blob)
        check(f"seal: {name} = the negative, nothing scanned",
              scx["verdict"].startswith("SEAL-NEGATIVE") and
              scx["rows"] == [], scx["verdict"])
    # a marker INSIDE a degenerate surface = still the negative
    trap = b"\x00" * 4080 + struct.pack("<I", v461a.SHAPE_250) + b"\x00" * 12
    sct = scan_surface_route_w("seal-trap", trap)
    check("seal: the marker inside the seal = the negative",
          sct["verdict"].startswith("SEAL-NEGATIVE"),
          sct["verdict"])

    # ---- 6. the floor discipline imported (the v451a law) ----
    fl = v451a.floor_for(4, 1 << 18)
    check("floor: the u32 floor over 256 KiB << 1",
          fl < 1, f"{fl:.9f}")

    # ---- 7. the free-list positive path (the HEAP-FREELIST first
    #         u64 = live content, scannable) ----
    buf = bytearray(rng.randbytes(4096))
    buf[0:8] = struct.pack("<Q", v462a.HEAP_FREELIST_MAGIC)
    scf = scan_surface_route_w("freelist-head", bytes(buf))
    check("freelist: the live surface scans (not the negative)",
          not scf["verdict"].startswith("SEAL-NEGATIVE"),
          scf["verdict"])
    check("freelist: the class = HEAP-FREELIST",
          scf["class"] == "HEAP-FREELIST", scf["class"])

    print(f"selftest v462c: {ok}/{tot} "
          f"{'PASS' if ok == tot else 'FAIL'}")
    return ok == tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default="lab/jalon411/v462c_route_w_scan.json")
    ap.add_argument("regions", nargs="*",
                    help="the route-W dumps, path[:label] (the B1 "
                         "windows and/or the MD window<sel>.bin blobs)")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1
    if not a.regions:
        print("no regions — run --selftest or pass the route-W dumps",
              file=sys.stderr)
        return 2
    if not selftest():
        print("SELFTEST FAILED — the scan refuses to run", file=sys.stderr)
        return 1

    scans = {}
    for spec in a.regions:
        path, _, label = spec.partition(":")
        p = Path(path)
        label = label or p.stem
        scans[label] = scan_surface_route_w(label, p.read_bytes())
        sc = scans[label]
        obj = sc["object"]
        print(f"[{label}] {sc['size']} B class={sc['class']} — "
              f"{sc['verdict']}"
              + (f" obj_base={hex(obj['obj_base'])} hits={obj['hits']} "
                 f"groups={obj['groups']} f18quad={obj['f18_quad_ok']}/4"
                 if obj.get("obj_base") is not None else ""))

    tm = build_target_map(scans)
    n_targets = len(tm["targets"])
    n_leads = len(tm["leads"])
    found = [s for s, sc in scans.items()
             if sc["object"].get("verdict") in
             ("OBJECT-FOUND", "OBJECT-CANDIDATE")]
    verdict = (
        ("HIT — the µW bases ARE in the FB heap: "
         + ", ".join(found)
         + " (the write-lane input NAMED; the write = the NEXT pass, "
           "ONE field per boot, the marker pre-verify = the 4.61 law)")
        if n_targets else
        ("LEAD — the marker echoes without the object consistency "
         "(the bigger window or the fresh dump decides)")
        if n_leads else
        ("MISS — no marker in any scanned surface (the honest close: "
         "the falcon-internal negative, or the window math — the "
         "re-decode day decides)"))
    out = {"pass": "4.62", "instrument": "v462c_route_w_scan",
           "source_tag": "610.57.04",
           "marker_family": {"250W": hex(v461a.SHAPE_250),
                             "240W": hex(v461a.SHAPE_240),
                             "280W": hex(v461a.SHAPE_280)},
           "surfaces": {label: {
               "size": sc["size"],
               "sha256_16": sc["sha256_16"],
               "class": sc["class"],
               "verdict": sc["verdict"],
               "object": sc["object"],
               "rows": sc.get("rows", []),
               "hits": sc.get("hits", []),
           } for label, sc in scans.items()},
           "target_map": tm,
           "verdict": verdict}
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(f"verdict: {verdict}")
    print(f"targets={n_targets} leads={n_leads} — written {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
