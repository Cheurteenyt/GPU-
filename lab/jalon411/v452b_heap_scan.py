#!/usr/bin/env python3
"""v452b_heap_scan.py — PASS 4.52 T2 — the sysmem-heap walker.

Input = the S5 dump (sysmemheap.bin, the Libos sysmem heap — RPC queues,
console, host-shared state) + the static references S1 (image.bin) and
S2 (ucodes.bin). Applies the v451a pattern set — IMPORTED, never re-
transcribed (the banked raw76 records, the 4.48 fingerprint vectors,
the (rc,rfc) pairs, the colo walk, the floor discipline) — and crosses
every heap hit against the statics.

THE CROSSING (the 4.52 brief, verbatim rule):
  HEAP-ONLY    the bytes exist in S5 and NOWHERE in S1/S2 -> the
               cleanest route-H candidate (the runtime state is not an
               echo of the image);
  HEAP+STATIC  the same bytes also appear in S1/S2 -> still a route-H
               candidate, but the static echo is named (the parse-input
               content also lives in the image);
  STATIC-ONLY  a hit in S1 ALONE = NOT the route H (the v451b route
               table: the image = the surface the booter VERIFIES —
               REFUSED-BY-CARD). Reported, never planned.

THE PLAN-READY MAP (what v452c may retarget, per hit kind — the byte
positions PROVEN, nothing else):
  verbatim (a raw 76-B record)  rc @+0, rfc @+1 (the pair is byte-true
                                in the VBIOS record — banked 4.51);
                                ras/faw/rrd = NO banked in-record
                                positions (the packed grammar = the
                                ring-33/34 target) -> INDECIDABLE;
  vec (a fingerprint vector)    fields at +i*lane in the VECTOR order;
                                the LAUNCH vector order = (rc, rfc, ras,
                                rp, cl) -> rc/rfc/ras plan-ready, faw/
                                rrd have NO launch-vector position
                                (INDECIDABLE), rp/cl = NOT in the
                                retight table (no vendor proof — never
                                touched);
  pair                          rc+rfc only;
  colo                          evidence, no positions (never plan).

THE LANDMINE (banked 4.51): a hit attributing to record id 19 (the
ALL-ZERO record) is flagged landmine=True and the plan REFUSES it.
The guard = is_landmine(record_id, old_bytes) — testable directly,
because the raw76 pattern set (id6/id26) can never surface id19 by
itself: the LAST-LINE defense is the pre-verify (the runtime bytes
must equal the plan's old bytes — an all-zero active record aborts
before any write).

PLAN ELIGIBILITY (the floor discipline carried to the plan): a
candidate is plan_eligible ONLY when verdict == HIT (SUSPECT = human
review, never a write), not landmine, and at least one proven field
position. A 2-byte pair alone can NEVER drive a write on a realistic
heap (the HIT bar exceeds the possible hit count) — the pairs
corroborate a nearby verbatim/vec hit, they do not plan.

GATED by default: no S5 -> nothing runs (the v451b pattern: targets
null until the bytes decide).
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import v451a_dmem_scan as v451a  # noqa: E402 — the banked patterns

LHR = v451a.LHR                    # {rc 70, rfc 175, ras 44, faw 20, rrd 5}
LAUNCH = v451a.LAUNCH              # {rc 78, rfc 210, ras 52, rp 26, cl 24}

# the retight table (v451b) — the ONLY fields with the vendor's own
# headroom proof; everything else = never touched
RETIGHT = {
    "rc":  {"launch": 76, "lhr": 70},
    "rfc": {"launch": 210, "lhr": 175},
    "ras": {"launch": 49, "lhr": 44},
    "faw": {"launch": 28, "lhr": 20},
    "rrd": {"launch": 7,  "lhr": 5},
}
# the proven per-kind plan positions (see the docstring)
VERBATIM_PLAN_FIELDS = ["rc", "rfc"]            # in-record +0/+1
LAUNCH_VEC_ORDER = ["rc", "rfc", "ras", "rp", "cl"]
VEC_PLAN_FIELDS = ["rc", "rfc", "ras"]          # faw/rrd: no launch pos
PAIR_PLAN_FIELDS = ["rc", "rfc"]


def _field_byte(vec, field):
    """The launch-era value of a field, from the banked vectors."""
    return LAUNCH.get(field)


def plan_ready_for(kind: str, lane: int, record_id=None) -> dict:
    """The per-kind plan-ready fields + the byte positions."""
    if kind == "verbatim":
        fields = {f: {"in_record_offset": i, "lane": 1}
                  for i, f in enumerate(VERBATIM_PLAN_FIELDS)}
        note = ("rc/rfc = the record bytes +0/+1 (byte-true, banked); "
                "ras/faw/rrd = no banked in-record position "
                "(INDECIDABLE — the packed grammar)")
        return {"fields": fields, "note": note}
    if kind == "vec":
        stride = {"u8": 1, "u16le": 2, "u32le": 4}.get(lane)
        fields = {}
        for i, f in enumerate(LAUNCH_VEC_ORDER):
            if f in VEC_PLAN_FIELDS:
                fields[f] = {"in_vec_offset": i * stride, "lane": stride}
        note = ("the launch-vector order (rc,rfc,ras,rp,cl); rc/rfc/ras "
                "plan-ready at +i*lane; faw/rrd = no launch-vector "
                "position (INDECIDABLE); rp/cl = not in the retight "
                "table (never touched)")
        return {"fields": fields, "note": note}
    if kind == "pair":
        stride = {"u8": 1, "u16le": 2, "u32le": 4}.get(lane)
        fields = {f: {"in_pair_offset": i * stride, "lane": stride}
                  for i, f in enumerate(PAIR_PLAN_FIELDS)}
        return {"fields": fields,
                "note": "the (rc,rfc) co-location only"}
    return {"fields": {}, "note": "evidence, no proven positions "
                                  "(never plan)"}


def is_landmine(record_id, old_bytes: bytes) -> bool:
    """The banked id-19 landmine: the ALL-ZERO record is never a
    retarget target. record_id 19 OR all-zero bytes -> refuse."""
    if record_id == 19:
        return True
    return old_bytes == b"\x00" * len(old_bytes)


def scan(heap: bytes, statics: dict, pats, recs, colo_records):
    """The crossed scan. statics = {label: bytes} (S1/S2/...)."""
    size = len(heap)
    candidates = []
    static_only = []

    def static_hits(pat):
        return {lbl: v451a.find_all(data, pat, limit=8)
                for lbl, data in statics.items()
                if v451a.find_all(data, pat, limit=1)}

    def classify_route(offs_in_statics):
        if any(offs_in_statics.values()):
            return "HEAP+STATIC"
        return "HEAP-ONLY"

    for name, pat, kind in pats:
        offs = v451a.find_all(heap, pat, limit=64)
        if not offs:
            continue
        verdict, fl = v451a.classify(len(pat), len(offs), size)
        if verdict not in ("HIT", "SUSPECT"):
            continue  # the floor discipline: noise never becomes a plan
        in_statics = static_hits(pat)
        route = classify_route(in_statics)
        record_id = None
        if kind == "verbatim":
            # the record attribution: which of the 65 records is this?
            for rid, rec in enumerate(recs):
                if rec == pat:
                    record_id = rid
                    break
        landmine = (record_id == 19) or (pat == b"\x00" * len(pat))
        lane = None
        if kind == "vec":
            for lane_name in ("u8", "u16le", "u32le"):
                if f"_{lane_name}" in name:
                    lane = lane_name
                    break
        elif kind == "pair":
            for lane_name in ("u8", "u16le", "u32le"):
                if f"_{lane_name}" in name:
                    lane = lane_name
                    break
        pr = plan_ready_for(kind, lane, record_id)
        landmine = is_landmine(record_id, pat)
        candidates.append({
            "pattern": name, "kind": kind, "lane": lane,
            "pattern_len": len(pat), "hits": len(offs),
            "verdict": verdict, "floor": round(fl, 6),
            "record_id": record_id,
            "heap_offsets": [hex(o) for o in offs[:8]],
            "old_bytes_hex": pat.hex(),
            "neighborhoods": {
                hex(o): heap[max(0, o - 32):o + len(pat) + 32].hex()
                for o in offs[:4]},
            "static_crossing": {lbl: [hex(o) for o in v[:4]]
                                for lbl, v in in_statics.items()},
            "route_class": route,
            "landmine": landmine,
            "plan_ready": None if landmine else pr,
            "plan_eligible": (verdict == "HIT" and not landmine
                              and bool(pr["fields"])),
        })
        if len(candidates) >= 64:
            break

    # the static-only section: the statics echo WITHOUT a heap hit —
    # named, routed to the v451b IMG refusal, never planned
    for name, pat, kind in pats:
        if kind != "verbatim":
            continue
        in_statics = {lbl: v451a.find_all(data, pat, limit=4)
                      for lbl, data in statics.items()}
        if any(in_statics.values()):
            if not v451a.find_all(heap, pat, limit=1):
                static_only.append({
                    "pattern": name, "kind": kind,
                    "static_crossing": {lbl: [hex(o) for o in v[:4]]
                                        for lbl, v in in_statics.items()
                                        if v},
                    "route_class": "STATIC-ONLY — NOT the route H "
                                   "(the v451b IMG refusal)",
                })

    # the colo walk (the packing-agnostic detector, the v451a logic)
    colo = []
    for rec_name, vec in colo_records:
        fields = list(vec.values())
        first = fields[0].to_bytes(4, "little")
        for off in v451a.find_all(heap, first, limit=4096):
            lo, hi = max(0, off - 32), min(size, off + 32)
            window = heap[lo:hi]
            sib = sum(1 for v in fields[1:]
                      if v.to_bytes(4, "little") in window)
            if sib >= 2:
                colo.append({"record": rec_name, "offset": hex(off),
                             "siblings_in_window": sib,
                             "window_hex": window.hex()})
                if len(colo) >= 32:
                    break

    return {
        "heap_size": size,
        "candidates": candidates,
        "static_only": static_only,
        "colo_u32_window32": colo,
        "route_h_count": sum(1 for c in candidates
                             if c["route_class"] == "HEAP-ONLY"),
        "route_h_with_static_count": sum(
            1 for c in candidates
            if c["route_class"] == "HEAP+STATIC"),
        "landmine_count": sum(1 for c in candidates if c["landmine"]),
    }


# -----------------------------------------------------------------------
# the selftest — every branch executed (the v451a/4.51 lesson)
# -----------------------------------------------------------------------

def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    import random
    pats, recs = v451a.build_patterns()
    rec6 = recs[6]
    rec26 = recs[26]
    rec19 = recs[19]
    rng = random.Random(0x4522)
    noise = rng.randbytes(1 << 20)

    def embed(base, pat, off):
        b = bytearray(base)
        b[off:off + len(pat)] = pat
        return bytes(b)

    # -- 1. HEAP+STATIC: rec6 in the heap AND in the image ---------------
    heap = embed(noise, rec6, 0x12340)
    image = embed(noise, rec6, 0x2000)
    res = scan(heap, {"image": image}, pats, recs,
               (("launch", LAUNCH), ("lhr", LHR)))
    cands = [c for c in res["candidates"]
             if c["pattern"] == "raw76_id6_launch"]
    check("rec6: the candidate exists", len(cands) == 1)
    c = cands[0]
    check("rec6: record_id=6", c["record_id"] == 6)
    check("rec6: route=HEAP+STATIC", c["route_class"] == "HEAP+STATIC")
    check("rec6: verdict=HIT (76 B, floor~0)", c["verdict"] == "HIT")
    check("rec6: plan_ready rc@+0 rfc@+1",
          c["plan_ready"]["fields"]["rc"]["in_record_offset"] == 0
          and c["plan_ready"]["fields"]["rfc"]["in_record_offset"] == 1)
    check("rec6: ras NOT plan-ready (no banked position)",
          "ras" not in c["plan_ready"]["fields"])
    check("rec6: not the landmine", c["landmine"] is False)

    # -- 2. HEAP-ONLY: the launch vec u32 in the heap, nothing static ----
    vec_u32 = bytes.fromhex(
        "4e000000d2000000340000001a00000018000000")
    heap2 = embed(noise, vec_u32, 0x23450)
    res2 = scan(heap2, {"image": noise, "ucodes": noise}, pats, recs,
                (("launch", LAUNCH), ("lhr", LHR)))
    vc = [c for c in res2["candidates"] if c["kind"] == "vec"]
    check("launch vec u32: found (HEAP-ONLY)",
          vc and all(c["route_class"] == "HEAP-ONLY" for c in vc))
    if vc:
        f = vc[0]["plan_ready"]["fields"]
        check("vec u32: rc@+0 rfc@+4 ras@+8",
              f["rc"]["in_vec_offset"] == 0
              and f["rfc"]["in_vec_offset"] == 4
              and f["ras"]["in_vec_offset"] == 8)
        check("vec u32: faw/rrd NOT plan-ready (no launch position)",
              "faw" not in f and "rrd" not in f)
        check("vec u32: rp/cl never planned",
              "rp" not in f and "cl" not in f)

    # -- 3. STATIC-ONLY: rec26 in the image alone = NOT the route H ------
    image3 = embed(noise, rec26, 0x3000)
    res3 = scan(noise, {"image": image3}, pats, recs,
                (("launch", LAUNCH), ("lhr", LHR)))
    check("rec26 static-only: named, NOT route-H",
          any("NOT the route H" in s["route_class"]
              for s in res3["static_only"]))
    check("rec26 static-only: zero heap candidates",
          res3["route_h_count"] == 0
          and res3["route_h_with_static_count"] == 0)

    # -- 4. the id-19 landmine: the guard function, every branch --------
    check("landmine: record_id 19 -> True",
          is_landmine(19, rec19) and is_landmine(19, rec6))
    check("landmine: all-zero bytes -> True (id-agnostic)",
          is_landmine(None, b"\x00" * 76))
    check("landmine: rec6 verbatim -> False",
          is_landmine(6, rec6) is False)
    heap4 = embed(noise, rec19, 0x34560)
    res4 = scan(heap4, {"image": noise}, pats, recs,
                (("launch", LAUNCH), ("lhr", LHR)))
    check("rec19 embedded: no crash, no candidate (not a pattern), "
          "no plan",
          res4["route_h_count"] == 0
          and res4["route_h_with_static_count"] == 0)

    # -- 5. the pair route: the FLOOR discipline carried to the plan -----
    # a 2-byte pair over 64 KiB: floor = 1; 12 embeds -> SUSPECT (human
    # review), NEVER plan-eligible (only HIT drives a write)
    small = rng.randbytes(1 << 16)
    pair = bytes([LHR["rc"], LHR["rfc"]])
    heap5 = small
    for i in range(12):
        heap5 = embed(heap5, pair, 0x1000 * (i + 1))
    res5 = scan(heap5, {"image": noise}, pats, recs,
                (("launch", LAUNCH), ("lhr", LHR)))
    pc = [c for c in res5["candidates"] if c["kind"] == "pair"
          and "lhr" in c["pattern"]]
    check("pair lhr u8: found as SUSPECT (the floor holds)",
          pc and pc[0]["verdict"] == "SUSPECT")
    check("pair lhr u8: plan_eligible=False (never plans alone)",
          pc and pc[0]["plan_eligible"] is False)
    check("pair lhr u8: the map still names rc+rfc",
          pc and set(pc[0]["plan_ready"]["fields"]) == {"rc", "rfc"})

    # -- 5b. plan_eligible on the strong candidates ----------------------
    check("rec6 candidate: plan_eligible=True",
          c["plan_eligible"] is True)
    check("vec u32 candidate: plan_eligible=True",
          vc[0]["plan_eligible"] is True)

    # -- 6. the floor discipline: pure noise = no candidates -------------
    res6 = scan(noise, {"image": noise}, pats, recs,
                (("launch", LAUNCH), ("lhr", LHR)))
    check("noise: zero route-H candidates (the floor holds)",
          res6["route_h_count"] == 0
          and res6["route_h_with_static_count"] == 0)

    print(f"selftest v452b: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--heap", default=None,
                    help="S5 sysmemheap.bin (the walk surface)")
    ap.add_argument("--static", action="append", default=[],
                    help="the static references, path[:label] "
                         "(S1 image.bin, S2 ucodes.bin)")
    ap.add_argument("--out", default="lab/jalon411/v452b_heap_scan.json")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1

    if not a.heap:
        print("GATED — no S5 heap dump. The walker runs its selftest "
              "only; the candidates assemble on the 451-day dump "
              "(targets null until the bytes decide).", file=sys.stderr)
        return 2
    if not selftest():
        print("SELFTEST FAILED — the scan refuses to run", file=sys.stderr)
        return 1

    pats, recs = v451a.build_patterns()
    hp = Path(a.heap)
    heap = hp.read_bytes()
    statics = {}
    for spec in a.static:
        path, _, label = spec.partition(":")
        p = Path(path)
        statics[label or p.stem] = p.read_bytes()

    out = {
        "pass": "4.52", "instrument": "v452b_heap_scan",
        "patterns": "v451a_dmem_scan.build_patterns (imported, "
                    "never re-transcribed)",
        "heap": {"path": str(hp), "size": len(heap),
                 "sha256_16": hashlib.sha256(heap).hexdigest()[:16]},
        "statics": {lbl: {"size": len(d),
                          "sha256_16": hashlib.sha256(d).hexdigest()[:16]}
                    for lbl, d in statics.items()},
        "scan": scan(heap, statics, pats, recs,
                     (("launch", LAUNCH), ("lhr", LHR))),
    }
    Path(a.out).write_text(json.dumps(out, indent=1))
    sc = out["scan"]
    print(f"[S5] {sc['heap_size']} B — route-H ONLY: "
          f"{sc['route_h_count']}, HEAP+STATIC: "
          f"{sc['route_h_with_static_count']}, "
          f"static-only (NOT route-H): {len(sc['static_only'])}, "
          f"landmines: {sc['landmine_count']}")
    for c in sc["candidates"][:12]:
        print(f"  {c['pattern']:<28s} {c['route_class']:<12s} "
              f"@{c['heap_offsets'][0] if c['heap_offsets'] else '-'} "
              f"plan={sorted(c['plan_ready']['fields'])
                    if c['plan_ready'] else 'REFUSED (landmine)'}"
              f"{'*' if c['plan_eligible'] else ''}")
    eligible = sum(1 for c in sc["candidates"] if c["plan_eligible"])
    verdict = (f"ROUTE-H OPENS — {eligible} plan-eligible candidate(s); "
               "v452c assembles the write plan"
               if eligible > 0
               else "NO plan-eligible candidate in S5 — the v451b table "
                    "holds (the WPR2 v2 probe / the falcon-internal "
                    "negative)")
    out["verdict"] = verdict
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(f"verdict: {verdict}")
    print(f"written {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
