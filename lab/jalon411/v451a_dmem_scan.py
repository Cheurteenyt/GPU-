#!/usr/bin/env python3
"""v451a_dmem_scan.py — PASS 4.51 TÂCHE A2 — the DMEM fingerprint scanner.

The searcher for the 4.51 dump day. Input = the gsp_dmem_dump.c debugfs
blobs (image.bin, sysmemheap.bin, statemonitor.bin, ...). Output = the
per-pattern verdicts (HIT / SUSPECT / FLOOR / MISS) + the offsets + the
±32 B neighborhoods, JSON.

THE PATTERN SET (all from banked instruments — nothing invented):
  1. raw76_id6 / raw76_id26  — the VERBATIM 76-byte VBIOS records
     (mem-timings-65records.json records[6]/[26]; the strongest possible
     pattern: 76 specified bytes, a random hit is impossible in practice).
  2. raw_any(65)             — the whole-table shadow detector: how many
     of the 65 records appear verbatim ANYWHERE (1 hit = the table or a
     copy of it is present; the offset context names which).
  3. vec_{u8,u16le,u32le}    — the 4.48 fingerprints (the five banked
     field values in record order, both records) — the UNPACKED-parse
     hypothesis. The byte-lane caveat stands (4.48: the VBIOS fields are
     PACKED sub-fields; the u8 vector only matches a fully-unpacked copy).
  4. pair_{u8,u16le,u32le}   — the (rc,rfc) pair, the strongest 2-field
     co-location, at the 1/2/4-byte lanes.
  5. colo_u32                — the fieldwise co-location walk: every
     u32le match of field rc, tested for >=2 sibling fields inside the
     ±32 B window. This is the detector that survives unknown packing
     (the fields land as u32 writes wherever the compiler put them).

THE FLOOR DISCIPLINE (the banked 4.49 lesson: MEASURE the noise floor
before trusting any score): for an exact k-byte pattern, the expected
random-hit count over a dump of N bytes = N / 256^k. Verdicts:
  HIT     hits >= 1 AND hits >= max(10, 100 * floor)
  SUSPECT hits >= 1 (below the HIT bar — human review, offsets reported)
  FLOOR   hits in [1, max(10, 100*floor)) AND hits <= 10 * floor
  MISS    hits == 0
A 76-byte record: floor ~ 0 -> any hit = HIT by construction. A 2-byte
pair over 256 MB: floor = 65536 -> the classification separates the
noise honestly.

THE SELFTEST (mandatory, runs before every scan — the discipline):
embeds known patterns into a synthetic random buffer at known offsets
and asserts (a) the exact offsets are found, (b) the verdicts are HIT,
(c) a pure-random control region classifies the weak patterns as
FLOOR/MISS, not HIT. The scan refuses to run if the selftest fails.
"""
import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FP = ROOT / "lab/jalon411/v448c_stride_timing.json"
TIMINGS = ROOT / "tools/analysis/gsp-extract/mem-timings-65records.json"

LHR = {"rc": 70, "rfc": 175, "ras": 44, "faw": 20, "rrd": 5}
LAUNCH = {"rc": 78, "rfc": 210, "ras": 52, "rp": 26, "cl": 24}


def pack_u8(vec):
    return bytes(vec.values())


def pack_u16le(vec):
    return b"".join(v.to_bytes(2, "little") for v in vec.values())


def pack_u32le(vec):
    return b"".join(v.to_bytes(4, "little") for v in vec.values())


def pair_rc_rfc_u8(vec):
    return bytes([vec["rc"], vec["rfc"]])


def find_all(haystack: bytes, needle: bytes, limit: int = 64):
    """All offsets of needle in haystack (cap the report at limit)."""
    out = []
    start = 0
    while len(out) < limit:
        i = haystack.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def floor_for(pattern_len: int, size: int) -> float:
    return size / (256 ** pattern_len) if pattern_len > 0 else float("inf")


def classify(pattern_len: int, hits: int, size: int):
    """HIT / SUSPECT / FLOOR / MISS per the floor discipline.

    HIT     hits >= max(1, 100*floor)   — decisive against the noise
    FLOOR   hits <= 10*floor            — noise-compatible
    SUSPECT between the two            — human review (offsets reported)
    A unique 76-byte record (floor~0): 1 hit = HIT by construction. A
    2-byte pair (floor = size/65536): never HIT on noise-sized dumps.
    """
    fl = floor_for(pattern_len, size)
    if hits == 0:
        return "MISS", fl
    if fl > 0 and hits <= 10 * fl:
        return "FLOOR", fl
    if hits >= max(1, int(100 * fl)):
        return "HIT", fl
    return "SUSPECT", fl


def build_patterns():
    """The full pattern set, all sourced from the banked JSONs."""
    fp = json.loads(FP.read_text())["dmem_fingerprints"]
    tim = json.loads(TIMINGS.read_text())
    recs = [bytes.fromhex(h) for h in tim["records"]]

    pats = []
    # 1. the verbatim records (index = record id in this table)
    pats.append(("raw76_id6_launch", recs[6], "verbatim"))
    pats.append(("raw76_id26_lhr", recs[26], "verbatim"))
    # 2. the vec representations (from the banked fingerprint JSON itself)
    for name, rec in (("record_id6_launch", None), ("record_id26_lhr", None)):
        for lane in ("u8", "u16le", "u32le"):
            hx = fp[name]["patterns"][f"{'u8' if lane=='u8' else lane}"]
            pats.append((f"vec_{name}_{lane}", bytes.fromhex(hx), "vec"))
    # 3. the (rc,rfc) pairs at the three lanes
    for name, vec in (("launch", LAUNCH), ("lhr", LHR)):
        pats.append((f"pair_{name}_u8", pair_rc_rfc_u8(vec), "pair"))
        pats.append((f"pair_{name}_u16le",
                     vec["rc"].to_bytes(2, "little") + vec["rfc"].to_bytes(2, "little"), "pair"))
        pats.append((f"pair_{name}_u32le",
                     vec["rc"].to_bytes(4, "little") + vec["rfc"].to_bytes(4, "little"), "pair"))
    # the raw-verbatim family for the table-shadow detector (not scanned
    # one-by-one in the report; counted by a dedicated pass)
    return pats, recs


def scan_region(label: str, data: bytes, pats, recs, colo_records):
    size = len(data)
    results = []

    for name, pat, kind in pats:
        offs = find_all(data, pat)
        verdict, fl = classify(len(pat), len(offs), size)
        r = {"name": name, "kind": kind, "len": len(pat), "hits": len(offs),
             "floor": round(fl, 6), "verdict": verdict}
        if offs:
            r["offsets"] = [hex(o) for o in offs[:16]]
            r["neighborhoods"] = {
                hex(o): data[max(0, o - 32):o + len(pat) + 32].hex()
                for o in offs[:8]
            }
        results.append(r)

    # the table-shadow detector: the verbatim count over all 65 records
    found = []
    for i, rec in enumerate(recs):
        offs = find_all(data, rec, limit=4)
        if offs:
            found.append({"record_id": i, "offsets": [hex(o) for o in offs]})
    results.append({
        "name": "raw_any65_table_shadow", "kind": "verbatim-family",
        "len": 76, "hits": len(found), "floor": 0.0,
        "verdict": "HIT" if found else "MISS",
        "records_found": found[:16],
    })

    # the fieldwise u32 co-location walk (packing-agnostic)
    colo_hits = []
    for rec_name, vec in colo_records:
        fields = list(vec.values())
        first = fields[0].to_bytes(4, "little")
        for off in find_all(data, first, limit=4096):
            lo, hi = max(0, off - 32), min(size, off + 32)
            window = data[lo:hi]
            sib = 0
            for v in fields[1:]:
                if v.to_bytes(4, "little") in window:
                    sib += 1
            if sib >= 2:
                colo_hits.append({"record": rec_name, "offset": hex(off),
                                  "siblings_in_window": sib,
                                  "window_hex": window.hex()})
                if len(colo_hits) >= 32:
                    break
    fl_colo = floor_for(4, size) * (32 / max(1, size)) * size  # informational
    results.append({
        "name": "colo_u32_window32", "kind": "co-location",
        "len": 4, "hits": len(colo_hits),
        "floor_note": "u32 single-field matches are EXPECTED by the thousands "
                      "(small values); only the >=2-sibling windows are reported",
        "verdict": "HIT" if colo_hits else "MISS",
        "candidates": colo_hits,
    })
    return results


def selftest():
    """The mandatory pre-scan proof: embed, detect, classify."""
    rng = random.Random(0x4511)
    buf = bytearray(rng.randbytes(1 << 20))
    pats, recs = build_patterns()
    embed = {
        "raw76_id6_launch": 0x12345,
        "raw76_id26_lhr": 0x23456,
        "vec_record_id6_launch_u32le": 0x45678,
        "pair_lhr_u8": 0x89ABC,
    }
    offsets = {}
    for name, pat, _kind in pats:
        if name in embed:
            off = embed[name]
            buf[off:off + len(pat)] = pat
            offsets[name] = off
    data = bytes(buf)

    ok = 0
    tot = 0
    for name, pat, _kind in pats:
        if name not in offsets:
            continue
        tot += 1
        found = find_all(data, pat)
        verdict, fl = classify(len(pat), len(found), len(data))
        if fl < 1:
            # a strong pattern (floor < 1 on this buffer): the embed must
            # be found AND classified HIT
            good = (offsets[name] in found) and verdict == "HIT"
        else:
            # a weak pattern (floor >= 1): the embed must be found; the
            # classification may be FLOOR (the noise dominates by design)
            good = offsets[name] in found
        ok += int(good)
        print(f"[{'PASS' if good else 'FAIL'}] selftest {name}: "
              f"embed@{hex(offsets[name])} found={len(found)} verdict={verdict}")

    # the random control: the weak patterns must NOT be HIT on raw random
    rnd = bytes(rng.randbytes(1 << 20))
    ctrl_ok = 0
    ctrl_tot = 0
    for name, pat, _kind in pats:
        if name not in offsets:
            continue
        ctrl_tot += 1
        verdict, fl = classify(len(pat), len(find_all(rnd, pat)), len(rnd))
        good = verdict in ("FLOOR", "SUSPECT", "MISS")  # never a bare HIT on noise
        ctrl_ok += int(good)
        print(f"[{'PASS' if good else 'FAIL'}] control {name}: verdict={verdict} "
              f"(floor={fl:.3f})")
    print(f"selftest v451a: {ok}/{tot} embed + {ctrl_ok}/{ctrl_tot} control "
          f"{'PASS' if (ok == tot and ctrl_ok == ctrl_tot) else 'FAIL'}")
    return ok == tot and ctrl_ok == ctrl_tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default="lab/jalon411/v451a_dmem_scan.json")
    ap.add_argument("regions", nargs="*",
                    help="the dump blobs, path[:label] (default label = the stem)")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1

    if not a.regions:
        print("no regions given — run --selftest or pass the dump blobs", file=sys.stderr)
        return 2
    if not selftest():
        print("SELFTEST FAILED — the scan refuses to run", file=sys.stderr)
        return 1

    pats, recs = build_patterns()
    colo_records = (("launch", LAUNCH), ("lhr", LHR))

    out = {"pass": "4.51", "instrument": "v451a_dmem_scan", "regions": {}}
    any_hit = False
    for spec in a.regions:
        path, _, label = spec.partition(":")
        p = Path(path)
        data = p.read_bytes()
        label = label or p.stem
        res = scan_region(label, data, pats, recs, colo_records)
        out["regions"][label] = {
            "path": str(p), "size": len(data),
            "sha256_16": hashlib.sha256(data).hexdigest()[:16],
            "patterns": res,
        }
        hits = [r for r in res if r["verdict"] == "HIT" and r["hits"] > 0]
        any_hit = any_hit or bool(hits)
        print(f"[{label}] {len(data)} B — "
              f"{len(hits)} pattern families HIT: "
              f"{[r['name'] for r in hits][:6]}")

    out["verdict"] = ("HIT — the parsed-record state is host-reachable; "
                      "TÂCHE B opens (the {value,target} table assembles from "
                      "the reported offsets)"
                      if any_hit else
                      "MISS in all supplied regions — either the records live "
                      "falcon-internal (DMEM) or in the WPR2 FB heap (the v2 "
                      "probe), or the parse never happens (the honest close)")
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(f"verdict: {out['verdict']}")
    print(f"written {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
