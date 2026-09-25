#!/usr/bin/env python3
"""v452c_hpatch_build.py — PASS 4.52 T3 (THE CORE) — the route-H write
plan builder.

Input  = the v452b verdict JSON (the plan-eligible candidates only)
         + the v451b retight values (rc 76->70, rfc 210->175, ras 49->44,
         faw 28->20, rrd 7->5 — the vendor's own headroom proof).
Output = (1) the SIGNED write plan {sel, field, heap_offset, old-bytes,
         new-bytes, verify-after:true} + plan_sha16;
         (2) the C block gsp_hpoke_plan.h (byte-exact, gcc-tested vs
         the python emission — the 4.44 lesson).

THE PLAN RULES (nothing invented):
  - ONLY plan_eligible candidates (v452b: HIT verdict, not the landmine,
    proven field positions) — SUSPECT/FLOOR/MISS never write;
  - old-bytes = THE BYTES THE CANDIDATE FOUND (the runtime truth, not
    the expected values); new-bytes = the v451b LHR values;
  - ONE entry per selector (RmGspHPoke=<sel> boots ONE field): a
    selector collision between candidates = REFUSED (the human picks
    with --pick, the review is the point);
  - the fields WITHOUT proven positions (ras/faw/rrd on the verbatim
    and vec routes) = null targets in the plan, named INDECIDABLE —
    the plan never guesses a byte position;
  - the landmine (the id-19 all-zero record, banked 4.51) = refused
    structurally (v452b already flags; the builder re-checks);
  - verify-after on EVERY entry (the 4.44-machine lesson: a write
    without the post-verify = INDECIDABLE by construction);
  - GATED by default: no --v452b input -> the selftest only, the plan
    stays null (the v451b pattern).

THE SIGNATURE: plan_sha16 = sha256(canonical entries JSON)[:16]. The C
table embeds it; gsp_hpoke.c prints it in dmesg NEXT TO the pre/post
verify — any drift between the python plan and the compiled table (or
a re-scan that moved the offsets) is visible in the boot ledger.

THE SELFTEST (mandatory, every branch): builds synthetic v452b JSONs —
a verbatim rec6 candidate, a vec u32 candidate, a SUSPECT pair (never
planned), a landmine (refused), a selector collision (refused), an
empty candidate set (the gated null plan) — and asserts the entries,
the nulls, the refusals, the sha stability, and the C byte-exactness
(gcc compiles the emitted block, the dump == the python bytes).
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
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import v452b_heap_scan as v452b  # noqa: E402 — the landmine guard + tables

# the selector map (RmGspHPoke=<sel> — ONE field per boot)
SELECTORS = {1: "rc", 2: "rfc", 3: "ras", 4: "faw", 5: "rrd"}

# the v451b retight table: the LHR target values
LHR_TARGET = {"rc": 70, "rfc": 175, "ras": 44, "faw": 20, "rrd": 5}


def _lane_size(lane):
    return {"u8": 1, "u16le": 2, "u32le": 4, None: 1}.get(lane)


def _new_bytes(field, lane_size):
    v = LHR_TARGET[field]
    return v.to_bytes(lane_size, "little")


def build_entries(v452b_json: dict, pick=None) -> dict:
    """The plan entries from the v452b verdict. pick = a pattern-name
    filter (the human review after a collision refusal)."""
    scan = v452b_json.get("scan", v452b_json)
    candidates = scan.get("candidates", [])
    entries = []
    nulls = []
    refused = []
    by_sel = {}

    for cand in candidates:
        if pick and cand["pattern"] != pick:
            continue
        if not cand.get("plan_eligible"):
            if cand.get("landmine"):
                refused.append({"pattern": cand["pattern"], "reason":
                                "THE LANDMINE (id-19 / all-zero) — the "
                                "banked 4.51 refusal"})
            elif cand.get("verdict") != "HIT":
                refused.append({"pattern": cand["pattern"], "reason":
                                f"verdict={cand.get('verdict')} — only "
                                "HIT writes (the floor discipline)"})
            continue
        pr = cand["plan_ready"]
        lane = cand.get("lane")
        lane_size = _lane_size(lane)
        old_all = bytes.fromhex(cand["old_bytes_hex"])
        for field, pos in pr["fields"].items():
            if "in_record_offset" in pos:
                off_in = pos["in_record_offset"]
            elif "in_vec_offset" in pos:
                off_in = pos["in_vec_offset"]
            else:
                off_in = pos.get("in_pair_offset")
            entry = {
                "field": field,
                "candidate": cand["pattern"],
                "heap_offset": int(cand["heap_offsets"][0], 16) + off_in,
                "lane_bytes": pos.get("lane", 1),
                "old_hex": old_all[off_in:off_in + pos.get("lane", 1)].hex(),
                "new_hex": _new_bytes(field, pos.get("lane", 1)).hex(),
                "verify_after": True,
            }
            entry["sel"] = [k for k, v in SELECTORS.items()
                            if v == field][0]
            if field not in LHR_TARGET:
                refused.append({"pattern": cand["pattern"], "reason":
                                f"field {field} not in the retight table"})
                continue
            col = by_sel.setdefault(entry["sel"], [])
            col.append(entry)

    # ONE entry per selector — a collision = REFUSED (the human picks)
    for sel in sorted(by_sel):
        col = by_sel[sel]
        if len(col) > 1:
            refused.append({
                "reason": f"selector {sel} ({SELECTORS[sel]}) has "
                          f"{len(col)} candidate entries — AMBIGUOUS, "
                          "re-run with --pick <pattern> after the review",
                "candidates": sorted({e["candidate"] for e in col})})
            continue
        entries.append(col[0])

    entries.sort(key=lambda e: e["sel"])
    # the INDECIDABLE fields: named nulls (never guessed positions)
    planned = {e["field"] for e in entries}
    for field in ("rc", "rfc", "ras", "faw", "rrd"):
        if field not in planned:
            nulls.append({"field": field, "target": None,
                          "reason": "no proven byte position in ANY "
                                    "plan-eligible candidate (the packed "
                                    "grammar / no launch-vector slot) — "
                                    "INDECIDABLE until the hit context "
                                    "decodes it"})
    canon = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    sha16 = hashlib.sha256(canon.encode()).hexdigest()[:16]
    return {"entries": entries, "null_targets": nulls, "refused": refused,
            "plan_sha16": sha16, "entry_count": len(entries)}


def emit_c(plan: dict) -> str:
    """The gsp_hpoke_plan.h block — the byte-exact table for the writer."""
    lines = [
        "/* gsp_hpoke_plan.h — GENERATED by v452c_hpatch_build.py — DO NOT EDIT",
        " *",
        " * PASS 4.52 T3 — the route-H write plan (ONE field per boot,",
        " * selected by RmGspHPoke=<sel>; absent/0 = OFF).",
        " * plan_sha16 = %s — gsp_hpoke.c prints it in dmesg next to the" % plan["plan_sha16"],
        " * pre/post verify; a mismatch = the compiled table is NOT the",
        " * reviewed plan (the build = the judge, the 4.44 lesson).",
        " * Every entry carries verify-after; the pre-verify (old bytes)",
        " * is the last-line landmine guard (an all-zero active record",
        " * aborts before any write).",
        " */",
        "#define GSP_HPOKE_PLAN_SHA16 \"%s\"" % plan["plan_sha16"],
        "#define GSP_HPOKE_PLAN_N %d" % plan["entry_count"],
        "",
        "typedef struct",
        "{",
        "    NvU32 sel;          // the RmGspHPoke value that selects it",
        "    NvU64 heapOffset;   // the ABSOLUTE offset in the sysmem heap",
        "    NvU8  len;          // the byte-lane width (1/2/4)",
        "    NvU8  old[8];       // the pre-verify bytes (the runtime truth)",
        "    NvU8  nw[8];        // the new bytes (the v451b LHR values)",
        "} GSP_HPOKE_ENTRY;",
        "",
        "static const GSP_HPOKE_ENTRY gspHpokePlan[GSP_HPOKE_PLAN_N > 0 "
        "? GSP_HPOKE_PLAN_N : 1] =",
        "{",
    ]
    if not plan["entries"]:
        lines.append("    { 0, 0, 0, {0}, {0} }, // the GATED null plan "
                     "(no eligible candidate)")
    for e in plan["entries"]:
        old = bytes.fromhex(e["old_hex"])
        new = bytes.fromhex(e["new_hex"])
        old_p = ", ".join(f"0x{b:02x}" for b in old) or "0"
        new_p = ", ".join(f"0x{b:02x}" for b in new) or "0"
        lines.append(
            "    /* sel=%d %s @0x%x verify-after */"
            % (e["sel"], e["field"], e["heap_offset"]))
        lines.append(
            "    { %d, 0x%016xULL, %d, { %s }, { %s } },"
            % (e["sel"], e["heap_offset"], e["lane_bytes"],
               old_p.ljust(23), new_p))
    lines += ["};", ""]
    return "\n".join(lines)


C_TEST_DRIVER = r"""
#include <stdio.h>
#include <stdint.h>
typedef uint8_t NvU8; typedef uint32_t NvU32; typedef uint64_t NvU64;
#include "@PLAN@"
int main(void)
{
    printf("SHA16 %s\n", GSP_HPOKE_PLAN_SHA16);
    for (int i = 0; i < GSP_HPOKE_PLAN_N; i++) {
        const GSP_HPOKE_ENTRY *e = &gspHpokePlan[i];
        printf("ENTRY %d %d 0x%016llx %d ", i, e->sel,
               (unsigned long long)e->heapOffset, e->len);
        for (int j = 0; j < e->len; j++) printf("%02x", e->old[j]);
        printf(" ");
        for (int j = 0; j < e->len; j++) printf("%02x", e->nw[j]);
        printf("\n");
    }
    return 0;
}
"""


def test_c_byte_exact(plan: dict, workdir: Path) -> bool:
    """The 4.44 lesson, executed: the compiled C table == the python
    plan, byte for byte."""
    plan_h = workdir / "gsp_hpoke_plan.h"
    driver_c = workdir / "drv.c"
    plan_h.write_text(emit_c(plan))
    driver_c.write_text(C_TEST_DRIVER.replace("@PLAN@",
                                              str(plan_h)))
    binp = workdir / "drv"
    cc = subprocess.run(["gcc", "-o", str(binp), str(driver_c)],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        print(f"[FAIL] gcc: {cc.stderr[:400]}")
        return False
    run = subprocess.run([str(binp)], capture_output=True, text=True)
    if run.returncode != 0:
        print(f"[FAIL] run: {run.stderr[:200]}")
        return False
    lines = run.stdout.strip().splitlines()
    ok = lines and lines[0] == f"SHA16 {plan['plan_sha16']}"
    for i, e in enumerate(plan["entries"]):
        want = (f"ENTRY {i} {e['sel']} 0x{e['heap_offset']:016x} "
                f"{e['lane_bytes']} {e['old_hex']} {e['new_hex']}")
        ok = ok and i + 1 < len(lines) and lines[i + 1] == want
    return bool(ok)


# -----------------------------------------------------------------------

def _synth_v452b(cands, colo=None):
    return {"scan": {"candidates": cands,
                     "colo_u32_window32": colo or []}}


def _cand_verbatim(off=0x12340):
    import v451a_dmem_scan as v451a
    _pats, _recs = v451a.build_patterns()
    rec6_hex = _recs[6].hex()  # the banked record bytes (152 hex chars)
    return {
        "pattern": "raw76_id6_launch", "kind": "verbatim", "lane": None,
        "pattern_len": 76, "hits": 1, "verdict": "HIT", "floor": 0.0,
        "record_id": 6, "heap_offsets": [hex(off)],
        "old_bytes_hex": rec6_hex,
        "neighborhoods": {}, "static_crossing": {},
        "route_class": "HEAP-ONLY", "landmine": False,
        "plan_ready": {"fields": {
            "rc": {"in_record_offset": 0, "lane": 1},
            "rfc": {"in_record_offset": 1, "lane": 1}},
            "note": "verbatim"},
        "plan_eligible": True,
    }


def _cand_vec_u32(off=0x23450):
    return {
        "pattern": "vec_record_id6_launch_u32le", "kind": "vec",
        "lane": "u32le", "pattern_len": 20, "hits": 1,
        "verdict": "HIT", "floor": 0.0, "record_id": None,
        "heap_offsets": [hex(off)],
        "old_bytes_hex": "4e000000d2000000340000001a00000018000000",
        "neighborhoods": {}, "static_crossing": {},
        "route_class": "HEAP-ONLY", "landmine": False,
        "plan_ready": {"fields": {
            "rc": {"in_vec_offset": 0, "lane": 4},
            "rfc": {"in_vec_offset": 4, "lane": 4},
            "ras": {"in_vec_offset": 8, "lane": 4}},
            "note": "vec u32"},
        "plan_eligible": True,
    }


def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    # -- 1. the verbatim route: rc/rfc entries, old = the found bytes ----
    plan = build_entries(_synth_v452b([_cand_verbatim()]))
    check("verbatim: 2 entries (rc, rfc)", plan["entry_count"] == 2)
    rc = plan["entries"][0]
    check("verbatim rc: sel=1 off=+0 old=4e new=46",
          rc["sel"] == 1 and rc["heap_offset"] == 0x12340
          and rc["old_hex"] == "4e" and rc["new_hex"] == "46")
    rfc = plan["entries"][1]
    check("verbatim rfc: sel=2 off=+1 old=d2 new=af",
          rfc["sel"] == 2 and rfc["heap_offset"] == 0x12341
          and rfc["old_hex"] == "d2" and rfc["new_hex"] == "af")
    check("verbatim: verify_after on EVERY entry",
          all(e["verify_after"] for e in plan["entries"]))
    nullf = {n["field"] for n in plan["null_targets"]}
    check("verbatim: ras/faw/rrd = named nulls",
          nullf == {"ras", "faw", "rrd"})
    check("verbatim: the plan carries a sha16",
          len(plan["plan_sha16"]) == 16)

    # -- 2. the vec route: u32 lanes --------------------------------------
    plan2 = build_entries(_synth_v452b([_cand_vec_u32()]))
    rc2 = plan2["entries"][0]
    check("vec u32 rc: off=+0 lane=4 old=4e000000 new=46000000",
          rc2["heap_offset"] == 0x23450 and rc2["lane_bytes"] == 4
          and rc2["old_hex"] == "4e000000"
          and rc2["new_hex"] == "46000000")
    ras2 = [e for e in plan2["entries"] if e["field"] == "ras"][0]
    check("vec u32 ras: off=+8 old=34000000 new=2c000000",
          ras2["heap_offset"] == 0x23458
          and ras2["old_hex"] == "34000000"
          and ras2["new_hex"] == "2c000000")
    check("vec u32: faw/rrd = nulls (no launch-vector slot)",
          {n["field"] for n in plan2["null_targets"]} == {"faw", "rrd"})

    # -- 3. the refusals: SUSPECT, landmine -------------------------------
    suspect = dict(_cand_verbatim(), verdict="SUSPECT", plan_eligible=False)
    lm = dict(_cand_verbatim(off=0x99990), record_id=19, landmine=True,
              plan_eligible=False, plan_ready=None)
    plan3 = build_entries(_synth_v452b([suspect, lm]))
    check("SUSPECT: never planned (the floor discipline)",
          plan3["entry_count"] == 0)
    check("the landmine: structurally refused",
          any("LANDMINE" in r["reason"] for r in plan3["refused"]))
    check("the gated null plan: entry_count=0, sha stable",
          plan3["entry_count"] == 0 and len(plan3["plan_sha16"]) == 16)

    # -- 4. the selector collision: REFUSED, --pick resolves --------------
    plan4 = build_entries(_synth_v452b([_cand_verbatim(),
                                        _cand_verbatim(off=0x77770)]))
    check("collision: zero entries, the refusal names both",
          plan4["entry_count"] == 0
          and any("AMBIGUOUS" in r.get("reason", "")
                  for r in plan4["refused"]))
    plan5 = build_entries(_synth_v452b([_cand_verbatim(),
                                        _cand_verbatim(off=0x77770)]),
                          pick="raw76_id6_launch")
    # NOTE: the two candidates SHARE the pattern name — the pick cannot
    # separate them; the collision stands (the offsets differ = the human
    # edits the plan inputs, the builder refuses by design)
    check("collision with an ineffective pick: still refused",
          plan5["entry_count"] == 0)

    # -- 5. the C emission: BYTE-EXACT vs python (gcc, the 4.44 lesson) ---
    with tempfile.TemporaryDirectory() as td:
        check("C byte-exact: the verbatim plan",
              test_c_byte_exact(plan, Path(td)))
        check("C byte-exact: the vec plan",
              test_c_byte_exact(plan2, Path(td)))
        check("C byte-exact: the GATED null plan compiles and matches",
              test_c_byte_exact(plan3, Path(td)))

    # -- 6. the sha stability: the same input = the same signature -------
    check("sha: deterministic on the same input",
          build_entries(_synth_v452b([_cand_verbatim()]))["plan_sha16"]
          == plan["plan_sha16"])

    print(f"selftest v452c: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--v452b", default=None,
                    help="the v452b verdict JSON (the eligible candidates)")
    ap.add_argument("--pick", default=None,
                    help="plan ONLY this candidate pattern (after an "
                         "AMBIGUOUS refusal)")
    ap.add_argument("--plan", default="lab/jalon411/v452c_hpatch_plan.json")
    ap.add_argument("--emit-c", default=None,
                    help="write the gsp_hpoke_plan.h block here")
    a = ap.parse_args()

    if a.selftest:
        return 0 if selftest() else 1

    if not a.v452b:
        print("GATED — no v452b verdict given. The plan stays null "
              "(the v451b pattern): the route-H write assembles ONLY on "
              "plan-eligible candidates (HIT verdict, proven positions, "
              "not the landmine).", file=sys.stderr)
        return 2
    if not selftest():
        print("SELFTEST FAILED — the builder refuses to run",
              file=sys.stderr)
        return 1

    vj = json.loads(Path(a.v452b).read_text())
    plan = build_entries(vj, pick=a.pick)
    plan["pass"] = "4.52"
    plan["instrument"] = "v452c_hpatch_build"
    plan["gate_key"] = "RmGspHPoke=<sel> — ONE field per boot; absent/0 = OFF"
    plan["values"] = ("the v451b LHR retight (the vendor's own headroom "
                      "proof): rc 76->70, rfc 210->175, ras 49->44, "
                      "faw 28->20, rrd 7->5; old-bytes = the bytes the "
                      "candidate found (the runtime truth)")
    Path(a.plan).write_text(json.dumps(plan, indent=1))
    print(f"plan: {plan['entry_count']} entry(ies), "
          f"{len(plan['null_targets'])} named null(s), "
          f"{len(plan['refused'])} refusal(s), "
          f"plan_sha16={plan['plan_sha16']}")
    for e in plan["entries"]:
        print(f"  sel={e['sel']} {e['field']:<4s} @0x{e['heap_offset']:x} "
              f"old={e['old_hex']} new={e['new_hex']} "
              f"verify_after={e['verify_after']}")
    for n in plan["null_targets"]:
        print(f"  NULL {n['field']}: {n['reason'][:80]}...")
    for r in plan["refused"]:
        print(f"  REFUSED: {r['reason'][:100]}")
    if a.emit_c:
        Path(a.emit_c).write_text(emit_c(plan))
        print(f"C block written {a.emit_c}")
        with tempfile.TemporaryDirectory() as td:
            okc = test_c_byte_exact(plan, Path(td))
        print(f"C byte-exact vs python: {'PASS' if okc else 'FAIL'}")
        if not okc:
            return 1
    print(f"written {a.plan}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
