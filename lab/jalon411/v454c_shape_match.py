#!/usr/bin/env python3
"""v454c — THE SHAPE-MATCH ANALYZER (the 4.54 read lane — the decision
criterion made machine-readable).

The 4.53 §5 discipline: the shape-match = the probe's decision
criterion. OUR card = 250 W stock ⇒ a u32 register reading
**0x0EE6B280 = 250000000 µW** = the POWER-BASE register DECODED on
GA104 (the 4.44 formula: limit = base × f18/100/1000). THIS tool
consumes the v454b dump and classifies EVERY row:

  verdict classes (the precedence: the exact markers FIRST):
    POWER-BASE-MATCH  the EXACT marker forms: 0x0EE6B280 (250 W),
                      0x0E4E1C00 (240 W), 0x10B07600 (280 W — the
                      surprise form, named as such). THE ONLY rows
                      that can name a write target.
    POWER-FORM        the plausible µW range [1e8, 6e8] without an
                      exact marker — a LEAD (the re-probe), NEVER a
                      write target (the fuzzy value = not the base
                      decode evidence).
    POWER-MW          the mW family [1e5, 6e5] (the 4.44 dual
                      hypothesis: percent vs permille) — the
                      secondary, low-confidence form.
    DEAD-FF           0xFFFFFFFF — the decode absent/masked (the
                      honest negative: the candidate = dead ON THIS
                      CARD, the exact 4.53 §5 wording).
    DEAD-ZERO         0x00000000 — unnamed, the decode reads zero.
    ERROR             the read failed (ERROR-OOR) — no data.
    UNPLAUSIBLE       everything else.

THE WRITE GATE (the O5 discipline EXECUTED IN CODE):
  no POWER-BASE-MATCH row ⇒ write_target = null AND write_lane =
  "REFUSED — no POWER-BASE-MATCH row" (the machine-readable refusal
  v454d and the runbook consume).
  a POWER-BASE-MATCH row ⇒ write_target = {offset, value_280w,
  source_row, ack_class} named — the WRITE ITSELF stays a LATER
  ACK-gated machine day (this lane = read-only; naming ≠ writing).

GATED BY DEFAULT: the analyzer touches no hardware, needs no ACK
(the verdicts = the file arithmetic); the ACKs live upstream (v454b)
and downstream (v454d consumes the REFUSED/NAMED lane state).

Run:  python3 v454c_shape_match.py --selftest
      python3 v454c_shape_match.py --dump v454b_probe_dump.json \
              --out v454c_verdict.json
Exit: 0 iff the selftest green / the verdict written.
"""
import argparse
import json
import sys
from pathlib import Path

# the shapes = the single source (v454a) — zero re-transcription
v454a_path = Path(__file__).resolve().parent / "v454a_probe_table.py"
_v454a = {"__file__": str(v454a_path), "__name__": "v454a_probe_table"}
exec(compile(v454a_path.read_text(), str(v454a_path), "exec"), _v454a)
SHAPE_250_UW = _v454a["SHAPE_250_UW"]
SHAPE_240_UW = _v454a["SHAPE_240_UW"]
SHAPE_280_UW = _v454a["SHAPE_280_UW"]

MARKERS_UW = {
    SHAPE_250_UW: "250 W — the stock base (the expected marker)",
    SHAPE_240_UW: "240 W — the LHR-class form",
    SHAPE_280_UW: "280 W — the SURPRISE form (a base already open)",
}
POWER_UW_LO, POWER_UW_HI = 100_000_000, 600_000_000
POWER_MW_LO, POWER_MW_HI = 100_000, 600_000

VALUE_280W = SHAPE_280_UW   # the write-plan value (the 4.44 pair, µW)


def classify(value, status):
    """(verdict, note) for one read row — the precedence: exact first."""
    if status != "OK":
        return "ERROR", "the read failed (ERROR-OOR) — no data"
    if value == 0xFFFFFFFF:
        return "DEAD-FF", "the decode absent/masked — the honest negative"
    if value in MARKERS_UW:
        return "POWER-BASE-MATCH", f"the exact marker: {MARKERS_UW[value]}"
    if value == 0:
        return "DEAD-ZERO", "the decode reads zero — unnamed"
    if POWER_UW_LO <= value <= POWER_UW_HI:
        return "POWER-FORM", ("the plausible µW — a LEAD for the "
                              "re-probe, NOT a write target")
    if POWER_MW_LO <= value <= POWER_MW_HI:
        return "POWER-MW", ("the mW family — the 4.44 dual hypothesis, "
                            "the secondary form")
    return "UNPLAUSIBLE", "outside every named family"


def analyze(dump_doc):
    """The dump → the verdict doc (the write gate included)."""
    verdicts = []
    for r in dump_doc.get("reads", []):
        verdict, note = classify(r.get("value"), r.get("status", "OK"))
        verdicts.append({"offset": r["offset"], "name": r["name"],
                         "ack_class": r["ack_class"],
                         "value_hex": r.get("value_hex"),
                         "verdict": verdict, "note": note})

    counts = {}
    for v in verdicts:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1

    matches = [v for v in verdicts if v["verdict"] == "POWER-BASE-MATCH"]
    if matches:
        m = matches[0]
        write_target = {"offset": m["offset"], "name": m["name"],
                        "stock_value": m["value_hex"],
                        "value_280w": f"0x{VALUE_280W:08X}",
                        "value_280w_dec": VALUE_280W,
                        "found_via": m["ack_class"]}
        write_lane = ("NAMED — the target exists; the write itself = "
                      "the LATER ACK-gated boot day (v454d emits the "
                      "plan, v446 the payload; this lane wrote nothing)")
    else:
        write_target = None
        write_lane = ("REFUSED — no POWER-BASE-MATCH row (the O5 "
                      "discipline: no write before a read-test row)")

    return {"instrument": "v454c_shape_match",
            "source_dump": dump_doc.get("instrument"),
            "mode": dump_doc.get("mode"),
            "counts": counts,
            "verdicts": verdicts,
            "marker_rows": matches,
            "write_target": write_target,
            "write_lane": write_lane}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--dump", default="lab/jalon411/v454b_probe_dump.json")
    ap.add_argument("--out", default="lab/jalon411/v454c_verdict.json")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    dump_doc = json.loads(Path(args.dump).read_text())
    doc = analyze(dump_doc)
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")

    print(f"[v454c] {doc['mode']}: " +
          " ".join(f"{k}={v}" for k, v in sorted(doc["counts"].items())))
    for m in doc["marker_rows"]:
        print(f"[v454c] POWER-BASE-MATCH @0x{m['offset']:08x} "
              f"({m['name']}, {m['value_hex']}) — {m['note']}")
    print(f"[v454c] write_lane: {doc['write_lane']}")
    return 0


def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    def row(off, val, cls="SAFE-PROBE", name="T"):
        return {"offset": off, "name": name, "ack_class": cls,
                "value": val, "value_hex": f"0x{val:08x}", "status": "OK"}

    # -- 0. the shapes: the single source re-asserted --------------------
    check("formes: 0x0EE6B280 == 250000000", SHAPE_250_UW == 0x0EE6B280)
    check("formes: 0x0E4E1C00 == 240000000", SHAPE_240_UW == 0x0E4E1C00)
    check("formes: 0x10B07600 == 280000000", SHAPE_280_UW == 0x10B07600)

    # -- 1. the classes, one by one --------------------------------------
    cases = [
        (row(0x100, 0xFFFFFFFF), "DEAD-FF"),
        (row(0x104, 0), "DEAD-ZERO"),
        (row(0x108, SHAPE_250_UW), "POWER-BASE-MATCH"),
        (row(0x10c, SHAPE_240_UW), "POWER-BASE-MATCH"),
        (row(0x110, SHAPE_280_UW), "POWER-BASE-MATCH"),
        (row(0x114, 350000000), "POWER-FORM"),
        (row(0x118, 250000), "POWER-MW"),
        (row(0x11c, 12345), "UNPLAUSIBLE"),
        (row(0x120, 0xDEADBEEF), "UNPLAUSIBLE"),
        ({"offset": 0x124, "name": "OOR", "ack_class": "SAFE-PROBE",
          "value": None, "value_hex": None, "status": "ERROR-OOR"},
         "ERROR"),
    ]
    for r, expect in cases:
        v, _ = classify(r["value"], r["status"])
        check(f"classe {expect} @0x{r['offset']:x}", v == expect)

    # -- 2. the precedence: the marker INSIDE the µW range wins ----------
    v, n = classify(SHAPE_250_UW, "OK")
    check("précédence: le marqueur avant la forme µW",
          v == "POWER-BASE-MATCH" and "expected marker" in n)
    v, _ = classify(SHAPE_280_UW, "OK")
    check("précédence: 280 W = le marqueur surprise",
          v == "POWER-BASE-MATCH")

    # -- 3. the gate: NO marker -> the REFUSAL machine-readable ----------
    doc = analyze({"instrument": "v454b_bar0_probe", "mode": "synthetic",
                   "reads": [row(0x100, 0xFFFFFFFF),
                             row(0x104, 350000000),
                             row(0x108, 0)]})
    check("porte: sans marqueur -> write_target = null",
          doc["write_target"] is None)
    check("porte: sans marqueur -> write_lane REFUSED",
          doc["write_lane"].startswith("REFUSED"))
    check("porte: les formes floues NE nomment RIEN",
          all(v["verdict"] != "POWER-BASE-MATCH"
              for v in doc["verdicts"]))

    # -- 4. the gate: the marker -> the target NAMED, the write stays out
    doc2 = analyze({"instrument": "v454b_bar0_probe", "mode": "synthetic",
                    "reads": [row(0x100, 0xFFFFFFFF),
                              row(0x00823814, SHAPE_250_UW,
                                  cls="RISK-PROBE", name="NB(+0x10@FEAT)")]})
    check("porte: le marqueur -> la cible nommée",
          doc2["write_target"] is not None
          and doc2["write_target"]["offset"] == 0x00823814
          and doc2["write_target"]["stock_value"].lower() == "0x0ee6b280"
          and doc2["write_target"]["value_280w"].lower() == "0x10b07600")
    check("porte: la cible nommée ≠ une écriture (le lane = NAMED, "
          "le write = le jour boot gaté)",
          doc2["write_lane"].startswith("NAMED"))
    check("porte: la cible via RISK = la provenance gardée",
          doc2["write_target"]["found_via"] == "RISK-PROBE")
    check("porte: la ligne marqueur bankée dans marker_rows",
          len(doc2["marker_rows"]) == 1)

    # -- 5. the counts + the round-trip ----------------------------------
    check("comptes: les classes sommées",
          doc2["counts"].get("POWER-BASE-MATCH") == 1
          and doc2["counts"].get("DEAD-FF") == 1)
    blob = json.dumps(doc2)
    back = json.loads(blob)
    check("JSON: le round-trip identique",
          back["verdicts"] == doc2["verdicts"]
          and back["write_target"] == doc2["write_target"])

    print(f"selftest v454c: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


if __name__ == "__main__":
    sys.exit(main())
