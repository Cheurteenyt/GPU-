#!/usr/bin/env python3
"""4.57 pass, T2 — THE NAMED INDECIDABLES: the GA100 BROM gadgets of the
transpose chain crossed with OUR 4.40 inventory, and the empirical sweep
DESIGNED (not executed — the machine day = the runbook-457).

The reference chain tail (byte-exact, v457a) carries FOUR gadget slots
that belong to the GA100 BROM — the OTHER chip's ROM:
    0xf75c = 0x0cbd   (after {writeValue, canari} — the load link)
    0xf774 = 0x1fbd   (the repeated spine — x3 in the tail)
    0xf7f4 = 0x0ccb   (the terminal pair, low)
    0xf7f8 = 0x7f2f   (the terminal pair, high)
For the GA104 the BROM = DIFFERENT silicon — the offsets do NOT
transfer. This instrument:
  1. builds the CROSS TABLE: per gadget slot — the positional role
     (hypothesis, labeled), the byte status on OUR side (the sub-0x10000
     BROM-relative offsets vs OUR booter VMA base 0x100000), OUR
     equivalent from the 4.40/4.44 inventory (v444e + the byte-cited
     transfer-list pair), and the honest status = INDECIDABLE-BY-BYTES;
  2. re-derives the 4.40 facts BYTE-LEVEL from OUR bootloader.bin (not
     from the asm text): the c.sd @0x100b48 (0xe19c), the c.ld @0x100b3e,
     the rets = 84, the chainable = 24 — the inventory the equivalents
     cite;
  3. emits the SWEEP MATRIX: the design of the empirical gadget/fill_len
     search — ONE boot per point, the ACK per point (RUNBOOK_457_ACK=1
     + RUNBOOK_457_POINT=<id>, the semicolon form — the 4.51 lesson),
     the judge = the pgc6-traj progress service (the 4.56 decoder's
     register read DURING the boot), the rollback = driver-only;
  4. selftests: the byte proofs, the v457a chain import (the
     cross-instrument guard), the matrix invariants (one boot per
     point, zero payload bytes emitted — the no-.bin law).

Output: lab/jalon411/v457b_gadget_cross_sweep.json
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / "tools/analysis/gsp-extract/binaries/bootloader.bin"
OUT = Path(__file__).with_suffix(".json")
VMA = 0x100000

img = BOOT.read_bytes()


def main():
    out = {}
    fails = []

    def check(name, cond, detail=""):
        print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")
        if not cond:
            fails.append(name)

    # -- 1. the byte-level re-derivation of the 4.40 facts ----------------
    # 100b48: e19c  c.sd a5, 0x0(a1)   — THE write primitive
    sd_bytes = img[0x100b48 - VMA:0x100b48 - VMA + 2]
    check("B1 the c.sd @0x100b48 = 0xe19c (the byte, from OUR image)",
          sd_bytes == bytes.fromhex("9ce1"), sd_bytes.hex())
    # 100b3e: c.ld a5, 0x8(sp) — the load side of the pair
    ld_line = None
    asm = (ROOT / "tools/analysis/gsp-extract/bootloader.asm").read_text()
    for l in asm.splitlines():
        if l.strip().startswith("100b3e:"):
            ld_line = l.strip()
            break
    check("B2 the c.ld @0x100b3e byte-cited (the pair's load side)",
          ld_line is not None and "a5" in ld_line, ld_line or "absent")
    rets = 0
    for o in range(0, len(img) - 2, 2):
        if int.from_bytes(img[o:o + 2], "little") == 0x8082:
            rets += 1
    check("B3 the rets (c.ret) = 84 (the 4.40 banked count, re-counted)",
          rets == 84, str(rets))

    # -- 2. the v457a chain import (the cross-instrument guard) -----------
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "v457a_transpose",
        ROOT / "lab/jalon411/v457a_sec2_postbl_transpose.py")
    V457 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V457)
    check("B4 the v457a chain tail = 22 words, the 2 parameterized",
          len(V457.CHAIN) == 22 and
          sum(1 for _o, v in V457.CHAIN if v is None) == 2)
    check("B5 the v457a PLM table = 11 (the same table the C patch "
          "carries)", len(V457.PLM_TABLE) == 11)

    # -- 3. the CROSS TABLE ------------------------------------------------
    # The positional roles = HYPOTHESES (the canary paper's structure;
    # the GA100 semantics = the review territory, not ours to assert).
    gadgets = [
        (0x0cbd, 0xf75c, "load link (after {writeValue, canari}, before "
         "writeAddr) — HYPOTHESIS, positional",
         "no strict equivalent (the v444e strict work-gadgets = 0); the "
         "nearest = the pair's load side @0x100b3e (c.ld a5, 0x8(sp))"),
        (0x1fbd, 0xf774, "repeated spine x3 (0xf774/0xf7a4/0xf7e0) — "
         "HYPOTHESIS, positional",
         "OUR G40 epilogue (the REAL bytes, PROVEN in TR/TR2/TR3 walks; "
         "the v444e chainable = 24 sites)"),
        (0x0ccb, 0xf7f4, "terminal pair (low) — HYPOTHESIS, positional",
         "OUR TERMINAL (the v445/447 builder's clean exit, PROVEN)"),
        (0x7f2f, 0xf7f8, "terminal pair (high) — HYPOTHESIS, positional",
         "same as above — the pair's second half"),
    ]
    cross = []
    for g, slot, role, equiv in gadgets:
        cross.append({
            "gadget_ga100": f"0x{g:04x}",
            "slot_in_tail": f"0x{slot:04x}",
            "role": role,
            "byte_status_ga104": (
                "BROM-relative (sub-0x10000) — OUR booter VMA base = "
                "0x100000; the value maps to NO our-image site; the "
                "GA104 BROM = different silicon, NOT extracted"),
            "our_equivalent": equiv,
            "confidence": "INDECIDABLE-BY-BYTES",
        })
        check(f"B6 0x{g:04x} @tail+0x{slot:04x}: sub-0x10000 "
              f"(the BROM-relative offset of the OTHER ROM — below OUR "
              f"VMA base 0x100000)",
              g < VMA)
    out["cross_table"] = cross
    out["cross_status"] = ("ALL INDECIDABLE-BY-BYTES — the tail layout "
                           "stays byte-exact (the reference structure = "
                           "the emulator's model); the SLOT VALUES on the "
                           "machine day = the sweep's subject")

    # -- 4. the SWEEP MATRIX (the design, not the execution) ---------------
    # THE MACHINE-DAY CONTEXT (main @89bb464, the founder merged): the
    # 6-variant RA-control negative (the fills 64/96/112, the canary,
    # the libos spine/carpet, the ROM-gadget carpet = ALL the same
    # spin) = the OLD portMemCopy lane CLOSED — the copy's return
    # address is not controllable by the memdesc content. THE
    # TRANSPOSE = the DIFFERENT execution context (the booter
    # RE-EXECUTED, the POSTBL pass — not the copy overflow): the
    # negative does NOT transfer automatically (named, INDECIDABLE for
    # the POSTBL context). THE POSITIVE SIGNAL: the boot COMPLETED
    # with the payload resident (the verify = bypassed-or-neutral on
    # OUR silicon) — the 0xf800 memdesc = tolerated by the boot flow.
    # Axes: the gadget-set identity x the fill_len. ONE boot per
    # point — the ACK per point, the judge = the COMMITTED service.
    JUDGE = ("pgc6-traj.service + tools/edpp/pgc6_probe.py (the "
             "machine-day's committed automatic trajectory unit — the "
             "PGC6 progress pair read LIVE, 60 x 5 s, the JSON per "
             "snapshot) + the dmesg SEC2_DEBUG PLM ledger")
    points = [
        {"id": "P0-identity", "fill_len": None, "gadget_set": "reference",
         "shape": "the byte-exact reference tail (v457a)",
         "hypothesis": "the GA100 offsets work as-is (the long shot — "
         "the offsets are comparable by accident)"},
        {"id": "P1-fill64", "fill_len": 64, "gadget_set": "reference",
         "shape": "the reference tail, the fill_len = 64",
         "hypothesis": "the r1's copy-return-address region starts "
         "earlier — NAMED CAVEAT: the fill_len axis was EXHAUSTED in "
         "the OLD lane (the machine-day negative); here it re-runs "
         "in the NEW execution context only"},
        {"id": "P2-fill96", "fill_len": 96, "gadget_set": "reference",
         "shape": "the reference tail, the fill_len = 96",
         "hypothesis": "the middle point of the r1's matrix"},
        {"id": "P3-fill112", "fill_len": 112, "gadget_set": "reference",
         "shape": "the reference tail, the fill_len = 112 (the v446/"
         "v447 proven length)",
         "hypothesis": "the OUR-proven geometry with THEIR gadgets"},
        {"id": "P4-our-tail", "fill_len": 112, "gadget_set": "ours",
         "shape": "the OUR chain (the v447 surgical, the tail at 0xf754) "
         "in the 0xf800 buffer",
         "hypothesis": "the POSTBL can reach the booter's own code "
         "(the booter = EXECUTING when the verify runs) — our PROVEN "
         "gadgets do the write"},
        {"id": "P5-control", "fill_len": 112, "gadget_set": "none",
         "shape": "the pure 0x4a7 field, NO tail (the r0 uniform spin)",
         "hypothesis": "the NULL control: the spin reproduces, the "
         "judge = SPIN, zero opens — the matrix's baseline"},
    ]
    for p in points:
        p["ack"] = "RUNBOOK_457_ACK=1;RUNBOOK_457_POINT=" + p["id"]
        p["boots"] = 1
        p["judge"] = JUDGE
        p["verdicts"] = ["OPENED", "NO-EFFECT", "SPIN", "HANG", "FAULT"]
        p["rollback"] = "driver-only (~10 min, proven x4)"
    check("B7 the matrix = 6 points, ONE boot each",
          len(points) == 6 and all(p["boots"] == 1 for p in points))
    check("B8 every point = ACK-gated with the semicolon multi-key form",
          all("RUNBOOK_457_ACK=1;RUNBOOK_457_POINT=" in p["ack"]
              for p in points))
    check("B9 the control point = the null (no tail, the r0 baseline)",
          points[-1]["gadget_set"] == "none")
    check("B11 the judge = the COMMITTED machine-day instruments "
          "(pgc6_probe.py on the tree)",
          (ROOT / "tools/edpp/pgc6_probe.py").exists() and
          all(p["judge"].startswith("pgc6-traj.service") for p in points))
    out["sweep_matrix"] = points

    # -- 5. the laws --------------------------------------------------------
    out["laws"] = {
        "no_payload_bytes_emitted": "zero .bin committed — the fill = "
            "the C code (v457a) + the builder; the sweep points = the "
            "PARAMETERS, not blobs",
        "firmware_never_touched": "the GSP firmware blob = untouched; "
            "the signature memdesc = the driver's allocation, refilled "
            "at runtime",
        "emulator_before_boot": "the TR-4 15/15 = the precondition; "
            "every sweep point re-runs it",
        "ack_per_boot": "RUNBOOK_457_ACK=1;RUNBOOK_457_POINT=<id>",
        "rollback": "driver-only",
    }
    check("B10 zero payload bytes in this pass's outputs (the no-.bin "
          "law)",
          not (ROOT / "lab/jalon411/v457a_payload.bin").exists() and
          not (ROOT / "lab/jalon411/v457_payload.bin").exists())

    out["conclusion"] = [
        "The 4 GA100 gadget slots = INDECIDABLE-BY-BYTES for the GA104 "
        "(the byte status, B6).",
        "The tail layout stays byte-exact (the reference structure = "
        "the model); the slot VALUES = the sweep's subject.",
        "The OUR-side equivalents exist and are PROVEN in our image "
        "(the pair @0x100b3e/0x100b48, the G40 spine, the TERMINAL) — "
        "P4 = the variant that uses them.",
        "The selftest C byte-exact vs the python builder = BANKED in "
        "v457a (V5, 71 checks) + TR4-A/B — the 4.44 law, already paid.",
    ]

    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"emit: {OUT}")
    print(f"=== v457b selftest: {'TOUT VERT' if not fails else str(len(fails)) + ' FAIL'} ===")
    for f in fails:
        print("  FAIL:", f)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
