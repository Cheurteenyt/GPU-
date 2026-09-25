#!/usr/bin/env python3
"""v454d — THE SURGICAL WRITE-PLAN SKELETON (the 4.54 read lane, the
OFFLINE end — the O5 discipline at its strictest).

WHAT THIS IS: the parameter document for the FUTURE write day. It
consumes the v454c verdict and, ONLY IF the write gate = NAMED (a
POWER-BASE-MATCH row exists), emits the invocation plan:

  ONE invocation a3=1, a1 = the RAW register offset, the walk list =
  [the value] — ONE SURGICAL MMIO write per hijack cycle (the wild #1
  IS the write; the scatter ring = untouched — the 4.53 §2 refined
  semantics, byte-confirmed). N registers = N cycles (the
  cmpunlocker ×4 = the same model). The a3=8 block form = ONLY IF a
  consecutive register block decodes (NOT the default — refused
  here without the block evidence).

WHAT THIS IS NOT: no payload, no hardware, no write. The payload =
the v446 builder (the documented command in the plan) — generated in
the NEXT pass, emulated (booter_emu --test-rop2) BEFORE any boot,
ACK-gated on the machine day. THIS tool cannot write anything —
the code IS the guarantee (the selftest asserts the machinery).

THE PLAN'S HONESTY ROWS (nothing hidden):
  a1 = the RAW offset (the GSP data space decodes the MMIO at the
       BAR0 offsets — the cmpunlocker's writeAddr = the raw form).
  the value = the u64 ZERO-EXTENDED 280 W (0x0000000010B07600, the
       4.44 pair through the MMIO door — the f18 object route stays
       dead): the u64 store ⇒ the +4 NEIGHBOR receives 0x00000000
       (the upper dword) — the side effect DOCUMENTED, never hidden.
  align8 = (a1 % 8 == 0) — the misaligned u64 store on the GSP data
       space = INDECIDABLE-BY-BYTES (the R2 emulation row decides;
       the plan flags it, never assumes).
  the ctx = the (ctx_off, a4) PAIR — the a4-conjugation law (the
       TR2-B discovery) named in the builder command.

THE GATES (exit 2, machine-readable):
  no verdict file / no write_target / a REFUSED lane → REFUSED.

Run:  python3 v454d_write_plan.py --selftest
      python3 v454d_write_plan.py --verdict v454c_verdict.json \
              --out v454d_write_plan.json
Exit: 0 iff the plan emitted (the gate NAMED) / the selftest green.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V446 = ROOT / "lab" / "jalon411" / "v446_rop_payload_build.py"
EMU = ROOT / "tools" / "booter_emu.py"

VALUE_280W_UW = 280_000_000
VALUE_280W_U64 = 0x0000000010B07600
assert VALUE_280W_U64 == VALUE_280W_UW          # the zero-extended form


class PlanRefused(Exception):
    pass


def plan(verdict_doc):
    """The verdict → the plan doc. Raises PlanRefused on the gate."""
    lane = verdict_doc.get("write_lane", "")
    target = verdict_doc.get("write_target")
    if target is None:
        raise PlanRefused(
            "REFUS: write_target absent — la porte O5 reste fermée")
    if not lane.startswith("NAMED"):
        raise PlanRefused(f"REFUS: write_lane = {lane!r}")

    a1 = target["offset"]
    if not (0 < a1 < 0x1000000):
        raise PlanRefused(f"REFUS: a1 = 0x{a1:x} hors BAR0 — jamais")

    return {
        "instrument": "v454d_write_plan",
        "gate": {"write_lane": lane,
                 "verdict_source": verdict_doc.get("instrument"),
                 "verdict_mode": verdict_doc.get("mode")},
        "target": {
            "a1_raw": a1,
            "a1_hex": f"0x{a1:08x}",
            "align8": (a1 % 8 == 0),
            "align_note": ("aligned u64 store" if a1 % 8 == 0 else
                           "the MISALIGNED u64 store = INDECIDABLE-BY-"
                           "BYTES — the R2 emulation row decides"),
            "stock_value": target.get("stock_value"),
            "value_280w_u64": f"0x{VALUE_280W_U64:016X}",
            "value_280w_dec": VALUE_280W_UW,
            "side_effect_plus4": ("[a1+4] <- 0x00000000 (the upper "
                                  "dword of the u64 store) — the "
                                  "neighbor register DOCUMENTED here, "
                                  "read-tested in the write-day runbook"),
            "found_via": target.get("found_via"),
        },
        "invocation": {
            "a1": "the RAW register offset (the GSP data space decodes "
                  "the MMIO at the BAR0 offsets)",
            "a3": 1,
            "walk_list": [VALUE_280W_UW],
            "cycles": 1,
            "note": "the wild #1 = THE write; the scatter ring "
                    "untouched; N registers = N cycles",
            "block_form_a3_8": ("REFUSED here — only IF a consecutive "
                                "register block decodes (the read-probe "
                                "evidence, absent today)"),
        },
        "payload_builder": {
            "tool": str(V446.relative_to(ROOT)),
            "emulator": str(EMU.relative_to(ROOT)),
            "law": ("the ctx = the (ctx_off, a4) PAIR — the "
                    "a4-conjugation law (TR2-B); the walk cell + the "
                    "list = FREE ([sp+8])"),
            "order": ("the payload generated in the NEXT pass, emulated "
                      "(--test-rop2) BEFORE any boot, ACK-gated "
                      "(RUNBOOK_45x_ACK=1) on the machine day"),
        },
        "refusals": [
            "no write before a read-test row (the O5 discipline — "
            "v454c owns the verdict)",
            "no payload from THIS tool (the v446 builder = the next "
            "pass, the emulation first)",
            "no machine gesture without the ACK (the runbook gate)",
            "the rollback = the driver alone, always",
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--verdict",
                    default="lab/jalon411/v454c_verdict.json")
    ap.add_argument("--out", default="lab/jalon411/v454d_write_plan.json")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    vp = Path(args.verdict)
    if not vp.is_file():
        print(f"REFUS: verdict absent ({vp}) — lance v454c d'abord",
              file=sys.stderr)
        return 2
    try:
        doc = plan(json.loads(vp.read_text()))
    except PlanRefused as e:
        print(str(e), file=sys.stderr)
        return 2
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")
    print(f"[v454d] PLAN émis: a1=0x{doc['target']['a1_raw']:08x} "
          f"a3=1 liste=[{VALUE_280W_UW}] -> {args.out}")
    print(f"[v454d] RAPPEL: ce plan n'est PAS une écriture — le payload "
          f"= la prochaine passe (émulée d'abord), le boot = gaté ACK.")
    return 0


def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    def verdict_with(offset, lane="NAMED — the target exists"):
        return {"instrument": "v454c_shape_match", "mode": "synthetic",
                "write_lane": lane,
                "write_target": {"offset": offset, "name": "NB(+0x10)",
                                 "stock_value": "0x0ee6b280",
                                 "value_280w": "0x10B07600",
                                 "value_280w_dec": 280000000,
                                 "found_via": "RISK-PROBE"}}

    # -- 0. the code IS the guarantee: no payload, no write call --------
    src = Path(__file__).read_text()
    machinery = src[:src.index("def selftest")]
    check("code: AUCUN build de payload dans la machinerie",
          "struct.pack" not in machinery and "build_chain" not in machinery
          and "build_carpet" not in machinery)
    check("code: la valeur 280 W = la forme u64 zero-étendue EXACTE",
          VALUE_280W_U64 == 0x0000000010B07600 == VALUE_280W_UW)

    # -- 1. the refusals (every path) ------------------------------------
    for bad, label in [
            ({"write_lane": "REFUSED — no POWER-BASE-MATCH row",
              "write_target": None}, "sans cible"),
            ({"write_lane": "REFUSED — no POWER-BASE-MATCH row",
              "write_target": {"offset": 0x100}}, "lane REFUSED"),
            ({"write_lane": "", "write_target": {"offset": 0x100}},
             "lane vide")]:
        try:
            plan(bad)
            check(f"refus ({label})", False)
        except PlanRefused:
            check(f"refus ({label})", True)

    # -- 2. the plan: the a1 = RAW, a3 = 1, the list exact ---------------
    p = plan(verdict_with(0x00823814))
    check("plan: a1 = l'offset BRUT (aucune base BAR ajoutée)",
          p["target"]["a1_raw"] == 0x00823814
          and p["target"]["a1_raw"] < 0x1000000)
    check("plan: a3 = 1, la liste = [280000000] exactement",
          p["invocation"]["a3"] == 1
          and p["invocation"]["walk_list"] == [280000000]
          and p["invocation"]["cycles"] == 1)
    check("plan: la forme u64 = 0x0000000010B07600",
          p["target"]["value_280w_u64"] == "0x0000000010B07600")
    check("plan: l'effet de bord +4 DOCUMENTÉ",
          "a1+4" in p["target"]["side_effect_plus4"])
    check("plan: align8 faux pour 0x00823814 (%8 = 4)",
          p["target"]["align8"] is False
          and "INDECIDABLE-BY-" in p["target"]["align_note"])
    p2 = plan(verdict_with(0x00823810))
    check("plan: align8 vrai pour 0x00823810 (%8 = 0)",
          p2["target"]["align8"] is True)
    check("plan: le block a3=8 REFUSÉ sans l'évidence",
          p["invocation"]["block_form_a3_8"].startswith("REFUSED"))
    check("plan: la loi (ctx_off, a4) nommée dans le builder",
          "(ctx_off, a4)" in p["payload_builder"]["law"])
    check("plan: v446 + l'émulateur existent dans l'arbre",
          V446.is_file() and EMU.is_file())
    check("plan: l'ordre = émulé AVANT le boot",
          "BEFORE any boot" in p["payload_builder"]["order"])

    # -- 3. the round-trip -----------------------------------------------
    blob = json.dumps(p)
    back = json.loads(blob)
    check("JSON: le round-trip identique",
          back == p)

    print(f"selftest v454d: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


if __name__ == "__main__":
    sys.exit(main())
