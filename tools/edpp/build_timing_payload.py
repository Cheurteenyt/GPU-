#!/usr/bin/env python3
"""build_timing_payload.py — le builder du payload timing (4.50).

La source de vérité = les fingerprints bankés
(lab/jalon411/v448c_stride_timing.json -> dmem_fingerprints):
  - record 26 (LHR):    rc=70, rfc=175, ras=44, faw=20, rrd=5
  - record 6  (launch): rc=78, rfc=210, ras=52, rp=26, cl=24

Ce builder:
  1. REPRODUIT les 4 représentations byte-patterns de chaque record
     (u8 / u16le / u32le / la paire (rc,rfc)) — le selftest = 8/8
     (la discipline: reproduire d'abord);
  2. émet les tables u64 plates (LE) pour la transfer-list — le format
     que --test-timings valide (TT-T 5/5);
  3. --emit-c: le bloc C (la future transfer_list_timings.c — les
     TARGETS réels viendront du dump §5, runbook-447);
  4. --table {lhr|launch}: l'émission d'une seule table.

Le layout byte-lane final des records parsés = INDECIDABLE-BY-BYTES
jusqu'au dump §5; ce builder est PARAMÉTRÉ par ce layout (le champ
--lanes u8|u16|u32 fixe la largeur d'empaquetage, défaut u32).
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FP = ROOT / "lab/jalon411/v448c_stride_timing.json"

LHR = {"rc": 70, "rfc": 175, "ras": 44, "faw": 20, "rrd": 5}
LAUNCH = {"rc": 78, "rfc": 210, "ras": 52, "rp": 26, "cl": 24}


def pack_u8(vec):
    return bytes(vec.values())


def pack_u16le(vec):
    b = b""
    for v in vec.values():
        b += v.to_bytes(2, "little")
    return b


def pack_u32le(vec):
    b = b""
    for v in vec.values():
        b += v.to_bytes(4, "little")
    return b


def pair_rc_rfc(vec):
    return bytes([vec["rc"], vec["rfc"]])


def hexs(b):
    return b.hex()


def table_u64(vec, lanes):
    """La table u64 plate pour la transfer-list: chaque champ empaqueté
    selon la largeur de lane, aligné dans le u64 (LE)."""
    out = []
    for v in vec.values():
        w = {"u8": 1, "u16": 2, "u32": 4}[lanes]
        out.append(int.from_bytes(v.to_bytes(w, "little")
                                  + b"\x00" * (8 - w), "little"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", choices=["lhr", "launch", "both"], default="both")
    ap.add_argument("--lanes", choices=["u8", "u16", "u32"], default="u32")
    ap.add_argument("--emit-c", action="store_true",
                    help="émettre le bloc C (les targets = PLACEHOLDER 0xDEAD_DMEM)")
    a = ap.parse_args()

    # -- 1. le selftest: reproduire les fingerprints bankés -----------------
    fp = json.loads(FP.read_text())["dmem_fingerprints"]
    ok = 0
    tot = 0
    for name, vec in (("record_id26_lhr", LHR), ("record_id6_launch", LAUNCH)):
        exp = fp[name]["patterns"]
        got = {"u8": hexs(pack_u8(vec)), "u16le": hexs(pack_u16le(vec)),
               "u32le": hexs(pack_u32le(vec)),
               "pair_u8_rc_rfc": hexs(pair_rc_rfc(vec))}
        for k in exp:
            tot += 1
            if got[k] == exp[k]:
                ok += 1
            else:
                print(f"  MISMATCH {name}/{k}: got {got[k]} "
                      f"attendu {exp[k]}", file=sys.stderr)
    print(f"selftest fingerprints: {ok}/{tot} "
          f"{'PASS' if ok == tot else 'FAIL'}")
    if ok != tot:
        return 1

    # -- 2-3. les tables ------------------------------------------------------
    tables = {"lhr": LHR, "launch": LAUNCH} \
        if a.table == "both" else {a.table: (LHR if a.table == "lhr" else LAUNCH)}
    for name, vec in tables.items():
        t = table_u64(vec, a.lanes)
        print(f"[{name}] lanes={a.lanes} n={len(t)} "
              f"u64={['%016x' % w for w in t]}")
        if a.emit_c:
            print(f"[{name}] C block:")
            print("static const u64 timing_table_%s[] = {" % name)
            for w in t:
                print(f"    0x{w:016X}ULL,   /* field */")
            print("}; /* TARGETS = PLACEHOLDER — le dump §5 (runbook-447) "
                  "fournit les adresses réelles; le {value,target} "
                  "s'assemble alors comme le gabarit 4.42 "
                  "(transfer_list_memdesc.c) */")
    return 0


if __name__ == "__main__":
    sys.exit(main())
