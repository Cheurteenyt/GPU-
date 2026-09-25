#!/usr/bin/env python3
"""v447 — THE R2B WRITE-CHAIN BUILDER (pass 4.56 T2): the v446
relocatable layout + the a3=8 scatter (the 4.44-proven mechanism) — the
day of writing, PREPARED but NEVER armed by this tool.

THE PRIMITIVE SEMANTICS (the real bytes, bootloader.asm re-read this
pass — the definitive loop decode, terminal = 0x100b3e):

  the hijack enters at 0x100b3e (the loop BODY, the head skipped):
    iter0: [a1] <- list[0]            a1 = THE ROM RESIDUE (W1/W2 — the
                                      wild write, named, never controllable)
    then the loop head recomputes a1 EVERY iteration:
      100b2e  ld a6, 0x488(a4)        a6 = ctx.slot
      100b32  ld a1, 0x498(a4)        a1 = ctx.dest
      100b36  slli a6, a6, 3          slot*8
      100b38  add a1, a1, a6          a1 = dest + slot*8
      100b48  sd a5, 0(a1)            THE RING WRITE
      100b4a-5a: slot += 1; if slot >= cap: slot = 1  (the wrap to 1,
                 NEVER 0 — the slot 0 = the counter cell, protected)
    the exit (i == a3):
      100b6e-76: [ctx.dest] += a3      THE COUNTER BUMP (the u64 RMW)
      100b78-7a: sp += 0x50; ret       W3: the re-entry (the spin)

  ⇒ the ring slots used = slot0+1 .. slot0+a3-1; the counter cell =
  [dest] (the slot 0); the wild = [a1-residue].

THE SCATTER GEOMETRY (the mission's "8 writes à a1+8k" — the 4.44
D-list conjugated to the block):
  the targets = the 8 u64 slots {B + 8k, k = 0..7} (B = the block base,
  the raw MMIO offset form — the GSP data space decodes the MMIO at the
  BAR0 offsets, the v454d law);
  ctx: slot0 = 1, cap = 0x40, dest = B - 8, magic = 8;
  the list = [V0..V7] (the u64 zero-extended values);
  the writes: the wild [a1-residue] <- V0; the ring [B+8] <- V1 ...
  [B+56] <- V7 (the slots 2..8); the counter [B-8] += 8 (the u64 RMW on
  the register BELOW the block — the named clobber, the read side
  effect INCLUDED: an RMW = a READ of [B-8]);
  IF the a1-residue = B (the A3-favorable assumption, the 4.44 pattern
  a1 = dest+8): the wild = [B] <- V0 = the first target — the FULL
  block lands; otherwise the wild lands WHEREVER the residue points
  (INDECIDABLE until the day's R0/R2 discovery) and [B] stays
  UNWRITTEN (the slot 1 = skipped — the honest hole, never hidden).

THE SURGICAL GEOMETRY (the v454d plan, unchanged):
  a3 = 1, the list = [V], a1 = the RAW offset (the residue assumption
  A3), the ctx dest = the counter home (named-safe or INDECIDABLE).

THE GATE (IN CODE — the mission's wording): the pairs {address, value}
come FROM T1 (the v456c map); the payload = REFUSED without the
POWER-BASE-MATCH row from the sonde 454 (the v454c verdict doc:
write_target = null or write_lane = REFUSED → exit 2, machine-readable).
The synthetic verdict fixture = the SAME code path (the 4.54 lesson) —
clearly tagged "synthetic" in every doc it produces; this pass commits
NO .bin: the payloads = emitted at the runbook-456 day, from the REAL
verdict, ACK-gated.

THE HONESTY ROWS (carried into every build doc):
  the +4 neighbors: each u64 slot write zeroes [B+8k+4] (the u64
  store's upper dword — 16 u32 registers touched per 8-slot block);
  the counter RMW reads AND writes [B-8]; the wild writes list[0] to
  the INDECIDABLE residue address; the (ctx_off, a4) PAIR law (the TR-2
  discovery: the ctx = a4-relative, byte-fixed — the ctx @0x91 = the
  a4 = PAY conjugation); align8 = INDECIDABLE-BY-BYTES flagged, never
  assumed (the v454d law).

Run:  python3 v447_rop_write_build.py --selftest
      python3 v447_rop_write_build.py --verdict v454c_verdict.json \
              --block 0x00823814 --values 280000000
          [--mode scatter|surgical] [--emit-c out.h] [--out out.bin]
Exit: 0 = built; 2 = REFUSED (the gate or the geometry).
"""
import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---- v446 imported (the relocatable layout — zero re-transcription) ----
_spec = importlib.util.spec_from_file_location(
    "v446_build", HERE / "v446_rop_payload_build.py")
V446 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V446)

# ---- v454a imported (the shapes — zero re-transcription) ---------------
_spec2 = importlib.util.spec_from_file_location(
    "v454a", HERE / "v454a_probe_table.py")
V454A = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(V454A)

# ---- v456c imported (the O5 map — the address candidates) --------------
_spec3 = importlib.util.spec_from_file_location(
    "v456c", HERE / "v456c_o5_map.py")
V456C = importlib.util.module_from_spec(_spec3)
_spec3.loader.exec_module(V456C)

SIZE = V446.SIZE
N_WORDS = V446.N_WORDS
G40, TERMINAL = V446.G40, V446.TERMINAL
VALUE_280W = V454A.SHAPE_280_UW          # 0x10B07600 (µW — the 4.44 pair)
BAR0_MAX = V454A.BAR0_MAX                # 16 MB

DEFAULT_CTX_OFF = 0x91                   # the a4 = PAY conjugation
DEFAULT_LIST_OFF = 0xA0
DEFAULT_SLOT0 = 1                        # the wrap law: the slots >= 1 used
DEFAULT_CAP = 0x40

MODES = ("surgical", "scatter")


class BuildRefused(Exception):
    """The gate / the geometry refusal — machine-readable, exit 2."""


# ---- the gate (IN CODE) --------------------------------------------------
def check_gate(verdict_doc):
    """The v454c verdict doc → (the target dict or the refusal). THE
    mission's guard: without a POWER-BASE-MATCH row, the payload =
    REFUSED."""
    if verdict_doc is None:
        raise BuildRefused("REFUS: aucun verdict v454c — la sonde 454 "
                           "n'a pas couru (le garde en code)")
    lane = verdict_doc.get("write_lane", "")
    target = verdict_doc.get("write_target")
    if target is None:
        raise BuildRefused(f"REFUS: {lane or 'write_target = null'} — "
                           "pas de rangée POWER-BASE-MATCH (le garde en "
                           "code)")
    if str(lane).startswith("REFUSED"):
        raise BuildRefused(f"REFUS: {lane}")
    if not target.get("value_280w_dec") == VALUE_280W:
        raise BuildRefused("REFUS: la cible nommée ne porte pas la valeur "
                           f"280 W attendue ({VALUE_280W})")
    return target


def check_targets_vs_map(block_base, n_slots, map_doc):
    """The O5 map consumption: the touched rows must EXIST as the map
    candidates (the address candidates = never invented). Returns the
    per-row flags (the found / INDECIDABLE notes)."""
    if not map_doc:
        return {"map": "absent — les cibles = non vérifiées contre la "
                       "carte (INDECIDABLE)", "rows": []}
    known = {r["offset"]: r for r in map_doc.get("rows", [])}
    known.update({r["offset"]: r for r in map_doc.get("additions_4_56", [])})
    rows, missing = [], []
    for k in range(n_slots):
        for off in (block_base + k * 8, block_base + k * 8 + 4):
            r = known.get(off)
            if r:
                rows.append({"offset": off, "in_map": True,
                             "map_name": r["name"],
                             "confidence": r["confidence"],
                             "verdict": r["verdict"]})
            else:
                missing.append(off)
                rows.append({"offset": off, "in_map": False,
                             "verdict": "NOT-IN-MAP"})
    return {"map": ("toutes les cibles touchées = des candidats de la "
                    "carte" if not missing else
                    f"{len(missing)} adresses touchées ABSENTES de la "
                    "carte — INDECIDABLE, le jour décide"), "rows": rows}


def build_write(mode="scatter", block_base=None, values=None,
                verdict_doc=None, map_doc=None,
                fill_len=112, hops=3, fill_value=0,
                base_addr=0x00000000016A000,
                ctx_off=DEFAULT_CTX_OFF, list_off=DEFAULT_LIST_OFF,
                counter_home=None):
    """The r2b payload + the doc. The geometry:

    scatter  a3=8, slot0=1, dest = B-8, the list = [V0..V7] — the ring
             covers [B+8..B+56] (the slots 2..8); the wild = [a1-residue]
             <- V0; the counter [B-8] += 8.
    surgical a3=1, slot0=1, dest = counter_home (REQUIRED — named-safe
             or explicitly INDECIDABLE), the list = [V]; the address =
             the a1-residue (the v454d A3 assumption).
    """
    if mode not in MODES:
        raise BuildRefused(f"REFUS: mode inconnu {mode!r}")
    target = check_gate(verdict_doc)

    if mode == "scatter":
        if block_base is None:
            raise BuildRefused("REFUS: --block requis (la base B du bloc "
                               "de 8 slots)")
        if block_base % 8 != 0:
            raise BuildRefused(f"REFUS: B = {block_base:#x} non aligné "
                               "u64 — la géométrie du ring l'exige")
        if not values or len(values) != 8:
            raise BuildRefused("REFUS: le scatter exige 8 valeurs "
                               "[V0..V7]")
        dest = block_base - 8
        slot0, cap = DEFAULT_SLOT0, DEFAULT_CAP
        a3 = 8
        ring_addrs = [dest + (slot0 + 1 + k) * 8 for k in range(7)]
        block_addrs = [block_base + k * 8 for k in range(8)]
        if ring_addrs != block_addrs[1:]:
            raise BuildRefused("REFUS: la géométrie du ring ne couvre pas "
                               "le bloc (l'invariant interne)")
    else:
        if not values or len(values) != 1:
            raise BuildRefused("REFUS: le surgical exige 1 valeur")
        dest = counter_home
        if dest is None:
            raise BuildRefused("REFUS: le surgical exige --counter-home "
                               "(le cellule compteur = [dest] += 1 — "
                               "nommée-safe ou INDECIDABLE assumé)")
        slot0, cap = DEFAULT_SLOT0, DEFAULT_CAP
        a3 = 1
        ring_addrs, block_addrs = [], []

    for off in ([dest] + [a for a in ring_addrs]):
        if not (0 < off < BAR0_MAX):
            raise BuildRefused(f"REFUS: l'adresse {off:#x} hors BAR0 — "
                               "jamais (la loi v454d)")

    tmap = check_targets_vs_map(block_base if mode == "scatter" else dest,
                                8 if mode == "scatter" else 1, map_doc)

    payload, meta = V446.build_chain(
        fill_len=fill_len, hops=hops, fill_value=fill_value,
        slot0=slot0, cap=cap, dest=dest,
        base_addr=base_addr, valeurs=tuple(values),
        ctx_off=ctx_off, list_off=list_off)

    A4 = base_addr + ctx_off * 8 - 0x488     # the TR-2 conjugation
    doc = {
        "instrument": "v447_rop_write_build",
        "mode": mode, "a3": a3,
        "gate": {"verdict_target": target,
                 "verdict_synthetic": bool(verdict_doc.get("synthetic")),
                 "rule": "POWER-BASE-MATCH row required (v454c) — the "
                         "guard IN CODE"},
        "geometry": {
            "block_base": (hex(block_base) if mode == "scatter" else None),
            "ctx": {"slot0": slot0, "cap": cap, "dest": hex(dest),
                    "magic": 8, "ctx_off": ctx_off},
            "a4_conjugation": hex(A4),
            "list_off": list_off, "n_values": len(values),
            "ring_addrs": [hex(a) for a in ring_addrs],
            "counter_cell": hex(dest),
            "counter_effect": f"[{dest:#x}] += {a3} (u64 RMW — the read "
                              "side effect INCLUDED)",
        },
        "honesty": {
            "wild_write": ("[a1-residue] <- V0 — the ROM residue (W1/W2): "
                           "INDECIDABLE until the day's R0/R2 discovery; "
                           "IF the residue = B (the A3-favorable) the "
                           "first target lands" if mode == "scatter" else
                           "[a1-residue] <- V with a1 = the RAW offset "
                           "(the v454d A3 assumption — the day verifies)"),
            "slot1_hole": ("the slot 1 = [dest+8] = [B] = skipped by the "
                           "ring (the ring = the slots 2..8) — covered "
                           "ONLY IF the wild's residue = B"
                           if mode == "scatter" else "n/a"),
            "plus4_neighbors": ([hex(block_base + k * 8 + 4) for k in
                                 range(8)] if mode == "scatter" else
                                ["the +4 of the a1-residue address"]),
            "align8": ("INDECIDABLE-BY-BYTES (the misaligned u64 store "
                       "behavior on the GSP data space — the v454d law)")
                        if (block_base or 0) % 8 else
                        "B aligned u64 — the STORE width itself stays "
                        "INDECIDABLE (the u64 vs 2x u32 decode)",
            "map_cross": tmap,
        },
        "payload_meta": meta,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }
    return payload, doc


def emit_c(payload, symbol="v447_payload"):
    return V446.emit_c(payload, symbol=symbol)


# ---- the synthetic verdict fixture (the SAME code path, tagged) ---------
def synthetic_verdict(offset=0x00823814):
    """The gate fixture: the POWER-BASE-MATCH verdict form the v454c
    analyzer emits — SYNTHETIC-tagged, for the selftest/TR-3 only."""
    return {"instrument": "v454c_shape_match", "mode": "SYNTHETIC-FIXTURE",
            "synthetic": True,
            "write_target": {"offset": offset, "name": "SYNTH",
                             "stock_value": f"0x{V454A.SHAPE_250_UW:08x}",
                             "value_280w": f"0x{VALUE_280W:08X}",
                             "value_280w_dec": VALUE_280W,
                             "found_via": "SYNTHETIC"},
            "write_lane": ("NAMED — the synthetic fixture (the same code "
                           "path)")}


def refused_verdict():
    return {"instrument": "v454c_shape_match", "mode": "SYNTHETIC-FIXTURE",
            "synthetic": True, "write_target": None,
            "write_lane": "REFUSED — no POWER-BASE-MATCH row"}


# ---- the selftest --------------------------------------------------------
def selftest():
    import subprocess
    ok, fail = 0, 0

    def check(label, cond, detail=""):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label} {detail}")

    synth = synthetic_verdict()
    rvd = refused_verdict()
    map_doc = V456C.build_map()

    # -- 1. THE GATE (the mission's guard, in code) -----------------------
    refused = 0
    for kw, doc in (("no-verdict", None), ("null-target", rvd)):
        try:
            build_write(mode="scatter", block_base=0x00823810,
                        values=[VALUE_280W] * 8, verdict_doc=doc)
        except BuildRefused:
            refused += 1
    check("porte: sans verdict / cible nulle → REFUS 2/2", refused == 2)
    try:
        build_write(mode="scatter", block_base=0x00823810,
                    values=[VALUE_280W] * 8, verdict_doc=synth)
        gate_ok = True
    except BuildRefused:
        gate_ok = False
    check("porte: la rangée synthétique POWER-BASE-MATCH → le build "
          "passe (le MÊME code path)", gate_ok)

    # -- 2. the scatter geometry (the 8-writes-at-B+8k conjugation) -------
    B = 0x00823810
    p, d = build_write(mode="scatter", block_base=B,
                       values=[VALUE_280W] * 8, verdict_doc=synth,
                       map_doc=map_doc)
    w = [int.from_bytes(p[i * 8:(i + 1) * 8], "little")
         for i in range(N_WORDS)]
    check("scatter: le ctx dest = B-8 (0x00823808), slot0=1, cap=0x40",
          d["payload_meta"]["dest"] == B - 8
          and d["payload_meta"]["slot0"] == 1
          and d["payload_meta"]["cap"] == 0x40)
    check("scatter: la liste = [V0..V7] @0xA0 (8 u64 = 280 W chacun)",
          all(w[DEFAULT_LIST_OFF + k] == VALUE_280W for k in range(8)))
    check("scatter: le ring couvre [B+8..B+56] (les slots 2..8)",
          [int(a, 16) for a in d["geometry"]["ring_addrs"]]
          == [B + 8 * k for k in range(1, 8)])
    check("scatter: la cellule compteur = [B-8] += 8 (le RMW nommé)",
          d["geometry"]["counter_cell"] == hex(B - 8)
          and "+= 8" in d["geometry"]["counter_effect"])
    check("scatter: la conjugaison a4 = PAY + ctx_off*8 - 0x488 "
          "(la loi TR-2)",
          d["geometry"]["a4_conjugation"]
          == hex(0x16A000 + DEFAULT_CTX_OFF * 8 - 0x488))
    check("scatter: les 8 voisins +4 nommés (les u32 zéro-étendus)",
          len(d["honesty"]["plus4_neighbors"]) == 8
          and d["honesty"]["plus4_neighbors"][0] == hex(B + 4))
    check("scatter: le trou du slot 1 nommé ([B] couvert SEULEMENT si "
          "le résidu = B)", "slot 1" in d["honesty"]["slot1_hole"])

    # -- 3. the surgical geometry (the v454d continuity) -------------------
    p2, d2 = build_write(mode="surgical", values=[VALUE_280W],
                         verdict_doc=synth, counter_home=0x008200fc,
                         map_doc=map_doc)
    check("surgical: a3=1, la liste = [V], le compteur = la maison "
          "nommée", d2["a3"] == 1
          and d2["geometry"]["counter_cell"] == "0x8200fc")
    refused = 0
    try:
        build_write(mode="surgical", values=[VALUE_280W],
                    verdict_doc=synth)
    except BuildRefused:
        refused = 1
    check("surgical: sans --counter-home → REFUS (la cellule compteur "
          "ne se choisit jamais en silence)", refused == 1)

    # -- 4. the refusals of geometry ---------------------------------------
    refused = 0
    for kw in (dict(block_base=0x00823814),                 # B % 8 != 0
               dict(block_base=B, values=[VALUE_280W] * 3),  # != 8 valeurs
               dict(mode="surgical", values=[1, 2])):        # != 1 valeur
        try:
            kw.setdefault("mode", "scatter")
            kw.setdefault("verdict_doc", synth)
            if "values" in kw and kw["mode"] == "scatter":
                kw.setdefault("block_base", B)
            build_write(**{**kw, "values": kw.get(
                "values", [VALUE_280W] * 8 if kw["mode"] == "scatter"
                else [VALUE_280W])})
        except BuildRefused:
            refused += 1
    check("refus: B non aligné / le compte de valeurs faux → REFUS 3/3",
          refused == 3)
    refused = 0
    try:
        build_write(mode="scatter", block_base=0x01000000,
                    values=[VALUE_280W] * 8, verdict_doc=synth)
    except BuildRefused:
        refused = 1
    check("refus: hors BAR0 (0x01000000 >= 16 MB) → REFUS (la loi v454d)",
          refused == 1)

    # -- 5. the map consumption (les paires DEPUIS T1) ---------------------
    check("carte: les cibles du bloc = des candidats de la carte "
          "(FUSE/PFB)",
          d["honesty"]["map_cross"]["rows"]
          and all(r["in_map"] for r in d["honesty"]["map_cross"]["rows"]),
          d["honesty"]["map_cross"]["map"][:60])
    check("carte: le verdict INDECIDABLE porté par rangée",
          all(r["verdict"] == "GA104-DECODE-INDECIDABLE-BY-BYTES"
              for r in d["honesty"]["map_cross"]["rows"]))

    # -- 6. the byte-exact C (the 4.44 lesson) ------------------------------
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "payload.h").write_text(emit_c(p))
        (td / "main.c").write_text(
            '#include <stdio.h>\n#include "payload.h"\n'
            "int main(void){ for (int i=0;i<V446_PAYLOAD_SIZE;i++) "
            'printf("%02x", v447_payload[i]); return 0; }\n')
        r = subprocess.run(["gcc", "-I", str(td), str(td / "main.c"),
                            "-o", str(td / "dump")], capture_output=True)
        if r.returncode != 0:
            check("C byte-exact: gcc", False, r.stderr.decode()[:120])
        else:
            dump = bytes.fromhex(subprocess.run(
                [str(td / "dump")], capture_output=True,
                text=True).stdout.strip())
            check("C byte-exact: le dump == le python", dump == p,
                  f"{len(dump)} B sha {d['sha256'][:12]}…")

    # -- 7. the freshness: the v446 selftest = the substrate intact -------
    r = subprocess.run(["python3", str(HERE / "v446_rop_payload_build.py"),
                        "--selftest"], capture_output=True, text=True)
    last = [l for l in r.stdout.strip().splitlines() if l][-1]
    check("fraîcheur: le selftest v446 = 28/28 (le substrat intact)",
          r.returncode == 0 and "28/28" in last, last)

    print(f"selftest v447: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--verdict", metavar="FILE",
                    help="the v454c verdict doc (the gate)")
    ap.add_argument("--map", metavar="FILE",
                    help="the v456c O5 map doc (the target cross)")
    ap.add_argument("--mode", default="scatter", choices=MODES)
    ap.add_argument("--block", metavar="HEX",
                    help="the block base B (the scatter)")
    ap.add_argument("--values", metavar="UW", nargs="+", type=int,
                    help="the values (µW) — 1 (surgical) or 8 (scatter)")
    ap.add_argument("--counter-home", metavar="HEX", type=lambda x: int(x, 0))
    ap.add_argument("--emit-c", metavar="FILE")
    ap.add_argument("--out", metavar="FILE")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    try:
        verdict = (json.loads(Path(args.verdict).read_text())
                   if args.verdict else None)
        map_doc = (json.loads(Path(args.map).read_text())
                   if args.map else None)
        payload, doc = build_write(
            mode=args.mode,
            block_base=(int(args.block, 16) if args.block else None),
            values=(args.values if args.values else None),
            verdict_doc=verdict, map_doc=map_doc,
            counter_home=args.counter_home)
    except BuildRefused as e:
        print(f"[v447] {e}")
        return 2

    if args.out:
        Path(args.out).write_bytes(payload)
    if args.emit_c:
        Path(args.emit_c).write_text(emit_c(payload))
    print(f"[v447] {args.mode} a3={doc['a3']} "
          f"sha256 {doc['sha256'][:16]}… {doc['size']} B")
    print(f"[v447] le compteur: {doc['geometry']['counter_effect']}")
    print(f"[v447] le sauvage: {doc['honesty']['wild_write'][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
