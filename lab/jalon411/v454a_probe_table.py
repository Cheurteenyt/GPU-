#!/usr/bin/env python3
"""v454a — THE READ-PROBE CANDIDATE TABLE (the 4.54 read lane, the O5
first gesture made executable).

The 4.53 findings §5 named the READ PROBE = the first gesture
NON-NEGOTIABLE (the write-test = REFUSED without a read-test row).
THIS instrument builds the candidate offset table — every row SOURCED,
never invented:

  SRC-PATCH  the cmpunlocker reference (imports/cmpunlocker/
             sec2-postbl.patch) — the GA100/CMP-170HX silicon-proven
             pipeline. Parsed FROM THE PATCH BYTES (the exact members,
             not plausible names): the PLM table (11 registers), the
             WPR2 save/restore window (2), the host config writes (4).
             ack_class = SAFE-PROBE (the same READ gesture the patch
             itself performs post-write on GA100).
  SRC-NB     the bounded neighborhoods around the POWER-DOMAIN anchors
             (the 0x0082xxxx / 0x001fa7xx / 0x009axxxx blocks — where
             the patch's own power/PLM registers cluster), span ±0x40
             at a 4-byte stride, anchors themselves EXCLUDED (they are
             already SAFE rows). ack_class = RISK-PROBE (unknown
             registers CAN be read-sensitive: FIFO pops, R1C forms) —
             the opt-in tier, gated by PROBE_454_NB=1 at probe time,
             each offset read EXACTLY ONCE (no polling, no repeats).
  The XVE / PJTAG / LMR neighborhoods = OUT OF SCOPE (the security-
  adjacent blocks — the scope discipline; the marker hunt targets the
  power domain only).

THE SHAPE-MATCH DISCIPLINE (the decision criterion, byte-grounded):
our card = 250 W stock => a u32 register reading 0x0EE6B280 =
250000000 µW = the POWER-BASE register DECODED on GA104 (the 4.44
formula: limit = base × f18/100/1000). The values asserted EXACT in
the selftest (250000000 = 0x0EE6B280, 240000000 = 0x0E4E1C00,
280000000 = 0x10B07600 — computed, never guessed).

GATED BY DEFAULT: the instrument only BUILDS the table (no hardware
touch — it cannot, it reads no device). The consumer = v454b (the
probe) which carries the ACK gate. The selftest runs first, ALWAYS
(the v451a lesson: the format synthesized and tested BEFORE the real
parse — the synthetic patch exercises the parser's every branch).

Run:  python3 v454a_probe_table.py [--out v454a_probe_table.json]
                                    [--nb-span 0x40]
Output: the JSON table {rows, counts, provenance, gate}
Exit: 0 iff the selftest passes AND the table built.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / "imports" / "cmpunlocker" / "sec2-postbl.patch"

NB_SPAN_DEFAULT = 0x40          # ±0x40 around each NB anchor
NB_STRIDE = 4                   # the u32 register stride
BAR0_MAX = 0x1000000            # 16 MB — the NVIDIA BAR0 form

# The power-domain blocks where the NB scan is IN scope (the patch's
# own power/PLM cluster). Everything else (XVE 0x00088xxx, PJTAG
# 0x0000c8xx, LMR 0x00100ce0) = out of scope, named.
NB_IN_SCOPE_BLOCKS = (
    (0x00820000, 0x00830000),   # FEAT / FEAT2 / OPT_PLM / SS0 / SS1
    (0x001fa000, 0x001fb000),   # WPR_CFG / WPR / the WPR2 window
    (0x009a0000, 0x009b0000),   # FBPA / CFG1
)

# The exact expected rows (the tree guard — the patch bytes re-asserted
# against the constants committed by the 4.53 findings §5 table).
EXPECT_PLM = [
    (0x001fa7cc, "WPR_CFG"),
    (0x009a0148, "FBPA"),
    (0x001fa7c4, "WPR"),
    (0x00823804, "FEAT"),
    (0x00088ff4, "XVE"),
    (0x00088ab4, "XVE_B"),
    (0x00088ff8, "XVE_C"),
    (0x00823b00, "FEAT2"),
    (0x008200fc, "OPT_PLM"),
    (0x0000c840, "PJTAG_PLM"),
    (0x0000c848, "PJTAG_SEC_PLM"),
]
EXPECT_WPR2 = [0x001fa824, 0x001fa828]
EXPECT_CFG = [
    (0x0082381c, "SS0"),
    (0x00823820, "SS1"),
    (0x009a0204, "CFG1"),
    (0x00100ce0, "LMR"),
]

# The shape values (asserted EXACT here — the single source for v454c
# which IMPORTS them; zero re-transcription across the v454 lane).
SHAPE_250_UW = 250000000
SHAPE_240_UW = 240000000
SHAPE_280_UW = 280000000
assert SHAPE_250_UW == 0x0EE6B280, hex(SHAPE_250_UW)
assert SHAPE_240_UW == 0x0E4E1C00, hex(SHAPE_240_UW)
assert SHAPE_280_UW == 0x10B07600, hex(SHAPE_280_UW)


class ParseError(Exception):
    pass


# ---- SRC-PATCH: the parser (the patch bytes = the single source) ----

def parse_patch(txt, expect_plm=11):
    """Extract the register rows FROM the patch text.

    Returns dict {plm: [(addr, name)...], wpr2: [addr...], cfg: [(addr,
    name)...]} — every value from the patch's own C code, never from a
    re-transcription. Raises ParseError when a section is missing (the
    tree changed = REFUSE, never guess). expect_plm = the count guard
    (11 = the real patch — the synthesis passes its own count).
    """
    out = {"plm": [], "wpr2": [], "cfg": []}

    # the plmTable[] C array — { 0xADDRU, 0xVALUEU, "NAME" },
    m = re.search(r"plmTable\[\]\s*=\s*\{(.*?)\};", txt, re.S)
    if not m:
        raise ParseError("plmTable[] introuvable dans le patch")
    for addr, name in re.findall(
            r"\{\s*(0x[0-9a-fA-F]+)U,\s*0x[0-9a-fA-F]+U,\s*\"([A-Z0-9_]+)\"\s*\}",
            m.group(1)):
        out["plm"].append((int(addr, 16), name))
    if len(out["plm"]) != expect_plm:
        raise ParseError(
            f"plmTable: {len(out['plm'])} lignes != {expect_plm} "
            "(le patch a changé)")

    # the WPR2 save/restore window — GPU_REG_RD32(pGpu, 0x001fa824U/…828U)
    wpr2 = sorted(set(int(a, 16) for a in re.findall(
        r"GPU_REG_RD32\(pGpu,\s*(0x001fa8(?:24|28))U\)", txt)))
    if len(wpr2) != 2:
        raise ParseError(f"WPR2 window: {len(wpr2)} != 2 registres")
    out["wpr2"] = wpr2

    # the host config — GPU_REG_WR32(pGpu, 0xADDRU, <value>) inside the
    # SS0/SS1/CFG1/LMR block (the 4-write run, the CMP devID forms).
    # The value = a hex constant (SS0/SS1) OR a variable (CFG1/LMR
    # — cfg1Value/lmrValue in the patch) — the SELFTEST caught the
    # constant-only form: 2 != 4 (the bug before the founder).
    wr = re.findall(
        r"GPU_REG_WR32\(pGpu,\s*(0x[0-9a-fA-F]+)U,\s*"
        r"(?:0x[0-9a-fA-F]+U|[A-Za-z_][A-Za-z0-9_]*U?)\)", txt)
    cfg_names = {0x0082381c: "SS0", 0x00823820: "SS1",
                 0x009a0204: "CFG1", 0x00100ce0: "LMR"}
    seen = []
    for a in wr:
        ai = int(a, 16)
        if ai in cfg_names and ai not in seen:
            seen.append(ai)
    if len(seen) != 4:
        raise ParseError(f"config host: {len(seen)} != 4 registres WR32")
    out["cfg"] = [(a, cfg_names[a]) for a in seen]
    return out


def build_rows(nb_span=NB_SPAN_DEFAULT):
    """Assemble the full table: SAFE rows from the patch, RISK rows from
    the bounded power-domain neighborhoods."""
    if not PATCH.is_file():
        raise ParseError(f"patch introuvable: {PATCH}")
    parsed = parse_patch(PATCH.read_text(errors="replace"))

    rows = []
    for addr, name in parsed["plm"]:
        rows.append({"offset": addr, "name": name, "source": "PATCH-PLM",
                     "ack_class": "SAFE-PROBE",
                     "note": "the cmpunlocker PLM table (GA100)"})
    for addr in parsed["wpr2"]:
        rows.append({"offset": addr, "name": f"WPR2_{addr:08x}",
                     "source": "PATCH-WPR2", "ack_class": "SAFE-PROBE",
                     "note": "the WPR2 save/restore window"})
    for addr, name in parsed["cfg"]:
        rows.append({"offset": addr, "name": name, "source": "PATCH-CFG",
                     "ack_class": "SAFE-PROBE",
                     "note": "the host config write (the CMP devID forms)"})

    safe_offsets = {r["offset"] for r in rows}

    # SRC-NB: the bounded neighborhoods, the power-domain blocks only.
    anchors = sorted(a for a, _ in parsed["plm"]
                     + parsed["cfg"]
                     if any(lo <= a < hi for lo, hi in NB_IN_SCOPE_BLOCKS))
    nb = []
    for anchor in anchors:
        for d in range(-nb_span, nb_span + 1, NB_STRIDE):
            if d == 0:
                continue
            off = anchor + d
            if off < 0 or off + NB_STRIDE > BAR0_MAX:
                continue          # hors BAR0 — REFUSE, never wrap
            if not any(lo <= off < hi for lo, hi in NB_IN_SCOPE_BLOCKS):
                continue          # the block edge — stay in scope
                # (the selftest caught the any(not(...)) quantifier bug:
                #  an offset in ONE block is absent from the OTHER two
                #  — the old form skipped EVERYTHING, 0 anchors)
            if off in safe_offsets:
                continue          # already a SAFE row — the anchors excluded
            if any(r["offset"] == off for r in nb):
                continue          # the overlap of two neighborhoods
            nb.append({"offset": off, "name": f"NB({d:+#x}@{anchor:08x})",
                       "source": f"NB±{nb_span:#x}@{anchor:08x}",
                       "ack_class": "RISK-PROBE",
                       "note": "the bounded neighborhood (read once, opt-in)"})
    rows.extend(nb)
    return rows, parsed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true",
                    help="the selftest only (main runs it anyway)")
    ap.add_argument("--out", default="lab/jalon411/v454a_probe_table.json")
    ap.add_argument("--nb-span", type=lambda x: int(x, 0),
                    default=NB_SPAN_DEFAULT,
                    help="the neighborhood span (default 0x40)")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    # the selftest FIRST, always (the v451a lesson)
    if not selftest():
        print("SELFTEST FAILED — the table refuses to build", file=sys.stderr)
        return 1

    rows, parsed = build_rows(args.nb_span)

    counts = {"SAFE-PROBE": sum(1 for r in rows
                                if r["ack_class"] == "SAFE-PROBE"),
              "RISK-PROBE": sum(1 for r in rows
                                if r["ack_class"] == "RISK-PROBE")}
    doc = {
        "instrument": "v454a_probe_table",
        "gate": ("the offsets ONLY — no hardware touch here; the ACK "
                 "gates live in v454b (PROBE_454_ACK=1, PROBE_454_NB=1)"),
        "provenance": {
            "SRC-PATCH": str(PATCH.relative_to(ROOT)),
            "SRC-NB": (f"±{args.nb_span:#x} @ the power-domain anchors, "
                       "stride 4, read-once, opt-in"),
            "out-of-scope": ("the XVE/PJTAG/LMR neighborhoods (the "
                             "security-adjacent blocks)"),
        },
        "counts": counts,
        "nb_span": args.nb_span,
        "rows": rows,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n")

    print(f"[v454a] rows: {len(rows)} "
          f"(SAFE {counts['SAFE-PROBE']} / RISK {counts['RISK-PROBE']}) "
          f"-> {out}")
    print(f"[v454a] the marker hunt: 0x0EE6B280 = {SHAPE_250_UW} µW "
          f"(250 W stock) — the POWER-BASE decoded on GA104")
    return 0


# ---- the selftest: every branch executed (the v451a/4.51 lessons) ----

def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    # -- 1. the format synthesis: a synthetic patch, the parser exact ---
    synth = """
        static const struct { NvU32 addr; NvU32 value; const char *name; } plmTable[] = {
            { 0x00001000U, 0xffffffffU, "AAA" },
            { 0x00002000U, 0xffffffffU, "BBB" },
            { 0x00003000U, 0xffffffffU, "CCC" },
        };
        NvU32 wpr2Lo = GPU_REG_RD32(pGpu, 0x001fa824U);
        NvU32 wpr2Hi = GPU_REG_RD32(pGpu, 0x001fa828U);
        GPU_REG_WR32(pGpu, 0x001fa824U, wpr2Lo);
        GPU_REG_WR32(pGpu, 0x001fa828U, wpr2Hi);
        GPU_REG_WR32(pGpu, 0x0082381cU, 0x88888888U);
        GPU_REG_WR32(pGpu, 0x00823820U, 0x00000008U);
        GPU_REG_WR32(pGpu, 0x009a0204U, cfg1Value);
        GPU_REG_WR32(pGpu, 0x00100ce0U, lmrValue);
    """
    try:
        s = parse_patch(synth, expect_plm=3)
        check("synth: 3 PLM extraites", len(s["plm"]) == 3
              and s["plm"][0] == (0x1000, "AAA")
              and s["plm"][2] == (0x3000, "CCC"))
        check("synth: WPR2 = les 2 registres", s["wpr2"] == [0x001fa824, 0x001fa828])
        check("synth: config = 4 WR32 dédupliqués",
              [a for a, _ in s["cfg"]] == [0x0082381c, 0x00823820,
                                            0x009a0204, 0x00100ce0])
    except ParseError as e:
        check(f"synth: le parse échoue ({e})", False)

    # -- 2. the malformed patch refuses (never guesses) ------------------
    for bad, label in [(synth.replace("plmTable", "plmTableX"), "sans plmTable"),
                       (synth.replace('0x00002000U, 0xffffffffU, "BBB" },\n', "")
                             .replace("0x00001000U", "0x1000U")
                             .replace("0x00003000U", "0x3000U"), "2 PLM != 3")]:
        try:
            parse_patch(bad, expect_plm=3)
            check(f"malformé ({label}): REFUSÉ", False)
        except ParseError:
            check(f"malformé ({label}): REFUSÉ", True)

    # -- 3. the REAL parse = the tree guard (the exact 17 patch rows) ----
    try:
        real = parse_patch(PATCH.read_text(errors="replace"))
        check("réel: 11 PLM = les addresses EXACTES",
              real["plm"] == EXPECT_PLM)
        check("réel: WPR2 = 0x001fa824/0x001fa828",
              real["wpr2"] == EXPECT_WPR2)
        check("réel: config = SS0/SS1/CFG1/LMR EXACTS",
              real["cfg"] == EXPECT_CFG)
        # the order = the patch's own (WPR_CFG, FBPA, WPR, FEAT, XVE...)
        check("réel: l'ordre du patch préservé (WPR_CFG 1er)",
              real["plm"][0] == (0x001fa7cc, "WPR_CFG"))
    except ParseError as e:
        check(f"réel: le parse échoue ({e})", False)

    # -- 4. the table build: the classes, the geometry, the invariants ---
    try:
        rows, _ = build_rows(NB_SPAN_DEFAULT)
        safe = [r for r in rows if r["ack_class"] == "SAFE-PROBE"]
        risk = [r for r in rows if r["ack_class"] == "RISK-PROBE"]
        check("table: 17 SAFE = 11 PLM + 2 WPR2 + 4 CFG", len(safe) == 17)
        check("table: RISK > 0 (les voisinages présents)", len(risk) > 0)
        check("table: tout offset aligné u32",
              all(r["offset"] % NB_STRIDE == 0 for r in rows))
        check("table: tout offset dans BAR0",
              all(0 <= r["offset"] < BAR0_MAX for r in rows))
        check("table: ZÉRO doublon",
              len({r["offset"] for r in rows}) == len(rows))
        # the NB = in-scope blocks ONLY (XVE/PJTAG/LMR neighborhoods absent)
        def in_scope(o):
            return any(lo <= o < hi for lo, hi in NB_IN_SCOPE_BLOCKS)
        nb_all_in = all(in_scope(r["offset"]) for r in risk)
        check("table: RISK = les blocs power SEULEMENT", nb_all_in)
        # the NB excludes the anchors themselves + all SAFE rows
        check("table: RISK n'écrase aucun SAFE",
              not ({r["offset"] for r in risk} & {r["offset"] for r in safe}))
        # the NB geometry: the dedup means one offset = ONE row named by
        # the FIRST anchor claiming it (FEAT/SS0/SS1 windows OVERLAP) —
        # the honest invariants = the coverage (nothing lost) + the
        # attribution (offset == anchor + delta, checked independently
        # against EXPECT_* — not against the builder's own code path).
        anchors_expected = sorted(
            a for a, _ in EXPECT_PLM + EXPECT_CFG
            if any(lo <= a < hi for lo, hi in NB_IN_SCOPE_BLOCKS))
        safe_offs = {r["offset"] for r in safe}
        covered = {r["offset"] for r in risk}
        cov_ok = True
        for a in anchors_expected:
            for d in range(-NB_SPAN_DEFAULT, NB_SPAN_DEFAULT + 1, NB_STRIDE):
                if d == 0:
                    continue
                off = a + d
                if not any(lo <= off < hi for lo, hi in NB_IN_SCOPE_BLOCKS):
                    continue
                if off in safe_offs:
                    continue
                if off not in covered:
                    cov_ok = False
        check(f"table: la couverture NB complète "
              f"({len(anchors_expected)} ancres)", cov_ok)
        attr_ok = True
        for r in risk:
            m = re.match(r"NB\(([+-]0x[0-9a-fA-F]+)@([0-9a-f]{8})\)",
                         r["name"])
            if not m or int(m.group(1), 16) + int(m.group(2), 16) != r["offset"]:
                attr_ok = False
        check("table: l'attribution NB (off == ancre + delta)", attr_ok)
    except ParseError as e:
        check(f"table: le build échoue ({e})", False)

    # -- 5. the shapes: computed, EXACT (the single source for v454c) ----
    check("formes: 250000000 == 0x0EE6B280", SHAPE_250_UW == 0x0EE6B280)
    check("formes: 240000000 == 0x0E4E1C00", SHAPE_240_UW == 0x0E4E1C00)
    check("formes: 280000000 == 0x10B07600", SHAPE_280_UW == 0x10B07600)

    # -- 6. the JSON round-trip ------------------------------------------
    try:
        rows, _ = build_rows(NB_SPAN_DEFAULT)
        blob = json.dumps({"rows": rows})
        back = json.loads(blob)["rows"]
        check("JSON: le round-trip identique", back == rows)
    except (ParseError, TypeError):
        check("JSON: le round-trip échoue", False)

    print(f"selftest v454a: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


if __name__ == "__main__":
    sys.exit(main())
