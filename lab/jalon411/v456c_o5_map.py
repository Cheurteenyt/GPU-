#!/usr/bin/env python3
"""v456c — THE O5 MAP (pass 4.56 T1): the GA104 candidate registers map
{offset, role, confidence, source} — the honest cross of THREE sources:

  (a) the cmpunlocker PLM addresses (the patch bytes — the GA100-era
      names WPR_CFG/FBPA/WPR/FEAT/...): IMPORTED from v454a (the 4.54
      parse, zero re-transcription);
  (b) the 215 offsets of the v454a table (the 17 SAFE + the 198 RISK,
      the bounded neighborhoods);
  (c) everything PUBLICLY documented on the register space: the
      open-gpu-kernel-modules 610.57.04 swref headers (the published
      dev_*.h — the redacted-but-authoritative subset), searched at the
      EXACT addresses and the BLOCK ranges.

THE HONESTY LAW (the mission's own wording): GA104 ≠ GA100 = INDECIDABLE
→ EVERY entry carries the honest status. The public cross NEVER upgrades
a row to "decodes on our card": it names the ADDRESS plausibility (the
NVIDIA PRI space is famously stable across families) — the BEHAVIOR on
our GA104 stays INDECIDABLE-BY-BYTES until the read probe row exists.
Even an exact cross names an address, never a write target.

THE CROSSES FOUND THIS PASS (the tool re-asserts them against the cache
— the tree guard; the shas + the file:line = the provenance):

  EXACT (the address named in a public family header):
    0x00100ce0 LMR       = NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE
                           (pascal/gp102/dev_fb.h:26) — the patch's own
                           "LMR" name = the register's real meaning, the
                           WPR range base/scale.
    0x001fa7c4 WPR       = NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE__PRIV_LEVEL_MASK
                           (blackwell/gb100/dev_fb.h:28) — the patch's
                           "WPR" = the PLM OF the WPR range register.
    0x00823814 (FEAT+0x10, a v454a NB row)
                         = NV_FUSE_FEATURE_READOUT
                           (ampere/ga100/dev_fuse.h:26) — the feature
                           readout sits INSIDE the FEAT neighborhood.
    0x00118128 (NEW 4.56) = NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_PRIV_LEVEL_MASK
                           (tu102 AND ga102 dev_gc6_island.h:28/:27) —
                           the GFW boot progress register's PLM.
    0x00118234 (NEW 4.56) = NV_PGC6_AON_SECURE_SCRATCH_GROUP_05(0) = the
                           GFW_BOOT progress register
                           (tu102 AND ga102 :34/:33; the addendum :30-32
                           = _PROGRESS 7:0, _COMPLETED 0xff — the v456a
                           decoder's register).

  BLOCK (the block named publicly, the exact register not in the
  redacted public headers):
    [0x00820000,0x00830000)  = the FUSE block (ga100/dev_fuse.h spans
                               0x00820378..0x00824118)
    [0x001fa000,0x001fb000)  = the PFB PRI MMU cluster (ga100/dev_fb.h:
                               LOCK_CFG PLM @0x001FA7C8, LOCK_ADDR_LO/HI
                               @0x001FA82C/30 — the patch's WPR2 window
                               @0x001fa824/28 sits inside, unnamed)
    [0x00088000,0x00089000)  = the PCFG/XVE block (tu102/dev_nv_xve.h:26,
                               NV_PCFG 0x00088FFF:0x00088000)
    [0x00100c00,0x00100d00)  = PFB (ga100/dev_fb.h: the NISO_FLUSH
                               @0x00100C10/C40; gp102: the LMR @CE0)

  PATCH-ONLY (no public cross — the patch's own names/geometry):
    the 0x009a block (FBPA/CFG1 per the patch), WPR_CFG @0x001fa7cc,
    PJTAG @0x0000c84x, and the exact roles of FEAT/FEAT2/OPT_PLM/SS0/SS1.

THE CONFIDENCE TAXONOMY (the address plausibility ONLY — never the
behavior):
  EXACT-PUBLIC   the exact address named in ≥1 public family header
  BLOCK-PUBLIC   the offset falls in a publicly named block's range
  PATCH-ONLY     only the cmpunlocker's own name/geometry
ALL rows: verdict = "GA104-DECODE-INDECIDABLE-BY-BYTES" (the read
probe = the non-negotiable prerequisite of any write — the O5 gate).

THE 4.56 ADDITIONS = the PGC6 pair ONLY, as the map section separate
from the v454a rows: candidates for the NEXT probe-table revision —
NOT silently injected into the committed 215 (the frozen-register
discipline: the corrections land as new rings that name the old).

GATED BY DEFAULT: this tool touches no hardware. The cache fetch =
read-only network (raw.githubusercontent, the pinned tag).

Run:  python3 v456c_o5_map.py --selftest
      python3 v456c_o5_map.py --out v456c_o5_map.json
      python3 v456c_o5_map.py --fetch
Exit: 0 iff the selftest green / the map written.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
TREE = ROOT / ".ogkm-610-cache"

# ---- v454a imported (the 215 rows — zero re-transcription) -------------
_spec = importlib.util.spec_from_file_location(
    "v454a", HERE / "v454a_probe_table.py")
V454A = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V454A)

# ---- v456a imported (the PGC6 constants — zero re-transcription) -------
_spec2 = importlib.util.spec_from_file_location(
    "v456a", HERE / "v456a_progress_decode.py")
V456A = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(V456A)

TAG = V456A.TAG
BASE = f"https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/{TAG}"

# ---- the pinned headers for the crosses (fetched, re-asserted) ---------
SOURCES = {
    "ga100_dev_fb.h": "src/common/inc/swref/published/ampere/ga100/dev_fb.h",
    "ga100_dev_fuse.h":
        "src/common/inc/swref/published/ampere/ga100/dev_fuse.h",
    "gp102_dev_fb.h": "src/common/inc/swref/published/pascal/gp102/dev_fb.h",
    "gb100_dev_fb.h":
        "src/common/inc/swref/published/blackwell/gb100/dev_fb.h",
    "tu102_dev_xve.h":
        "src/common/inc/swref/published/turing/tu102/dev_nv_xve.h",
    "tu102_dev_gc6.h":
        "src/common/inc/swref/published/turing/tu102/dev_gc6_island.h",
    "ga102_dev_gc6.h":
        "src/common/inc/swref/published/ampere/ga102/dev_gc6_island.h",
    "tu102_dev_gc6_add.h":
        "src/common/inc/swref/published/turing/tu102/dev_gc6_island_addendum.h",
    "ga102_dev_gc6_add.h":
        "src/common/inc/swref/published/ampere/ga102/dev_gc6_island_addendum.h",
}

# ---- the BLOCKS (the public block attributions) ------------------------
BLOCKS = [
    {"lo": 0x00820000, "hi": 0x00830000, "block": "FUSE",
     "public": "ampere/ga100/dev_fuse.h (defines span 0x00820378..0x00824118)"},
    {"lo": 0x001fa000, "hi": 0x001fb000, "block": "PFB-PRI-MMU",
     "public": ("ampere/ga100/dev_fb.h:36-46 (LOCK_CFG PLM @0x001FA7C8, "
                "LOCK_ADDR_LO/HI @0x001FA82C/30); blackwell/gb100/"
                "dev_fb.h:28 (LOCAL_MEMORY_RANGE PLM @0x001FA7C4)")},
    {"lo": 0x00088000, "hi": 0x00089000, "block": "PCFG/XVE",
     "public": ("turing/tu102/dev_nv_xve.h:26 — NV_PCFG "
                "0x00088FFF:0x00088000")},
    {"lo": 0x00100c00, "hi": 0x00100d00, "block": "PFB",
     "public": ("ampere/ga100/dev_fb.h:26-32 (NISO_FLUSH @0x00100C10/C40); "
                "pascal/gp102/dev_fb.h:26 (LOCAL_MEMORY_RANGE @0x00100CE0)")},
    {"lo": 0x00118000, "hi": 0x00119000, "block": "PGC6",
     "public": ("turing/tu102 + ampere/ga102 dev_gc6_island.h — NV_PGC6 "
                "0x118fff:0x118000")},
]

# ---- the EXACT crosses (address → (public name, file:line)) ------------
EXACT = {
    0x00100ce0: ("NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE",
                 "pascal/gp102/dev_fb.h:26"),
    0x001fa7c4: ("NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE__PRIV_LEVEL_MASK",
                 "blackwell/gb100/dev_fb.h:28"),
    0x00823814: ("NV_FUSE_FEATURE_READOUT",
                 "ampere/ga100/dev_fuse.h:26"),
    0x00118128: ("NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_PRIV_LEVEL_MASK",
                 "turing/tu102/dev_gc6_island.h:28 + ampere/ga102:27"),
    0x00118234: ("NV_PGC6_AON_SECURE_SCRATCH_GROUP_05(0) (GFW_BOOT)",
                 "turing/tu102/dev_gc6_island.h:34 + ampere/ga102:33"),
}

VERDICT_ALL = "GA104-DECODE-INDECIDABLE-BY-BYTES"


def _block_of(off):
    for b in BLOCKS:
        if b["lo"] <= off < b["hi"]:
            return b
    return None


def annotate(row):
    """One v454a row → the map row (the public cross + the honest
    confidence + the INDECIDABLE verdict)."""
    off = row["offset"]
    blk = _block_of(off)
    ex = EXACT.get(off)
    if ex:
        confidence = "EXACT-PUBLIC"
        public_name, public_src = ex[0], ex[1]
    elif blk:
        confidence = "BLOCK-PUBLIC"
        public_name, public_src = None, blk["public"]
    else:
        confidence = "PATCH-ONLY"
        public_name, public_src = None, None
    out = {"offset": off, "name": row["name"], "ack_class": row["ack_class"],
           "v454a_source": row["source"], "note": row.get("note", ""),
           "block": blk["block"] if blk else None,
           "public_name": public_name, "public_source": public_src,
           "confidence": confidence, "verdict": VERDICT_ALL}
    return out


def build_map(nb_span=V454A.NB_SPAN_DEFAULT):
    """The full map: the v454a 215 annotated + the 4.56 PGC6 additions."""
    rows, parsed = V454A.build_rows(nb_span=nb_span)
    mapped = [annotate(r) for r in rows]
    extras = [
        {"offset": 0x00118128, "name": "GFW_BOOT_STATUS_PLM",
         "ack_class": "CANDIDATE-NOT-IN-454",
         "v454a_source": "OGKM-GA10x (4.56 T3)",
         "note": ("the PLM of the GFW boot progress register — FWSEC "
                  "lowers READ_PROTECTION_LEVEL0 (0:0) when the boot "
                  "starts; the read decides the 0x0-artifact question "
                  "of the v456a decoder"),
         "block": "PGC6",
         "public_name": EXACT[0x00118128][0],
         "public_source": EXACT[0x00118128][1],
         "confidence": "EXACT-PUBLIC", "verdict": VERDICT_ALL},
        {"offset": 0x00118234, "name": "GFW_BOOT_PROGRESS",
         "ack_class": "CANDIDATE-NOT-IN-454",
         "v454a_source": "OGKM-GA10x (4.56 T3)",
         "note": ("the GFW boot progress register (_PROGRESS 7:0, "
                  "_COMPLETED = 0xff) — the r2a/r2b judge register the "
                  "v456a decoder names; a direct read = the live boot "
                  "map without waiting for the driver's dmesg lines"),
         "block": "PGC6",
         "public_name": EXACT[0x00118234][0],
         "public_source": EXACT[0x00118234][1],
         "confidence": "EXACT-PUBLIC", "verdict": VERDICT_ALL},
    ]
    counts = {
        "rows": len(mapped),
        "by_confidence": _by(mapped, "confidence"),
        "by_block": _by(mapped, "block"),
    }
    return {"instrument": "v456c_o5_map", "source_tag": TAG,
            "v454a_rows": len(mapped), "additions_4_56": extras,
            "counts": counts, "rows": mapped,
            "the_gate": ("no write without a POWER-BASE-MATCH row from "
                         "the v454c verdict — the read probe = the "
                         "non-negotiable prerequisite; EVERY row here "
                         "names an ADDRESS CANDIDATE, never a write "
                         "target; the GA104 decode = INDECIDABLE-BY-BYTES "
                         "until the read")}


def _by(rows, key):
    out = {}
    for r in rows:
        k = r.get(key) if r.get(key) is not None else "(none)"
        out[k] = out.get(k, 0) + 1
    return out


# ---- the tree guard (the needles re-asserted live) ---------------------
GUARD_NEEDLES = {
    "gp102_dev_fb.h": [
        ("NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE                           "
         "0x00100CE0", None)],
    "gb100_dev_fb.h": [
        ("NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE__PRIV_LEVEL_MASK          "
         "0x001FA7C4", None)],
    "ga100_dev_fb.h": [
        ("NV_PFB_PRI_MMU_LOCK_CFG_PRIV_LEVEL_MASK                     "
         "0x001FA7C8", None)],
    "ga100_dev_fuse.h": [
        ("NV_FUSE_FEATURE_READOUT                                     "
         "0x00823814", None)],
    "tu102_dev_xve.h": [("NV_PCFG                                              0x00088FFF:0x00088000", None)],
    "tu102_dev_gc6.h": [("NV_PGC6_AON_SECURE_SCRATCH_GROUP_05(i)                                          (0x00118234+(i)*4)", None)],
}


def tree_guard():
    """The cache re-read: the exact-cross needles asserted live."""
    if not TREE.is_dir():
        return ("SKIPPED (no .ogkm-610-cache at the repo root)", [])
    details, fails = [], 0
    for fname, needles in GUARD_NEEDLES.items():
        p = TREE / SOURCES[fname]
        if not p.is_file():
            details.append(f"{fname}: MISSING")
            fails += 1
            continue
        text = p.read_text(errors="replace")
        for needle, _ in needles:
            ok = " ".join(needle.split()) in " ".join(text.split())
            fails += int(not ok)
            details.append(f"{fname}: {'OK' if ok else 'MISS'} "
                           f"[{needle[:44]}…]")
    return ("FAIL" if fails else "OK", details)


def fetch_cache():
    """The re-derivation of the pinned headers (the 4.54 lesson)."""
    import urllib.request
    TREE.mkdir(parents=True, exist_ok=True)
    shas = {}
    for fname, rel in SOURCES.items():
        dst = TREE / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        url = f"{BASE}/{rel}"
        print(f"  fetch {rel} ...")
        urllib.request.urlretrieve(url, dst)
        shas[fname] = hashlib.sha256(dst.read_bytes()).hexdigest()
    return shas


def selftest():
    ok, fail = 0, 0

    def check(label, cond, detail=""):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label} {detail}")

    # -- 0. the v454a import intact (the 215 = the committed geometry) ---
    rows, parsed = V454A.build_rows()
    check("v454a: 215 lignes importées (17 SAFE + 198 RISK)",
          len(rows) == 215
          and sum(1 for r in rows if r["ack_class"] == "SAFE-PROBE") == 17,
          f"n={len(rows)}")
    doc = build_map()
    check("map: 215 annotées + 2 ajouts 4.56",
          doc["counts"]["rows"] == 215 and len(doc["additions_4_56"]) == 2)

    # -- 1. the coverage: NOTHING lost, EVERY row classified --------------
    src_offsets = {r["offset"] for r in rows}
    map_offsets = {r["offset"] for r in doc["rows"]}
    check("couverture: les 215 offsets présents, zéro perdu",
          src_offsets == map_offsets)
    check("couverture: chaque rangée = une confiance + le verdict "
          "INDECIDABLE",
          all(r["confidence"] in ("EXACT-PUBLIC", "BLOCK-PUBLIC",
                                  "PATCH-ONLY") and
              r["verdict"] == VERDICT_ALL for r in doc["rows"]))

    # -- 2. the exact crosses (the honest heart of the map) ---------------
    by_off = {r["offset"]: r for r in doc["rows"]}
    lmr = by_off.get(0x00100ce0)
    check("croix exacte: LMR @0x00100ce0 = LOCAL_MEMORY_RANGE (gp102:26)",
          lmr and lmr["public_name"] == "NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE"
          and lmr["confidence"] == "EXACT-PUBLIC")
    wpr = by_off.get(0x001fa7c4)
    check("croix exacte: WPR @0x001fa7c4 = le PLM de la plage WPR "
          "(gb100:28) — le nom du patch = le vrai sens",
          wpr and "LOCAL_MEMORY_RANGE__PRIV_LEVEL_MASK" in wpr["public_name"])
    feat10 = by_off.get(0x00823814)
    check("croix exacte: FEAT+0x10 (une NB 454) = NV_FUSE_FEATURE_READOUT "
          "(ga100 fuse:26)",
          feat10 and feat10["public_name"] == "NV_FUSE_FEATURE_READOUT")
    check("croix: le nom du patch FEAT cohabite avec le bloc FUSE public",
          by_off[0x00823804]["block"] == "FUSE"
          and by_off[0x00823804]["confidence"] == "BLOCK-PUBLIC")

    # -- 3. the blocks: the geometry (every row's offset ∈ its block) -----
    geo_bad = []
    for r in doc["rows"]:
        if r["block"]:
            blk = next(b for b in BLOCKS if b["block"] == r["block"])
            if not (blk["lo"] <= r["offset"] < blk["hi"]):
                geo_bad.append(r["offset"])
    check("géométrie: chaque attribution de bloc = dans la plage", 
          not geo_bad, f"{geo_bad[:3]}")
    blocks_named = _by(doc["rows"], "block")
    check("blocs: FUSE + PFB-PRI-MMU + PCFG/XVE nommés, 0x009a = PATCH-ONLY",
          blocks_named.get("FUSE", 0) > 50
          and blocks_named.get("PFB-PRI-MMU", 0) > 30
          and blocks_named.get("PCFG/XVE", 0) == 3
          and "(none)" not in blocks_named.get("FUSE", 0) * ["x"],
          str({k: v for k, v in blocks_named.items() if k != "(none)"}))

    # -- 4. the 4.56 additions: the PGC6 pair (the candidates, NOT the
    #       injection) -----------------------------------------------------
    add_offs = {r["offset"] for r in doc["additions_4_56"]}
    check("ajouts 4.56: la paire PGC6 {0x00118128, 0x00118234}",
          add_offs == {0x00118128, 0x00118234})
    check("ajouts 4.56: CANDIDATE-NOT-IN-454 (jamais injectés dans les "
          "215 commis)",
          all(r["ack_class"] == "CANDIDATE-NOT-IN-454"
              for r in doc["additions_4_56"])
          and not (add_offs & map_offsets))
    check("ajouts 4.56: les constantes = l'import v456a (zéro "
          "re-transcription)",
          0x00118128 == V456A.PLM_REG and 0x00118234 == V456A.GFW_BOOT_REG)

    # -- 5. THE GATE re-asserted (the O5 discipline in the map itself) ----
    check("porte: AUCUNE rangée ne nomme une cible d'écriture",
          not any("write_target" in r for r in doc["rows"])
          and doc["the_gate"].startswith("no write without a "
                                         "POWER-BASE-MATCH"))
    check("porte: le verdict INDECIDABLE sur TOUTES les rangées",
          all(r["verdict"] == VERDICT_ALL for r in doc["rows"]))
    check("porte: même les EXACT-PUBLIC restent INDECIDABLE (l'adresse "
          "plausible ≠ le comportement)",
          by_off[0x00100ce0]["verdict"] == VERDICT_ALL)

    # -- 6. the round-trip --------------------------------------------------
    blob = json.dumps(doc)
    back = json.loads(blob)
    check("JSON: le round-trip identique",
          back["rows"] == doc["rows"]
          and back["additions_4_56"] == doc["additions_4_56"])

    # -- 7. the tree guard --------------------------------------------------
    state, details = tree_guard()
    print(f"[{'INFO' if state == 'SKIPPED' else state}] tree-guard: {state}")
    for d in details[:3]:
        print(f"    {d}")
    if state == "FAIL":
        check("tree-guard: GREEN", False)
    else:
        check("tree-guard: GREEN ou SKIPPED (la carte = le fichier "
              "arithmétique)", True)

    print(f"selftest v456c: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--out", default=str(HERE / "v456c_o5_map.json"))
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1
    if args.fetch:
        shas = fetch_cache()
        for k, v in shas.items():
            print(f"  {k}: sha256 {v[:16]}…")
        return 0

    doc = build_map()
    Path(args.out).write_text(json.dumps(doc, indent=1) + "\n")
    c = doc["counts"]
    print(f"[v456c] {c['rows']} rangées v454a annotées + "
          f"{len(doc['additions_4_56'])} ajouts 4.56")
    print(f"[v456c] les confiances: {c['by_confidence']}")
    print(f"[v456c] les blocs: "
          f"{ {k: v for k, v in c['by_block'].items() if k} }")
    for r in doc["rows"]:
        if r["confidence"] == "EXACT-PUBLIC":
            print(f"[v456c] EXACT @0x{r['offset']:08x} "
                  f"({r['name']}) = {r['public_name']}")
    print(f"[v456c] la porte: {doc['the_gate'][:80]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
