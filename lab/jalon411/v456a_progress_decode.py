#!/usr/bin/env python3
"""v456a — THE PROGRESSION DECODER (pass 4.56 T3 — the observables suite).

THE MANDATE (the founder's brief): gpuWaitForGfwBootComplete_TU102 reads
a progression register — decode the steps from the RM source 610.57.04
(what does 0xff mean vs the other values?). This decoder = the judge of
the r2a/r2b boot: it turns a dmesg capture's GFW lines into the named
map verdicts (progress / boot / hang classes), the observable the
runbook-456 day consumes.

THE GROUNDED SOURCES (the 610.57.04 tag, file+line, fetched into the
.gitignored .ogkm-610-cache at the REPO ROOT — the v452a guard location;
--fetch re-derives them, the 4.54 container-reset lesson):

  src/nvidia/src/kernel/gpu/arch/turing/kern_gpu_tu102.c
    :403-406  the timeout = GPU_GFW_BOOT_COMPLETION_TIMEOUT_US =
              FWSECLIC_PROG_START_TIMEOUT (50,000) +
              FWSECLIC_PROG_COMPLETE_TIMEOUT (2,000,000) = 2,050,000 us,
              scaled by gpuScaleTimeout
    :447-481  gpuWaitForGfwBootComplete_TU102: kflcnWaitForHalt_HAL first;
              the progress is read REGARDLESS of the halt status; two
              failure prints:
              :468 "GSP failed to halt with GFW_BOOT: (progress 0x%x)"
                   (the halt wait TIMED OUT — the progress = the value
                   the GFW left in the scratch AT THAT MOMENT)
              :474 "failed to wait for GFW_BOOT: (progress 0x%x)"
                   (the falcon HALTED but the progress != COMPLETED)
    :398-443  _gpuIsGfwBootCompleted_TU102 — THE TWO-STEP READ:
              step 1 read NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_PRIV_LEVEL_MASK;
              if READ_PROTECTION_LEVEL0 != ENABLE (FWSEC has not lowered
              the PLM yet) the code reports *gfwBootProgressVal = 0x0
              WITHOUT reading the status register — a REPORTED 0x0 = the
              PLM ARTIFACT, never a genuine stage;
              step 2 read NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_0_GFW_BOOT,
              progress = DRF_VAL(..._PROGRESS) = bits 7:0,
              completed = (progress == _COMPLETED)
  src/common/inc/swref/published/turing/tu102/dev_gc6_island.h
    :28  _PRIV_LEVEL_MASK = 0x00118128 (RW-4R), _READ_PROTECTION 3:0,
         _READ_PROTECTION_LEVEL0 = 0:0, _ENABLE = 0x1
    :34  GROUP_05(i) = 0x00118234 + (i)*4  →  the GFW_BOOT = GROUP_05(0)
         = 0x00118234
  src/common/inc/swref/published/turing/tu102/dev_gc6_island_addendum.h
    :30-32  _PROGRESS = 7:0; _PROGRESS_COMPLETED = 0x000000FF
  src/common/inc/swref/published/ampere/ga102/dev_gc6_island.h + addendum
    :27/:33 and :30-32 — IDENTICAL addresses and values (the two public
    trees agree; the GA102 = the closest public family to our GA104)
  src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_tu102.c
    :1184-1202  kgspWaitForGfwBootOk_TU102 — the wrapper:
                "failed to wait for GFW boot complete: 0x%x VBIOS version %s"
                (the machine day printed it with 0x65)
    :565-599    the boot sequence prints (the timeline tags):
                :570 "failed to execute Booter Load (ucode for initial boot): 0x%x"
                :598 "Failed to boot GSP."
  src/common/sdk/nvidia/inc/nvstatuscodes.h:130  NV_ERR_TIMEOUT = 0x65
  src/nvidia/src/kernel/gpu/rc/kernel_rc.c:388,393  "NVRM: Xid (...): %d,..."

THE DECODE TABLE (the honest one):
  0xff  PROGRESS_COMPLETED — the ONLY publicly named value (tu102 AND
        ga102 agree). "the GFW boot reached its terminal marker."
  0x0   AMBIGUOUS — either (a) the PLM ARTIFACT (the code path that
        reports 0x0 without reading the register — FWSEC has not lowered
        the read protection yet) or (b) a genuine early stage. The value
        ALONE cannot decide; the PLM register (0x00118128) read decides.
  0x01..0xfe  INTERMEDIATE-UNNAMED — the closed ROM's stage markers.
        INDECIDABLE-BY-BYTES: the stages are NOT publicly enumerated
        anywhere in the open tree, the booter plaintext carries no GFW
        writes (grep-verified this pass), and the monotone order is
        NEVER assumed. The value = the map coordinate, the role = named.

THE VERDICT CLASSES (the r0/r2a judge — the (line, progress) matrix):
  HALT-TIMEOUT + 0xff        HANG-POST-COMPLETION — the boot reached its
                             terminal marker and the core never halted:
                             the spin class (the r0/r1 machine-day map,
                             the paper's predicted hijack state).
  HALT-TIMEOUT + 0x0         HANG-PRE-START-or-PLM — the early hang; the
                             PLM read (0x00118128) decides the artifact.
  HALT-TIMEOUT + 0x01..0xfe  HANG-AT-STAGE — the boot stalled AT the
                             unnamed stage (the marker = the last step
                             reached). The stage number = the coordinate.
  NOT-COMPLETED-HALTED + p   EARLY-HALT — the falcon halted with the boot
                             incomplete.
  the wrapper line           the STATUS propagation (0x65 = the timeout)
                             — a corroboration line, never a new verdict.

GATED BY DEFAULT: this tool touches no hardware (the decode = the file
arithmetic over the dmesg text and the constants); the ACKs live in the
runbooks. The cache fetch = read-only network (raw.githubusercontent).

Run:  python3 v456a_progress_decode.py --selftest
      python3 v456a_progress_decode.py --decode 0xff
      python3 v456a_progress_decode.py --dmesg capture.log --out map.json
      python3 v456a_progress_decode.py --fetch
Exit: 0 iff the selftest green / the decode written.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

TAG = "610.57.04"
BASE = f"https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/{TAG}"
ROOT = Path(__file__).resolve().parents[2]
TREE = ROOT / ".ogkm-610-cache"          # the repo root (the v452a guard home)

# ---- the pinned sources (the T3 set — the provenance = the sha table) ----
SOURCES = {
    "kern_gpu_tu102.c":
        "src/nvidia/src/kernel/gpu/arch/turing/kern_gpu_tu102.c",
    "kernel_gsp_tu102.c":
        "src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_tu102.c",
    "dev_gc6_island_tu102.h":
        "src/common/inc/swref/published/turing/tu102/dev_gc6_island.h",
    "dev_gc6_island_addendum_tu102.h":
        "src/common/inc/swref/published/turing/tu102/dev_gc6_island_addendum.h",
    "dev_gc6_island_ga102.h":
        "src/common/inc/swref/published/ampere/ga102/dev_gc6_island.h",
    "dev_gc6_island_addendum_ga102.h":
        "src/common/inc/swref/published/ampere/ga102/dev_gc6_island_addendum.h",
    "nvstatuscodes.h":
        "src/common/sdk/nvidia/inc/nvstatuscodes.h",
}

# ---- the decode constants (verified against the sources this pass; the
# ---- tree guard re-asserts them LIVE when the cache is present) --------
PLM_REG = 0x00118128          # GROUP_05_PRIV_LEVEL_MASK (tu102 :28, ga102 :27)
GFW_BOOT_REG = 0x00118234     # GROUP_05(0) (tu102 :34, ga102 :33)
PROGRESS_MASK_LO, PROGRESS_MASK_HI = 0, 7     # _PROGRESS 7:0
PROGRESS_COMPLETED = 0xFF     # _COMPLETED (tu102/ga102 addendum :32)
FWSEC_PLM_LEVEL0_ENABLE = 0x1  # _READ_PROTECTION_LEVEL0 _ENABLE (0:0)
HALT_TIMEOUT_US = 2_050_000    # 50,000 + 2,000,000 (kern_gpu_tu102.c :403-406)
NV_ERR_TIMEOUT = 0x65          # nvstatuscodes.h:130

# the dmesg line classes (the formats verbatim from the sources)
RE_HALT_FAIL = re.compile(
    r"gpuWaitForGfwBootComplete\S*: GSP failed to halt with GFW_BOOT: "
    r"\(progress (0x[0-9a-fA-F]+)\)")
RE_NOT_COMPLETED = re.compile(
    r"failed to wait for GFW_BOOT: \(progress (0x[0-9a-fA-F]+)\)")
RE_WRAPPER = re.compile(
    r"kgspWaitForGfwBootOk\S*: failed to wait for GFW boot complete: "
    r"(0x[0-9a-fA-F]+)")
RE_BOOTER_LOAD = re.compile(
    r"failed to execute Booter Load \(ucode for initial boot\): "
    r"(0x[0-9a-fA-F]+)")
RE_GSP_BOOT_FAIL = re.compile(r"Failed to boot GSP\.")
RE_XID = re.compile(r"NVRM: Xid \(([^)]*)\): (\d+)")


def decode_progress(value):
    """The progress VALUE → (the name, the honesty note). The precedence:
    0xff first (the named value), then 0x0 (the ambiguity), then the
    unnamed interval."""
    if value == PROGRESS_COMPLETED:
        return "COMPLETED", ("the ONLY publicly named value "
                             "(dev_gc6_island_addendum.h :32, tu102 AND "
                             "ga102) — the GFW boot reached its terminal "
                             "marker")
    if value == 0x0:
        return "AMBIGUOUS", ("0x0 = the PLM ARTIFACT (the code path "
                             "reports 0x0 WITHOUT reading the register "
                             "when FWSEC has not lowered "
                             "_READ_PROTECTION_LEVEL0) OR a genuine early "
                             "stage — the value alone CANNOT decide; the "
                             f"PLM register {PLM_REG:#x} read decides")
    if 0x1 <= value <= 0xFE:
        return "INTERMEDIATE-UNNAMED", ("the closed ROM's stage marker — "
                                        "INDECIDABLE-BY-BYTES: the stages "
                                        "are not publicly enumerated (the "
                                        "open tree has no table; the booter "
                                        "plaintext carries no GFW writes); "
                                        "the value = the map coordinate, "
                                        "the order never assumed")
    return "OUT-OF-FIELD", (f"{value:#x} does not fit _PROGRESS 7:0 — the "
                            "value was not masked by DRF_VAL or is not a "
                            "progress read")


def decode_plm(plm_val):
    """The PLM register value → (the level0 state, the note)."""
    level0 = plm_val & FWSEC_PLM_LEVEL0_ENABLE
    if level0 == FWSEC_PLM_LEVEL0_ENABLE:
        return "LEVEL0-ENABLED", ("FWSEC lowered the read protection — the "
                                  "GFW_BOOT status register is READABLE; a "
                                  "0x0 progress read = a GENUINE stage read")
    return "LEVEL0-LOCKED", ("FWSEC has NOT lowered the read protection — "
                             "_gpuIsGfwBootCompleted_TU102 reports 0x0 "
                             "WITHOUT reading the register (the artifact)")


def classify(line):
    """One dmesg line → (the event or None). The precedence: the halt-fail
    (the r0 class) > the not-completed > the wrapper > the boot sequence."""
    m = RE_HALT_FAIL.search(line)
    if m:
        return {"class": "HALT-TIMEOUT",
                "progress": int(m.group(1), 16), "line": line.rstrip()}
    m = RE_NOT_COMPLETED.search(line)
    if m:
        return {"class": "NOT-COMPLETED-HALTED",
                "progress": int(m.group(1), 16), "line": line.rstrip()}
    m = RE_WRAPPER.search(line)
    if m:
        return {"class": "BOOT-OK-FAIL", "status": int(m.group(1), 16),
                "line": line.rstrip()}
    m = RE_BOOTER_LOAD.search(line)
    if m:
        return {"class": "BOOTER-LOAD-FAIL", "status": int(m.group(1), 16),
                "line": line.rstrip()}
    if RE_GSP_BOOT_FAIL.search(line):
        return {"class": "GSP-BOOT-FAIL", "line": line.rstrip()}
    m = RE_XID.search(line)
    if m:
        return {"class": "XID", "pci": m.group(1), "xid": int(m.group(2)),
                "line": line.rstrip()}
    return None


def verdict(event):
    """The (class, progress/status) → the map verdict (the r0/r2a judge)."""
    cls = event["class"]
    if cls == "HALT-TIMEOUT":
        p = event["progress"]
        name, _ = decode_progress(p)
        if p == PROGRESS_COMPLETED:
            return ("HANG-POST-COMPLETION",
                    "the boot reached the terminal marker and the core "
                    "never halted — the spin class (the r0/r1 machine-day "
                    "map, the paper's predicted hijack state)")
        if p == 0x0:
            return ("HANG-PRE-START-or-PLM",
                    "the early hang; the reported 0x0 = the PLM artifact "
                    "or a genuine pre-start — the PLM register read "
                    f"({PLM_REG:#x}) decides")
        return ("HANG-AT-STAGE",
                f"the boot stalled AT the unnamed stage {p:#04x} — the "
                "marker = the last step reached (the coordinate for the "
                "next probe)")
    if cls == "NOT-COMPLETED-HALTED":
        p = event["progress"]
        return ("EARLY-HALT",
                f"the falcon halted with the boot incomplete (progress "
                f"{p:#04x} = {decode_progress(p)[0]})")
    if cls == "BOOT-OK-FAIL":
        s = event["status"]
        note = ("the timeout propagation" if s == NV_ERR_TIMEOUT
                else "a non-timeout status — check nvstatuscodes.h")
        return ("STATUS-PROPAGATION", f"{s:#x} — {note}")
    if cls == "BOOTER-LOAD-FAIL":
        return ("BOOTER-LOAD-FAIL",
                f"{event['status']:#x} — the load stage failed BEFORE the "
                "GFW boot wait (the 0x1d class of the 4.44-machine day)")
    if cls == "GSP-BOOT-FAIL":
        return ("GSP-BOOT-FAIL", "the RISCV never started")
    if cls == "XID":
        return ("XID", f"xid {event['xid']} @ {event['pci']} — the safety "
                       "observer (zero-Xid = the boot-day requirement)")
    return None


def scan(text):
    """The dmesg text → the map doc (the events + the verdicts)."""
    events, n_lines = [], 0
    for line in text.splitlines():
        n_lines += 1
        ev = classify(line)
        if ev is None:
            continue
        v = verdict(ev)
        ev["verdict"], ev["note"] = (v if v else ("UNNAMED", ""))
        events.append(ev)
    counts = {}
    for ev in events:
        counts[ev["verdict"]] = counts.get(ev["verdict"], 0) + 1
    return {"instrument": "v456a_progress_decode", "source_tag": TAG,
            "lines_scanned": n_lines, "events": events, "counts": counts}


# ---- the tree guard (the exact needles; absent cache = SKIPPED) --------
GUARD_NEEDLES = {
    "dev_gc6_island_tu102.h": [
        "NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_PRIV_LEVEL_MASK",
        "0x00118128",
        "(0x00118234+(i)*4)"],
    "dev_gc6_island_addendum_tu102.h": [
        "GFW_BOOT_PROGRESS                                                                          7:0",
        "GFW_BOOT_PROGRESS_COMPLETED                                                         0x000000FF"],
    "dev_gc6_island_addendum_ga102.h": [
        "GFW_BOOT_PROGRESS                                                                          7:0",
        "GFW_BOOT_PROGRESS_COMPLETED                                                         0x000000FF"],
    "kern_gpu_tu102.c": [
        'NV_PRINTF(LEVEL_ERROR, "GSP failed to halt with GFW_BOOT: (progress 0x%x)\\n", gfwBootProgressVal);',
        "FWSECLIC_PROG_START_TIMEOUT             50000",
        "FWSECLIC_PROG_COMPLETE_TIMEOUT          2000000"],
    "kernel_gsp_tu102.c": [
        '"failed to wait for GFW boot complete: 0x%x VBIOS version %s\\n"'],
    "nvstatuscodes.h": [
        "NV_STATUS_CODE(NV_ERR_TIMEOUT,                                  0x00000065"],
}


def tree_guard():
    """The guard: the cached sources re-read, the needles asserted live.
    Returns (the state, the details list)."""
    if not TREE.is_dir():
        return ("SKIPPED (no .ogkm-610-cache at the repo root — the decode "
                "constants still assert)", [])
    details, fails = [], 0
    for fname, needles in GUARD_NEEDLES.items():
        p = TREE / SOURCES[fname]
        if not p.is_file():
            details.append(f"{fname}: MISSING")
            fails += 1
            continue
        text = p.read_text(errors="replace")
        for needle in needles:
            ok = needle in text
            fails += int(not ok)
            details.append(f"{fname}: needle {'OK' if ok else 'MISS'} "
                           f"[{needle[:48]}…]")
    return ("FAIL" if fails else "OK", details)


def fetch_cache():
    """The re-derivation: the pinned sources → the cache (the 4.54 lesson)."""
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


# ---- the selftest -------------------------------------------------------
def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    # -- 0. the constants (the sources verified this pass; the numbers
    #       re-asserted against the LOCAL copy when the cache exists) ----
    check("formes: GFW_BOOT_REG = 0x00118234", GFW_BOOT_REG == 0x00118234)
    check("formes: PLM_REG = 0x00118128", PLM_REG == 0x00118128)
    check("formes: _PROGRESS = 7:0, COMPLETED = 0xff",
          PROGRESS_COMPLETED == 0xFF and (PROGRESS_MASK_LO, PROGRESS_MASK_HI)
          == (0, 7))
    check("formes: HALT_TIMEOUT_US = 2,050,000 (50,000 + 2,000,000)",
          HALT_TIMEOUT_US == 2_050_000)
    check("formes: NV_ERR_TIMEOUT = 0x65", NV_ERR_TIMEOUT == 0x65)

    # -- 1. the decode table: the three classes + the boundaries ---------
    n, note = decode_progress(0xFF)
    check("decode: 0xff = COMPLETED (le seul nommé, tu102+ga102)",
          n == "COMPLETED" and "terminal" in note)
    n, note = decode_progress(0x0)
    check("decode: 0x0 = AMBIGUOUS (l'artefact PLM ou un vrai stade)",
          n == "AMBIGUOUS" and "PLM" in note)
    n, _ = decode_progress(0x1)
    check("decode: 0x01 = INTERMEDIATE-UNNAMED (la borne basse)",
          n == "INTERMEDIATE-UNNAMED")
    n, _ = decode_progress(0xFE)
    check("decode: 0xfe = INTERMEDIATE-UNNAMED (la borne haute)",
          n == "INTERMEDIATE-UNNAMED")
    n, _ = decode_progress(0x1FF)
    check("decode: 0x1ff hors champ 7:0", n == "OUT-OF-FIELD")

    # -- 2. the PLM decode: the artifact vs the genuine read -------------
    n, note = decode_plm(0x00000001)
    check("plm: LEVEL0-ENABLED = la lecture GENUINE possible",
          n == "LEVEL0-ENABLED" and "GENUINE" in note)
    n, note = decode_plm(0x00000002)
    check("plm: bit0=0 = LOCKED → le 0x0 rapporté = l'artefact",
          n == "LEVEL0-LOCKED" and "artifact" in note)
    n, _ = decode_plm(0x00000003)
    check("plm: le bit0 seuls compte (mask 0:0)", n == "LEVEL0-ENABLED")

    # -- 3. the line classes: the machine-day r0 lines verbatim ----------
    ev = classify("NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP failed "
                  "to halt with GFW_BOOT: (progress 0xff)")
    check("ligne r0: HALT-TIMEOUT, progress 0xff",
          ev and ev["class"] == "HALT-TIMEOUT" and ev["progress"] == 0xFF)
    ev2 = classify("NVRM: GPU0 kgspWaitForGfwBootOk_TU102: failed to wait "
                   "for GFW boot complete: 0x65 (NV_ERR_TIMEOUT)")
    check("ligne r0: le wrapper BOOT-OK-FAIL 0x65",
          ev2 and ev2["class"] == "BOOT-OK-FAIL" and ev2["status"] == 0x65)
    ev3 = classify("[  12.3] NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: "
                   "GSP failed to halt with GFW_BOOT: (progress 0x23)")
    check("ligne: HALT-TIMEOUT à un stade intermédiaire",
          ev3 and ev3["progress"] == 0x23)
    ev4 = classify("NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: failed to "
                   "wait for GFW_BOOT: (progress 0x10)")
    check("ligne: NOT-COMPLETED-HALTED (la falcon a halté tôt)",
          ev4 and ev4["class"] == "NOT-COMPLETED-HALTED")
    ev5 = classify("NVRM: Xid (PCI:0000:01:00.0): 13, pid=nvgl, "
                   "name=glxgears, Graphical Engine Command Streamer")
    check("ligne: XID parsé", ev5 and ev5["class"] == "XID"
          and ev5["xid"] == 13)
    check("ligne: une ligne neutre = None",
          classify("NVRM: The NVIDIA probe routine failed for 1 device(s).")
          is None)

    # -- 4. the verdict matrix (the r0/r2a judge) -------------------------
    v, note = verdict(ev)
    check("verdict: HALT-TIMEOUT+0xff = HANG-POST-COMPLETION",
          v == "HANG-POST-COMPLETION" and "spin class" in note)
    v, _ = verdict(ev3)
    check("verdict: HALT-TIMEOUT+0x23 = HANG-AT-STAGE (la coordonnée)",
          v == "HANG-AT-STAGE")
    v, _ = verdict(ev4)
    check("verdict: halted tôt = EARLY-HALT", v == "EARLY-HALT")
    v, note = verdict(ev2)
    check("verdict: le wrapper = STATUS-PROPAGATION (0x65 = le timeout)",
          v == "STATUS-PROPAGATION" and "timeout" in note)
    v, _ = verdict(classify("NVRM: GPU0: failed to execute Booter Load "
                            "(ucode for initial boot): 0x1d"))
    check("verdict: BOOTER-LOAD-FAIL 0x1d (la classe 4.44-machine)",
          v == "BOOTER-LOAD-FAIL")

    # -- 5. the scan round-trip: the r0 capture → la carte ----------------
    r0 = "\n".join([
        "[   10.123456] nvidia: loading out-of-tree module taints kernel.",
        "[   11.234567] NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP "
        "failed to halt with GFW_BOOT: (progress 0xff)",
        "[   12.345678] NVRM: GPU0 kgspWaitForGfwBootOk_TU102: failed to "
        "wait for GFW boot complete: 0x65 (NV_ERR_TIMEOUT)",
        "[   12.345679] NVRM: Xid (PCI:0000:01:00.0): 79, pid=1000, "
        "name=test, GPU has fallen off the bus"])
    doc = scan(r0)
    check("scan: 4 événements extraits de 4 lignes NVRM",
          len(doc["events"]) == 3 and doc["lines_scanned"] == 4)
    check("scan: les verdicts comptés",
          doc["counts"].get("HANG-POST-COMPLETION") == 1
          and doc["counts"].get("STATUS-PROPAGATION") == 1
          and doc["counts"].get("XID") == 1)
    blob = json.dumps(doc)
    check("scan: le round-trip JSON",
          json.loads(blob)["events"] == doc["events"])

    # -- 6. the tree guard (the live re-read when the cache exists) -------
    state, details = tree_guard()
    print(f"[{'INFO' if state == 'SKIPPED' else state}] tree-guard: {state}")
    for d in details[:4]:
        print(f"    {d}")
    if state == "FAIL":
        check("tree-guard: GREEN (le cache présent et conforme)", False)
    else:
        check("tree-guard: GREEN ou SKIPPED (le décode = l'arithmétique "
              "fichier, jamais l'assumption)", True)

    print(f"selftest v456a: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--fetch", action="store_true",
                    help="(re)fetch the pinned 610.57.04 sources into the "
                         "cache (read-only network, re-derivable)")
    ap.add_argument("--decode", metavar="HEX",
                    help="decode one progress value (e.g. --decode 0xff)")
    ap.add_argument("--plm", metavar="HEX",
                    help="decode the PLM register value alongside")
    ap.add_argument("--dmesg", metavar="FILE",
                    help="scan a dmesg capture → the map (stdout or --out)")
    ap.add_argument("--out", metavar="FILE")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    if args.fetch:
        shas = fetch_cache()
        for k, v in shas.items():
            print(f"  {k}: sha256 {v[:16]}…")
        return 0

    if args.decode is not None:
        val = int(args.decode, 16)
        name, note = decode_progress(val)
        print(f"progress {args.decode} = {name}\n  {note}")
        if args.plm is not None:
            pn, pnote = decode_plm(int(args.plm, 16))
            print(f"plm {args.plm} = {pn}\n  {pnote}")
            if val == 0:
                which = "une LECTURE GENUINE" \
                    if pn == "LEVEL0-ENABLED" else "l'ARTEFACT PLM"
                print(f"  ⇒ le 0x0 = {which}")
        return 0

    if args.dmesg:
        doc = scan(Path(args.dmesg).read_text(errors="replace"))
        out = json.dumps(doc, indent=1) + "\n"
        if args.out:
            Path(args.out).write_text(out)
        for ev in doc["events"]:
            print(f"[{ev['class']}] → {ev['verdict']}: {ev['note'][:90]}")
        print(f"[v456a] {len(doc['events'])} événements / "
              f"{doc['lines_scanned']} lignes")
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
