#!/usr/bin/env python3
"""v456b — THE BOOT TIMELINE (pass 4.56 T3 — the observables suite).

THE MANDATE: the timestamps dmesg → the boot map. The companion of the
decoder v456a (the value semantics): this tool puts the GFW events on
the TIME axis — the deltas between the anchors and the failures — the
map the runbook-456 day fills (progress / boot / hang) and the founder
reads after every gated boot.

THE INPUT = a dmesg capture (the file, or stdin with --dmesg -):
  [   10.123456] nvidia: loading out-of-tree module taints kernel.
  [   11.234567] NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP failed
                 to halt with GFW_BOOT: (progress 0xff)
  ...

THE GROUNDED SOURCES (the 610.57.04 tag — see v456a for the full chain):
  the event classes = v456a's classifier IMPORTED (zero re-transcription):
  the halt-fail / not-completed / the wrapper 0x65 / the Booter Load /
  "Failed to boot GSP." / the Xid lines (kernel_rc.c:388,393).
  THE BOOT-START ANCHORS, honestly named:
  - "nvidia: loading out-of-tree module taints kernel." = the KERNEL
    module loader's printk (not in the driver tree — the kernel's own
    format; present on every driver load).
  - "NVRM: The NVIDIA probe routine was not called for %d device(s)."
    and "...probe routine failed for %d device(s)." (nv.c:937,959) =
    the error-path anchors only — the SUCCESSFUL probe line of the
    older drivers does NOT exist in the 610 tree (grep-verified this
    pass): the first NVRM/nvidia line of the capture = the practical
    boot-start anchor, and the map labels it AS SUCH.
  THE LEVEL-GATE LESSON (the 4.51 day): the RM NV_PRINTF = level-gated —
  only the LEVEL_ERROR lines reach dmesg by default. The healthy boot =
  a QUIET capture: the absence of the failure lines in the capture is
  NOT a proof of the boot health (the map verdicts name it).

THE OUTPUT = the map JSON:
  events[]: {ts, dt_first, dt_prev, class, verdict, note, line}
  cycles[]: the anchor-to-anchor runs (the module load → the next load)
  summary:  the worst verdict + the counts (the honest aggregate)

Run:  python3 v456b_boot_timeline.py --selftest
      python3 v456b_boot_timeline.py --dmesg capture.log --out map.json
      sudo dmesg | python3 v456b_boot_timeline.py --dmesg -
Exit: 0 iff the selftest green / the map written.
"""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

# ---- v456a imported (the classifier + the verdicts — zero re-transcription)
_spec = importlib.util.spec_from_file_location(
    "v456a", Path(__file__).resolve().parent / "v456a_progress_decode.py")
V456A = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(V456A)

RE_TS = re.compile(r"^\[\s*(\d+\.\d+)\]\s?")
RE_MODLOAD = re.compile(r"nvidia: loading out-of-tree module taints kernel")
RE_PROBE_NOTCALLED = re.compile(r"The NVIDIA probe routine was not called")
RE_PROBE_FAILED = re.compile(r"The NVIDIA probe routine failed")

# the worst-first ordering (the aggregate = the first match)
VERDICT_SEVERITY = [
    "BOOTER-LOAD-FAIL", "GSP-BOOT-FAIL", "HANG-POST-COMPLETION",
    "HANG-AT-STAGE", "HANG-PRE-START-or-PLM", "EARLY-HALT", "XID",
    "STATUS-PROPAGATION", "BOOT-CLEAN",
]


def parse(text):
    """The capture → the raw rows {ts, line, ev}. The lines without the
    kernel timestamp = ts None (the -a escapes / the continuation lines),
    carried, never dropped."""
    rows = []
    for line in text.splitlines():
        m = RE_TS.match(line)
        ts = float(m.group(1)) if m else None
        ev = V456A.classify(line)
        anchor = None
        if RE_MODLOAD.search(line):
            anchor = "MODULE-LOAD"
        elif RE_PROBE_NOTCALLED.search(line):
            anchor = "PROBE-NOT-CALLED"
        elif RE_PROBE_FAILED.search(line):
            anchor = "PROBE-FAILED"
        if ev or anchor:
            rows.append({"ts": ts, "line": line.rstrip(),
                         "ev": ev, "anchor": anchor})
    return rows


def build_map(text):
    """The capture → the map doc (the events + the cycles + the summary)."""
    rows = parse(text)
    events, first_ts, prev_ts = [], None, None
    for r in rows:
        ts = r["ts"]
        dt_first = (ts - first_ts) if (ts is not None and first_ts is not None) \
            else None
        dt_prev = (ts - prev_ts) if (ts is not None and prev_ts is not None) \
            else None
        if ts is not None and first_ts is None:
            first_ts = ts
        if ts is not None:
            prev_ts = ts
        if r["ev"]:
            ev = dict(r["ev"])
            v = V456A.verdict(ev)
            ev["verdict"], ev["note"] = (v if v else ("UNNAMED", ""))
            ev["ts"] = ts
            ev["dt_first"] = dt_first
            ev["dt_prev"] = dt_prev
            events.append(ev)
        elif r["anchor"]:
            events.append({"class": "ANCHOR", "anchor": r["anchor"],
                           "verdict": "ANCHOR", "note": ("the boot-start "
                           "anchor (the module load / the probe error "
                           "path)"), "ts": ts, "dt_first": dt_first,
                           "dt_prev": dt_prev, "line": r["line"]})

    # the cycles: split on each MODULE-LOAD anchor
    cycles, cur = [], []
    for ev in events:
        if ev.get("anchor") == "MODULE-LOAD" and cur:
            cycles.append(cur)
            cur = []
        cur.append(ev)
    if cur:
        cycles.append(cur)
    cycles = [c for c in cycles if c] if len(cycles) > 1 else [events]

    counts = {}
    for ev in events:
        counts[ev["verdict"]] = counts.get(ev["verdict"], 0) + 1

    # the aggregate: the worst verdict present, else BOOT-CLEAN
    worst = "BOOT-CLEAN"
    for sev in VERDICT_SEVERITY:
        if counts.get(sev):
            worst = sev
            break
    quiet = not any(c for c in counts if c not in ("ANCHOR", "BOOT-CLEAN"))
    summary = {
        "worst_verdict": worst,
        "counts": counts,
        "n_events": len(events),
        "n_cycles": max(1, len(cycles)),
        "note": ("the failure lines are LEVEL_ERROR only — a QUIET capture "
                 "is NOT a health proof (the 4.51 level-gate lesson); "
                 "cross-check nvidia-smi and the boot logs on the day"
                 if worst == "BOOT-CLEAN" else
                 "the map verdict = the r0/r2a judge class (v456a's matrix)"),
    }
    return {"instrument": "v456b_boot_timeline",
            "source_instrument": "v456a_progress_decode",
            "events": events, "cycles": [len(c) for c in cycles],
            "summary": summary, "quiet_capture": quiet}


def render(doc):
    """The console render (the map the founder reads)."""
    lines = []
    for ev in doc["events"]:
        ts = f"{ev['ts']:12.3f}" if ev.get("ts") is not None else "     —    "
        dt = (f"Δ{ev['dt_first']:9.3f}" if ev.get("dt_first") is not None
              else "         —")
        name = ev.get("class", "?")
        extra = (f" progress={ev['progress']:#04x}" if "progress" in ev
                 else f" status={ev['status']:#x}" if "status" in ev
                 else f" {ev.get('anchor')}" if ev.get("anchor")
                 else f" xid={ev['xid']}" if "xid" in ev else "")
        lines.append(f"[{ts}{dt}] {name:<22}{extra} → {ev['verdict']}")
    s = doc["summary"]
    lines.append(f"map: worst={s['worst_verdict']} "
                 f"cycles={s['n_cycles']} events={s['n_events']}")
    return "\n".join(lines)


def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    # -- the r0 fixture: the REAL machine-day lines (findings-4.45) ------
    r0 = "\n".join([
        "[    8.123456] nvidia: loading out-of-tree module taints kernel.",
        "[   10.234567] NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP "
        "failed to halt with GFW_BOOT: (progress 0xff)",
        "[   10.567890] NVRM: GPU0 kgspWaitForGfwBootOk_TU102: failed to "
        "wait for GFW boot complete: 0x65 (NV_ERR_TIMEOUT)",
    ])
    doc = build_map(r0)
    check("r0: 3 événements (l'ancre + 2 GFW)", len(doc["events"]) == 3)
    check("r0: l'ancre MODULE-LOAD première",
          doc["events"][0]["verdict"] == "ANCHOR"
          and doc["events"][0]["anchor"] == "MODULE-LOAD")
    check("r0: les deltas croissants (2.111 / 0.333)",
          abs(doc["events"][1]["dt_first"] - 2.111111) < 1e-3
          and abs(doc["events"][2]["dt_prev"] - 0.333323) < 1e-3)
    check("r0: le verdict agrégé = HANG-POST-COMPLETION",
          doc["summary"]["worst_verdict"] == "HANG-POST-COMPLETION")
    check("r0: un seul cycle", doc["summary"]["n_cycles"] == 1)

    # -- the healthy fixture: the QUIET capture (the honesty note) -------
    quiet = "\n".join([
        "[    9.000000] nvidia: loading out-of-tree module taints kernel.",
        "[    9.500000] nvidia-nvlink: NvlinkCore is being initialized, "
        "major device number 236",
    ])
    doc2 = build_map(quiet)
    check("quiet: le verdict = BOOT-CLEAN MAIS la note = le level-gate",
          doc2["summary"]["worst_verdict"] == "BOOT-CLEAN"
          and "NOT a health proof" in doc2["summary"]["note"]
          and doc2["quiet_capture"] is True)

    # -- the HANG-AT-STAGE fixture: le 0x23 -------------------------------
    staged = ("[   10.1] NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP "
              "failed to halt with GFW_BOOT: (progress 0x23)\n")
    doc3 = build_map(staged)
    check("stage: le verdict = HANG-AT-STAGE (la coordonnée 0x23)",
          doc3["summary"]["worst_verdict"] == "HANG-AT-STAGE"
          and doc3["events"][0]["progress"] == 0x23)

    # -- the Xid fixture: the safety observer ------------------------------
    xid = ("[   11.0] NVRM: Xid (PCI:0000:01:00.0): 79, pid=1000, "
           "name=test, GPU has fallen off the bus\n")
    doc4 = build_map(xid)
    check("xid: XID reconnu et sévérité sous le hang",
          doc4["summary"]["worst_verdict"] == "XID"
          and doc4["events"][0]["xid"] == 79)

    # -- the multi-cycle fixture: two module loads -------------------------
    two = "\n".join([
        "[    8.000000] nvidia: loading out-of-tree module taints kernel.",
        "[   10.000000] NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP "
        "failed to halt with GFW_BOOT: (progress 0xff)",
        "[   30.000000] nvidia: loading out-of-tree module taints kernel.",
        "[   32.000000] NVRM: Xid (PCI:0000:01:00.0): 13, pid=p, name=n, "
        "Graphical Engine Command Streamer"])
    doc5 = build_map(two)
    check("cycles: 2 cycles découpés aux MODULE-LOAD (chaque cycle = "
          "son ancre + ses échecs)",
          doc5["summary"]["n_cycles"] == 2 and doc5["cycles"] == [2, 2])
    check("cycles: le pire = HANG-POST-COMPLETION (le 1er)",
          doc5["summary"]["worst_verdict"] == "HANG-POST-COMPLETION")

    # -- the tolerance: the lines sans timestamp portées, jamais perdues --
    mixed = ("NVRM: GPU0 gpuWaitForGfwBootComplete_TU102: GSP failed to "
             "halt with GFW_BOOT: (progress 0xff)\n")
    doc6 = build_map(mixed)
    check("mixed: la ligne sans ts = portée (ts None)",
          len(doc6["events"]) == 1
          and doc6["events"][0]["ts"] is None)

    # -- the render + the round-trip ---------------------------------------
    out = render(doc)
    check("render: la carte lisible (les Δ + les verdicts)",
          "HANG-POST-COMPLETION" in out and "Δ" in out)
    blob = json.dumps(doc)
    check("round-trip: le JSON identique",
          json.loads(blob)["summary"] == doc["summary"])

    print(f"selftest v456b: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--dmesg", metavar="FILE|-", required=False,
                    help="the dmesg capture ('-' = stdin)")
    ap.add_argument("--out", metavar="FILE")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    if args.dmesg:
        text = (sys.stdin.read() if args.dmesg == "-"
                else Path(args.dmesg).read_text(errors="replace"))
        doc = build_map(text)
        print(render(doc))
        out = json.dumps(doc, indent=1) + "\n"
        if args.out:
            Path(args.out).write_text(out)
            print(f"map: {args.out}")
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
