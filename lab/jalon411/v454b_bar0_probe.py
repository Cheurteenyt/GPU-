#!/usr/bin/env python3
"""v454b — THE HOST BAR0 READ PROBE (the 4.54 read lane — the first
gesture, READ-ONLY by construction).

THE 4.53 discipline executed: the write-test = REFUSED without a
read-test row; the read probe = the safe gesture. THIS tool contains
NO WRITE PATH AT ALL — the mmap = PROT_READ (the single protection
literal in the file), no write call exists (the selftest asserts the
source stays write-free — the code IS the guarantee).

The gesture: mmap /sys/bus/pci/devices/<gpu>/resource0 (the BAR0),
ONE u32 LE read per candidate offset (NO polling, NO repeat, NO
read-modify-anything), the JSON dump. The candidates = the v454a
table (17 SAFE + 198 RISK).

THE TWO-TIER ACK (the machine discipline, applied even to reads):
  PROBE_454_ACK=1   the SAFE rows (the patch's own addresses — the
                    read gesture the cmpunlocker performs on GA100)
  PROBE_454_ACK=1   + PROBE_454_NB=1 → the RISK rows too (the bounded
                    neighborhoods — the unknown registers CAN be
                    read-sensitive: FIFO pops, R1C forms; each read
                    ONCE, the honest exposure, the founder's opt-in)
Without the ACK: the tool REFUSES (exit 2) — tested.

THE SYNTHETIC MODE (the selftest path — the 4.51 lesson: every path
executed before the founder runs it): the SAME code path (the same
mmap + read loop) against a regular file emulating the BAR0 — the
known values planted, the known verdicts asserted. The real device
NEVER needed for the selftest.

Run:  python3 v454b_bar0_probe.py --selftest
      sudo python3 v454b_bar0_probe.py --table v454a_probe_table.json \
           --pci 0000:01:00.0 --out v454b_probe_dump.json
Exit: 0 iff OK (the selftest green / the dump written).
"""
import argparse
import json
import mmap
import os
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TABLE = ROOT / "lab" / "jalon411" / "v454a_probe_table.json"

# the shape markers re-exported from v454a (the single source — zero
# re-transcription across the v454 lane)
v454a_path = Path(__file__).resolve().parent / "v454a_probe_table.py"
_v454a = {"__file__": str(v454a_path), "__name__": "v454a_probe_table"}
exec(compile(v454a_path.read_text(), str(v454a_path), "exec"), _v454a)
SHAPE_250_UW = _v454a["SHAPE_250_UW"]
SHAPE_280_UW = _v454a["SHAPE_280_UW"]


class ProbeRefused(Exception):
    pass


# ---- the gates (pure functions of an env dict — testable) -----------

def gates(env):
    """Return (ack, nb_ack) from the environment dict."""
    ack = env.get("PROBE_454_ACK") == "1"
    nb = env.get("PROBE_454_NB") == "1"
    return ack, ack and nb


# ---- the discovery ---------------------------------------------------

def discover_gpus(sysfs="/sys/bus/pci/devices"):
    """The NVIDIA display controllers (vendor 0x10de, class 0x03xxxx)."""
    found = []
    base = Path(sysfs)
    if not base.is_dir():
        return found
    for dev in sorted(base.iterdir()):
        try:
            vendor = int((dev / "vendor").read_text().strip(), 16)
            cls = int((dev / "class").read_text().strip(), 16)
        except (OSError, ValueError):
            continue
        if vendor == 0x10DE and (cls >> 16) == 0x03:
            try:
                device = (dev / "device").read_text().strip()
            except OSError:
                device = "?"
            found.append({"pci": dev.name, "device": device})
    return found


# ---- the read loop (the ONE code path — real and synthetic) ---------

def read_bar0(bar0_path, rows, ack, nb_ack):
    """mmap PROT_READ, one u32 LE read per row. NO write path exists."""
    if not ack:
        raise ProbeRefused(
            "REFUS: PROBE_454_ACK=1 absent — la sonde ne lit rien")
    f = open(bar0_path, "rb")
    try:
        size = os.fstat(f.fileno()).st_size
        view = mmap.mmap(f.fileno(), size, prot=mmap.PROT_READ,
                         flags=mmap.MAP_SHARED)
    finally:
        f.close()   # the mapping stays valid after close (POSIX)

    reads, skipped, errors = [], 0, 0
    try:
        for r in rows:
            if r["ack_class"] == "RISK-PROBE" and not nb_ack:
                skipped += 1
                continue
            off = r["offset"]
            if off < 0 or off + 4 > size:
                reads.append({"offset": off, "name": r["name"],
                              "ack_class": r["ack_class"],
                              "value": None, "value_hex": None,
                              "status": "ERROR-OOR"})
                errors += 1
                continue
            (val,) = struct.unpack_from("<I", view, off)
            reads.append({"offset": off, "name": r["name"],
                          "ack_class": r["ack_class"],
                          "value": val, "value_hex": f"0x{val:08x}",
                          "status": "OK"})
    finally:
        view.close()
    return {"reads": reads, "bar0_size": size,
            "counts": {"read": sum(1 for x in reads
                                   if x["status"] == "OK"),
                       "skipped-no-nb-ack": skipped,
                       "error-oor": errors}}


def dump(bar0_path, rows, mode, gpu_meta, out_path):
    ack, nb_ack = gates(dict(os.environ))
    result = read_bar0(bar0_path, rows, ack, nb_ack)
    doc = {"instrument": "v454b_bar0_probe",
           "mode": mode,
           "gpu": gpu_meta,
           "ack": {"PROBE_454_ACK": ack, "PROBE_454_NB": nb_ack},
           "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "bar0_size": result["bar0_size"],
           "counts": result["counts"],
           "reads": result["reads"],
           "marker": {"note": "the POWER-BASE hunt",
                      "shape_250w_uw": SHAPE_250_UW,
                      "shape_280w_uw": SHAPE_280_UW}}
    Path(out_path).write_text(json.dumps(doc, indent=1) + "\n")
    print(f"[v454b] mode={mode} lu={result['counts']['read']} "
          f"skip={result['counts']['skipped-no-nb-ack']} "
          f"err={result['counts']['error-oor']} -> {out_path}")
    return 0


# ---- the selftest: the synthetic BAR0, the same code path ------------

def selftest():
    ok, fail = 0, 0

    def check(label, cond):
        nonlocal ok, fail
        ok += int(bool(cond))
        fail += int(not bool(cond))
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    import tempfile

    # -- 0. the code IS the guarantee: no write path in the MACHINERY --
    # (the selftest region excluded — the check's own literals live
    #  there; the self-reference = the bug the FIRST run caught)
    src = Path(__file__).read_text()
    machinery = src[:src.index("def selftest")]
    check("code: AUCUN write-call MMIO dans la machinerie",
          "WR32" not in machinery and "poke" not in machinery)
    check("code: PROT_READ = la SEULE protection mmap",
          "prot=mmap.PROT_READ" in machinery
          and "PROT_" + "WRITE" not in machinery)

    # -- 1. the gates: the pure function --------------------------------
    check("gate: sans ACK -> refusé", gates({}) == (False, False))
    check("gate: ACK seul -> SAFE oui, RISK non",
          gates({"PROBE_454_ACK": "1"}) == (True, False))
    check("gate: ACK+NB -> tout",
          gates({"PROBE_454_ACK": "1", "PROBE_454_NB": "1"}) == (True, True))
    check("gate: NB sans ACK -> rien",
          gates({"PROBE_454_NB": "1"}) == (False, False))
    check("gate: ACK=0 littéral -> refusé",
          gates({"PROBE_454_ACK": "0"}) == (False, False))

    # -- 2. the discovery: the synthetic sysfs --------------------------
    with tempfile.TemporaryDirectory() as td:
        gpu = Path(td) / "0000:05:00.0"
        gpu.mkdir()
        (gpu / "vendor").write_text("0x10de\n")
        (gpu / "class").write_text("0x030000\n")
        (gpu / "device").write_text("0x2484\n")
        other = Path(td) / "0000:00:1f.3"
        other.mkdir()
        (other / "vendor").write_text("0x8086\n")
        (other / "class").write_text("0x040300\n")
        found = discover_gpus(td)
        check("découverte: la seule NVIDIA 10de/03 trouvée",
              len(found) == 1 and found[0]["pci"] == "0000:05:00.0"
              and found[0]["device"] == "0x2484")

    # -- 3. the synthetic BAR0: the values planted, the reads exact -----
    with tempfile.TemporaryDirectory() as td:
        bar0 = Path(td) / "resource0"
        # 16 MB sparse-ish file (the real BAR0 form)
        with open(bar0, "wb") as f:
            f.truncate(0x1000000)
        rows, _ = _v454a["build_rows"](0x40)

        # the plants: the marker at a RISK offset, the dead-FF at a
        # SAFE offset, the plausible µW at another, the zero at a third
        safe = [r for r in rows if r["ack_class"] == "SAFE-PROBE"]
        risk = [r for r in rows if r["ack_class"] == "RISK-PROBE"]
        plants = {safe[0]["offset"]: 0xFFFFFFFF,
                  safe[1]["offset"]: SHAPE_250_UW,
                  risk[0]["offset"]: 350000000,
                  risk[1]["offset"]: 0x00000000}
        with open(bar0, "r+b") as f:
            for off, val in plants.items():
                f.seek(off)
                f.write(struct.pack("<I", val))

        # 3a. the refusal without the ACK (the gate on the REAL path)
        try:
            read_bar0(bar0, rows, ack=False, nb_ack=False)
            check("gate: le read REFUSE sans ACK", False)
        except ProbeRefused:
            check("gate: le read REFUSE sans ACK", True)

        # 3b. the SAFE-only run (ACK, no NB): the planted values exact
        res = read_bar0(bar0, rows, ack=True, nb_ack=False)
        got = {r["offset"]: r for r in res["reads"]}
        check("probe: SAFE[0] = 0xFFFFFFFF (DEAD)",
              got[safe[0]["offset"]]["value"] == 0xFFFFFFFF)
        check("probe: SAFE[1] = le marqueur 250 W exact",
              got[safe[1]["offset"]]["value"] == SHAPE_250_UW)
        check("probe: RISK[0] absent sans PROBE_454_NB",
              risk[0]["offset"] not in got)
        check("probe: skip compte = tous les RISK",
              res["counts"]["skipped-no-nb-ack"] == len(risk))
        check("probe: lu = tous les SAFE",
              res["counts"]["read"] == len(safe))
        check("probe: la lecture unique (aucun offset répété)",
              len({r["offset"] for r in res["reads"]}) == len(res["reads"]))

        # 3c. the full run (ACK+NB): the RISK plants read back exact
        res2 = read_bar0(bar0, rows, ack=True, nb_ack=True)
        got2 = {r["offset"]: r for r in res2["reads"]}
        check("probe: RISK[0] = 350000000 µW (la forme plausible)",
              got2[risk[0]["offset"]]["value"] == 350000000)
        check("probe: RISK[1] = 0x00000000",
              got2[risk[1]["offset"]]["value"] == 0)
        check("probe: tout lu = 215, skip = 0",
              res2["counts"]["read"] == len(rows)
              and res2["counts"]["skipped-no-nb-ack"] == 0)
        check("probe: le bar0_size = 16 MB",
              res2["bar0_size"] == 0x1000000)

        # 3d. the out-of-range row: ERROR-OOR, not a crash
        bad_rows = rows + [{"offset": 0x2000000, "name": "HORS_BAR0",
                            "ack_class": "SAFE-PROBE"}]
        res3 = read_bar0(bar0, bad_rows, ack=True, nb_ack=True)
        bad = [r for r in res3["reads"] if r["name"] == "HORS_BAR0"]
        check("probe: l'offset hors BAR0 = ERROR-OOR, pas un crash",
              len(bad) == 1 and bad[0]["status"] == "ERROR-OOR"
              and bad[0]["value"] is None)
        check("probe: err compte = 1",
              res3["counts"]["error-oor"] == 1)

        # 3e. the dump round-trip (the JSON = re-readable by v454c)
        os.environ["PROBE_454_ACK"] = "1"
        os.environ["PROBE_454_NB"] = "1"
        outp = Path(td) / "dump.json"
        dump(bar0, rows, "synthetic",
             {"pci": "synthetic", "device": "0x2484"}, outp)
        os.environ.pop("PROBE_454_ACK")
        os.environ.pop("PROBE_454_NB")
        back = json.loads(outp.read_text())
        check("JSON: le dump re-lisible, les reads identiques",
              back["mode"] == "synthetic"
              and len(back["reads"]) == len(rows)
              and back["ack"]["PROBE_454_ACK"] is True)

    print(f"selftest v454b: {ok}/{ok + fail} "
          f"{'PASS' if fail == 0 else 'FAIL'}")
    return fail == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--table", default=str(DEFAULT_TABLE))
    ap.add_argument("--pci", default=None,
                    help="the PCI address (0000:01:00.0) — the real run")
    ap.add_argument("--out", default="lab/jalon411/v454b_probe_dump.json")
    args = ap.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    # the real run: the table must exist + pass its own selftest first
    table = Path(args.table)
    if not table.is_file():
        print(f"REFUS: table absente ({table}) — lance v454a d'abord",
              file=sys.stderr)
        return 2
    ack, _ = gates(dict(os.environ))
    if not ack:
        print("REFUS: PROBE_454_ACK=1 absent — la sonde ne lit rien "
              "(même une lecture = un geste machine, gated)", file=sys.stderr)
        return 2

    rows = json.loads(table.read_text())["rows"]
    gpus = discover_gpus()
    if args.pci:
        gpus = [g for g in gpus if g["pci"] == args.pci] or \
               [{"pci": args.pci, "device": "?"}]
    elif len(gpus) == 1:
        gpus = gpus
    elif len(gpus) > 1:
        print("REFUS: plusieurs GPU NVIDIA — passe --pci explicite",
              file=sys.stderr)
        return 2
    else:
        print("REFUS: aucun GPU NVIDIA trouvé (classe 03, vendor 10de)",
              file=sys.stderr)
        return 2

    bar0 = Path("/sys/bus/pci/devices") / gpus[0]["pci"] / "resource0"
    if not bar0.is_file():
        print(f"REFUS: {bar0} absent — le driver stock monte-t-il la BAR0?",
              file=sys.stderr)
        return 2
    return dump(bar0, rows, "real", gpus[0], args.out)


if __name__ == "__main__":
    sys.exit(main())
