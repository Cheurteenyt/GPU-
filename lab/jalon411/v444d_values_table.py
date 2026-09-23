#!/usr/bin/env python3
"""4.44 pass, TÂCHE A3+A4 — the captures cross-check and the VALUE table.

A3: can the equation limit = base x f18 / 100 / 1000 be SOLVED BY DATA
today? The available captures:
  - tools/edpp/edpp_payload_1616.bin (the 0x2080d031 send-side capture,
    1616 B, the 5 nonzero u32s banked 4.24);
  - the recv dumps (the 4.25/4.26 hook) = ARMED, NEVER RUN — no capture
    exists in the repo (the honest negative, bounded to this repo).
The scan: every u32 pair {b, f} in the payload windows solving
b*f/100000 in {250000, 240000, 100000}; every u32 equal to the
base-unit candidates {250000000, 240000000, 100000000} (the f18=100
percent reading) and {250000, 240000} (the per-mille reading); plus
the whole rm.elf + container data scan for the same u32s (the static
seed hunt, extending the 4.21 mW scan with the micro-watt forms).

A4: the VALUE table per idx (0..3 — the PROVEN iteration count) with
the formula-inverted minimal modification for 280000, computed for
BOTH unit readings, never guessed.

Output: lab/jalon411/v444d_values_table.json
"""
import json
import zlib
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
PAY = ROOT / "tools/edpp/edpp_payload_1616.bin"
OUT = Path(__file__).with_suffix(".json")

LIMITS = (250000, 240000, 100000)
BASE_MW_CANDIDATES = (250000, 240000, 100000)          # the per-mille reading
BASE_UW_CANDIDATES = (250000000, 240000000, 100000000)  # the percent reading


def u32_scan(buf, values):
    hits = {}
    arr = np.frombuffer(buf, dtype="<u4")
    for v in values:
        idx = np.where(arr == v)[0]
        hits[v] = [int(i) for i in idx]
    return hits


def main():
    out = {}
    img = A.read_bytes()[0x40:0x40 + 0xE9B000]
    container = B.read_bytes()
    payload = PAY.read_bytes()

    # -- the capture sanity (the banked 4.24 fieldmap)
    arr = np.frombuffer(payload, dtype="<u4")
    nz = [(int(i) * 4, int(arr[i])) for i in np.where(arr != 0)[0]]
    out["payload_nonzero_u32"] = [{"off": o, "val": v} for o, v in nz]
    print(f"payload nonzero u32s: {len(nz)} (the 4.24 banked = 5)")

    # -- A3.1: the pair-solve over the payload (every u32 window pair
    #          {x@p, y@p+4k} with x*y % 100000 == 0 and the quotient hit)
    solves = []
    n = len(arr)
    for i in range(n):
        for j in range(i + 1, min(i + 9, n)):   # the +-32 B window
            x, y = int(arr[i]), int(arr[j])
            if x == 0 or y == 0:
                continue
            prod = x * y
            if prod % 100000:
                continue
            lim = prod // 100000
            if lim in LIMITS:
                solves.append({"i_off": i * 4, "x": x, "j_off": j * 4,
                               "y": y, "limit": lim})
    out["payload_pair_solves"] = solves
    print(f"payload pair-solves of the equation: {len(solves)}")

    # -- A3.2: the unit-candidate u32 scan in the payload
    out["payload_unit_hits"] = {
        str(v): h for v, h in u32_scan(payload,
                                       BASE_MW_CANDIDATES +
                                       BASE_UW_CANDIDATES).items()}

    # -- A3.3: the static-seed hunt (rm.elf + container, both readings)
    out["rmelf_unit_hits"] = {
        str(v): {"count": len(h), "first": h[:8]}
        for v, h in u32_scan(img, BASE_MW_CANDIDATES +
                             BASE_UW_CANDIDATES).items()}
    out["container_unit_hits"] = {
        str(v): {"count": len(h), "first": h[:8]}
        for v, h in u32_scan(container, BASE_MW_CANDIDATES +
                             BASE_UW_CANDIDATES).items()}
    for name in ("rmelf_unit_hits", "container_unit_hits"):
        for v, d in out[name].items():
            print(f"{name}[{v}]: {d['count']}")

    # -- A3.4: the recv-capture existence (bounded: this repo)
    recv_files = []
    for p in (ROOT / "tools/edpp").iterdir():
        if p.suffix in (".txt", ".log"):
            recv_files.append(p.name)
    out["recv_capture_files"] = recv_files or []
    out["recv_capture_exists"] = bool(recv_files)

    # -- A4: the value table (both unit readings, computed)
    #     the equation: limit = base x f18 / 100000. The stock pair is
    #     NOT observable today -> the table = the two candidate pairs
    #     (the SAME equation family, both producing 250000):
    #       percent  : (base, f18) = (250,000,000 uW, 100)   — the
    #                  physically-coherent reading (/100 = the percent
    #                  scale, /1000 = uW->mW);
    #       permille : (base, f18) = (25,000,000, 1000)      — the
    #                  arithmetically-possible alternative (the base
    #                  unit scale unknown).
    #     The MINIMAL modification = scale ONE factor by 28/25 (= 1.12,
    #     250 -> 280). The decider = reading the stock f18 (the runbook
    #     U2 experiment).
    table = []
    for reading, f18_stock, base_stock, unit_note in (
            ("percent (base=uW, f18=%)", 100, 250000000,
             "/100 = the percent scale, /1000 = uW->mW — coherent"),
            ("permille (f18=1/1000)", 1000, 25000000,
             "the arithmetic alternative — the base unit scale unknown")):
        f18_new = f18_stock * 28 // 25
        base_new = base_stock * 28 // 25
        table.append({
            "reading": reading,
            "unit_note": unit_note,
            "stock": {"f18": f18_stock, "base": base_stock,
                      "limit_check": base_stock * f18_stock // 100000},
            "f18_route": {"f18_new": f18_new,
                          "exact": f18_stock * 28 % 25 == 0,
                          "limit_check": base_stock * f18_new // 100000,
                          "u64_value": f"0x{f18_new:016x}",
                          "target": "obj+0x18+idx*0x30 (u64, aligned)",
                          "collateral": "record+0x1c = the field the"
                                        " recompute ZEROES every pass"
                                        " (0x143ff04) — self-healing",
                          "persistence": "the recompute write set EXCLUDES"
                                         " record f14/f18 (v444c PROVEN)"},
            "base_route": {"base_new": base_new,
                           "exact": base_stock * 28 % 25 == 0,
                           "limit_check": base_new * f18_stock // 100000,
                           "u64_value": f"0x{base_new:016x}",
                           "target": "obj+0x618+idx*0x10 (u64, aligned)",
                           "collateral": "the neighbor u32 (A[k+1]/"
                                         "mirror[3]) = recompute-owned",
                           "persistence": "VOLATILE — the recompute"
                                          " rewrites the base array"},
        })
    out["value_table"] = table

    # -- the records the payload entries carry (the 4.44 payload = the
    #     f18 route for the 4 records + the base route for the active idx)
    entries = []
    for idx in range(4):
        entries.append({
            "id": f"R{idx}",
            "target": f"obj+0x{0x18 + idx * 0x30:x}",
            "u64_percent": f"0x{112:016x}",
            "u64_permille": f"0x{1120:016x}",
            "note": "record[idx].f18 <- 112 (the percent reading) — the"
                    " persistent route; the +0x1c half = 0 = the"
                    " recompute-zeroed field"})
    for idx in range(4):
        entries.append({
            "id": f"B{idx}",
            "target": f"obj+0x{0x618 + idx * 0x10:x}",
            "u64_percent": f"0x{280000000:016x}",
            "u64_permille": f"0x{280000:016x}",
            "note": "base[idx].D <- 280000-equivalent — the timing-window"
                    " route (volatile)"})
    out["payload_entries"] = entries

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
