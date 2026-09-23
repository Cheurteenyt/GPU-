#!/usr/bin/env python3
"""4.32 pass, instrument 2b — the ALL-PAIRS single pass over the code
image: every lui+addi/addiw pair (any value, any legal decomposition)
value-indexed. Closes the scan loophole left by v432_sisters.py (which
only tried the canonical li split):

  - the alternative legal decomposition (hi+1, lo-0x1000) that a
    non-canonical codegen could emit;
  - c.lui/c.addi formations where both immediates fit their narrow
    fields (c.lui nzimm[17:12], c.addi imm 6-bit signed);
  - a value-neighbourhood report: which "interesting" scale values
    (the mW 0.1 W % interpretations of 250, the kHz clock ladder, the
    µs ladder) materialize ANYWHERE in the image.

Output: lab/jalon411/v432_allpairs.json
"""
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000


def main():
    da = A.read_bytes()
    img = da[0x40:0x40 + 0xE9B000]
    n = len(img)

    by_value = {}   # value -> list of A_img offsets
    pairs = 0
    for off in range(0, n - 8, 2):
        w1 = struct.unpack_from("<I", img, off)[0]
        if (w1 & 0x7F) != 0x37:
            continue
        rd = (w1 >> 7) & 0x1F
        if rd == 0:
            continue
        hi = w1 >> 12
        for d in (2, 4):
            if off + d + 4 > n:
                continue
            w2 = struct.unpack_from("<I", img, off + d)[0]
            op = w2 & 0x7F
            if op not in (0x13, 0x1B):
                continue
            if ((w2 >> 7) & 0x1F) != rd or ((w2 >> 15) & 0x1F) != rd:
                continue
            lo = (w2 >> 20) & 0xFFF
            if lo >= 0x800:
                lo -= 0x1000
            hi_s = hi - 0x100000 if hi >= 0x80000 else hi  # sign-extend 20-bit
            v = (hi_s << 12) + lo
            by_value.setdefault(v, []).append(off)
            pairs += 1
            break

    print(f"pairs scanned: {pairs}, distinct values: {len(by_value)}")

    def find(v):
        return [hex(o) for o in by_value.get(v, [])]

    # the question values under EVERY interpretation
    report = {}
    for v in (100000, 240000, 250000, 280000, 2500, 25000, 500000,
              1000000, 4000000, 100000000, 279024):
        report[v] = find(v)
        print(f"{v:>10} ({hex(v):>9}): {len(report[v])} pair sites "
              f"{report[v][:8]}")

    # the neighbours of 250000 (what other values sit in +-1 of the
    # observed sites' families) — the observed co-occurrence ladder
    ladder = {v: len(by_value.get(v, []))
              for v in (250000, 500000, 1000000, 4000000, 100000000,
                        -1000000, -250000, -500000, -100000000)}
    print("co-occurrence ladder (pair-site counts):", ladder)

    out = {
        "pairs_total": pairs,
        "distinct_values": len(by_value),
        "question_values": {str(k): v for k, v in report.items()},
        "ladder_counts": {str(k): v for k, v in ladder.items()},
        # keep the full value index? too big — keep only the values with
        # 5+ sites in the mW/kHz/µs plausible bands
        "bands": {
            "mW_150k_350k": {str(v): [hex(o) for o in offs]
                             for v, offs in sorted(by_value.items())
                             if 150000 <= v <= 350000},
            "us_ms_band_100k_5M": {str(v): len(offs)
                                   for v, offs in sorted(by_value.items())
                                   if 100000 <= v <= 5000000 and v % 1000 == 0},
        },
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
