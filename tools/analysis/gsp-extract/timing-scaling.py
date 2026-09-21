#!/usr/bin/env python3
"""timing-scaling — classify every timing-table byte by its scaling behavior
across the frequency bins. Fields scaling with frequency = cycle counts;
fields constant = nanosecond-based parameters; noise = unpacked elsewhere.
This is the empirical grammar discovery for the GDDR6 timing records.
"""
import json
from pathlib import Path

d = Path('/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/acquisitions/MSI.RTX3070.8192.210519_1.rom').read_bytes()
T = 571520; HLEN = 6; BLEN = 76
base = T + HLEN

# the bin → timing-ID map (from gx5-timings register, the 7 non-empty bins)
BINS = {
    'bin0_0-540':    [0, 10, 20, 0, 10, 0, 30, 10, 0, 0],
    'bin1_541-1249': [1, 11, 21, 1, 11, 1, 31, 11, 1, 1],
    'bin2_2005-4699':[2, 12, 22, 2, 12, 2, 32, 12, 2, 2],
    'bin3_4700-5250':[2, 12, 22, 2, 12, 2, 32, 12, 2, 2],
    'bin4_5251-5799':[3, 13, 23, 3, 13, 3, 33, 13, 3, 3],
    'bin5_5800-6300':[4, 14, 24, 4, 14, 4, 34, 14, 4, 4],
    'bin6_6301+':    [6, 16, 26, 8, 18, 8, 38, 19, 8, 8],
}
# representative frequency (MHz, memory clock) per bin — midpoints
FREQ = {'bin0_0-540': 270, 'bin1_541-1249': 900, 'bin2_2005-4699': 3300,
        'bin3_4700-5250': 5000, 'bin4_5251-5799': 5500, 'bin5_5800-6300': 6050,
        'bin6_6301+': 6801}

records = {name: d[base + ids[slot] * BLEN: base + ids[slot] * BLEN + BLEN]
           for name, ids in BINS.items()
           for slot in range(10)}  # all slot-bin records

# for each slot: classify each byte position across the 7 bins
SLOT_NAMES = ['slot1', 'slot2', 'slot3', 'slot4', 'slot5', 'slot6', 'slot7', 'slot8', 'slot9', 'slot10']
classification = {}
for slot in range(10):
    bin_names = list(BINS.keys())
    rows = []
    for bname in bin_names:
        rid = BINS[bname][slot]
        rec = d[base + rid * BLEN: base + rid * BLEN + BLEN]
        freq = FREQ[bname]
        rows.append((freq, rec, bname, rid))
    rows.sort()
    for pos in range(BLEN):
        series = [(f, rec[pos]) for f, rec, _, _ in rows]
        vals = [v for _, v in series]
        distinct = len(set(vals))
        if distinct == 1:
            kind = 'constant'
        else:
            # scaling test: correlation with frequency for nonzero values
            pts = [(f, v) for f, v in series if v]
            if len(pts) < 3:
                kind = 'sparse'
            else:
                # ratio between the fastest and a mid bin
                fx = pts[-1][0] / pts[0][0] if pts[0][0] else 0
                vx = pts[-1][1] / pts[0][1] if pts[0][1] else 0
                if vx > 0 and 0.5 < fx / vx < 2.0 and pts[-1][1] > pts[0][1]:
                    kind = 'cycles?'
                elif all(v == pts[0][1] for _, v in pts):
                    kind = 'ns-constant?'
                else:
                    kind = 'packed/mixed'
        classification.setdefault(SLOT_NAMES[slot], {}).setdefault(kind, []).append({'pos': pos, 'series': series})

out = {'slots': {}}
for slot, kinds in classification.items():
    out['slots'][slot] = {kind: fields for kind, fields in kinds.items()}
    print(f'--- {slot} ---')
    for kind, fields in sorted(kinds.items()):
        print(f'  {kind}: {len(fields)} fields -> {[f["pos"] for f in fields][:14]}')

Path(__file__).with_name('timing-scaling.json').write_text(json.dumps(out, indent=1))
print('saved: timing-scaling.json')
