#!/usr/bin/env python3
"""4.44 baseline — the banked-count reproduction BEFORE any production.

The discipline (since 4.19, re-asserted 4.43): reproduce the banked
counts on THIS machine before producing anything new. This instrument:
  1. the auipc census = 416,206 (banked 4.35b, reproduced 4.43) —
     counted at the byte level (opcode 0x17) over the code image;
  2. the coordinate law B_file = A_img - 0x38 = 512/512 windows;
  3. the booter_emu battery (run separately in the shell):
     --selftest 5/5, --test-transfer 11/11 (banked 4.42, reproduced
     this pass — see the run log).

Output: lab/jalon411/v4440_baseline.json
"""
import json
import zlib
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38

da = A.read_bytes()
db = B.read_bytes()
img = da[0x40:0x40 + 0xE9B000]
out = {}

# -- 1. the auipc census (byte-level: auipc = opcode 0x17, 4-byte aligned)
img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
u0 = np.frombuffer(img4, dtype="<u4")
cnt = 0
for base_off in (0, 2):
    pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
    uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
    k = np.arange((len(img4) - 4 - base_off) >> 2, dtype=np.int64)
    cnt += int(((uarr[k] & 0x7F) == 0x17).sum())
out["auipc_census"] = cnt
out["auipc_banked"] = 416206
out["auipc_match"] = cnt == 416206
print(f"auipc census: {cnt} (banked 416,206) match={cnt == 416206}")

# -- 2. the coordinate law, 512 windows
fails = 0
step = len(img) // 512
for i in range(512):
    o = 0x38 + i * step
    if img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
        fails += 1
out["law_fails"] = fails
print(f"coordinate law: {512 - fails}/512 windows")
assert fails == 0, "the map law is broken on this machine"

# -- 3. the covered map = decompressable, the census regions live
blob = zlib.decompress(MAP.read_bytes())
out["map_bytes"] = len(blob)
half = len(blob) // 2
covered = blob[half:]
out["covered_regions"] = sum(
    1 for i in range(1, len(covered))
    if covered[i] and not covered[i - 1])
print(f"map: {len(blob)} B, {out['covered_regions']} covered regions")

assert out["auipc_match"], "the auipc census does NOT reproduce — STOP"
OUT.write_text(json.dumps(out, indent=1))
print(f"written {OUT}")
