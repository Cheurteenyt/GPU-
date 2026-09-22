#!/usr/bin/env python3
"""Revalidation indépendante des affirmations byte-level du pass 4.24 (Task 1).

Re-vérifie SANS réutiliser v424_payload_map.py :
  A. sha256 du payload
  B. cmd @abs 0x08 == 0x2080d031 ; paramsSize @abs 0x10 == 1544
  C. abs 104 == 250000 (0x3D090)
  D. 100000 (0x186A0) : zéro occurrence u32 step-1 sur tout le fichier
  E. 240000 (0x3A980) : zéro occurrence
  F. recensement u32 non-nuls de la zone params (abs 40..1583) -> 5 attendus
  G. loi de longueur : 1616 = corps 1584 + résidu 32 ; résidu 1584..1615 tout-zéro
  H. test du field-order EDPP_LIMIT_INFO (base 96)
  I. occurrences de 250000 ailleurs que @104
"""
import hashlib, struct, sys

import os
PAY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools", "edpp", "edpp_payload_1616.bin")
data = open(PAY, "rb").read()
results = []
def rec(name, claimed, got, ok):
    results.append((name, claimed, got, ok))

# A. sha256
sha = hashlib.sha256(data).hexdigest()
rec("A. sha256 (prefix)", "573a2836428bda3c…", sha[:18], sha.startswith("573a2836428bda3c"))

# B. header fields
cmd = struct.unpack_from("<I", data, 0x08)[0]
psz = struct.unpack_from("<I", data, 0x10)[0]
rec("B1. cmd @0x08", "0x2080d031", hex(cmd), cmd == 0x2080D031)
rec("B2. paramsSize @0x10", "1544", psz, psz == 1544)

# C. offset 104
v104 = struct.unpack_from("<I", data, 104)[0]
rec("C. u32 @abs 104", "250000 (0x3D090)", f"{v104} ({hex(v104)})", v104 == 250000 and v104 == 0x3D090)

# D/E. zero-hit scans
hits_100k, hits_240k = [], []
for off in range(0, len(data) - 3):
    w = struct.unpack_from("<I", data, off)[0]
    if w == 100000: hits_100k.append(off)
    if w == 240000: hits_240k.append(off)
rec("D. occurrences 100000 (0x186A0)", "0", len(hits_100k), len(hits_100k) == 0)
rec("E. occurrences 240000 (0x3A980)", "0", len(hits_240k), len(hits_240k) == 0)

# F. nonzero u32 census in params body (abs 40..1583)
nz = [(o, struct.unpack_from("<I", data, o)[0]) for o in range(40, 1584, 4)
      if struct.unpack_from("<I", data, o)[0] != 0]
expected_nz = [(40, 255), (44, 3), (48, 257), (96, 257), (104, 250000)]
rec("F. census u32 non-nuls params", str(expected_nz), str(nz), nz == expected_nz)

# G. capture-length law
res = data[1584:1616]
rec("G1. len == 1616", "1616", len(data), len(data) == 1616)
rec("G2. résidu 1584..1615 tout-zéro", "32×0x00", f"{len(res)} B, nz={sum(1 for b in res if b)}",
    len(res) == 32 and all(b == 0 for b in res))

# H. field-order test EDPP (base 96 reads limitMin=257, limitRated=0 per the pass)
lm = struct.unpack_from("<I", data, 96)[0]
lr = struct.unpack_from("<I", data, 100)[0]
rec("H. base96 limitMin/limitRated", "257 / 0", f"{lm} / {lr}", lm == 257 and lr == 0)

# I. occurrences de 250000 ailleurs que @104 (le rewriter 4.23 réécrivait TOUT)
hits_250k = [o for o in range(0, len(data) - 3)
             if struct.unpack_from("<I", data, o)[0] == 250000]
rec("I. occurrences 250000", "[104] uniquement", str(hits_250k), hits_250k == [104])

print(f"{'CHECK':44s} {'CLAIMED':26s} {'GOT':30s} VERDICT")
fails = 0
for name, claimed, got, ok in results:
    print(f"{name:44s} {str(claimed):26s} {str(got):30s} {'PASS' if ok else 'FAIL'}")
    fails += 0 if ok else 1
print(f"\n{len(results)-fails}/{len(results)} PASS, {fails} FAIL")
sys.exit(1 if fails else 0)
