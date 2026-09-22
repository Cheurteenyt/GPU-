#!/usr/bin/env python3
"""L'analyseur v2 : réassemble les payloads fn=76 (RPCDUMP76 off=...) et
chasse les valeurs power/timings.
Usage: journalctl -b -k | grep RPCDUMP76 | python3 rpcdump76_analyze.py
"""
import sys
import re
import struct

POWER_MW = {100000: "100 W (min)", 120000: "120 W", 210000: "210 W",
            220000: "220 W", 240000: "240 W", 250000: "250 W (le max VBIOS)",
            265000: "265 W", 280000: "280 W (LA CIBLE)"}
SIGS = {struct.pack("<I", mw): label for mw, label in POWER_MW.items()}

payloads = []          # [(len, bytes)]
cur = None
for ln in sys.stdin.read().splitlines():
    m = re.search(r"RPCDUMP76 seq=(\d+) off=(\d+) len=(\d+):(.*)", ln)
    if not m:
        continue
    seq, off, ln_len = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hx = bytes(int(x, 16) for x in m.group(4).split())
    while len(payloads) <= seq:
        payloads.append(None)
    if payloads[seq] is None:
        payloads[seq] = [ln_len, bytearray()]
    if len(payloads[seq][1]) < off + len(hx):
        payloads[seq][1].extend(bytes(off + len(hx) - len(payloads[seq][1])))
    payloads[seq][1][off:off + len(hx)] = hx
if cur:
    payloads.append(cur)

payloads = [p for p in payloads if p is not None]
print(f"payloads fn=76 réassemblés : {len(payloads)}")
total = sum(len(p[1]) for p in payloads)
print(f"volume total : {total} octets")

print("\n=== les signatures power (mW, little-endian) ===")
found = False
for idx, pl in enumerate(payloads):
    ln_len, data = pl
    for sig, label in SIGS.items():
        start = 0
        while True:
            off = data.find(sig, start)
            if off == -1:
                break
            print(f"  payload #{idx} (len {ln_len}) : {label} @ offset {off}")
            found = True
            start = off + 1
if not found:
    print("  (aucune)")

print("\n=== le recensement mW-like (u32 100000..300000, multiple de 500) ===")
census = {}
for idx, pl in enumerate(payloads):
    ln_len, data = pl
    for off in range(0, len(data) - 3):
        v = struct.unpack_from("<I", data, off)[0]
        if 100000 <= v <= 300000 and v % 500 == 0:
            key = (idx, v)
            census[key] = census.get(key, 0) + 1
for (idx, v), n in sorted(census.items()):
    label = POWER_MW.get(v, "")
    print(f"  payload #{idx} : {v} mW ×{n} {label}")
