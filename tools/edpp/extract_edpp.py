#!/usr/bin/env python3
"""Extrait la structure EDPp des payloads fn=76 (stdin = le journal greppé)."""
import sys
import re
import struct

payloads = []
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

sig = struct.pack('<I', 250000)
cands = [(i, pl) for i, pl in enumerate(payloads) if pl and sig in pl[1]]
print(f"les payloads avec 250000 : {len(cands)}")
if not cands:
    sys.exit(1)
# le plus proche de 1616 = la table EDPp
cands.sort(key=lambda c: abs(len(c[1][1]) - 1616))
i0, (declared, p) = cands[0]
off104 = p.find(sig)
print(f"payload #{i0} : déclaré={declared}, réassemblé={len(p)}, 250000 @ +{off104}")
print(f"=== le contexte {off104-40}..{off104+68} ===")
for off in range(max(0, off104 - 40), min(len(p) - 3, off104 + 68), 4):
    v = struct.unpack_from('<I', p, off)[0]
    tag = "   <<< 250 W (limitMax ?)" if v == 250000 else ""
    print(f"  +{off:4d}: {v:>12} (0x{v:08x}){tag}")
# les payloads jumeaux : identiques ?
twin = [(i, pl) for i, pl in enumerate(payloads) if pl and len(pl[1]) == len(p) and pl[1] == p]
print(f"les jumeaux byte-identiques : {len(twin)} payloads")
open('/tmp/edpp_payload.bin', 'wb').write(bytes(p))
print(f"sauvegardé: /tmp/edpp_payload.bin ({len(p)} octets)")
