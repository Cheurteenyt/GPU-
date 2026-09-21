#!/usr/bin/env python3
"""v50-jtscan — vague 4.10 : le dernier mécanisme de référence indirecte.

Le firmware est EXEC sans relocations. Les jump-tables rodata stockent des
offsets RELATIFS (base + w = cible). Scan : toute position p (alignée 4 ou
8) du fichier telle que VA(p) + w(p) = cible, w 32 bits signé.

Cibles : pré-wrapper 0x12c7a1e, wrapper 0x12b5c88, consommateur 0x1bd979c.

Sortie : stdout + scratch-gsp/v50/v50_jtscan.json
"""
import struct
from pathlib import Path

OUT = Path("/home/z/my-project/scratch-gsp/v50")
ELF = Path("/home/z/my-project/scratch-gsp/rm.elf")
data = ELF.read_bytes()
LOAD1_END_OFF = 0xE85000  # fichier ; VA = off + 0x1000000

TARGETS = {0x12C7A1E: "pré-wrapper", 0x12B5C88: "wrapper", 0x1BD979C: "consommateur"}

for t, name in TARGETS.items():
    hits = []
    for off in range(0, LOAD1_END_OFF - 4, 4):
        va_p = off + 0x1000000
        w = struct.unpack_from("<i", data, off)[0]
        if va_p + w == t and w != 0:
            hits.append((va_p, w))
    print(f"=== {name} ({t:#08x}) : {len(hits)} position(s) base+off ===")
    for va_p, w in hits:
        print(f"  table/position VA {va_p:#08x} (fichier {va_p - 0x1000000:#x})"
              f"  offset {w:+#x}")
    # détection d'une TABLE : positions consécutives → contextes
    if hits:
        vs = [h[0] for h in hits]
        for v0 in vs:
            print(f"  contexte de {v0:#08x} :")
            for d in range(-0x20, 0x28, 4):
                w2 = struct.unpack_from("<i", data, v0 - 0x1000000 + d)[0]
                mark = " ←" if d == 0 else ""
                print(f"    +{d:+#04x}: {w2:+#010x} (→ {v0 + d + w2:#08x}){mark}")
        print()

json.dump({"scan": "done"}, (OUT / "v50_jtscan.json").open("w"))
print(f"-> {OUT / 'v50_jtscan.json'}")
