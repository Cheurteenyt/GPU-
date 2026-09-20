#!/usr/bin/env python3
"""scan-kcore-power — hunt for the GPU power-limit values in kernel RAM.

The question: does the host driver parse the VBIOS power table (100/240/250 W
= 100000/240000/250000 mW)? If the values exist in kernel RAM (outside the
WPR), the parse is host-side and the values are patchable in memory -> the
GSP receives the raised limits -> nvidia-smi -pl 280 works.

Pure reads via /proc/kcore (not subject to /dev/mem seals).
Usage: echo <password> | sudo -S python3 tools/scan-kcore-power.py
"""
import struct
import sys
import time
from collections import defaultdict

# les valeurs de power en mW (u32 LE) — la table VBIOS (0x8fc04) + les EDPp
TARGETS = {
    100000: "100 W (min)",
    240000: "240 W (rated)",
    250000: "250 W (peak)",
    280000: "280 W (target)",
    265000: "265 W (avg)",
}
CHUNK = 1 << 26  # 64 MiB

f = open('/proc/kcore', 'rb')
assert f.read(4) == b'\x7fELF'
is64 = f.read(1)[0] == 2
f.seek(0x20 if is64 else 0x1c)
phoff = struct.unpack('<Q' if is64 else '<I', f.read(8 if is64 else 4))[0]
f.seek(0x36 if is64 else 0x2a)
phentsize, phnum = struct.unpack('<HH', f.read(4))
segs = []
for i in range(phnum):
    f.seek(phoff + i * phentsize)
    ph = f.read(phentsize)
    p_type = struct.unpack_from('<I', ph, 0)[0]
    if p_type != 1:
        continue
    p_offset, p_vaddr = struct.unpack_from('<QQ', ph, 8)
    p_filesz = struct.unpack_from('<Q', ph, 32)[0]
    if p_filesz > 0:
        segs.append((p_offset, p_vaddr, p_filesz))
total = sum(s[2] for s in segs)
print(f"kcore: {len(segs)} segments PT_LOAD, {total/2**30:.1f} GiB à scanner")

hits = defaultdict(list)
done = 0
t0 = time.time()
for seg_off, seg_vaddr, seg_size in segs:
    pos = seg_off
    end = seg_off + seg_size
    while pos < end:
        n = min(CHUNK, end - pos)
        f.seek(pos)
        blob = f.read(n)
        for val, name in TARGETS.items():
            pat = struct.pack('<I', val)
            start = 0
            while True:
                i = blob.find(pat, start)
                if i < 0:
                    break
                vaddr = seg_vaddr + (pos - seg_off) + i
                hits[name].append((hex(vaddr), val))
                start = i + 1
        pos += n
        done += n
        if int(done / 2**30) != int((done - n) / 2**30):
            print(f"  {done/2**30:.1f} GiB scannés ({time.time()-t0:.0f}s)...")
print(f"scan complet en {time.time()-t0:.0f}s")
print("--- les valeurs de power trouvées dans la RAM du kernel ---")
total_found = 0
for val in sorted(TARGETS):
    h = hits.get(val, [])
    print(f"  {TARGETS[val]}: {len(h)} occurrence(s)")
    for v in h[:8]:
        print(f"    @vaddr {v}")
    total_found += len(h)
if total_found == 0:
    print("  AUCUNE valeur 100000/240000/250000 mW dans la RAM du host —")
    print("  les limites = dans la WPR du GSP (le domaine fermé) ou")
    print("  en u64/encodage différent — la voie host = à réévaluer")
