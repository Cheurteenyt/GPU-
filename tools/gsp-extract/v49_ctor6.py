#!/usr/bin/env python3
"""v49-ctor6 — vague 4.9 : les gabarits data des pointeurs +0x288.

1. win.elf : charger segments LOAD ; lire le code aux stubs 0x1915574 /
   0x193cc44 (confirmation).
2. Chercher dans TOUTES les sections data (fichier) les qwords == pointeurs
   de la fenêtre stub → adresses VA des gabarits.
3. Dispatcher : fonction contenant 0x1634bb8, prologue + origine de s1.
"""
import bisect
import json
import struct
from pathlib import Path

V45 = Path("/home/z/my-project/scratch-gsp/v45")
OUT = Path("/home/z/my-project/scratch-gsp/v49")
ELF = Path("/home/z/my-project/scratch-gsp/rm.elf")

data = ELF.read_bytes()

# ---- parse program headers (64-bit LE)
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from(
        "<QQQQQ", data, off + 8)
    if p_type == 1:
        loads.append({"off": p_offset, "va": p_vaddr, "filesz": p_filesz,
                      "memsz": p_memsz, "flags": p_flags})
print("=== segments LOAD ===")
for L in loads:
    print(f"  VA {L['va']:#010x}+{L['filesz']:#x} (mem {L['memsz']:#x}) "
          f"off {L['off']:#x} flags {L['flags']}")


def va2off(va):
    for L in loads:
        if L["va"] <= va < L["va"] + L["filesz"]:
            return L["off"] + (va - L["va"])
    return None


def read_va(va, n):
    o = va2off(va)
    return data[o:o + n] if o is not None else None


# ---- 1 : confirmation des stubs
for stub in (0x1915574, 0x193CC44):
    b = read_va(stub, 16)
    print(f"\nstub {stub:#08x} : {b.hex(' ') if b else 'HORS FICHIER'}")

# ---- 2 : gabarits — qwords == stub dans tout le fichier
print("\n=== qwords == pointeurs stub dans le fichier ===")
STUBS = set(range(0x1915540, 0x1915600)) | set(range(0x193CC00, 0x193CC90))
found = []
for L in loads:
    blob = data[L["off"]:L["off"] + L["filesz"]]
    for k in range(0, len(blob) - 7, 8):
        w = struct.unpack_from("<Q", blob, k)[0]
        if w in STUBS:
            found.append((L["va"] + k, w))
from collections import Counter
c = Counter(w for _, w in found)
print(f"  {len(found)} qword(s) ; répartition : "
      f"{ {hex(w): n for w, n in c.most_common(10)} }")
for va, w in found[:40]:
    print(f"  VA {va:#010x} = {w:#x}")
(OUT / "v49_templates.txt").write_text(
    "\n".join(f"{va:#010x} = {w:#x}" for va, w in found) + "\n")

# ---- 3 : dispatcher, fonction de 0x1634bb8
rows = []
for line in (V45 / "text.tsv").read_text().splitlines():
    a, s, m, o = line.split("\t", 3)
    rows.append((int(a, 16), int(s), m, o))
addrs = [r[0] for r in rows]


def parse(o):
    return [x.strip() for x in o.split(",")]


di = bisect.bisect_left(addrs, 0x1634BB8)
fstart = None
for i in range(di, -1, -1):
    a, s, m, o = rows[i]
    p = parse(o)
    if (m in ("addi", "c.addi") and len(p) == 3 and p[0] == "sp"
            and p[1] == "sp" and p[2].startswith("-")) or \
       (m == "c.addi16sp" and p and p[-1].startswith("-")):
        fstart = i
        break
print(f"\n=== dispatcher : fonction contenant 0x1634bb8, début "
      f"{rows[fstart][0]:#08x} ===")
out = []
for i in range(fstart, min(fstart + 45, len(rows))):
    a, s, m, o = rows[i]
    out.append(f"  {a:#08x}  {m:10} {o}")
print("\n".join(out))

json.dump({"stub_qwords": [(hex(va), hex(w)) for va, w in found]},
          (OUT / "v49_ctor6.json").open("w"), indent=1)
