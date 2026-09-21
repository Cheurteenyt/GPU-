#!/usr/bin/env python3
"""v45-build-text — désassemblage linéaire INTÉGRAL du segment X-R de rm.elf.

Segment [0] : X-R, file 0x0..0xE85000, VA 0x1000000..0x1E85000 (code+rodata).
Capstone disasm_lite (rapide), RVC actif. Sortie : text.tsv
(addr, size, mnem, ops) — 1 ligne par instruction décodée.
Le sweep linéaire peut désynchroniser sur les zones rodata : les requêtes
v45 filtrent par mnémonique, et les faux positifs sont bénins (rodata).
"""
import time
from pathlib import Path

import capstone

RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
OUT = Path("/home/z/my-project/scratch-gsp/v45")
OUT.mkdir(exist_ok=True)

TEXT_OFF, TEXT_SZ, TEXT_VA = 0x0, 0xE85000, 0x1000000

md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)
md.skipdata = True  # les octets non décodables passent en .byte, le sweep reste aligné

rm = RM.read_bytes()
text = rm[TEXT_OFF:TEXT_OFF + TEXT_SZ]

t0 = time.time()
n = 0
with (OUT / "text.tsv").open("w") as f:
    for addr, size, mnem, ops in md.disasm_lite(text, TEXT_VA):
        f.write(f"{addr:x}\t{size}\t{mnem}\t{ops}\n")
        n += 1
        if n % 1_000_000 == 0:
            print(f"  {n} instructions... {time.time()-t0:.0f}s", flush=True)

print(f"DONE: {n} instructions en {time.time()-t0:.0f}s -> {OUT/'text.tsv'}")
