#!/usr/bin/env python3
"""v50-semantics — vague 4.10, chantier 2 : la carte champ→sémantique.

Les 28 identités JT1 (0x1DEB210 : valeurs 0..0x11 + 0x1e/0x1f + 0x1c×3)
décodent les champs 5 bits [8:4]/[20:16] du second registre 0x68A01C —
une famille de domaines clk/voltage. Cherchons l'espace de noms :

1. Extraction ASCII (runs ≥ 6) du LOAD1 file-backed, VA taggées.
2. Filtrage par lexique de domaines (gpc/ltc/xbar/sys/hub/fb/clk/volt...).
3. Regroupement par zones rodata (tables de strings = espaces de noms).
4. Zoom : voisinage des zones candidates (±0x100).

Sortie : stdout + scratch-gsp/v50/v50_semantics.json
"""
import json
import re
from pathlib import Path

OUT = Path("/home/z/my-project/scratch-gsp/v50")
ELF = Path("/home/z/my-project/scratch-gsp/rm.elf")
data = ELF.read_bytes()
LOAD1_VA, LOAD1_SZ = 0x1000000, 0xE85000

LEX = re.compile(rb"(?i)^(gpc|ltc|xbar|sys|hub|fb|fbpa|clk|clock|volt|voltage|"
                 rb"mux|l2|mcc|ce[0-9]|pmu|gr|host|disp|sec2|nvdec|nvenc|nvjpg|"
                 rb"ofa|msenc|imem|dmem|pmu|stripes|soc|therm|vmin|vmax|"
                 rb"tmargin|freq|vfeq|point|curve|rail|domain|engine| pll|"
                 rb"osc|xtal|sppll|mpll|gpcclk|sysclk|hubclk|ltcclk|xbarclk|"
                 rb"clkdomain|voltdomain)[a-z0-9_]{0,40}$")

# ---- 1. runs ASCII ≥ 6 dans le LOAD1 (zone rodata : après le texte)
# le texte est au début ; les rodata file-backed lues en 4.8/4.9 vivent à
# 0x1DEBxxx/0x1E83xxx — on scanne TOUT le LOAD1 et on regroupe par zone.
runs = []
i = 0
n = min(LOAD1_SZ, len(data))
pat = re.compile(rb"[\x20-\x7e]{6,}")
for m in pat.finditer(data, 0, n):
    va = LOAD1_VA + m.start()
    runs.append((va, m.group().decode("ascii", "replace")))
print(f"strings ASCII ≥ 6 dans LOAD1 : {len(runs)}")

# ---- 2. filtre lexique
hits = [(va, s) for va, s in runs if LEX.match(s.encode("ascii"))]
print(f"strings candidats domaine : {len(hits)}")

# ---- 3. regroupement par zone (fenêtre de 0x400)
zones = {}
for va, s in hits:
    zones.setdefault(va & ~0x3FF, []).append((va, s))
print(f"zones (fenêtres 0x400) contenant des candidats : {len(zones)}")
dense = sorted(zones.items(), key=lambda kv: -len(kv[1]))[:20]
for zone, lst in dense:
    print(f"\n=== zone {zone:#08x} : {len(lst)} strings ===")
    for va, s in lst[:14]:
        print(f"  {va:#08x}  {s!r}")

json.dump({"n_strings": len(runs),
           "candidates": [{"va": hex(va), "s": s} for va, s in hits[:400]],
           "zones": {hex(z): [{"va": hex(va), "s": s} for va, s in lst]
                     for z, lst in dense}},
          (OUT / "v50_semantics.json").open("w"), indent=1)
print(f"-> {OUT / 'v50_semantics.json'}")
