#!/usr/bin/env python3
"""v42-extract — pour chaque fenêtre win-*.txt, imprime l'extrait compact autour
de chaque site de consommation (auipc) connu de xrefs.json."""
import json
import re
import sys
from pathlib import Path

OUT = Path("/home/z/my-project/scratch-gsp/v42")

names = sys.argv[1:] if len(sys.argv) > 1 else None
for f in sorted(OUT.glob("win-*.txt")):
    if names and not any(n in f.name for n in names):
        continue
    text = f.read_text().splitlines()
    # toutes les adresses présentes
    addrs = {}
    for i, l in enumerate(text):
        m = re.match(r"0x([0-9a-f]+):", l)
        if m:
            addrs[int(m.group(1), 16)] = i
    # sites = adresses dont la cible est le string du fichier (auipc seg + addi)
    print(f"\n########## {f.name} ##########")
    # trouver les paires auipc/addi: heuristique — lignes 'auipc' suivies de 'addi aN'
    shown = set()
    for i, l in enumerate(text):
        if re.match(r"0x[0-9a-f]+:\s+auipc", l):
            for j in range(i + 1, min(i + 6, len(text))):
                if re.match(rf"0x[0-9a-f]+:\s+addi\s+(a[0-9]+|t[0-9]+),\s*(a[0-9]+|t[0-9]+),", text[j]):
                    lo, hi = max(0, i - 18), min(len(text), j + 46)
                    key = (lo, hi)
                    if key in shown:
                        break
                    shown.add(key)
                    print(f"--- extrait ligne {lo}..{hi} ---")
                    for l2 in text[lo:hi]:
                        print(l2)
                    break
    if not shown:
        print("(aucune paire auipc/addi détectée)")
