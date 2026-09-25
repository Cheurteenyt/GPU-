#!/usr/bin/env python3
"""patch445.py — le drop-in v445 r0 pour kernel_gsp.c (les ancres EXACTES).
2 édits :
  1. le #include "v445_memdesc_patch.c" après le bloc d'includes ;
  2. l'appel v445_patch_signature_memdesc(pSignatureVa) juste APRÈS le
     portMemCopy de _kgspCreateSignatureMemdesc.
Idempotent (v445Marker)."""
import sys

path = sys.argv[1]
src = open(path).read()

if "v445Marker" in src:
    print("already patched (idempotent)")
    sys.exit(0)

# ---- l'appel (l'ancre EXACTE : le portMemCopy de la signature) ----
anchor = """    portMemCopy(pSignatureVa, memdescGetSize(pKernelGsp->pSignatureMemdesc),
        pGspFw->pSignatureData, pGspFw->signatureSize);"""
n = src.count(anchor)
if n != 1:
    print(f"REFUSÉ: l'ancre portMemCopy = {n} occurrences (attendu 1)")
    sys.exit(1)
call = anchor + "\n    v445_patch_signature_memdesc(pSignatureVa);   /* v445Marker: le r0 = le débordement bénin */"
src = src.replace(anchor, call)

# ---- l'include (la dernière ligne #include du bloc du haut) ----
lines = src.split("\n")
last_inc = -1
for i, line in enumerate(lines[:400]):
    if line.startswith("#include"):
        last_inc = i
if last_inc < 0:
    print("REFUSÉ: pas de bloc #include")
    sys.exit(1)
lines.insert(last_inc + 1, '#include "v445_memdesc_patch.c"   /* v445Marker: le payload r0 */')
open(path, "w").write("\n".join(lines))
print(f"PATCH OK 445: l'include après la ligne {last_inc + 1}, l'appel après le portMemCopy")
