#!/usr/bin/env python3
"""v42-build-index — l'instrument de navigation du rm.elf (vague 4.2).

Construit et met en cache dans scratch-gsp/v42/ :
  strings.json    : {va_hex: text} pour toute string imprimable >= 5 chars
  xrefs.json      : {target_va_hex: [site_va,...]} — auipc+addi -> VA cible
  sites_of.json   : {site_va_hex: target_va_hex} (inverse, 1 site = 1 cible)
  clusters.json   : fenêtres 2Ko triées par densité M-extension (mul/div/rem)
  cluster_strings : strings référencées par chaque cluster (injecté dans clusters.json)

Usage : python3 v42_build_index.py            (construit tout, ~1-2 min)
        python3 v42_build_index.py --load     (recharge et résume)
"""
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

import capstone

RM = Path("/home/z/my-project/scratch-gsp/rm.elf")
OUT = Path("/home/z/my-project/scratch-gsp/v42")
OUT.mkdir(exist_ok=True)

TEXT_OFF, TEXT_VA, TEXT_SZ = 0x0, 0x1000000, 0xE85000
DATA_OFF, DATA_VA, DATA_SZ = 0xE85000, 0x4000000, 0x19C000


def off_to_va(off):
    return TEXT_VA + off if off < TEXT_SZ else DATA_VA + (off - DATA_OFF)


def scan_strings(rm):
    """toute zone imprimable >= 5 octets, nulle-terminée ou non, image entière."""
    import re
    strings = {}
    for m in re.finditer(rb"[\x20-\x7e]{5,}", rm):
        s = m.group().decode()
        strings[hex(off_to_va(m.start()))] = s
    return strings


def scan_xrefs(rm):
    """paires auipc rd / addi rd (mot 32 bits, opcode 0x17 puis 0x13 même rd)."""
    text = rm[:TEXT_SZ]
    n = len(text)
    xrefs = defaultdict(list)   # target_file_off -> [site_off]
    site_of = {}
    auips = []
    for off in range(0, n - 8, 2):
        w = struct.unpack_from("<I", text, off)[0]
        if (w & 0x7F) == 0x17:
            rd = (w >> 7) & 0x1F
            imm20 = (w >> 12) & 0xFFFFF
            if imm20 & 0x80000:
                imm20 -= 1 << 20
            auips.append((off, rd, imm20))
    for off, rd, imm20 in auips:
        hi = off + (imm20 << 12)
        for lo_off in range(off + 2, min(off + 32, n - 4), 2):
            w2 = struct.unpack_from("<I", text, lo_off)[0]
            if (w2 & 0x7F) == 0x13 and ((w2 >> 7) & 0x1F) == rd:
                lo = (w2 >> 20) & 0xFFF
                if lo & 0x800:
                    lo -= 1 << 12
                tgt = hi + lo
                if 0 <= tgt < n:  # offset fichier valide (text OU data)
                    tgt_va = off_to_va(tgt)
                    xrefs[tgt_va].append(off + TEXT_VA)
                    site_of[off + TEXT_VA] = tgt_va
                break
    return xrefs, site_of


def scan_mext_clusters(rm, win=0x800, stride=0x400):
    """densité M-extension (opcode 0x33, funct7 0x01) par fenêtre."""
    text = rm[:TEXT_SZ]
    counts = defaultdict(int)
    n = len(text)
    for off in range(0, n - 4, 2):
        w = struct.unpack_from("<I", text, off)[0]
        # R-type M: opcode 0x33, funct7 == 0x01, pas rd==0/x0 filter (approx ok)
        if (w & 0x7F) == 0x33 and ((w >> 25) & 0x7F) == 0x01:
            counts[off & ~(stride - 1)] += 1
    clusters = sorted(counts.items(), key=lambda kv: -kv[1])
    # fenêtres plus larges (win) fusionnées pour le rapport
    wide = defaultdict(int)
    for base, c in counts.items():
        wide[base & ~(win - 1)] += c
    return counts, sorted(wide.items(), key=lambda kv: -kv[1])


def cluster_strings(clusters_wide, site_of, strings, top=60):
    """pour chaque cluster: les strings dont le site d'xref tombe dans la fenêtre."""
    sites_by_base = defaultdict(list)
    for site_s, tgt_s in site_of.items():
        site = site_s if isinstance(site_s, int) else int(site_s, 16)
        tgt = tgt_s if isinstance(tgt_s, int) else int(tgt_s, 16)
        base = (site & 0xFFFFF800) & ~0x7FF  # fenêtre 2Ko du site
        wide_base = site & ~0x7FF
        sites_by_base[wide_base & ~0x7FF].append(tgt)
    out = []
    for base, cnt in clusters_wide[:top]:
        refs = sites_by_base.get(base, []) + sites_by_base.get(base - 0x800, []) + sites_by_base.get(base + 0x800, [])
        names = []
        for t in refs[:200]:
            s = strings.get(hex(t + TEXT_VA), "")
            if s and len(s) >= 5:
                names.append(s[:48])
        out.append({"base": hex(base + TEXT_VA), "count": cnt, "strings": names[:14]})
    return out


def main():
    rm = RM.read_bytes()
    if "--load" in sys.argv:
        strings = json.loads((OUT / "strings.json").read_text())
        xrefs = {k: v for k, v in json.loads((OUT / "xrefs.json").read_text()).items()}
        print(f"chargé: {len(strings)} strings, {sum(len(v) for v in xrefs.values())} xrefs")
        return
    print("scan strings…")
    strings = scan_strings(rm)
    (OUT / "strings.json").write_text(json.dumps(strings))
    print(f"  {len(strings)} strings")
    print("scan xrefs auipc/addi…")
    xrefs, site_of = scan_xrefs(rm)
    (OUT / "xrefs.json").write_text(json.dumps({hex(k): [hex(s) for s in v] for k, v in xrefs.items()}))
    (OUT / "sites_of.json").write_text(json.dumps({hex(k): hex(v) for k, v in site_of.items()}))
    print(f"  {sum(len(v) for v in xrefs.values())} xrefs depuis {len(site_of)} sites")
    print("scan densité M-ext…")
    counts, wide = scan_mext_clusters(rm)
    print(f"  {sum(counts.values())} instructions mul/div/rem")
    enriched = cluster_strings(wide, site_of, strings)
    (OUT / "clusters.json").write_text(json.dumps(enriched, indent=1))
    for c in enriched[:25]:
        sig = " | ".join(c["strings"][:4])
        print(f"  cluster @{c['base']} densité {c['count']:>4} — {sig[:110]}")
    print(f"index écrit dans {OUT}")


if __name__ == "__main__":
    main()
