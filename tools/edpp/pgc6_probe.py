#!/usr/bin/env python3
"""pgc6_probe.py — la sonde bis : la paire PGC6 (4.56 T3) sur le système vivant.
ZÉRO patch, ZÉRO reboot, lecture seule PROT_READ — le même pattern v454b.
La paire (le 4.56 T3) :
  0x00118234 = NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_0_GFW_BOOT — le champ
               _PROGRESS 7:0 : 0xFF = _COMPLETED (le header addendum),
               0x01..0xfe = les stades non nommés (le ROM fermé),
               0x0 = l'artefact PLM (lu sans la protection LEVEL0 baissée).
  0x00118128 = le PLM qui décide si le registre = lisible.
Les voisins ±0x8 = le contexte borné (une lecture par offset, jamais répété).
"""
import argparse, json, mmap, os, struct, sys

PGC6_PROGRESS = 0x00118234
PGC6_PLM      = 0x00118128

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/home/cheurteen/dmem-451/pgc6_probe.json")
    a = ap.parse_args()

    pci = "/sys/bus/pci/devices/0000:07:00.0/resource0"
    fd = os.open(pci, os.O_RDONLY | os.O_SYNC)
    size = os.fstat(fd).st_size
    mm = mmap.mmap(fd, 0, prot=mmap.PROT_READ)  # LA LECTURE SEULE — par construction
    assert size >= PGC6_PROGRESS + 4, "Bar0 trop petit"

    targets = sorted({PGC6_PLM + d for d in (-8, 0, 4, 8)} |
                     {PGC6_PROGRESS + d for d in (-8, -4, 0, 4, 8)})
    reads = []
    for off in targets:
        v = struct.unpack("<I", mm[off:off + 4])[0]
        reads.append({"offset": off, "offset_hex": f"0x{off:08x}", "value": v,
                      "value_hex": f"0x{v:08x}",
                      "role": ("PLM" if off == PGC6_PLM else
                               "PROGRESS" if off == PGC6_PROGRESS else "neighbor")})
    mm.close(); os.close(fd)

    plm = next(r["value"] for r in reads if r["role"] == "PLM")
    prog_raw = next(r["value"] for r in reads if r["role"] == "PROGRESS")
    prog = prog_raw & 0xFF
    verdict = {
        "plm_raw": f"0x{plm:08x}",
        "progress_raw": f"0x{prog_raw:08x}",
        "progress_field": f"0x{prog:02x}",
        "interpretation": (
            "COMPLETED (0xff)" if prog == 0xFF else
            "STAGE (0x01-0xfe) — le stade non nommé (le ROM fermé)" if prog else
            "0x0 = l'artefact PLM ou le pre-boot (le registre lu sans la protection LEVEL0 baissée)"
        ),
        "plm_note": "le PLM = à décoder (le 4.56 T1 : le niveau de protection décide la lisibilité)",
    }
    out = {"pass": "4.56-machine", "probe": "pgc6-bis", "reads": reads, "verdict": verdict}
    print(json.dumps(out, indent=1))
    json.dump(out, open(a.out, "w"), indent=1)
    print(f"écrit: {a.out}")

if __name__ == "__main__":
    main()
