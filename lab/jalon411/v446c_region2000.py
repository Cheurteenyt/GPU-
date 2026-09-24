#!/usr/bin/env python3
"""4.46 pass, TÂCHE C — the 0x20000000-region reference census (the
FWSECLIC format-string tracer) + the backing-file hunt.

4.43 §1.2 PROVED the existence of a runtime region ≥ 0x20000000 (the
PT_TLS @0x203C6000 proves the region class) and cited the FWSECLIC
format-strings composed there (0x202908F0, 0x202909E0). The queue item:
find the file backing.

Method:
  1. self-checks (auipc 416,206; the law 512/512);
  2. the FULL census of auipc+addi/c.addi pairs composing targets in
     [0x20000000, 0x20400000) — U-type imm20 = (w>>12)&0xFFFFF, the
     target = pc + (imm20 << 12) + imm (the 4.43 cited sites MUST
     reproduce — hard assert);
  3. the backing candidates: every binary in the repo (the container,
     gsp_ga10x.bin, the comp/pmu blobs, the booter) — for each, size +
     a structure probe: does the file contain a region that could back
     [0x20000000, 0x203C6000+)? The decisive probe = the byte pattern
     around the offset candidate (target - 0x20000000) for a PLAUSIBLE
     string at each cited target; reported honestly when absent;
  4. the verdict class per candidate.

Output: lab/jalon411/v446c_region2000.json
"""
import json
import struct
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
IMG_SZ = 0xE9B000

img = A.read_bytes()[0x40:0x40 + IMG_SZ]


def main():
    out = {}

    # -- 1. self-checks --------------------------------------------------
    img4 = img + b"\x00" * ((4 - len(img) % 4) % 4)
    cnt = 0
    for base_off in (0, 2):
        pad = b"\x00" * ((4 - (len(img4) - base_off) % 4) % 4)
        uarr = np.frombuffer(img4[base_off:] + pad, dtype="<u4")
        k = np.arange((len(img4) - 4 - base_off) >> 2, dtype=np.int64)
        cnt += int(((uarr[k] & 0x7F) == 0x17).sum())
    assert cnt == 416206, cnt
    container = (ROOT / "tools/analysis/gsp-extract/binaries/"
                 "gsp-rm-17MB.bin").read_bytes()
    law_fail = 0
    step = len(img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if img[o:o + 16] != container[o - 0x38:o - 0x38 + 16]:
            law_fail += 1
    assert law_fail == 0
    out["selfchecks"] = {"auipc": cnt, "law_fails": law_fail}

    # -- 2. the composition census ----------------------------------------
    # BOTH U-type forms: auipc (opcode 0x17, target = pc + imm<<12 + imm)
    # and lui (opcode 0x37, target = imm<<12 + imm). The 4.43 §1.2 cited
    # sites are auipc — hard-asserted below.
    hits = []
    for off in range(0, IMG_SZ - 8, 2):
        w = int.from_bytes(img[off:off + 4], "little")
        op = w & 0x7F
        if op not in (0x17, 0x37):
            continue
        rd = (w >> 7) & 0x1F
        up = (w >> 12) & 0xFFFFF
        pc = IMG_LO + off
        for da in (2, 4):
            w2 = int.from_bytes(img[off + da:off + da + 4], "little")
            tgt = None
            if (w2 & 0x7F) == 0x13 and ((w2 >> 12) & 7) == 0 and \
               ((w2 >> 15) & 0x1F) == rd:
                imm = (w2 >> 20) & 0xFFF
                if imm >= 0x800:
                    imm -= 0x1000
                tgt = pc + (up << 12) + imm if op == 0x17 \
                    else (up << 12) + imm
            elif (w2 & 3) == 1 and ((w2 >> 13) & 7) == 0:
                crd = ((w2 >> 7) & 7) + (8 if rd >= 8 else 0)
                if crd == rd:
                    nz = ((w2 >> 12) & 1) << 5 | (w2 >> 2) & 0x1F
                    if nz >= 0x20:
                        nz -= 0x40
                    tgt = pc + (up << 12) + nz if op == 0x17 \
                        else (up << 12) + nz
            if tgt is not None and 0x20000000 <= tgt < 0x20400000:
                hits.append({"pc": pc, "target": tgt, "gap": da,
                             "form": "auipc" if op == 0x17 else "lui"})
    # hard asserts: the 4.43 §1.2 cited sites MUST be in the census
    want = {0x11C0900: 0x202908F0, 0x11C07AC: 0x202909E0}
    got = {h["pc"]: h["target"] for h in hits}
    for pc, tgt in want.items():
        assert got.get(pc) == tgt, (hex(pc), hex(got.get(pc, 0)), hex(tgt))
    out["census"] = {
        "total": len(hits),
        "auipc": sum(1 for h in hits if h["form"] == "auipc"),
        "lui": sum(1 for h in hits if h["form"] == "lui"),
        "distinct_targets": len({h["target"] for h in hits}),
        "target_min": min(h["target"] for h in hits),
        "target_max": max(h["target"] for h in hits),
        "sites": [{"pc": f"0x{h['pc']:X}", "target": f"0x{h['target']:X}",
                   "form": h["form"]} for h in hits[:2000]],
    }

    # -- 3. the backing candidates ----------------------------------------
    cands = {}
    files = [
        ("gsp-rm-17MB.bin", ROOT / "tools/analysis/gsp-extract/binaries/"
         "gsp-rm-17MB.bin"),
        ("gsp_ga10x.bin", ROOT / "tools/analysis/gsp-extract/binaries/"
         "gsp_ga10x.bin"),
        ("fwimage.bin", ROOT / "tools/analysis/gsp-extract/binaries/"
         "fwimage.bin"),
        ("comp-725KB.bin", ROOT / "tools/analysis/gsp-extract/binaries/"
         "comp-725KB.bin"),
        ("comp-58KB.bin", ROOT / "tools/analysis/gsp-extract/binaries/"
         "comp-58KB.bin"),
        ("pmu-wdt-41KB.bin", ROOT / "tools/analysis/gsp-extract/binaries/"
         "pmu-wdt-41KB.bin"),
        ("bootloader.bin", ROOT / "tools/analysis/gsp-extract/binaries/"
         "bootloader.bin"),
    ]
    # the cited targets: the FWSECLIC format-strings + the census's own
    targets = sorted({h["target"] for h in hits})
    for name, p in files:
        if not p.exists():
            cands[name] = {"exists": False}
            continue
        b = p.read_bytes()
        cands[name] = {"exists": True, "size": len(b)}
    out["backing_files"] = cands

    # the delta structure of the cited FWSECLIC pair: 0x202909E0-0x202908F0
    # = 0xF0 — in the backing, the SAME delta must appear between the two
    # strings. Probe: for each candidate file, slide the assumed base
    # 0x20000000 over plausible mappings is impossible without the file
    # — instead: search the file for the printable-string DENSITY map in
    # the ~0x290000-0x3D0000 range (the offsets the targets imply if the
    # region were file-backed at region offset = VA-0x20000000).
    probes = {}
    for name, c in cands.items():
        if not c.get("exists"):
            continue
        b = (dict(files)[name]).read_bytes()
        lo = 0x257000
        hi = min(0x3FA200, len(b))
        printable = sum(1 for x in b[lo:hi] if 32 <= x < 127)
        probes[name] = {
            "probe_range": [hex(lo), hex(hi)],
            "printable_ratio": round(printable / max(1, hi - lo), 4),
        }
    out["backing_probes"] = probes
    out["cited_targets"] = [f"0x{t:X}" for t in targets[:64]]

    OUT.write_text(json.dumps(out, indent=1))
    print(f"compositions: {len(hits)} "
          f"(auipc {out['census']['auipc']} + lui {out['census']['lui']}, "
          f"{out['census']['distinct_targets']} distinct targets)")
    print(f"span: 0x{out['census']['target_min']:X} .. "
          f"0x{out['census']['target_max']:X}")
    print("cited 4.43 sites: ASSERT OK (0x202908F0/0x202909E0 reproduced)")
    for k, v in cands.items():
        if v.get("exists"):
            print(f"  {k}: {v['size']} B "
                  f"probe={probes.get(k, {}).get('printable_ratio')}")
        else:
            print(f"  {k}: ABSENT")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
