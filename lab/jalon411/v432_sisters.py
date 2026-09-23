#!/usr/bin/env python3
"""4.32 pass, instrument 2 (T2) — the sister constants 100000 and 240000:
exact lui+addi encodings, exhaustive scans, co-occurrence with the six
250000 sites.

The mission's decisive question: do the SAME rm.elf functions manipulate
{100000, 240000, 250000} together (the power-table signature, the ring-3
decoded 100/240/250 W), and what unit does the encoding imply?

Method:
  1. the canonical RV64 li-decomposition printed for the whole candidate
     scale set (250000 mW; 2500 = 0.1-W units; 25000 = %; the clocks
     250000/500000/1000000/4000000 kHz; the sisters 100000/240000);
  2. exhaustive 2-byte-step scan of the code image (A image, PROVEN = B)
     for lui+addi/addiw pairs materializing 100000 and 240000
     (rd==rs1, rd!=0, both add opcodes — the gspbuild law);
  3. u32 data-word scan for the same values in the code image AND the
     data LOAD segment of gsp-rm-17MB.bin (file 0xe9b000..0x1070000);
  4. for every hit: distance to the nearest 250000 site, same-covered-
     region flag; hits within 0x1000 of a 250000 site get an
     anchor-synced +-24-instruction disassembly window (cited).

Output: lab/jalon411/v432_sisters.json
"""
import json
import re
import struct
import zlib
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
SITES_250 = [0x190FE, 0x1A062, 0x1F09E0, 0x7C46B4, 0xB99BEC, 0xB99CC8]  # A coords

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)


def riscv_split(v):
    lo = v & 0xFFF
    if lo >= 0x800:
        lo -= 0x1000
    hi = (v - lo) >> 12
    return hi, lo


def scan_pairs(img, value):
    """exhaustive lui+addi/addiw pair census materializing `value`."""
    hi, lo = riscv_split(value)
    hi_b = hi & 0xFFFFF
    lo_b = lo & 0xFFF
    rd_mask, hits = {}, []
    n = len(img)
    for off in range(0, n - 8, 2):
        w1 = struct.unpack_from("<I", img, off)[0]
        if (w1 & 0x7F) != 0x37:
            continue
        rd = (w1 >> 7) & 0x1F
        if rd == 0 or (w1 >> 12) != hi_b:
            continue
        # candidate addi/addiw at +2 or +4 (canonical pairs are adjacent)
        for d in (2, 4):
            if off + d + 4 > n:
                continue
            w2 = struct.unpack_from("<I", img, off + d)[0]
            if (w2 & 0x7F) not in (0x13, 0x1B):
                continue
            if ((w2 >> 20) & 0xFFF) != lo_b:
                continue
            if ((w2 >> 7) & 0x1F) != rd or ((w2 >> 15) & 0x1F) != rd:
                continue
            hits.append({"A_img": hex(off), "VA": hex(IMG_LO + off),
                         "rd": rd, "op2": "addiw" if (w2 & 0x7F) == 0x1B else "addi",
                         "gap": d})
            break
    return hits


def scan_u32(img, value):
    pat = struct.pack("<I", value & 0xFFFFFFFF)
    out, i = [], 0
    while True:
        i = img.find(pat, i)
        if i < 0:
            break
        out.append(hex(i))
        i += 1
    return out


def regions(covered):
    starts, ends = [], []
    i, n = 0, len(covered)
    while i < n:
        if covered[i]:
            j = i
            while j < n and covered[j]:
                j += 1
            if j - i >= 2:
                starts.append(i)
                ends.append(j)
            i = j
        else:
            i += 1
    return starts, ends


def window(img, aoff, back=24, fwd=24):
    """anchor-synced window: forward from the anchor; backward by the
    predecessor chain (v432_sites law)."""
    fwdw = []
    off = aoff
    for _ in range(fwd + 6):
        try:
            ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
        except StopIteration:
            break
        fwdw.append((IMG_LO + off, ins.mnemonic, ins.op_str))
        off += ins.size
    bwd = []
    off = aoff
    while aoff - off < 0x80 and len(bwd) < back:
        p2 = off - 2
        if len(img[p2:p2 + 2]) == 2 and (img[p2] & 3) != 3:
            try:
                ins = next(md.disasm(img[p2:p2 + 2], IMG_LO + p2))
                if ins.size == 2:
                    bwd.append((IMG_LO + p2, ins.mnemonic, ins.op_str))
                    off = p2
                    continue
            except StopIteration:
                pass
            break
        p4 = off - 4
        try:
            ins = next(md.disasm(img[p4:p4 + 4], IMG_LO + p4))
            if ins.size == 4 and (img[p4] & 3) == 3:
                bwd.append((IMG_LO + p4, ins.mnemonic, ins.op_str))
                off = p4
                continue
        except StopIteration:
            pass
        break
    bwd.reverse()
    return bwd + fwdw


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    data_seg = db[0xE9B000:0x1070000]  # the RW LOAD of B @VA 0x4000000
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    starts, ends = regions(covered)

    def enclosing_region(a_off):
        for s0, e0 in zip(starts, ends):
            if s0 <= a_off < e0:
                return (s0, e0)
        return None

    # 1. the encodings table
    enc = {}
    for v in (100000, 240000, 250000, 2500, 25000, 280000, 500000,
              1000000, 4000000, 279024):
        hi, lo = riscv_split(v)
        enc[v] = {"hex": hex(v), "lui_imm": hex(hi), "addi_imm": hex(lo),
                  "addi_signed": lo,
                  "note": "" if lo >= 0 else "negative addi (canonical split)"}
    print("encodings:")
    for v, e in enc.items():
        print(f"  {v:>8} {e['hex']:>9}: lui {e['lui_imm']:>7} ; addi {e['addi_signed']:>7} ({e['addi_imm']})")

    # 2. the pair scans
    res = {}
    for val in (100000, 240000, 250000, 500000):
        hits = scan_pairs(a_img, val)
        for h in hits:
            a_off = int(h["A_img"], 16)
            dmin = min(abs(a_off - s) for s in SITES_250)
            h["dist_to_nearest_250"] = dmin
            h["nearest_250"] = hex(min(SITES_250, key=lambda s: abs(a_off - s)))
            r = enclosing_region(a_off)
            h["region"] = [hex(IMG_LO + r[0]), hex(IMG_LO + r[1])] if r else None
            near250r = enclosing_region(min(SITES_250, key=lambda s: abs(a_off - s)))
            h["same_region_as_nearest_250"] = bool(
                r and near250r and r == near250r)
        res[val] = hits
        print(f"pair sites materializing {val}: {len(hits)}")
        for h in hits:
            print(f"   {h['VA']} rd=x{h['rd']} {h['op2']} dist250={h['dist_to_nearest_250']} "
                  f"same_region={h['same_region_as_nearest_250']}")

    # 3. the u32 data scans
    data_hits = {}
    for val in (100000, 240000, 250000, 500000, 280000):
        data_hits[val] = {
            "code_image": scan_u32(a_img, val),
            "data_segment_B": scan_u32(data_seg, val),
        }
        print(f"u32 {val}: code {len(data_hits[val]['code_image'])} hits "
              f"{data_hits[val]['code_image'][:6]}, data {len(data_hits[val]['data_segment_B'])} hits "
              f"{data_hits[val]['data_segment_B'][:6]}")

    # 4. windows for sister sites near the 250000 family
    windows = {}
    for val in (100000, 240000):
        for h in res[val]:
            if h["dist_to_nearest_250"] <= 0x1000:
                a_off = int(h["A_img"], 16)
                w = window(a_img, a_off)
                windows[h["VA"]] = [{"va": hex(x[0]), "m": x[1], "o": x[2]}
                                    for x in w]
    # and the neighborhoods of the 250000 sites: all pair-constants within
    # +-0x300 bytes, from a local pair scan (any value) — the "what else
    # lives here" sweep
    fam = {}
    for s in SITES_250:
        lo_off, hi_off = s - 0x300, s + 0x300
        consts = []
        for off in range(max(0, lo_off), min(len(a_img) - 8, hi_off), 2):
            w1 = struct.unpack_from("<I", a_img, off)[0]
            if (w1 & 0x7F) != 0x37:
                continue
            rd = (w1 >> 7) & 0x1F
            if rd == 0:
                continue
            hi_v = w1 >> 12
            for d in (2, 4):
                if off + d + 4 > len(a_img):
                    continue
                w2 = struct.unpack_from("<I", a_img, off + d)[0]
                if (w2 & 0x7F) not in (0x13, 0x1B):
                    continue
                lo_v = (w2 >> 20) & 0xFFF
                if lo_v >= 0x800:
                    lo_v -= 0x1000
                if ((w2 >> 7) & 0x1F) != rd or ((w2 >> 15) & 0x1F) != rd:
                    continue
                v = (hi_v << 12) + lo_v
                consts.append({"at": hex(IMG_LO + off), "value": v,
                               "u32": v & 0xFFFFFFFF})
                break
        fam[hex(IMG_LO + s)] = sorted({c["u32"] for c in consts})
        print(f"250 site {hex(IMG_LO+s)}: pair-constants in +-0x300: "
              f"{[hex(x) for x in sorted({c['u32'] for c in consts})]}")

    out = {
        "encodings": {str(k): v for k, v in enc.items()},
        "pair_sites": {str(k): v for k, v in res.items()},
        "u32_hits": {str(k): v for k, v in data_hits.items()},
        "sister_windows_near_250": windows,
        "constants_within_0x300_of_250_sites": fam,
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
