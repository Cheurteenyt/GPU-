#!/usr/bin/env python3
"""4.34 PART C — the tick rate: the last TIME residual of 4.32.

Part B found the smoking gun: a c.lui-100000 body COMPARES 100000
against a value and reads `rdtime` in the same window (@0x141b654/6) —
the time-counter CSR. This instrument answers: WHAT is the tick period
the rm.elf programs/converts?

Method, all byte-derived on the proven coordinates (law B = A - 0x38):
  1. the CSR census: every system-op (0x73) instruction at a seen start,
     decoded csr number — rdtime (0xC01), rdcycle (0xC00), rdinstret
     (0xC02), and the CONFIG CSRs around them;
  2. per rdtime site: the +-24-insn window; the CONSTANTS that appear in
     the window (full-form lui+addi pairs, c.lui pairs, and raw u32
     multiples of 1000) — the conversion form is read off the window;
  3. the frequency hunt: the known GPU/GSP clock constants searched in
     BOTH the code image (instruction-materialized) and the data image —
     31250000 (31.25 MHz), 15625000, 27000000 (27 MHz), 25000000,
     3906250, 31250 (kHz), 1000000000 (ns/s), plus the u32 raw forms;
  4. the multiplication chain: every mul whose window carries both a
     time constant and a divu — the ticks->us/->ns converter shape;
  5. the verdict: the tick period the firmware assumes, the domain of
     the 100000 family (ticks? ns? us?), PROVEN or HYPOTHESIS per site.

Output: lab/jalon411/v434c_tickrate.json
"""
import json
import struct
import zlib
from collections import Counter
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000

db = B.read_bytes()
blob = zlib.decompress(MAP.read_bytes())
half = len(blob) // 2
seen, covered = blob[:half], blob[half:]
assert seen[0x1A02A] == 1 and seen[0x1A02C] == 0

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True


def dis1(off, va=None):
    if off + 2 > len(db):
        return None
    if db[off] & 3 == 3:
        if off + 4 > len(db):
            return None
        return next(md.disasm(db[off:off + 4], (va if va is not None else off)), None)
    return next(md.disasm(db[off:off + 2], (va if va is not None else off)), None)


IMG = db[SHIFT:]                      # the code image in B-file coords
print("[1] CSR census (system ops 0x73 at seen starts)")
csr_hits = []
for off in range(0, len(IMG) - 4, 2):
    if not seen[off + SHIFT] if off + SHIFT < len(seen) else False:
        continue
    w = struct.unpack_from("<I", IMG, off)[0]
    if (w & 0x7F) != 0x73:
        continue
    csr = (w >> 20) & 0xFFF
    rd = (w >> 7) & 0x1F
    rs1 = (w >> 15) & 0x1F
    f3 = (w >> 12) & 7
    csr_hits.append((off, csr, rd, rs1, f3))
csr_hist = Counter(c for _, c, _, _, _ in csr_hits)
print(f"    {len(csr_hits)} system ops; top csr numbers:",
      csr_hist.most_common(12))
time_reads = [(o, c) for o, c, rd, rs1, f3 in csr_hits
              if c in (0xC00, 0xC01, 0xC02) and f3 == 2 and rs1 == 0]
print(f"    rdcycle/rdtime/rdinstret reads: {len(time_reads)}")
for o, c in time_reads:
    print(f"      {'rdcycle' if c == 0xC00 else 'rdtime' if c == 0xC01 else 'rdinstret'}"
          f" @B {o + SHIFT:#x} (VA {o + IMG_LO + SHIFT:#x})")


def window_consts(start, end):
    """constants materialized in [start, end): full pairs + c.lui pairs
    + raw u32 multiples of 1000."""
    vals = []
    off = start & ~1
    while off + 8 <= end:
        w = struct.unpack_from("<I", IMG, off)[0]
        if (w & 0x7F) == 0x37 and ((w >> 7) & 0x1F) != 0:
            rd = (w >> 7) & 0x1F
            w2 = struct.unpack_from("<I", IMG, off + 4)[0]
            if (w2 & 0x7F) in (0x13, 0x1B) and ((w2 >> 12) & 7) == 0 \
                    and ((w2 >> 15) & 0x1F) == rd and ((w2 >> 7) & 0x1F) == rd:
                hi = w >> 12
                lo = (w2 >> 20) & 0xFFF
                v = (hi << 12) + (lo - 0x1000 if lo >= 0x800 else lo)
                if abs(v) >= 1000:
                    vals.append((hex(off + SHIFT), "full", v))
                off += 8
                continue
        w16 = IMG[off] | (IMG[off + 1] << 8)
        if (w16 & 3) == 1 and (w16 >> 13) == 3:
            rd = (w16 >> 7) & 0x1F
            if rd not in (0, 2):
                imm6 = ((w16 >> 12) & 1) << 5 | ((w16 >> 2) & 0x1F)
                if imm6 >= 0x20:
                    imm6 -= 0x40
                if imm6 != 0 and abs(imm6) >= 2:
                    w2 = struct.unpack_from("<I", IMG, off + 2)[0]
                    if (w2 & 0x7F) == 0x13 and ((w2 >> 12) & 7) == 0 \
                            and ((w2 >> 15) & 0x1F) == rd and \
                            ((w2 >> 7) & 0x1F) == rd:
                        lo = (w2 >> 20) & 0xFFF
                        v = (imm6 << 12) + (lo - 0x1000 if lo >= 0x800 else lo)
                        if abs(v) >= 1000:
                            vals.append((hex(off + SHIFT), "clui", v))
                        off += 8
                        continue
        off += 2
    return vals


print("[2] per-rdtime windows + conversion shapes")
win_data = []
for o, c in time_reads:
    lo_b = o + SHIFT
    lines = []
    cur = o
    for _ in range(14):
        ins = dis1(cur)
        if ins is None:
            break
        lines.append(f"0x{cur + IMG_LO + SHIFT:x}: {ins.mnemonic:<8} {ins.op_str}")
        cur += ins.size
    consts = window_consts(max(0, o - 0x60), min(len(IMG), o + 0x80))
    win_data.append(dict(csr=c, B_file=hex(lo_b),
                         VA=hex(o + IMG_LO + SHIFT),
                         window=lines, consts=consts))
    print(f"  {'rdtime' if c == 0xC01 else 'rdcycle'} @VA {o + IMG_LO + SHIFT:#x}")
    for ln in lines:
        print("   ", ln)
    if consts:
        print(f"    consts: {[v for _, _, v in consts]}")

print("[3] the frequency hunt (code + data)")
FREQS = {31250000: "31.25 MHz (the classic GSP/PTIMER tick)",
         15625000: "15.625 MHz", 27000000: "27 MHz (ref clk)",
         25000000: "25 MHz", 3906250: "3.90625 MHz",
         31250: "31250 kHz-ns scale", 1000000000: "ns per s",
         1000000: "us per s", 100000: "the Part-B family"}
hits = {}
for v, label in FREQS.items():
    code = window_consts(0, len(IMG))
    cnt_full = sum(1 for _, _, x in code if x == v)
    # raw u32 in the data image (the tail after the code image)
    data = db[SHIFT + 0xE9B000:]
    raw = 0
    needle = struct.pack("<I", v & 0xFFFFFFFF)
    pos = 0
    while True:
        i = data.find(needle, pos)
        if i < 0:
            break
        if i % 4 == 0:
            raw += 1
        pos = i + 1
    hits[v] = dict(label=label, full_form=cnt_full, raw_u32_data=raw)
    print(f"  {v:>12,}  full={cnt_full:<4} data-u32={raw:<4}  {label}")

print("[4] verdict assembly")
out = dict(
    law="B_file = A_img - 0x38; VA = A_img + 0x1000000",
    csr_census=dict(total=len(csr_hits),
                    top=csr_hist.most_common(20),
                    time_reads=[dict(csr=c, B_file=hex(o + SHIFT),
                                     VA=hex(o + IMG_LO + SHIFT))
                                for o, c in time_reads]),
    rdtime_windows=win_data,
    freq_hunt={str(k): v for k, v in hits.items()},
)
OUT.write_text(json.dumps(out, indent=1))
print(f"[5] {OUT}")
