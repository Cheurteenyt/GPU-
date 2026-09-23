#!/usr/bin/env python3
"""4.38 TASK A, instrument 3 — the enclosing-dispatcher hunt for the two
internal-event handler entry points (the mid-function-entry architecture
of 4.24: the dispatch-table handler VA is a TAIL entry, the real logic —
including the store that fills buf[0x10] which becomes obj+0x660 — lives
in the enclosing dispatcher body).

Method (all on the proven v416 map):
  1. the seen bitmap gates every decode (only map-verified instruction
     starts are disassembled — the desync-proof walk);
  2. backward prologue hunt: from the handler VA, walk DOWN through
     seen=1 starts; a function start = a prologue (addi sp,sp,-N /
     c.addi16sp sp,-N) whose preceding instruction is an epilogue
     (ret/c.jr ra/j). The LAST such prologue <= handler VA whose linear
     forward walk reaches the handler = the enclosing function;
  3. the enclosing function walk: every STORE via the buffer-candidate
     registers (the handler block's buf register and its copies), the
     id comparisons (the 0x2080a**** materializations), the call list,
     the lui+addi constants;
  4. the same for the second handler 0x1768bc4 and its enclosing body.

Output: lab/jalon411/v438a3_dispatchers.json
"""
import json
import re
import zlib
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp"}
CALLS = {"jal", "jalr", "c.jal", "c.jalr"}
EPILOGUES = {"ret", "c.jr", "j", "c.j", "mret"}


def seen_starts(seen, lo, hi):
    return [o for o in range(lo, hi) if seen[o]]


def decode(img, off):
    try:
        ins = next(md.disasm(img[off:off + 4], IMG_LO + off))
        return ins
    except (StopIteration, Exception):
        return None


def find_enclosing(img, seen, hoff, region_lo, region_hi, max_back=0x3000):
    """walk down from hoff (A_img offset); return the candidate function starts."""
    starts = [o for o in range(hoff - max_back, hoff)
              if region_lo <= o < region_hi and seen[o]]
    cands = []
    for o in starts:
        ins = decode(img, o)
        if ins is None:
            continue
        m = ins.mnemonic
        if m in ("addi", "c.addi16sp") and ("sp" in ins.op_str) and (
                "-0x" in ins.op_str or re.search(r", sp, -(?:0x[0-9a-f]+|\d+)$", ins.op_str)):
            if m == "c.addi16sp" or (m == "addi" and re.search(r"sp, sp, -(0x[0-9a-f]+|\d+)$", ins.op_str)):
                cands.append(o)
    # keep candidates whose previous seen instruction is an epilogue
    good = []
    for o in cands:
        prevs = [p for p in starts if p < o]
        if not prevs:
            continue
        p = prevs[-1]
        pin = decode(img, p)
        if pin is not None and (pin.mnemonic in EPILOGUES or pin.mnemonic.startswith("c.jr")):
            good.append(o)
    return good, starts


def walk_seen(img, seen, lo, hi):
    out = []
    o = lo
    while o < hi:
        if not seen[o]:
            o += 1
            continue
        ins = decode(img, o)
        if ins is None:
            o += 2
            continue
        out.append({"off": o, "va": IMG_LO + o, "m": ins.mnemonic,
                    "o": ins.op_str, "size": ins.size, "ins": ins})
        o += ins.size
    return out


def fmt(w):
    return [{"va": hex(x["va"]), "m": x["m"], "o": x["o"]} for x in w]


def analyze_function(img, seen, start_off, end_off, label):
    w = walk_seen(img, seen, start_off, end_off)
    stores = [{"va": hex(x["va"]), "m": x["m"], "o": x["o"]}
              for x in w if x["m"] in STORES]
    calls = [{"va": hex(x["va"]), "m": x["m"], "o": x["o"]}
             for x in w if x["m"] in CALLS]
    ids = []
    for x in w:
        m = re.search(r"0x2080a([0-9a-f]{3})", x["o"])
        if x["m"] == "lui" and m:
            ids.append({"va": hex(x["va"]), "o": x["o"]})
    consts = []
    for i, x in enumerate(w):
        if x["m"] == "lui":
            m = re.match(r"^(\w+), (0x[0-9a-f]+)$", x["o"])
            if m:
                rd, hi2 = m.group(1), int(m.group(2), 16)
                hv = hi2 if hi2 < 0x80000 else hi2 - 0x100000
                val = hv << 12
                for j in range(i + 1, min(i + 5, len(w))):
                    w2 = w[j]
                    m2 = re.match(rf"^addiw?, {re.escape(rd)}, {re.escape(rd)}, (-?0x[0-9a-f]+|-?\d+)$", w2["o"])
                    if m2:
                        val += int(m2.group(1), 0)
                        consts.append({"va": hex(x["va"]), "value": val & 0xFFFFFFFF, "signed": val})
                        break
                    m3 = re.match(r"^(\w+),", w2["o"])
                    if m3 and m3.group(1) == rd and w2["m"] not in ("addi", "addiw"):
                        break
    return {"label": label, "start": hex(IMG_LO + start_off),
            "end": hex(IMG_LO + end_off), "n_insns": len(w),
            "stores": stores, "calls": calls, "event_ids": ids,
            "constants": consts, "window": fmt(w)}


def main():
    da = A.read_bytes()
    img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]

    # the regions from the 4.20 resolve table (A_img offsets)
    regions = {
        "0x2080A080": (6617664, 6655024, 0x16502D0 - IMG_LO),
        "0x2080A618": (7761020, 7773778, 0x1768BC4 - IMG_LO),
    }
    out = {}
    for ev, (lo, hi, hoff) in regions.items():
        print(f"\n=== {ev}: handler A_img {hex(hoff)}, region [{hex(lo)},{hex(hi)}) ===")
        goods, starts = find_enclosing(img, seen, hoff, lo, hi)
        print("prologue candidates:", [hex(g) for g in goods])
        # for each candidate, walk forward to see if it reaches the handler
        chosen = None
        for g in reversed(goods):
            w = walk_seen(img, seen, g, min(g + 0x2000, hi))
            vas = [x["off"] for x in w]
            if hoff in vas:
                chosen = (g, w)
                break
        if chosen is None:
            print("NO enclosing function found reaching the handler; "
                  "fallback: the 0x1000 window before the handler")
            g = max(lo, hoff - 0x1000)
            w = walk_seen(img, seen, g, hoff + 0x400)
            chosen = (g, w)
        g, w = chosen
        # the function end = the next prologue after the handler
        end = min(g + 0x2000, hi)
        for x in w:
            if x["off"] > hoff and x["m"] in ("c.addi16sp",) and "sp" in x["o"] and "-0x" in x["o"]:
                end = x["off"]
                break
        fn = analyze_function(img, seen, g, end, f"{ev} enclosing dispatcher")
        out[ev] = fn
        print(f"enclosing start={fn['start']} end={fn['end']} insns={fn['n_insns']}")
        print("event ids in body:", fn["event_ids"])
        print("constants:", [c for c in fn["constants"]][:20])
        print("stores:", json.dumps(fn["stores"])[:2000])
        # print the window around the handler VA
        idx = next((i for i, x in enumerate(w) if x["off"] == hoff), None)
        if idx is not None:
            print("--- the window [handler-12, handler+30]:")
            for x in w[max(0, idx - 12): idx + 30]:
                print(f"  {hex(x['va'])}: {x['m']:<8} {x['o']}")

    OUT.write_text(json.dumps(out, indent=1))
    print(f"\nwritten {OUT}")


if __name__ == "__main__":
    main()
