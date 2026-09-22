#!/usr/bin/env python3
"""
v428f — the NVML sites: disassembly windows around the two 0x2080d031
occurrences in libnvidia-ml.so.610.57.04 (sha256 50feda0f…, extracted verbatim
from the official 610.57.04 package — same provenance law as the substrate).

Question: does NVML build the 1544-B params of the captured GET_EDPP_LIMIT_INFO
request, and does the 100000 quantum get written into it?

Method: ET_DYN, no symbols (NVML is stripped) — capstone over ±0x120 B windows
around each cmd site, starting the decode at the nearest C3 (ret) / CC
boundary; every call/jmp target and every immediate recorded; the 28 x 0x186a0
and 12 x 0x608 and 2 x 0x630 offsets listed for neighbourhood cross-checks.
Facts only; nothing named from memory.
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = "/home/z/my-project/work/downloads/extracted/libnvidia-ml.so.610.57.04"
REG = os.path.join(HERE, "v428f_nvvm_sites.json")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)


def hits_of(d, value, size=4):
    nd = struct.pack("<I" if size == 4 else "<Q", value)
    out, s = [], 0
    while True:
        i = d.find(nd, s)
        if i < 0:
            break
        out.append(i)
        s = i + 1
    return out


def best_window(d, site, back=0x80, fwd=0x90):
    """try every start in [site-back, site), keep the decode that flows
    continuously through the site and farthest past it (x86 has no backward
    sync; the correct start is the one that decodes the longest valid run)."""
    best = None
    for start in range(site - back, site):
        got = list(md.disasm(d[start:site + fwd], start))
        if not got:
            continue
        # must decode an instruction containing the site, and run past it
        end = got[-1].address + got[-1].size
        through = any(i.address <= site < i.address + i.size for i in got)
        if through and end >= site + 0x30:
            if best is None or end > best[1]:
                best = (got, end)
    return best[0] if best else []


def main():
    d = open(LIB, "rb").read()

    reg = {"lib": {"path": "libnvidia-ml.so.610.57.04", "size": len(d),
                   "sha256": hashlib.sha256(d).hexdigest()}}

    sites = hits_of(d, 0x2080D031)
    reg["cmd_sites"] = sites
    reg["needles"] = {
        "val_100000_0x186a0": hits_of(d, 0x186A0),
        "size_1544_0x608": hits_of(d, 0x608),
        "size_1584_0x630": hits_of(d, 0x630),
        "val_240000_0x3a980": hits_of(d, 0x3A980),
        "val_250000_0x3d090": hits_of(d, 0x3D090),
        "val_255": hits_of(d, 255),
        "val_257": hits_of(d, 257),
    }

    reg["windows"] = []
    for site in sites:
        insns = best_window(d, site)
        rows = [{"a": "0x%x" % i.address, "m": i.mnemonic, "ops": i.op_str}
                for i in insns]
        reg["windows"].append({"site": site,
                               "window_start": rows[0]["a"] if rows else None,
                               "insns": rows,
                               "hex_before": d[site - 0x48:site + 4].hex()})

    with open(REG, "w") as f:
        json.dump(reg, f, indent=1, sort_keys=True)

    print("== v428f nvml sites ==")
    print("lib %d B sha256=%s…" % (len(d), reg["lib"]["sha256"][:16]))
    for k, v in reg["needles"].items():
        print("  %-22s x%-3d %s" % (k, len(v), v[:14]))
    for w in reg["windows"]:
        print("--- window around site @0x%x (hex before: %s)"
              % (w["site"], w["hex_before"]))
        for e in w["insns"]:
            mark = "  <<<<" if abs(int(e["a"], 16) - w["site"]) < 4 else ""
            print("  %s %-8s %s%s" % (e["a"], e["m"], e["ops"], mark)[:160])
    print("register written:", os.path.relpath(REG, HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
