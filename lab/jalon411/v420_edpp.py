#!/usr/bin/env python3
"""4.20 pass III — the EDPp policy object: the consumer census.

From v420_resolve.py: GET_EDPP_LIMIT_INFO handler @0x1458bec (boundary-
verified) does memset(obj, 0, 0x6d0) with obj = *(state + 0x5000 - 0x168)
— the RM's EDPp policy object (1744 bytes), pointer cached at state+0x4E98.

This census walks the 4.16 verified regions and captures EVERY access to
the object pointer: `ld/lw/sd/sw/..., -0x168(<base>)` where <base> was
formed within the previous 3 insns by the page-5 idiom (either form:
  A: c.lui rd2, 5 ; c.add base, rd2
  B: c.lui base, 5 ; c.add base, x
). The match window is the wave-4.19 discipline (verified-region walk,
window reset per region) — the census covers the verified 66 % only and
is a LOWER BOUND, banked honestly.

The consumer population = the fill/clamp/enforcement candidates for the
next pass.

Output: lab/jalon411/v420_edpp.json
"""
import json
import struct
import zlib
import re
from collections import Counter

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/analysis/gsp-extract/rm-full.elf"
MAP = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/lab/jalon411/v416_map.bin"
OUT = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/lab/jalon411/v420_edpp.json"

IMG_LO = 0x1000000
OFF = "-0x168("


def load():
    d = open(SUBSTRATE, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    for i in range(struct.unpack_from("<H", d, 56)[0]):
        o = e_phoff + i * struct.unpack_from("<H", d, 54)[0]
        if struct.unpack_from("<I", d, o)[0] == 1:
            p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
            if p_filesz == p_memsz:
                return d[p_off:p_off + p_filesz]
    raise SystemExit("no image")


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


def main():
    img = load()
    base = IMG_LO
    blob = zlib.decompress(open(MAP, "rb").read())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    starts, ends = regions(covered)

    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    sites = []
    for s0, e0 in zip(starts, ends):
        window = []
        off = s0
        while off < e0:
            try:
                ins = next(md.disasm(img[off:off + 4], base + off))
            except StopIteration:
                break
            if off + ins.size > e0:
                break
            if ins.mnemonic in ("ld", "lw", "lbu", "sd", "sw", "sb") and OFF in ins.op_str:
                rs1 = ins.op_str.split("(")[1].rstrip(")")
                hit = None
                for i2 in range(len(window) - 1, max(-1, len(window) - 8), -1):
                    w = window[i2]
                    if w[1] in ("c.add", "add") and w[2].split(", ")[0] == rs1:
                        rd_add, rs_add = w[2].split(", ")[0], w[2].split(", ")[1]
                        for i3 in range(i2 - 1, max(-1, i2 - 4), -1):
                            w3 = window[i3]
                            if w3[1] in ("c.lui", "lui") and re.match(r"^\w+, (0x5|5)$", w3[2]):
                                rd_lui = w3[2].split(", ")[0]
                                if rd_lui == rs_add or (rd_lui == rd_add == rs1):
                                    hit = {"lui": w3[0], "add": w[0],
                                           "form": "A" if rd_lui == rs_add else "B"}
                                    break
                        if hit:
                            break
                if hit:
                    sites.append({
                        "va": hex(base + off), "insn": f"{ins.mnemonic} {ins.op_str}",
                        "verified": bool(seen[off]),
                        "region": [hex(base + s0), hex(base + e0)],
                        "formed": hit,
                    })
            window.append((base + off, ins.mnemonic, ins.op_str))
            window = window[-8:]
            off += ins.size

    out = {
        "object": {"size": 0x6D0, "pointer_slot": "state + 0x4E98 (0x5000 - 0x168)",
                   "allocator_caller": "0x1458cf8 (window), allocator ~0x18C373C",
                   "reset_by": "GET_EDPP_LIMIT_INFO handler 0x1458bec"},
        "census_scope": "verified regions only (4.16 map, 66%) — a lower bound",
        "sites": sites,
        "stats": {
            "total": len(sites),
            "by_op": dict(Counter(s["insn"].split()[0] for s in sites)),
            "by_64k_page": {hex(IMG_LO + k * 0x10000): v for k, v in
                            Counter(((int(s["va"], 16) - IMG_LO) >> 16) for s in sites).most_common()},
        },
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    print(f"EDPp object consumers (verified regions): {len(sites)} sites")
    print("by page:", out["stats"]["by_64k_page"])
    for s in sites:
        print(f"  {s['va']} {s['insn']}  [{s['formed']['form']}] lui@{s['formed']['lui']:#x} add@{s['formed']['add']:#x}")


if __name__ == "__main__":
    main()
