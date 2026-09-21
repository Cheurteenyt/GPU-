#!/usr/bin/env python3
"""4.15 audit — (a) fam588 first24 vs the banked 4.14 list (site-for-site
agreement), (b) the false-pair mechanism: disasm around real call sites that
resolved into the 0x1aa2xxx mid-instruction region."""
import json
import struct

from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC
import capstone

CODE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
CENSUS = "/home/z/my-project/repo-gpu/lab/jalon411/v415_census2.json"
O2 = "/home/z/my-project/repo-gpu/lab/jalon411/v415_o2hunt.json"
OLD = "/home/z/my-project/repo-gpu/lab/jalon411/v414_datflow.json"

code = open(CODE, "rb").read()


def rd(va, n):
    return code[0x78 + (va - 0x1000000):0x78 + (va - 0x1000000) + n]


md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.skipdata = True


def window(center, back=0x18, fwd=0x10):
    out = []
    for i in md.disasm(rd(center - back, back + fwd), center - back):
        mark = "  <<<" if i.address == center else ""
        out.append(f"  {hex(i.address)}: {i.mnemonic} {i.op_str}{mark}")
    return out


print("=== (a) fam588 site-for-site vs 4.14 ===")
new = json.load(open(CENSUS))["fam588_direct"]["first24"]
new_addrs = [t[0] for t in new]
old = [t[0] for t in json.load(open(OLD))["detail"]["companion_sites_first40"]]
print("new first24:", new_addrs[:12])
print("old first24:", old[:12])
print("overlap in first24:", len(set(new_addrs) & set(old)), "/ 24")

print("\n=== (b) false-pair call sites into the 0x1aa2 region ===")
o2 = json.load(open(O2))
suspects = [c["target"] for c in o2["top_candidates"][:6] if c.get("data_suspect")]
print("suspects:", suspects)
# call sites were capped at 16 and NOT saved into the o2 json -> re-resolve them
# by scanning the image for auipc+jalr pairs landing on the suspect targets.

# Reimplement the pair resolution in a linear sweep, but ONLY report pairs
# whose target is in the suspect list.
from collections import deque
IMM20 = 0xFFFFF
IMG_LO, IMG_HI = 0x1000000, 0x1000000 + 0xE9B000
pend = {}
idx = 0
hits = []
for ins in md.disasm(rd(0x1000000, 0xE9B000), 0x1000000):
    idx += 1
    m = ins.mnemonic
    if m.startswith("c."):
        m = m[2:]
    ops = ins.op_str
    if m == "auipc":
        p = ops.split(", ")
        if len(p) == 2:
            try:
                pend[p[0].strip()] = (ins.address, idx, int(p[1], 0) & IMM20)
            except Exception:
                pass
    elif m == "jalr":
        if "(" in ops:
            p = ops.replace("(", ",").replace(")", "").split(",")
            if len(p) == 3:
                try:
                    rd_, rs1, off = p[0].strip(), p[2].strip(), int(p[1].strip(), 0)
                except Exception:
                    continue
            else:
                continue
        else:
            parts = [x.strip() for x in ops.split(",")]
            if len(parts) == 1:
                rd_, rs1, off = "x0", parts[0], 0
            elif len(parts) == 3:
                try:
                    rd_, rs1, off = parts[0], parts[1], int(parts[2], 0)
                except Exception:
                    continue
            else:
                continue
        q = pend.get(rs1)
        if q and idx - q[1] <= 4 and rd_ == "ra":
            t = ((q[0] & 0xFFFFF000) + (q[2] << 12) + off) & 0xFFFFFFFFFFFFFFFF
            if hex(t) in suspects:
                hits.append((ins.address, q[0], hex(t)))
    if len(hits) >= 6:
        break

for site, apc, tgt in hits[:3]:
    print(f"\ncall site {hex(site)} -> {tgt} (auipc at {hex(apc)}):")
    print("\n".join(window(site, 0x14, 0x8)))
