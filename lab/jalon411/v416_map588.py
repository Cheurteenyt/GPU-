#!/usr/bin/env python3
"""4.16 pass — the `lui X - 0x588` slot-family map.

Queue item 3 of 4.15: 59 stores at displacement -0x588 from bases that are
NOT the known state marker (lui 4 + s-reg = state + 0x3A78). 44 of them are
"static-plus-reg": the base register is formed by `lui rd, X` (+ add/c.add
with an s-reg). The X value defines the wide slot family
`slot = s_reg + (X << 12) - 0x588`. This instrument maps X per site:

  linear sweep; at every store (sd/sw/sh/sb) with displacement == -0x588,
  walk backward (<= 40 insns) for the last insn writing the base register:
    lui/c.lui rd, X            -> X captured (pure static page)
    lui/c.lui rd, X + add rd   -> X captured (static-plus-reg form)
    other                      -> honest 'other-formation' bucket
  every site is judged against the verified map (seen[]).

Output: lab/jalon411/v416_map588.json
"""
import json
import struct
import zlib
from collections import defaultdict, deque

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map588.json"

IMG_LO = 0x1000000
STORES = {"sd", "sw", "sh", "sb"}
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
BACK = 260
TARGET = -0x588


def load():
    d = open(SUBSTRATE, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if p_type == 1:
            return d[p_off:p_off + p_filesz]


def load_map():
    blob = zlib.decompress(open(MAP, "rb").read())
    half = len(blob) // 2
    return blob[:half], blob[half:]


def norm(m):
    return m[2:] if m.startswith("c.") else m


def sign_ext(v, bits):
    return v - (1 << bits) if v > (1 << (bits - 1)) - 1 else v


def main():
    code = load()
    n = len(code)
    seen, _ = load_map()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    fam = defaultdict(lambda: {"sites": 0, "verified": 0, "widths": defaultdict(int),
                               "first16": []})
    other = {"sites": 0, "verified": 0, "first16": []}

    pc = 0
    win = deque(maxlen=BACK + 2)
    while pc < n - 2:
        try:
            insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            win.clear()
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        size = insn.size
        if m not in (".byte", "(bad)"):
            win.append((m, ops, pc, size))
        mn = norm(m)
        if mn in STORES:
            p1 = ops.split(", ")
            if len(p1) == 2 and "(" in p1[1]:
                try:
                    off_s, bas = p1[1][:-1].split("(", 1)
                    off = int(off_s.strip(), 0)
                except Exception:
                    off = None
                if off == TARGET:
                    # walk back to the base formation: lui/c.lui (page const),
                    # crossing add/addi/c.add bas, bas, ... merges.
                    # NOTE: norm() collapses c.add->add and c.lui->lui; the
                    # compressed forms are told apart by operand count / size.
                    X = None
                    sreg = None
                    form = "other-formation"
                    for jm, jops, jpc, jsize in reversed(win):
                        if jpc == pc:
                            continue
                        jn = norm(jm)
                        jp = [t.strip() for t in jops.split(",")]
                        wr = jp[0] if jp else None
                        if wr != bas:
                            continue
                        if jn == "lui" and len(jp) == 2:
                            if jsize == 2:   # c.lui — imm already resolved, 6-bit signed
                                X = int(jp[1], 0)
                            else:            # lui — 20-bit raw page number
                                X = sign_ext(int(jp[1], 0) & 0xFFFFF, 20)
                            form = "lui" if jsize == 4 else "c.lui"
                            break
                        if jn == "add" and len(jp) == 2 and jp[0] == bas:
                            if jp[1] in S_REGS:
                                sreg = jp[1]
                                continue
                            break  # bas += non-s-reg — honest give-up
                        if jn == "add" and len(jp) == 3 and jp[1] == bas:
                            if jp[2] in S_REGS:
                                sreg = jp[2]
                            continue
                        if jn == "addi" and len(jp) == 3 and jp[1] == bas:
                            continue
                        break  # other redefinition of the base — honest give-up
                    entry = {
                        "site": hex(IMG_LO + pc), "width": mn, "src": p1[0].strip(),
                        "base": bas, "X": X, "form": form,
                        "sreg": sreg,
                        "slot_if_sreg": (hex((X << 12) - 0x588) if X is not None else None),
                        "verified": bool(seen[pc]),
                    }
                    key = f"X={hex(X) if X is not None else '?'}" + (f"+{sreg}" if sreg else "")
                    fam[key]["sites"] += 1
                    fam[key]["verified"] += 1 if seen[pc] else 0
                    fam[key]["widths"][mn] += 1
                    if len(fam[key]["first16"]) < 16:
                        fam[key]["first16"].append(entry)
        pc += size

    out = {
        "pass": "4.16-map588",
        "substrate": SUBSTRATE,
        "note": "X is the lui page constant; the wide slot = s_reg + (X<<12) - 0x588. "
                "X=4 is the banked state marker (slot 0x3A78).",
        "families": {k: {"sites": v["sites"], "verified": v["verified"],
                         "widths": dict(v["widths"]), "first16": v["first16"]}
                     for k, v in sorted(fam.items(), key=lambda kv: -kv[1]["sites"])},
    }
    json.dump(out, open(OUT, "w"), indent=1)
    tot = sum(v["sites"] for v in fam.values())
    print("neg-0x588 stores captured:", tot)
    print("families:", [(k, v["sites"], f"ver={v['verified']}") for k, v in
                        sorted(fam.items(), key=lambda kv: -kv[1]["sites"])[:12]])
    print("OUT", OUT)


if __name__ == "__main__":
    main()
