#!/usr/bin/env python3
"""4.16 pass — the indirect-dispatch chase (state-table idiom census).

Queue item 2 of 4.15: 33,050 indirect tails in the linear sweep needed the
boundary proof first. This instrument scans the VERIFIED instruction map
(v416_rdescensus map, seen[] = boundary-verified instruction starts) and, at
every indirect transfer (jalr / c.jalr / c.jr / jr), walks BACKWARD for the
single-def feeder: the last insn writing rs1 before the transfer. If that is
`ld rd, off(base)` the dispatch is classified:

  state-frame feeder : base is a callee-saved reg and off < 0  — the
                       `ld a5, -0x6f0(s2); jalr a5` state-table idiom; the
                       (base-class, off) pair is a DISPATCH SLOT of the state
                       structure — these are the runtime-reachable targets the
                       static descent can never follow;
  object-vtable      : base is an argument reg or off >= 0 — virtual dispatch
                       through an object pointer;
  carried            : no memory feeder within 8 insns (target formed earlier).

Output: lab/jalon411/v416_chase.json
"""
import json
import struct
import zlib
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v416_chase.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
BACK = 8


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


def main():
    code = load()
    n = len(code)
    seen, covered = load_map()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    stats = defaultdict(int)
    slot_map = defaultdict(lambda: {"sites": 0, "first12": []})
    obj_map = defaultdict(int)
    carried = []
    total = 0
    unverified = 0

    pc = 0
    win = []  # (mnem, ops, pc) rolling window
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
            win.append((m, ops, pc))
            if len(win) > BACK + 2:
                win.pop(0)
        if m in ("jalr", "c.jalr", "c.jr", "jr") and seen[pc]:
            total += 1
            rd = rs = None
            off = 0
            if m == "jalr":
                if "(" in ops:
                    p = ops.replace("(", ",").replace(")", "").split(",")
                    rd, rs, off = p[0].strip(), p[2].strip(), int(p[1].strip(), 0)
                else:
                    parts = [x.strip() for x in ops.split(",")]
                    if len(parts) == 1:
                        rd, rs, off = "ra", parts[0], 0
                    else:
                        rd, rs, off = parts[0], parts[1], int(parts[2], 0)
            else:
                parts = [x.strip() for x in ops.split(",")]
                rs = parts[-1]
                rd = "ra" if m == "c.jalr" else "x0"
            kind = "call" if rd not in ("zero", "x0") else ("ret" if rs == "ra" else "tail")
            # single-def backward feeder
            feeder = None
            for jm, jops, jpc in reversed(win[:-1]):
                if jpc == pc:
                    continue
                jm_n = norm(jm)
                if jm_n in ("ld", "lw", "c.ld", "c.lw", "ldsp", "c.ldsp") and jm_n != "lw":
                    pass
                # does this insn WRITE rs?
                wr = None
                p1 = [t.strip() for t in jops.split(",")]
                if jm_n in ("ld", "c.ld", "ldsp", "c.ldsp") and p1:
                    wr = p1[0]
                elif p1 and jm_n not in ("sd", "sw", "c.sd", "c.sdsp", "sdsp", "swsp"):
                    wr = p1[0]
                if wr == rs:
                    if jm_n in ("ld", "c.ld", "ldsp", "c.ldsp") and len(p1) == 2 and "(" in p1[1]:
                        try:
                            off_s, bas = p1[1][:-1].split("(", 1)
                            feeder = (jm_n, bas.strip(), int(off_s.strip(), 0), hex(IMG_LO + jpc))
                        except Exception:
                            feeder = None
                    break
            if feeder:
                _, bas, foff, site = feeder
                if bas in S_REGS and foff < 0:
                    stats["state-frame feeder"] += 1
                    key = f"{bas}+{hex(foff)}"
                    slot_map[key]["sites"] += 1
                    if len(slot_map[key]["first12"]) < 12:
                        slot_map[key]["first12"].append((hex(IMG_LO + pc), m, kind, site))
                elif bas in A_REGS or foff >= 0:
                    stats["object-vtable feeder"] += 1
                    obj_map[f"{bas}+{hex(foff)}"] += 1
                else:
                    stats["feeder-other"] += 1
            else:
                stats["carried"] += 1
                if kind == "tail" and len(carried) < 40:
                    carried.append((hex(IMG_LO + pc), m, ops))
        elif m in ("jalr", "c.jalr", "c.jr", "jr"):
            unverified += 1
        pc += size

    out = {
        "pass": "4.16-chase",
        "substrate": SUBSTRATE,
        "indirect_transfers_verified": total,
        "unverified_regions_skipped": unverified,
        "classes": dict(stats),
        "state_table_slots": {
            k: {"sites": v["sites"], "first12": v["first12"]}
            for k, v in sorted(slot_map.items(), key=lambda kv: -kv[1]["sites"])},
        "object_slots_top32": dict(sorted(obj_map.items(), key=lambda kv: -kv[1])[:32]),
        "carried_tails_first40": carried,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("verified indirect transfers:", total, "unverified skipped:", unverified)
    print("classes:", dict(stats))
    print("top state slots:", [(k, v["sites"]) for k, v in
                               sorted(slot_map.items(), key=lambda kv: -kv[1]["sites"])[:10]])
    print("OUT", OUT)


if __name__ == "__main__":
    main()
