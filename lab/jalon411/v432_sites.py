#!/usr/bin/env python3
"""4.32 pass, instrument 1 (T1) — the six 250000 sites: the contextual
disassembly and the use-classification of the constant.

Substrate: gsp-rm-17MB.bin (the mission's), coordinates PROVEN by
v432_coord_check.py:
  B_file = A_img - 0x38   (A_img = the v416-map / campaign image offset;
  VA_A = A_img + 0x1000000; VA_B = B_file + 0x1000000)
The v416 map transfers to this substrate under that law (image-wide,
3739/3739 windows byte-identical).

For each site: the enclosing covered region (the 4.16 verified
instruction stream), a linear capstone walk of the region (detail=True),
the +-40 instruction window around the site, and a register-use trace of
the site's destination register forward until redefinition:
  - every consumer instruction is recorded (branch / call / store /
    divide / other);
  - EVERY lui+addi materialized constant inside the window is
    enumerated (the T2 sister sweep rides on this).

Output: lab/jalon411/v432_sites.json
"""
import json
import re
import zlib
from pathlib import Path

import capstone
from capstone import (CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC,
                      CS_OP_REG, CS_OP_MEM)

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
SHIFT = 0x38
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
RDS = [15, 12, 12, 15, 15, 18]
SITE_NAMES = ["s0", "s1", "s2", "s3", "s4", "s5"]
WIN = 40

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True

BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
            "bltz", "bgez", "blez", "bgtz", "c.beqz", "c.bnez"}
STORES = {"sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp"}
DIVS = {"divu", "divuw", "div", "div", "rem", "remu", "remuw"}
CALLS = {"jal", "jalr", "c.jal", "c.jalr"}
RET = {"ret", "c.ret"}


def rw_regs(ins):
    """(writes, reads) from capstone detail operands, RISC-V conventions."""
    m = ins.mnemonic
    ops = ins.operands
    regs = [o.reg for o in ops if o.type == CS_OP_REG]
    mems = [o.mem.base for o in ops if o.type == CS_OP_MEM]
    writes, reads = [], []
    if m in STORES:
        reads = regs + [b for b in mems]
    elif m in BRANCHES:
        reads = regs + [b for b in mems]
    elif m in ("c.jr",):
        reads = regs
    elif m in ("c.jalr",):
        writes = ["ra"]
        reads = regs
    elif m in ("ret", "c.ret"):
        reads = ["ra"]
    elif m in ("j", "c.j", "ecall", "ebreak", "fence", "fence.i", "nop",
               "c.nop", "wfi", "mret", "sret", "uret", "sfence.vma"):
        reads = regs  # usually none
    else:
        # destination-form: first operand = destination (if reg)
        if regs and ins.op_str and not ins.op_str.startswith(","):
            writes = [regs[0]]
            reads = regs[1:] + [b for b in mems]
            # jal ra, target / jal target: ra written either way
            if m == "jal" and len(regs) == 1:
                writes = [regs[0]]
        else:
            reads = regs + [b for b in mems]
    # register names
    def nm(r):
        try:
            return ins.reg_name(r)
        except Exception:
            return str(r)
    return [nm(r) for r in writes], [nm(r) for r in reads]


def materialized(walk):
    """every lui+addi/addiw pair value in a walked window list."""
    vals = []
    for i in range(len(walk) - 1):
        a, b = walk[i], walk[i + 1]
        if a["m"] in ("lui", "c.lui") and b["m"] in ("addi", "addiw", "c.addi", "c.addiw"):
            ma = re.match(r"^(?P<rd>\w+), (?P<imm>-?0x[0-9a-f]+|-?\d+)$", a["o"])
            mb = re.match(r"^(?P<rd>\w+), (?P<rs>\w+), (?P<imm>-?0x[0-9a-f]+|-?\d+)$", b["o"])
            if ma and mb and ma["rd"] == mb["rd"] == mb["rs"]:
                hi = int(ma["imm"], 0)
                lo = int(mb["imm"], 0)
                vals.append({"va": hex(a["va"]), "value": (hi << 12) + lo,
                             "site_reg": ma["rd"], "op2": b["m"]})
    return vals


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
    da = A.read_bytes()
    db = B.read_bytes()
    # the A image (v416-map coordinates): ONE RWX LOAD p_offset=0x40 (PROVEN
    # by v432_coord_check: B_file = A_img - 0x38, image-wide byte-identical)
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    starts, ends = regions(covered)

    def enclosing(a_off):
        for s0, e0 in zip(starts, ends):
            if s0 <= a_off < e0:
                return s0, e0
        return None

    out_sites = []
    for k, boff in enumerate(SITES_B):
        aoff = boff + SHIFT
        reg = enclosing(aoff)
        rec = {"name": SITE_NAMES[k], "idx": k,
               "B_file": hex(boff), "A_img": hex(aoff),
               "VA_A": hex(IMG_LO + aoff), "VA_B": hex(IMG_LO + boff),
               "region": [hex(IMG_LO + reg[0]), hex(IMG_LO + reg[1])] if reg else None,
               "covered": bool(covered[aoff]) if reg else None,
               "seen": bool(seen[aoff]) if reg else None}

        # ---- anchor-synced walk: the site itself is the anchor (its bytes
        # are PROVEN lui+addi 250000 by v432_coord_check on both substrates).
        # forward: from the anchor. backward: try 2-byte-phase starts below
        # site-0x100..0x140, keep the alignment whose walk lands on the site.
        site_va = IMG_LO + aoff
        # per-site re-assertion of the coordinate law (bytes identical B<->A)
        assert db[aoff - SHIFT:aoff - SHIFT + 8] == a_img[aoff:aoff + 8], \
            f"coordinate law broken at site {k}"
        fwd = []
        off = aoff
        for _ in range(WIN + 30):
            try:
                ins = next(md.disasm(a_img[off:off + 4], IMG_LO + off))
            except StopIteration:
                break
            fwd.append({"va": IMG_LO + off, "m": ins.mnemonic,
                        "o": ins.op_str, "size": ins.size, "ins": ins})
            off += ins.size

        bwd = []
        # backward predecessor chain (deterministic, no overlapping insns):
        #   if the 2 bytes before the current start decode as a compressed
        #   instruction -> predecessor = start-2;
        #   elif the 4 bytes at start-4 decode as a 4-byte insn -> start-4;
        #   else the stream boundary is reached (data/padding).
        off = aoff
        stops = []
        while aoff - off < 0x200 and len(bwd) < 130:
            p2 = off - 2
            w2 = a_img[p2:p2 + 2]
            if len(w2) == 2 and (w2[0] & 3) != 3:
                try:
                    ins = next(md.disasm(a_img[p2:p2 + 2], IMG_LO + p2))
                    if ins.size == 2:
                        bwd.append({"va": IMG_LO + p2, "m": ins.mnemonic,
                                    "o": ins.op_str, "size": 2, "ins": ins})
                        off = p2
                        continue
                except StopIteration:
                    pass
                stops.append(f"compressed-decode-fail@{hex(IMG_LO + p2)}")
                break
            p4 = off - 4
            try:
                ins = next(md.disasm(a_img[p4:p4 + 4], IMG_LO + p4))
                if ins.size == 4 and (a_img[p4] & 3) == 3:
                    bwd.append({"va": IMG_LO + p4, "m": ins.mnemonic,
                                "o": ins.op_str, "size": 4, "ins": ins})
                    off = p4
                    continue
            except StopIteration:
                pass
            stops.append(f"no-predecessor@{hex(IMG_LO + p4)}")
            break
        bwd.reverse()
        rec["backward_stops"] = stops
        rec["backward_bytes"] = aoff - off if bwd else 0
        walk = bwd + fwd
        idx = len(bwd)
        rec["walk_ok"] = bool(bwd)
        if idx is None:
            out_sites.append(rec)
            print(f"site {k}: BACKWARD SYNC FAILED (forward only)")
            continue

        lo_i = max(0, idx - WIN)
        hi_i = min(len(walk), idx + 2 + WIN)
        rec["window"] = [{"va": hex(w["va"]), "m": w["m"], "o": w["o"]}
                         for w in walk[lo_i:hi_i]]

        # the site register name (rd of the lui)
        rname = walk[idx]["o"].split(",")[0].strip()
        rec["site_reg_name"] = rname

        # forward trace until redefinition
        consumers = []
        cur = rname
        for w in walk[idx + 2:]:
            wr, rd_ = rw_regs(w["ins"])
            if cur in rd_:
                consumers.append({"va": hex(w["va"]), "m": w["m"], "o": w["o"]})
            if cur in wr and w["m"] not in STORES:
                cur = None
            if cur is None:
                break
        rec["consumers"] = consumers

        kinds = []
        for c in consumers:
            if c["m"] in BRANCHES:
                kinds.append("BRANCH-COMPARE")
            elif c["m"] in CALLS:
                kinds.append("CALL-ARG")
            elif c["m"] in STORES:
                kinds.append("STORE")
            elif c["m"] in DIVS:
                kinds.append("DIVIDE")
            else:
                kinds.append("ARITH/OTHER")
        rec["use_kinds"] = kinds

        rec["window_constants"] = materialized(
            walk[lo_i:min(len(walk), hi_i + 24)])
        out_sites.append(rec)
        print(f"site {k} {SITE_NAMES[k]}: covered={rec['covered']} "
              f"region={rec['region']} uses={sorted(set(kinds))} "
              f"consts={[hex(c['value'] & 0xFFFFFFFF) for c in rec['window_constants']]}")
        for c in consumers:
            print(f"    consumer {c['va']}: {c['m']} {c['o']}")

    OUT.write_text(json.dumps({
        "law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000; VA_B = B_file + 0x1000000",
        "window_instructions": WIN,
        "sites": out_sites,
    }, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
