#!/usr/bin/env python3
"""4.18 pass — binding the 5 `-0x588` dispatch sites.

Queue item 2 of 4.17: the companion offset (0xA78 mod 0x1000) turned out to
feed 5 dispatch sites (bases s2/s4/s5) — the field is not exclusively an
object pointer. This instrument binds those sites:

  - re-derive the chase, keep ONLY state-frame feeders with off == -0x588
    (the companion page-offset itself), record every site;
  - per site: the base's PROVENANCE chased backward over the verified
    trail, stopping at the first ret (function boundary — the walk never
    crosses into the previous function):
      entry-arg        : mv base, aX  (aX = argument reg)
      ABI-carried      : no def before the ret — the value came in the
                         callee-saved register across the ABI
      restored         : ld base, off(sp) mid-function
      static-formed    : auipc/lui (resolve auipc+addi against the map)
      copied-carried   : mv base, sY (one hop chased)
  - the slot NEIGHBORS: memory ops on the SAME base within +/-0x40 of the
    slot offset, in the enclosing verified window — are the surrounding
    fields treated as data (ld/st, object-like) or code (dispatched)?

Output: lab/jalon411/v418_dispatch588.json
"""
import json
import struct
import zlib
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v418_dispatch588.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
BACK = 8
TARGET_OFF = -0x588
TRAIL_LIMIT = 1024
NB_WINDOW = 48   # insns around the site for neighbor census
NB_RANGE = 0x40


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


def decode_at(md, code, pc):
    try:
        return next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
    except StopIteration:
        return None


def back_trail(md, code, seen, site_off, limit=TRAIL_LIMIT):
    trail = []
    pc = site_off
    while len(trail) < limit:
        cands = []
        for s in (pc - 2, pc - 4):
            if s < 0 or not seen[s]:
                continue
            ins = decode_at(md, code, s)
            if ins is None or ins.size != pc - s or ins.mnemonic in (".byte", "(bad)"):
                continue
            cands.append((s, ins))
        if len(cands) == 1:
            s, ins = cands[0]
            trail.append((ins.mnemonic, ins.op_str, s, ins.size))
            pc = s
        else:
            break
    trail.reverse()
    return trail


def provenance(trail, bas):
    """Walk the trail backward (chronological list, site last), stop at ret.
    Classify the defining event of `bas`."""
    code_target = None
    hop = None
    for jm, jops, jpc, jsize in reversed(trail[:-1]):
        jn = norm(jm)
        # function boundary: a return instruction ends the search
        if (jn == "ret" or (jn == "jr" and jops.strip() == "ra")
                or (jn == "c.jr" and jops.strip() == "ra")):
            return "ABI-carried", code_target, hop
        jp = [t.strip() for t in jops.split(",")]
        wr = jp[0] if jp else None
        if wr != bas:
            continue
        if jn == "mv" and len(jp) == 2:
            src = jp[1]
            if src in A_REGS:
                return "entry-arg", code_target, hop
            if src in S_REGS:
                return "copied-carried", code_target, src
            return "mv-other", code_target, src
        if jn == "ld" and len(jp) == 2 and "(" in jp[1]:
            try:
                off_s, b2 = jp[1][:-1].split("(", 1)
                if b2.strip() == "sp":
                    return "restored", code_target, hop
            except Exception:
                pass
            return "ld-other", code_target, hop
        if jn == "auipc" and len(jp) == 2:
            return "auipc-static", code_target, hop
        if jn == "lui" and len(jp) == 2:
            return "lui-static", code_target, hop
        if jn == "addi" and len(jp) == 3 and jp[1] == bas:
            continue                      # bas += imm — keep walking
        if jn == "add" and len(jp) == 3 and jp[1] == bas:
            if jp[2] in S_REGS:
                return "copied-carried", code_target, jp[2]
            continue                      # bas += non-s-reg — keep walking
        if jn == "add" and len(jp) == 2:
            if jp[1] in S_REGS and jp[1] != bas:
                return "copied-carried", code_target, jp[1]
            continue
        return "other-def", code_target, hop
    return "no-def-in-trail", code_target, hop


def neighbors(md, code, seen, site_off, base):
    """memory ops on `base` with |off - (-0x588)| <= 0x40 around the site."""
    lo, hi = site_off - NB_WINDOW * 4, site_off + NB_WINDOW * 4
    lo = max(0, lo)
    out = []
    pc = lo
    while pc < hi - 2:
        if seen[pc]:
            ins = decode_at(md, code, pc)
            if ins is not None and ins.mnemonic not in (".byte", "(bad)") and ins.size > 0:
                m, ops = ins.mnemonic, ins.op_str
                mn = norm(m)
                if mn in ("ld", "lw", "sd", "sw", "lb", "lbu", "sb", "sh") and "(" in ops:
                    p = ops.split(", ")
                    if len(p) == 2:
                        try:
                            off_s, b = p[1][:-1].split("(", 1)
                            if b.strip() == base:
                                off = int(off_s.strip(), 0)
                                if abs(off - TARGET_OFF) <= NB_RANGE:
                                    out.append({"pc": hex(IMG_LO + pc), "op": mn,
                                                "off": hex(off),
                                                "kind": "code-dispatch" if mn in ("ld",) and False else "mem"})
                        except Exception:
                            pass
                pc += ins.size
                continue
        pc += 2
    return out


def main():
    code = load()
    n = len(code)
    seen, _ = load_map()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    sites = []
    pc = 0
    win = []
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
            if m == "jalr":
                if "(" in ops:
                    p = ops.replace("(", ",").replace(")", "").split(",")
                    rs = p[2].strip()
                else:
                    parts = [x.strip() for x in ops.split(",")]
                    rs = parts[0] if len(parts) == 1 else parts[1]
            else:
                rs = [x.strip() for x in ops.split(",")][-1]
            feeder = None
            for jm, jops, jpc in reversed(win[:-1]):
                if jpc == pc:
                    continue
                jm_n = norm(jm)
                p1 = [t.strip() for t in jops.split(",")]
                wr = None
                if jm_n in ("ld", "c.ld", "ldsp", "c.ldsp") and p1:
                    wr = p1[0]
                elif p1 and jm_n not in ("sd", "sw", "c.sd", "c.sdsp", "sdsp", "swsp"):
                    wr = p1[0]
                if wr == rs:
                    if jm_n in ("ld", "c.ld", "ldsp", "c.ldsp") and len(p1) == 2 and "(" in p1[1]:
                        try:
                            off_s, bas = p1[1][:-1].split("(", 1)
                            feeder = (bas.strip(), int(off_s.strip(), 0), jm_n)
                        except Exception:
                            feeder = None
                    break
            if feeder and feeder[0] in S_REGS and feeder[1] == TARGET_OFF:
                sites.append({"site": pc, "xfer": m, "base": feeder[0],
                              "feeder": feeder[2]})
        pc += size

    print("dispatch sites at -0x588:", len(sites))
    results = []
    provs = defaultdict(int)
    for s in sites:
        trail = back_trail(md, code, seen, s["site"])
        prov, tgt, hop = provenance(trail, s["base"])
        provs[prov] += 1
        nb = neighbors(md, code, seen, s["site"], s["base"])
        entry = {
            "site": hex(IMG_LO + s["site"]), "xfer": s["xfer"],
            "base": s["base"], "feeder": s["feeder"],
            "trail_len": len(trail),
            "provenance": prov,
            "provenance_hop": hop,
            "neighbors": nb,
        }
        results.append(entry)
        print(f"  {entry['site']} base={s['base']} trail={len(trail)} prov={prov} neighbors={len(nb)}")

    out = {
        "pass": "4.18-dispatch588",
        "substrate": SUBSTRATE,
        "sites_found": len(sites),
        "provenance": dict(provs),
        "results": results,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("OUT", OUT)


if __name__ == "__main__":
    main()
