#!/usr/bin/env python3
"""4.19 pass — the entry-point census (who forms the circulating pointers?).

Queue item 2 of 4.18: extend the provenance pass to the 103 cross-register
offsets of 4.17 — for EVERY state-frame dispatch site whose slot offset is
shared by >= 3 distinct carried bases (the one-structure-many-pointers
evidence), classify the BASE register's provenance with the 4.18 machine
(verified-trail backward walk, first return = function boundary).

The aggregate answers: where do the handed-down pointers COME FROM at the
dispatch sites — function arguments (entry-arg), the callee-saved ABI
(ABI-carried), local formation (static-formed), the stack frame (restored /
sp-derived), or pointer sums (sum-of-carried)? The histogram is the
entry-point census of the circulating pointer population.

Trail cap: 1024 verified insns (the classification needs the base's first
defining event or the first return — both near the site; sites whose base
is defined deeper report trail-cap-stop honestly).

Output: lab/jalon411/v419_entrypoints.json
"""
import json
import struct
import zlib
from bisect import bisect_right
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v419_entrypoints.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
TRAIL_LIMIT = 1024
BACK = 8
CROSSREG_MIN = 3


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


def build_regions(covered):
    starts, ends = [], []
    n = len(covered)
    i = 0
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
    reason = "trail-limit"
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
        elif len(cands) > 1:
            reason = "ambiguous-backstep"
            break
        else:
            reason = "unverified-edge"
            break
    trail.reverse()
    return trail, reason


BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
            "c.beqz", "c.bnez", "j", "c.j"}


def classify_418(trail, bas):
    rets = 0
    hops = []
    merges = []
    for jm, jops, jpc, jsize in reversed(trail[:-1]):
        jn = norm(jm)
        if (jn == "ret" or (jn == "jr" and jops.strip() == "ra")
                or (jn == "c.jr" and jops.strip() == "ra")):
            rets += 1
            if rets == 1:
                if merges:
                    return "abi-carried-plus-reg", hops, None
                return "ABI-carried", hops, None
        if jn in BRANCHES:
            continue
        jp = [t.strip() for t in jops.split(",")]
        wr = jp[0] if jp else None
        if wr != bas:
            continue
        if jn == "mv" and len(jp) == 2:
            src = jp[1]
            if src in A_REGS:
                return "entry-arg", hops, None
            if src in S_REGS:
                hops.append(f"={src}")
                merges.append(f"={src}")
                bas = src
                continue
            return "other-def", hops, f"mv {jops}"
        if jn in ("ld", "lw") and len(jp) == 2 and "(" in jp[1]:
            try:
                off_s, b2 = jp[1][:-1].split("(", 1)
                if b2.strip() == "sp":
                    return "restored", hops, None
                if b2.strip() in A_REGS:
                    return "loaded-from-arg", hops, f"{jn} {jops}"
                return "loaded-from-carried", hops, f"{jn} {jops}"
            except Exception:
                pass
            return "other-def", hops, f"{jn} {jops}"
        if jn == "auipc" and len(jp) == 2:
            try:
                X = sign_ext(int(jp[1], 0) & 0xFFFFF, 20)
            except Exception:
                X = None
            return f"static-formed({'auipc+merge' if merges else 'auipc'})", hops, X
        if jn == "lui" and len(jp) == 2 and jsize == 4:
            try:
                X = sign_ext(int(jp[1], 0) & 0xFFFFF, 20)
            except Exception:
                X = None
            return f"static-formed({'lui+merge' if merges else 'lui'})", hops, X
        if jn == "lui" and len(jp) == 2 and jsize == 2:
            try:
                X = int(jp[1], 0)
            except Exception:
                X = None
            return f"static-formed({'c.lui+merge' if merges else 'c.lui'})", hops, X
        if jn == "addi" and len(jp) == 3 and jp[1] == bas:
            continue
        if jn == "addi" and len(jp) == 3 and jp[1] == "sp":
            return "sp-derived-frame", hops, jp[2]
        if jn in ("addiw", "addw") and len(jp) == 3 and jp[1] == bas:
            continue
        if jn == "add" and len(jp) == 3:
            if jp[1] == bas:
                if jp[2] in S_REGS or jp[2] in A_REGS:
                    hops.append(f"+{jp[2]}")
                    merges.append(f"+{jp[2]}")
                    continue
                return "other-def", hops, f"add {jops}"
            if jp[1] == bas:
                continue
            if jp[1] in S_REGS and jp[2] in S_REGS:
                return "sum-of-carried", hops, f"{jp[1]}+{jp[2]}"
            if (jp[1] in S_REGS and jp[2] in A_REGS) or (jp[1] in A_REGS and jp[2] in S_REGS):
                return "sum-of-carried-and-arg", hops, f"{jp[1]}+{jp[2]}"
            return "other-def", hops, f"add {jops}"
        if jn == "add" and len(jp) == 2:
            if jp[1] in A_REGS:
                hops.append(f"+{jp[1]}")
                merges.append(f"+{jp[1]}")
                continue
            if jp[1] in S_REGS and jp[1] != bas:
                hops.append(f"={jp[1]}")
                merges.append(f"={jp[1]}")
                bas = jp[1]
                continue
            return "other-def", hops, f"add {jops}"
        return "other-def", hops, f"{jn} {jops}"
    return "no-def-before-trail-end", hops, None


def main():
    code = load()
    n = len(code)
    seen, covered = load_map()
    reg_starts, reg_ends = build_regions(covered)
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    def region_of(pc):
        k = bisect_right(reg_starts, pc) - 1
        if k >= 0 and reg_starts[k] <= pc < reg_ends[k]:
            return k
        return None

    # ---- pass 1: the 4.17 census re-derivation + site collection ----
    total = 0
    by_offset = defaultdict(lambda: {"sites": 0, "regs": set()})
    sites = []  # (pc, bas, foff)
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
            total += 1
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
                            feeder = (bas.strip(), int(off_s.strip(), 0))
                        except Exception:
                            feeder = None
                    break
            if feeder:
                bas, foff = feeder
                if bas in S_REGS and foff < 0:
                    by_offset[foff]["sites"] += 1
                    by_offset[foff]["regs"].add(bas)
                    sites.append((pc, bas, foff))
        pc += size

    cross_offsets = {off for off, v in by_offset.items() if len(v["regs"]) >= CROSSREG_MIN}
    targets = [(pc, bas, foff) for pc, bas, foff in sites if foff in cross_offsets]
    print("census:", total, "indirects |", len(by_offset), "offsets |",
          len(cross_offsets), "cross-register offsets (>=3 regs)")
    print("dispatch sites on cross-register offsets:", len(targets))

    # ---- pass 2: the provenance of every base ----
    provs = defaultdict(int)
    by_off_prov = defaultdict(lambda: defaultdict(int))
    by_reg_prov = defaultdict(lambda: defaultdict(int))
    x_by_off = defaultdict(lambda: defaultdict(int))   # offset -> X page histogram
    merge_kind = defaultdict(int)                      # what merges into the page
    per_offset = {}
    results = []
    for pc, bas, foff in targets:
        trail, reason = back_trail(md, code, seen, pc)
        if not trail:
            prov = "no-trail"
            hops = []
            extra = None
        else:
            prov, hops, extra = classify_418(trail, bas)
        provs[prov] += 1
        by_off_prov[foff][prov] += 1
        by_reg_prov[bas][prov] += 1
        if prov.startswith("static-formed") and isinstance(extra, int):
            x_by_off[foff][f"X={hex(extra)}"] += 1
        if "+merge" in prov:
            for hh in hops:
                if hh.startswith("+"):
                    merge_kind["merge-arg" if hh[1:] in A_REGS else "merge-carried"] += 1
                elif hh.startswith("="):
                    merge_kind["mv-arg" if hh[1:] in A_REGS else "mv-carried"] += 1
        if len(results) < 400:
            results.append({"site": hex(IMG_LO + pc), "slot": f"{bas}+{hex(foff)}",
                            "provenance": prov,
                            "detail": (extra if not isinstance(extra, int) else hex(extra)),
                            "trail": len(trail), "stop": reason})
    print("provenance:", dict(provs))
    print("X pages per offset:", {hex(o): dict(x) for o, x in
                                  sorted(x_by_off.items(), key=lambda kv: -sum(kv[1].values()))[:10]})
    print("merge kinds:", dict(merge_kind))

    for off in sorted(cross_offsets, key=lambda o: -by_offset[o]["sites"])[:12]:
        per_offset[hex(off)] = {
            "sites": by_offset[off]["sites"],
            "n_regs": len(by_offset[off]["regs"]),
            "provenance": dict(by_off_prov[off]),
        }

    out = {
        "pass": "4.19-entrypoints",
        "substrate": SUBSTRATE,
        "trail_cap": TRAIL_LIMIT,
        "rule": "the 4.18 machine (verified-trail backward walk, first return "
                "= function boundary) applied to the base of every state-frame "
                "dispatch site on the cross-register offsets (>=3 carried bases).",
        "census_reproduced": {"indirects": total, "offsets": len(by_offset)},
        "cross_register_offsets": len(cross_offsets),
        "sites_classified": len(targets),
        "provenance_histogram": dict(provs),
        "X_pages_per_offset": {hex(o): dict(x) for o, x in
                               sorted(x_by_off.items(), key=lambda kv: -sum(kv[1].values()))},
        "merge_kinds": dict(merge_kind),
        "per_offset_top12": per_offset,
        "per_register": {r: dict(p) for r, p in sorted(by_reg_prov.items(),
                                                       key=lambda kv: -sum(kv[1].values()))},
        "results_first400": results,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("OUT", OUT)


if __name__ == "__main__":
    main()
