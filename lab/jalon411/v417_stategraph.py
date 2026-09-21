#!/usr/bin/env python3
"""4.17 pass — the state-frame dispatch graph.

Queue item 1 of 4.16: the 1,201 state-frame dispatch slots become
pseudo-seeds. The slot VALUES are runtime, but the slot OFFSETS are static.
This instrument rebuilds the 4.16 chase census (same feeder rules, same
window, comparable numbers) and adds the structural layer:

  - every state-frame dispatch site is bound to its enclosing COVERED region
    (from the 4.16 verified map, byte-level covered[] bitmap);
  - the slot census is re-aggregated by OFFSET alone (dropping the s-reg):
    if the same negative offsets recur across DIFFERENT callee-saved bases,
    the state structure is ONE shape addressed through multiple carried
    pointers, not many structures;
  - the region<->slot bipartite graph: slots per region (dispatch hubs?),
    regions per slot (diffusion degree), degree histograms;
  - the companion intersection: do any dispatch offsets hit the 0xA78
    (mod 0x1000) family (the -0x588 companion-slot pages of 4.15/4.16)?

Output: lab/jalon411/v417_stategraph.json
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
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v417_stategraph.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
BACK = 8
COMPANION_MASK = 0xA78  # mod 0x1000 — the 4.15/4.16 companion-slot field


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
    return blob[:half], blob[half:]  # seen (insn starts), covered (bytes)


def build_regions(covered):
    """runs of covered bytes -> (starts, ends) arrays for bisect lookup."""
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


def main():
    code = load()
    n = len(code)
    seen, covered = load_map()
    reg_starts, reg_ends = build_regions(covered)
    print("covered regions (>=2B runs):", len(reg_starts))

    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    def region_of(pc):
        k = bisect_right(reg_starts, pc) - 1
        if k >= 0 and reg_starts[k] <= pc < reg_ends[k]:
            return k
        return None

    stats = defaultdict(int)
    by_reg_slot = defaultdict(lambda: {"sites": 0, "regions": set()})
    by_offset = defaultdict(lambda: {"sites": 0, "regs": set(), "regions": set()})
    region_slots = defaultdict(set)          # region idx -> {(sreg, off)}
    total = 0
    unverified = 0
    verified_state_sites = []                # first 64, for the record

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
                    stats["state-frame feeder"] += 1
                    r = region_of(pc)
                    rname = (hex(IMG_LO + reg_starts[r]) + "-" + hex(IMG_LO + reg_ends[r])
                             if r is not None else "UNCOVERED")
                    key = f"{bas}+{hex(foff)}"
                    by_reg_slot[key]["sites"] += 1
                    by_reg_slot[key]["regions"].add(rname)
                    by_offset[foff]["sites"] += 1
                    by_offset[foff]["regs"].add(bas)
                    by_offset[foff]["regions"].add(rname)
                    region_slots[rname].add(key)
                    if len(verified_state_sites) < 64:
                        verified_state_sites.append(
                            {"site": hex(IMG_LO + pc), "xfer": m, "kind": kind,
                             "slot": key, "region": rname})
                elif bas in A_REGS or foff >= 0:
                    stats["object-vtable feeder"] += 1
                else:
                    stats["feeder-other"] += 1
            else:
                stats["carried"] += 1
        elif m in ("jalr", "c.jalr", "c.jr", "jr"):
            unverified += 1
        pc += size

    # degree histograms
    deg_slot_sites = defaultdict(int)   # how many slots have N sites
    for v in by_reg_slot.values():
        deg_slot_sites[v["sites"]] += 1
    deg_off_sites = defaultdict(int)
    for v in by_offset.values():
        deg_off_sites[v["sites"]] += 1
    deg_off_regs = defaultdict(int)
    for v in by_offset.values():
        deg_off_regs[len(v["regs"])] += 1
    deg_region_slots = defaultdict(int)  # how many regions use N distinct slots
    for s in region_slots.values():
        deg_region_slots[len(s)] += 1

    # cross-register offsets (same off, >= 3 distinct s-regs) — the
    # one-structure-many-pointers test
    crossreg = {hex(off): {"sites": v["sites"], "regs": sorted(v["regs"]),
                           "n_regs": len(v["regs"]), "n_regions": len(v["regions"])}
                for off, v in sorted(by_offset.items(), key=lambda kv: -kv[1]["sites"])
                if len(v["regs"]) >= 3}

    # companion-family intersection (off & 0xFFF == 0xA78)
    comp = {hex(off): {"sites": v["sites"], "regs": sorted(v["regs"])}
            for off, v in by_offset.items() if (off & 0xFFF) == COMPANION_MASK}

    # hubs — regions using >= 4 distinct state slots
    hubs = {r: sorted(s) for r, s in sorted(region_slots.items(),
            key=lambda kv: -len(kv[1]))[:16] if len(s) >= 4}

    out = {
        "pass": "4.17-stategraph",
        "substrate": SUBSTRATE,
        "covered_regions": len(reg_starts),
        "indirect_transfers_verified": total,
        "unverified_regions_skipped": unverified,
        "classes": dict(stats),
        "distinct_slots_regform": len(by_reg_slot),
        "distinct_offsets": len(by_offset),
        "top_slots_regform16": {
            k: {"sites": v["sites"], "n_regions": len(v["regions"])}
            for k, v in sorted(by_reg_slot.items(), key=lambda kv: -kv[1]["sites"])[:16]},
        "top_offsets16": {
            hex(off): {"sites": v["sites"], "n_regs": len(v["regs"]),
                       "n_regions": len(v["regions"])}
            for off, v in sorted(by_offset.items(), key=lambda kv: -kv[1]["sites"])[:16]},
        "degree_slot_sites": {str(k): v for k, v in sorted(deg_slot_sites.items())},
        "degree_offset_regs": {str(k): v for k, v in sorted(deg_off_regs.items())},
        "degree_region_slots": {str(k): v for k, v in sorted(deg_region_slots.items())},
        "cross_register_offsets": crossreg,
        "companion_family_intersection": comp,
        "dispatch_hubs": hubs,
        "first64_verified_state_sites": verified_state_sites,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("verified indirect:", total, "| state-frame:", stats["state-frame feeder"])
    print("distinct (reg,off) slots:", len(by_reg_slot), "| distinct offsets:", len(by_offset))
    print("cross-register offsets (>=3 regs):", len(crossreg))
    print("companion-family dispatch offsets:", len(comp))
    print("hubs (>=4 slots in one region):", sum(1 for s in region_slots.values() if len(s) >= 4))
    print("OUT", OUT)


if __name__ == "__main__":
    main()
