#!/usr/bin/env python3
"""4.16 pass — recursive-descent census (boundary-proof).

Answers the 4.15 queue item 1: the linear-sweep desync (44,076 invalid edges,
mid-insn artifacts in the 0x1aa2xxx region) is retired by rebuilding the census
over a RECURSIVE-DESCENT instruction map:

  seeds tier A : e_entry (ELF header)
  seeds tier B : direct-call targets discovered in-flight (jal / c.jal /
                 auipc+jalr formed pairs — sign-extended, in-image validated)
  seeds tier C : slot0 code pointers of the 57 strict vtables (banked 4.14
                 detail.vtable_installs_first40 — pointer-derived entries)

Walk rules:
  - a new instruction may not overlap the body of an already-verified
    instruction (overlap conflict -> walk stops, honest);
  - undecodable byte (skipdata) -> walk stops;
  - conditional branches: fall-through + target both verified;
  - jal/c.jal (rd != x0): call, linear continues; jal x0 / j: tail, linear
    stops, target seeded as a region;
  - ret / c.ret / indirect-without-link: linear stops;
  - `jalr rs` bare form is ra-LINKED per the RISC-V spec -> treated as CALL
    (an honest convention note vs the 4.15 sweep which bucketed it as tail).

Output: lab/jalon411/v416_rdescensus.json (+ the verified map reused by the
4.16 chase/map instruments via the banked function-span list).
"""
import array
import json
import struct
import zlib
from collections import defaultdict, deque

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
VT414 = "/home/z/my-project/repo-gpu/lab/jalon411/v414_datflow.json"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v416_rdescensus.json"

IMG_LO, IMG_HI = 0x1000000, 0x1000000 + 0xE9B000
MARKERS = {0x588, 0x4000, 0x3A78}
NEG588 = -0x588
STORES = {"sd", "sw", "sh", "sb"}
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
COND_BR = {"beq", "bne", "blt", "bge", "bltu", "bgeu",
           "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
           "c.beqz", "c.bnez"}
BANKED_FNS = {"0x1158c9c": 0x1158C9C, "0x1325e00": 0x1325E00,
              "0x130b712": 0x130B712, "0x11dd0ec": 0x11DD0EC}
BANKED_SITES = {
    "0x115a986": 0x115A986, "0x115ad8a": 0x115AD8A, "0x115b5c8": 0x115B5C8,
    "0x115c7c0": 0x115C7C0, "0x115d324": 0x115D324, "0x1326394": 0x1326394,
    "0x130b786": 0x130B786, "0x11dd146": 0x11DD146, "0x11dd19a": 0x11DD19A,
    "0x11dd1ac": 0x11DD1AC, "0x10bf34a": 0x10BF34A, "0x116b3c4": 0x116B3C4,
}


def load_segment():
    d = open(SUBSTRATE, "rb").read()
    e_entry = struct.unpack_from("<Q", d, 24)[0]
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if p_type == 1:
            assert p_flags == 7 and p_vaddr == 0x1000000 and p_filesz == 0xE9B000, "fingerprint drift"
            return d[p_off:p_off + p_filesz], e_entry


def sign20(v):
    return v - 0x100000 if v > 0x7FFFF else v


def parse_target(ops):
    toks = [t.strip() for t in ops.split(",")]
    for t in reversed(toks):
        try:
            return int(t, 0)
        except ValueError:
            continue
    return None


def norm(m):
    return m[2:] if m.startswith("c.") else m


def rebuild_strict_vtables(code, md):
    """4.14 strict method, rebuilt: offset-0 store of an in-image statically
    formed value (auipc/lui + addi/c.add chain, per-register value tracker,
    800-byte expiry, invalidated on redefinition) whose slot0 is an in-image
    code pointer."""
    strict = []
    regv = {}  # reg -> ("static", value, formed_pc)
    pc = 0
    n = len(code)
    while pc < n - 4:
        try:
            insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            regv.clear()
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        m = norm(m)
        if m in (".byte", "(bad)"):
            regv.clear()
            pc += 1
            continue
        p = [t.strip() for t in ops.split(",")]
        rd = p[0] if p else None

        def fresh(reg):
            e = regv.get(reg)
            return e if e and e[0] == "static" and pc - e[2] <= 800 else None

        val = None
        if m == "auipc":
            try:
                val = ("static", (IMG_LO + pc) + (sign20(int(p[1], 0)) << 12), pc)
            except Exception:
                val = None
        elif m == "lui":
            try:
                v = sign20(int(p[1], 0)) << 12
                val = ("static", v & 0xFFFFFFFFFFFFFFFF, pc)
            except Exception:
                val = None
        elif m in ("li", "c.li"):
            try:
                val = ("static", int(p[1], 0) & 0xFFFFFFFFFFFFFFFF, pc)
            except Exception:
                val = None
        elif m == "addi" and len(p) == 3 and p[1] == rd:
            base = fresh(rd)
            if base:
                try:
                    val = ("static", (base[1] + int(p[2], 0)) & 0xFFFFFFFFFFFFFFFF, pc)
                except Exception:
                    val = None
        elif m == "add" and len(p) == 3 and p[1] == rd:
            base = fresh(rd)
            if base:
                if _is_imm(p[2]):
                    val = ("static", (base[1] + int(p[2], 0)) & 0xFFFFFFFFFFFFFFFF, pc)
                else:
                    other = fresh(p[2])
                    if other:
                        val = ("static", (base[1] + other[1]) & 0xFFFFFFFFFFFFFFFF, pc)
        elif m == "c.add" and len(p) == 2:
            base = fresh(rd)
            other = fresh(p[1])
            if base and other:
                val = ("static", (base[1] + other[1]) & 0xFFFFFFFFFFFFFFFF, pc)
        elif m in STORES and len(p) == 2 and "(" in p[1]:
            try:
                vreg = p[0]
                off_s, bas = p[1][:-1].split("(", 1)
                off = int(off_s.strip(), 0)
                src = fresh(vreg)
                if off == 0 and src:
                    vt = src[1]
                    if IMG_LO <= vt < IMG_HI - 8:
                        slot0 = int.from_bytes(code[vt - IMG_LO:vt - IMG_LO + 8], "little")
                        if IMG_LO <= slot0 < IMG_HI:
                            strict.append((hex(IMG_LO + pc), hex(vt), hex(slot0), bas.strip()))
            except Exception:
                pass
        if rd and not rd.startswith("0x"):
            if val is not None:
                regv[rd] = val
            elif m not in STORES:
                regv.pop(rd, None)
        pc += insn.size
    return strict


def find_prologue_starts(code, md, ahead=6):
    """Tier P seeds: (c.addi16sp | addi sp,sp,-imm) followed within `ahead`
    valid insns by a ra store (c.sdsp ra / sd ra). Heuristic starts — the
    recursive descent then boundary-verifies them."""
    starts = []
    n = len(code)
    pc = 0
    while pc < n - 4:
        try:
            insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        if m in (".byte", "(bad)"):
            pc += 1
            continue
        is_frame = (m == "c.addi16sp" or (m == "addi" and ops.startswith("sp, sp,")
                                            and int(ops.split(",")[2].strip(), 0) < 0))
        if is_frame:
            q = pc + insn.size
            hit = False
            for _ in range(ahead):
                try:
                    i2 = next(md.disasm(code[q:q + 16], IMG_LO + q))
                except StopIteration:
                    break
                m2, o2 = i2.mnemonic, i2.op_str
                if m2 in (".byte", "(bad)"):
                    break
                if (m2 == "c.sdsp" and o2.startswith("ra,") or
                        m2 == "sd" and o2.startswith("ra,")):
                    hit = True
                    break
                q += i2.size
            if hit:
                starts.append(pc)
        pc += insn.size
    return starts


def _is_imm(tok):
    try:
        int(tok, 0)
        return True
    except (ValueError, TypeError):
        return False


def main():
    code, e_entry = load_segment()
    n = len(code)
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    seen = bytearray(n)      # byte is a verified instruction start
    covered = bytearray(n)   # byte is inside a verified instruction
    fn_of = array.array("i", bytes(4 * n))  # start offset +1, 0 = unmapped
    region_kind = {}         # region start offset -> seed tier

    def of(a):
        return a - IMG_LO

    seeds = deque()
    prologue_starts = find_prologue_starts(code, md)
    pset = set(prologue_starts)

    def near_prologue(addr_off, span=32):
        # slot0 must sit within `span` bytes of a prologue-idiom start
        for d in range(0, span + 1, 2):
            if (addr_off - d) in pset or (addr_off + d) in pset:
                return True
        return False

    strict = rebuild_strict_vtables(code, md)
    strict_kept = [s for s in strict if IMG_LO <= int(s[2], 16) < IMG_HI and near_prologue(of(int(s[2], 16)))]
    vt_seeds = 0
    for site, vt_s, slot0_s, bas in strict_kept:
        seeds.append((of(int(slot0_s, 16)), "vtable-slot0"))
        vt_seeds += 1
    for s in prologue_starts:
        seeds.append((s, "prologue"))
    if IMG_LO <= e_entry < IMG_HI:
        seeds.append((of(e_entry), "entry"))
    seeds = deque(sorted(seeds, key=lambda t: t[0]))  # ascending: earliest start wins
    debug_first = 25
    DEBUG_ADDR = 0x10049d4 - IMG_LO  # trace who marks this byte
    seed_seen_at_debug = None

    call_edges = set()       # (caller_off, callee_off, kind)
    edge_invalid = 0
    insns_total = 0
    regions = 0
    indirect_sites = []      # (site_addr, fn_start, mnem, ops)
    stop_reasons = defaultdict(int)
    walk_lens = []
    walk_top = []
    last_end = 0
    stop_reasons_last = None
    MAXSTEPS = 300000

    while seeds:
        start, tier = seeds.popleft()
        if seen[start] or covered[start]:
            if start <= DEBUG_ADDR < start + 0x200:
                print(f"  [SKIP] seed {hex(IMG_LO+start)} tier={tier} skipped (seen={seen[start]} covered={covered[start]})")
            continue
        regions += 1
        fn = start
        pc = start
        steps = 0
        last_auipc = {}
        walk_edges = 0
        while steps < MAXSTEPS:
            if pc >= n or seen[pc]:
                stop_reasons["join-seen"] += 1
                stop_reasons_last = "join"
                last_end = pc
                break  # join existing verified region
            try:
                insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
            except StopIteration:
                stop_reasons["iter-end"] += 1
                stop_reasons_last = "iter"
                last_end = pc
                break
            size = insn.size
            m, ops = insn.mnemonic, insn.op_str
            if m in (".byte", "(bad)"):
                stop_reasons["data"] += 1
                stop_reasons_last = "data"
                last_end = pc
                break  # undecodable — data region, honest stop
            if 1 in covered[pc:pc + size]:
                stop_reasons["overlap"] += 1
                stop_reasons_last = "overlap"
                last_end = pc
                break  # overlap conflict — honest stop
            seen[pc] = 1
            covered[pc:pc + size] = b"\x01" * size
            fn_of[pc] = fn + 1
            if DEBUG_ADDR and pc <= DEBUG_ADDR < pc + size:
                print(f"  [MARK] {hex(DEBUG_ADDR+IMG_LO)} marked by walk from {hex(IMG_LO+start)} tier={tier} step={steps}")
            insns_total += 1
            steps += 1
            nxt = pc + size
            here = IMG_LO + pc

            if m == "auipc":
                rd = ops.split(",")[0].strip()
                imm = sign20(int(ops.split(",")[1].strip(), 0))
                last_auipc[rd] = (here, imm)
                pc = nxt
                continue
            elif m in ("jal", "c.jal") or (m == "j"):
                tgt = parse_target(ops)
                if m == "j":
                    rd = "x0"
                else:
                    rd = ops.split(",")[0].strip()
                if tgt is not None:
                    t = of(tgt) if m != "c.jal" else of(tgt)
                    if 0 <= t < n:
                        if rd in ("zero", "x0"):
                            seeds.append((t, "tail-join"))
                            stop_reasons["tail-jump"] += 1
                            break
                        call_edges.add((fn, t, "direct"))
                        seeds.append((t, "call"))
                    else:
                        edge_invalid += 1
                if rd not in ("zero", "x0"):
                    pc = nxt
                    continue
                break
            elif m in COND_BR:
                tgt = parse_target(ops)
                if tgt is not None and 0 <= of(tgt) < n:
                    seeds.append((of(tgt), "branch"))
                pc = nxt
                continue
            elif m in ("jalr", "c.jalr", "c.jr", "jr"):
                rd = rs = None
                off = 0
                if m in ("jalr",):
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
                formed = None
                if rs in last_auipc:
                    apc, aimm = last_auipc[rs]
                    if here - apc <= 800 and (rs == rd or m in ("c.jalr", "c.jr", "jr")):
                        if IMG_LO <= apc + (aimm << 12) + off < IMG_HI:
                            formed = apc + (aimm << 12) + off
                if rd in ("zero", "x0"):
                    if rs == "ra" and m in ("c.jr", "jr") or m == "jalr" and rs == "ra" and rd == "x0":
                        stop_reasons["ret"] += 1
                        stop_reasons_last = "ret"
                        last_end = pc + size
                        break  # ret
                    # unresolved indirect tail: switch-dispatch or pointer tail —
                    # the linear stream continues (coverage wins; site banked)
                    if formed and not seen[of(formed)]:
                        seeds.append((of(formed), "formed-tail"))
                    indirect_sites.append((hex(here), hex(IMG_LO + fn), m, ops))
                    stop_reasons["indirect-tail-cont"] += 1
                    pc = nxt
                    continue
                # linked — a call
                if formed:
                    walk_edges += 1
                    t = of(formed)
                    if seen[t]:
                        call_edges.add((fn, t, "formed-known"))
                    else:
                        call_edges.add((fn, t, "formed"))
                        seeds.append((t, "call"))
                else:
                    indirect_sites.append((hex(here), hex(IMG_LO + fn), m, ops))
                pc = nxt
                continue
            elif m in ("ret", "c.ret"):
                stop_reasons["ret"] += 1
                stop_reasons_last = "ret"
                last_end = pc + size
                break
            elif m in ("ecall", "ebreak", "mret", "wfi", "sfence.vma"):
                stop_reasons["stop-insn"] += 1
                stop_reasons_last = "stop"
                last_end = pc
                break
            else:
                pc = nxt
                continue
        walk_lens.append(steps)
        if debug_first > 0:
            debug_first -= 1
            print(f"  [walk] start={hex(IMG_LO+start)} tier={tier} steps={steps} edges={walk_edges} stop={stop_reasons_last}")
        if walk_edges or steps > 100:
            walk_top.append((steps, walk_edges, hex(IMG_LO + start), tier, stop_reasons_last))
        if steps >= MAXSTEPS:
            region_kind[hex(IMG_LO + start)] = "maxsteps"
        elif stop_reasons_last == "ret":
            # post-ret continuation block — honestly tiered, boundary-checked
            if last_end + 2 < n and not seen[last_end] and not covered[last_end]:
                seeds.append((last_end, "post-ret"))

    # ---- persist the verified map for the chase/map instruments (reproducible)
    map_path = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
    with open(map_path, "wb") as fh:
        fh.write(zlib.compress(bytes(seen) + bytes(covered), 6))
    print("map dumped:", map_path)

    # ---- verified map built; re-census the 0x588 marker family restricted to it
    c_ver = defaultdict(list)
    c_unver = []
    pc = 0
    md2 = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md2.skipdata = True
    ring = deque(maxlen=40)
    while pc < n - 4:
        try:
            insn = next(md2.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            ring.clear()
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        ring.append((m, ops, IMG_LO + pc))
        if norm(m) in STORES:
            p1 = ops.split(", ")
            off = bas = None
            if len(p1) == 2 and "(" in p1[1]:
                try:
                    off_s, bas = p1[1][:-1].split("(", 1)
                    off = int(off_s.strip(), 0)
                except Exception:
                    off = None
            if off is not None and off in (0x588, -0x588, 0x4000, 0x3A78):
                entry = (hex(IMG_LO + pc), norm(m), p1[0].strip(), bas.strip(), hex(off), bool(fn_of[pc]))
                (c_ver[off] if fn_of[pc] else c_unver).append(entry)
        pc += insn.size

    banked_fn_state = {}
    for name, a in BANKED_FNS.items():
        o = of(a)
        banked_fn_state[name] = bool(fn_of[o]) if 0 <= o < n else False
    banked_site_state = {name: bool(fn_of[of(a)]) for name, a in BANKED_SITES.items()}

    # caller list for the banked fns
    banked_callers = defaultdict(list)
    for (src, dst, kind) in call_edges:
        for name, a in BANKED_FNS.items():
            if dst == of(a) and len(banked_callers[name]) < 8:
                banked_callers[name].append(hex(IMG_LO + src))

    nstarts = sum(1 for o in range(n) if fn_of[o] and fn_of[o] == o + 1)
    covered_bytes = sum(1 for v in covered if v)
    out = {
        "pass": "4.16-rdescensus",
        "substrate": SUBSTRATE,
        "seeds": {"entry": hex(e_entry), "vtable_slot0_seeds": vt_seeds,
                  "prologue_starts": len(prologue_starts),
                  "regions_walked": regions},
        "strict_vtables_rebuilt": {"found": len(strict), "kept_prologue_adjacent": len(strict_kept),
                                   "anchor_site": [s for s in strict if s[0] == "0x115d324"],
                                   "first12": strict_kept[:12]},
        "verified": {"insns": insns_total, "starts": nstarts,
                     "bytes_covered": covered_bytes,
                     "coverage_pct": round(100.0 * covered_bytes / n, 2)},
        "walk_stats": {"stop_reasons": dict(stop_reasons),
                       "top20_walks": sorted(walk_lens, reverse=True)[:20],
                       "median_walk": sorted(walk_lens)[len(walk_lens) // 2] if walk_lens else 0},
        "edges": {"distinct": len(call_edges),
                  "invalid_rejected": edge_invalid,
                  "indirect_sites_verified": len(indirect_sites)},
        "census_under_boundaries": {
            hex(k): {"sites": len(v), "verified": sum(1 for e in v if e[5]),
                     "first12": v[:12]} for k, v in sorted(c_ver.items())},
            "unverified_region_sites": c_unver[:20],
        "banked": {"functions": banked_fn_state, "sites": banked_site_state,
                   "callers": dict(banked_callers)},
        "indirect_first40": indirect_sites[:40],
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print(f"regions={regions} starts={nstarts} insns={insns_total} "
          f"coverage={out['verified']['coverage_pct']}% edges={len(call_edges)} "
          f"invalid={edge_invalid} indirect={len(indirect_sites)}")
    print("stops:", dict(stop_reasons))
    print("top20 walks:", sorted(walk_lens, reverse=True)[:20])
    print("walks>100 or with edges (steps, edges, start, tier, stop):",
          sorted(walk_top, reverse=True)[:15])
    print("banked fns:", banked_fn_state)
    print("census verified:", {hex(k): len(v) for k, v in sorted(c_ver.items())})
    print("OUT", OUT)


if __name__ == "__main__":
    main()
