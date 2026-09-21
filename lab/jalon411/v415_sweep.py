#!/usr/bin/env python3
"""4.15 pass — census v2 (the aliased marker forms) + the O2 allocator hunt.

ONE streaming sweep over the v414 image collecting:
  (a) census v2 — the extended marker set:
        fam588   : sd/sw x, +0x588(base)                       (the 4.14 form)
        fam4000  : sd/sw x, +0x4000(base)                      (the 4.14 form)
        fam3A78  : sd/sw x, +0x3A78(s-reg)  — the absolute slot
        alias3A78: sd/sw x, -0x588(base) where base = lui 4 + add s-reg
                   (the NEGATIVE alias of the same slot — the 0x1326394 form)
                   split install vs release (rs2 == zero)
        readers  : ld/lw x, -0x588(alias-base) / +0x3A78       (the read side)
  (b) call graph — direct jal + auipc/jalr pairs resolved; tails counted
  (c) the mv-a0-post-call pool (the 4.14 criterion, 22,375 raw) with
      RESOLVED call targets -> callee histogram -> allocator candidates

Substrate: tools/gsp-extract/rm-full.elf (v414, ONE RWX LOAD 0x1000000/0xE9B000).
"""
import bisect
import json
import struct
from collections import defaultdict, deque

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
OUT_CENSUS = "/home/z/my-project/repo-gpu/lab/jalon411/v415_census2.json"
OUT_O2 = "/home/z/my-project/repo-gpu/lab/jalon411/v415_o2hunt.json"

M588, M4000, M3A78 = 0x588, 0x4000, 0x3A78
GAP_SITE = 0x1326394
A_REGS = {f"a{i}" for i in range(8)}
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
RING = 800
STORES = {"sd", "sw", "sh", "sb"}
LOADS = {"ld", "lw", "lh", "lb", "lbu", "lhu"}


def norm(m):
    if m.startswith("c."):
        m = m[2:]
    if m == "sdsp":
        m = "sd"
    elif m == "ldsp":
        m = "ld"
    elif m == "addi16sp":
        m = "addi"
    return m


def load_segment():
    d = open(SUBSTRATE, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if p_type == 1:
            assert p_flags == 7 and p_vaddr == 0x1000000 and p_filesz == 0xE9B000, "fingerprint drift"
            return d[p_off:p_off + p_filesz]


def store_parts(ops):
    p1 = ops.split(", ")
    if len(p1) == 2 and "(" in p1[1]:
        try:
            off_s, bas = p1[1][:-1].split("(", 1)
            return p1[0].strip(), bas.strip(), int(off_s.strip(), 0)
        except Exception:
            return None
    if len(p1) == 3:
        try:
            return p1[0].strip(), p1[1].strip(), int(p1[2].strip(), 0)
        except Exception:
            return None
    return None


def load_parts(ops):
    """'rd, off(base)' -> (rd, base, off)"""
    p1 = ops.split(", ")
    if len(p1) == 2 and "(" in p1[1]:
        try:
            off_s, bas = p1[1][:-1].split("(", 1)
            return p1[0].strip(), bas.strip(), int(off_s.strip(), 0)
        except Exception:
            return None
    return None


def jalr_parts(ops):
    """Normalize jalr ops -> (rd, rs1, off) ; c.jalr 'rs1' -> ('x0', rs1, 0)."""
    if "(" in ops:
        p = ops.replace("(", ",").replace(")", "").split(",")
        if len(p) == 3:
            try:
                return p[0].strip(), p[2].strip(), int(p[1].strip(), 0)
            except Exception:
                return None
        return None
    parts = [x.strip() for x in ops.split(",")]
    if len(parts) == 1:
        return ("x0", parts[0], 0)
    if len(parts) == 3:
        try:
            return parts[0], parts[1], int(parts[2], 0)
        except Exception:
            return None
    return None


def main():
    code = load_segment()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    ring = deque(maxlen=RING)
    starts = set()
    auipc_pending = {}          # reg -> (addr, idx, imm)
    # census buckets
    c588, c4000, c3a78, alias_inst, alias_rel, readers, neg588_other = [], [], [], [], [], [], []
    # call graph
    call_edges = defaultdict(int)
    tail_edges = defaultdict(int)
    indirect_calls = indirect_tails = 0
    # pool
    last_call = None            # (addr, idx, target_or_None)
    pool_raw = []               # (mv_addr, call_addr, target_or_None, dst)
    idx = 0

    def resolve(pos, reg, window=600, depth=0):
        """pos counts from newest (0 = newest). Returns (tag, value, extra)."""
        n = len(ring)
        if depth > 6:
            return ("depth-limit", None, reg)
        start = max(0, n - 1 - pos - window)
        for j in range(n - 1 - pos, start - 1, -1):
            addr, m, ops = ring[j]
            parts = [p.strip() for p in ops.split(",")]
            if not parts:
                continue
            dst = parts[0]
            if dst != reg:
                continue
            if m == "lui" and len(parts) == 2:
                try:
                    return ("static-formed", int(parts[1], 0) << 12, addr)
                except Exception:
                    return ("lui-raw", None, addr)
            if m == "auipc" and len(parts) == 2:
                try:
                    return ("static-formed", (addr & 0xFFFFF000) + (int(parts[1], 0) << 12), addr)
                except Exception:
                    return ("auipc-raw", None, addr)
            if m == "addi" and len(parts) == 3:
                try:
                    imm = int(parts[2], 0)
                except Exception:
                    return ("addi-opaque", None, addr)
                if parts[1] == "sp":
                    return ("stack-frame", (addr, imm), addr)
                if parts[1] in ("s11", "s0", "fp", "gp", "tp") and imm == 0:
                    return ("reg-base", parts[1], addr)
                if parts[1] in ("s11", "s0", "fp", "gp", "tp"):
                    return ("reg-base-off", (parts[1], imm), addr)
                sub = resolve(n - j, parts[1], window // 2, depth + 1)
                if sub[0] == "static-formed" and sub[1] is not None:
                    return ("static-formed", sub[1] + imm, addr)
                return ("derived-addi", (parts[1], imm), addr)
            if m == "mv" and len(parts) == 2:
                if parts[1] in A_REGS:
                    return ("argument", parts[1], addr)
                return resolve(n - j, parts[1], window // 2, depth + 1)
            if m == "add" and len(parts) == 2:
                # add rd, rs  -> rd = rd + rs ; resolve rd's earlier def
                sub = resolve(n - j, parts[0], window // 4, depth + 1)
                if sub[0] == "static-formed" and sub[1] is not None:
                    return ("static-plus-reg", (sub[1], parts[1]), addr)
                return ("derived-add", f"{m} {ops}", addr)
            if m == "add" and len(parts) == 3:
                s1 = resolve(n - j, parts[1], window // 4, depth + 1)
                if s1[0] == "static-formed" and s1[1] is not None:
                    return ("static-plus-reg", (s1[1], parts[2]), addr)
                s2 = resolve(n - j, parts[2], window // 4, depth + 1)
                if s2[0] == "static-formed" and s2[1] is not None:
                    return ("static-plus-reg", (s2[1], parts[1]), addr)
                return ("derived-add", f"{m} {ops}", addr)
            if m in ("ld", "lw") and len(parts) == 2:
                return ("memory-load", ops, addr)
            if m == "jalr":
                return ("call-result", ops, addr)
            if m == "li" and len(parts) == 2:
                return ("li-imm", ops, addr)
            if m in ("sub", "slli", "srli", "andi", "ori", "xori", "slt", "sltu", "addiw"):
                return ("derived-other", f"{m} {ops}", addr)
            return ("clobbered-pattern", f"{m} {ops}", addr)
        return ("entry-value", reg, None)

    print(f"streaming sweep ...", flush=True)
    for ins in md.disasm(code, 0x1000000):
        idx += 1
        addr, ops = ins.address, ins.op_str
        m = norm(ins.mnemonic)
        ring.append((addr, m, ops))

        # --- prologue starts (same heuristics as 4.14) ---
        if m == "sd" and "ra," in ops and "(sp)" in ops:
            starts.add(addr)
        elif m == "addi" and ops.startswith("sp, sp, -"):
            starts.add(addr)

        # --- auipc tracking for call resolution ---
        if m == "auipc":
            p = ops.split(", ")
            if len(p) == 2:
                try:
                    auipc_pending[p[0].strip()] = (addr, idx, int(p[1], 0))
                except Exception:
                    pass

        # --- calls / tails ---
        if m == "jal":
            p = ops.split(", ")
            if len(p) == 2:
                rd, tgt = p[0].strip(), p[1].strip()
                try:
                    t = int(tgt, 0)
                except Exception:
                    t = None
                if rd == "ra":
                    call_edges[t] += 1
                    last_call = (addr, idx, t)
                elif rd in ("x0", "zero"):
                    tail_edges[t] += 1
        elif m == "j":
            try:
                tail_edges[int(ops.strip(), 0)] += 1
            except Exception:
                pass
        elif m == "jalr":
            jp = jalr_parts(ops)
            if jp:
                rd, rs1, off = jp
                pend = auipc_pending.get(rs1)
                tgt = None
                if pend and idx - pend[1] <= 4:
                    tgt = (pend[0] & 0xFFFFF000) + (pend[2] << 12) + off
                    tgt &= 0xFFFFFFFFFFFFFFFF
                if rd == "ra":
                    if tgt is not None:
                        call_edges[tgt] += 1
                    else:
                        indirect_calls += 1
                    last_call = (addr, idx, tgt)
                else:
                    if tgt is not None:
                        tail_edges[tgt] += 1
                    else:
                        indirect_tails += 1

        # --- the pool: mv dst, a0 within 40 of the last call ---
        if m == "mv" and ", " in ops and last_call is not None:
            two = ops.split(", ")
            if len(two) == 2 and two[1].strip() in ("a0", "x10") and idx - last_call[1] <= 40:
                pool_raw.append((addr, last_call[0], last_call[2], two[0].strip()))

        # --- census v2 ---
        if m in STORES:
            sp = store_parts(ops)
            if sp:
                rs2, bas, off = sp
                if off == M588:
                    c588.append((addr, rs2, bas))
                elif off == M4000:
                    c4000.append((addr, rs2, bas))
                elif off == M3A78:
                    c3a78.append((addr, rs2, bas))
                elif off == -M588:
                    prov = resolve(1, bas)
                    if prov[0] == "static-plus-reg" and prov[1][0] == M4000 and str(prov[1][1]).rstrip("0123456789") in ("s", "fp"):
                        (alias_rel if rs2 in ("zero", "x0") else alias_inst).append((addr, rs2, bas))
                    else:
                        neg588_other.append((addr, rs2, bas, prov[0]))
        elif m in LOADS:
            lp = load_parts(ops)
            if lp:
                rd, bas, off = lp
                if off in (-M588, M3A78):
                    readers.append((addr, rd, bas, off))

        if idx % 1000000 == 0:
            print(f"  ... {idx} insns | 588={len(c588)} 4000={len(c4000)} 3a78={len(c3a78)} "
                  f"alias_i={len(alias_inst)} alias_r={len(alias_rel)} readers={len(readers)} "
                  f"pool={len(pool_raw)}", flush=True)

    starts_sorted = sorted(starts)

    def func_of(a):
        i = bisect.bisect_right(starts_sorted, a) - 1
        return starts_sorted[i] if i >= 0 else 0

    # ============ census v2 outputs ============
    def bucket_stats(bucket, with_prov=False):
        fns = sorted({func_of(a) for a, *_ in bucket})
        return {"sites": len(bucket), "functions": len(fns)}

    gap_in_alias = [t for t in alias_rel if t[0] == GAP_SITE]
    census2 = {
        "pass": "4.15 — census v2 (the aliased marker forms; the honest gap closed?)",
        "substrate": SUBSTRATE,
        "linear_sweep": {"insns_streamed": idx, "prologue_starts": len(starts_sorted)},
        "fam588": {**bucket_stats(c588),
                   "null_stores": sum(1 for _, r, _ in c588 if r in ("zero", "x0")),
                   "first20": [[hex(a), r, b] for a, r, b in c588[:20]]},
        "fam4000": {**bucket_stats(c4000),
                    "null_stores": sum(1 for _, r, _ in c4000 if r in ("zero", "x0")),
                    "first20": [[hex(a), r, b] for a, r, b in c4000[:20]]},
        "fam3A78_direct": {**bucket_stats(c3a78),
                           "first20": [[hex(a), r, b] for a, r, b in c3a78[:20]]},
        "alias3A78": {"install": {**bucket_stats(alias_inst),
                                  "first20": [[hex(a), r, b] for a, r, b in alias_inst[:20]]},
                      "release": {**bucket_stats(alias_rel),
                                  "first20": [[hex(a), r, b] for a, r, b in alias_rel[:20]]},
                      "gap_site_0x1326394_joins_release": bool(gap_in_alias)},
        "readers_3A78": {**bucket_stats(readers),
                         "first20": [[hex(a), r, b, hex(o)] for a, r, b, o in readers[:20]]},
        "neg588_unresolved": {"sites": len(neg588_other),
                              "prov_dist": {p: sum(1 for t in neg588_other if t[3] == p) for p in {t[3] for t in neg588_other}} or {},
                              "first20": [[hex(a), r, b, p] for a, r, b, p in neg588_other[:20]]},
        "banked_4_14": "87 sites / 29 functions (markers {+0x588, +0x4000} only)",
    }
    union_sites = sorted({a for a, *_ in c588} | {a for a, *_ in c4000} | {a for a, *_ in c3a78}
                         | {a for a, *_ in alias_inst} | {a for a, *_ in alias_rel})
    census2["union"] = {"sites": len(union_sites),
                        "functions": len({func_of(a) for a in union_sites})}
    with open(OUT_CENSUS, "w") as fh:
        json.dump(census2, fh, indent=1)

    # ============ O2 hunt outputs ============
    strict = [t for t in pool_raw if t[3] in S_REGS]
    hist = defaultdict(int)
    for _, _, tgt, _ in strict:
        if tgt is not None:
            hist[tgt] += 1
    top = sorted(hist.items(), key=lambda kv: -kv[1])[:25]

    def fn_extent(fn):
        i = bisect.bisect_right(starts_sorted, fn)
        end = starts_sorted[i] if i < len(starts_sorted) else fn + 0x20000
        return min(end, fn + 0x20000)

    INTEREST = {0x4000, 0x3A78, 0x588, 0x90, 0x10, 0xF, 0xFFF, 0x80, 0x1000}
    cands = []
    for tgt, n in top[:15]:
        ext = fn_extent(tgt)
        seg = code[tgt - 0x1000000:ext - 0x1000000]
        consts = defaultdict(int)
        calls_out = indirect_out = 0
        for ins2 in md.disasm(seg, tgt):
            m2 = norm(ins2.mnemonic)
            o2 = ins2.op_str
            if m2 in ("li", "addi", "lui", "andi", "ori"):
                p = [x.strip() for x in o2.split(",")]
                try:
                    v = int(p[-1], 0)
                    if m2 == "lui":
                        v <<= 12
                    consts[v] += 1
                except Exception:
                    pass
            if (m2 == "jal" or m2 == "jalr") and o2.split(",")[0].strip() == "ra":
                calls_out += 1
            if m2 == "jalr" and o2.split(",")[0].strip() != "ra":
                indirect_out += 1
        interesting = {hex(k): v for k, v in consts.items() if k in INTEREST}
        cands.append({"target": hex(tgt), "callers_mv_a0_save": n,
                      "fn_extent": f"{hex(tgt)}..{hex(ext)}",
                      "fn_bytes": ext - tgt,
                      "outgoing_ra_calls": calls_out, "indirect_jumps": indirect_out,
                      "interesting_constants": interesting,
                      "top_consts": {hex(k): v for k, v in sorted(consts.items(), key=lambda kv: -kv[1])[:12]}})

    o2 = {
        "pass": "4.15 — the O2 allocator hunt (call-graph pass on the mv-a0-post-call pool)",
        "pool": {"raw_any_dst": len(pool_raw),
                 "strict_sreg_dst": len(strict),
                 "resolved_targets": sum(1 for _, _, t, _ in strict if t is not None),
                 "unresolved_calls_in_strict": sum(1 for _, _, t, _ in strict if t is None)},
        "call_graph": {"resolved_call_edges": sum(call_edges.values()),
                       "distinct_callees": len(call_edges),
                       "resolved_tail_edges": sum(tail_edges.values()),
                       "indirect_calls": indirect_calls, "indirect_tails": indirect_tails},
        "top_candidates": cands,
        "note": "rank = number of strict call sites where a0 is immediately saved into a callee-saved register",
    }
    with open(OUT_O2, "w") as fh:
        json.dump(o2, fh, indent=1)

    print(json.dumps({"census2_union": census2["union"],
                      "alias3A78": census2["alias3A78"],
                      "gap_joins": bool(gap_in_alias),
                      "o2_top5": cands[:5]}, indent=1))
    print(f"\nJSONs written: {OUT_CENSUS}\n                {OUT_O2}")


if __name__ == "__main__":
    main()
