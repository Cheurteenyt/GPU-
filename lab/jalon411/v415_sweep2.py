#!/usr/bin/env python3
"""4.15 pass — sweep v2 (supersedes the first v415_sweep run).

Fixes over run 1:
  - auipc immediates masked to 20 bits; resolved call targets validated
    against the image span; out-of-image targets -> honest 'invalid' bucket
    (run 1 produced 0x10100d65c-style artifacts);
  - every census bucket records the store width (sd/sw/sh/sb) — the honest
    4.14 delta (4.14 counted sd only);
  - branch-b replicated: off==0 stores from a base resolving to
    s-reg+{0x588,0x4000,0x3A78};
  - reader bases resolved (alias-confirmed vs other);
  - call sites retained per callee (cap 16);
  - context windows banked for the probe sites (gap, 0x11dd146 cluster,
    0x130b786 release twin).

Outputs: lab/jalon411/v415_census2.json + v415_o2hunt.json (overwritten).
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
CLUSTER = (0x11DD146, 0x11DD19A, 0x11DD1AC)
TWIN_RELEASE = 0x130B786
IMM20 = 0xFFFFF
IMG_LO, IMG_HI = 0x1000000, 0x1000000 + 0xE9B000
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


def mem_parts(ops):
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


def jalr_parts(ops):
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
    auipc_pending = {}
    c588, c4000, c3a78, alias_inst, alias_rel, readers_alias, readers_other, neg588_other, branchb = \
        [], [], [], [], [], [], [], [], []
    call_edges = defaultdict(int)
    call_sites = defaultdict(list)
    tail_edges = defaultdict(int)
    indirect_calls = indirect_tails = invalid_edges = 0
    last_call = None
    pool_raw = []
    idx = 0

    def resolve(pos, reg, window=600, depth=0):
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
                    return ("static-formed", (int(parts[1], 0) & IMM20) << 12, addr)
                except Exception:
                    return ("lui-raw", None, addr)
            if m == "auipc" and len(parts) == 2:
                try:
                    return ("static-formed", (addr & 0xFFFFF000) + ((int(parts[1], 0) & IMM20) << 12), addr)
                except Exception:
                    return ("auipc-raw", None, addr)
            if m == "addi" and len(parts) == 3:
                try:
                    imm = int(parts[2], 0)
                except Exception:
                    return ("addi-opaque", None, addr)
                if parts[1] == "sp":
                    return ("stack-frame", (addr, imm), addr)
                if parts[1] in ("s11", "s0", "fp", "gp", "tp"):
                    return ("reg-base", (parts[1], imm), addr)
                sub = resolve(n - j, parts[1], window // 2, depth + 1)
                if sub[0] == "static-formed" and sub[1] is not None:
                    return ("static-formed", sub[1] + imm, addr)
                return ("derived-addi", (parts[1], imm), addr)
            if m == "mv" and len(parts) == 2:
                if parts[1] in A_REGS:
                    return ("argument", parts[1], addr)
                return resolve(n - j, parts[1], window // 2, depth + 1)
            if m == "add" and len(parts) == 2:
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

    print("streaming sweep v2 ...", flush=True)
    for ins in md.disasm(code, 0x1000000):
        idx += 1
        addr, ops = ins.address, ins.op_str
        m = norm(ins.mnemonic)
        ring.append((addr, m, ops))

        if m == "sd" and "ra," in ops and "(sp)" in ops:
            starts.add(addr)
        elif m == "addi" and ops.startswith("sp, sp, -"):
            starts.add(addr)

        if m == "auipc":
            p = ops.split(", ")
            if len(p) == 2:
                try:
                    auipc_pending[p[0].strip()] = (addr, idx, int(p[1], 0) & IMM20)
                except Exception:
                    pass

        if m == "jal":
            p = ops.split(", ")
            if len(p) == 2:
                rd = p[0].strip()
                try:
                    t = int(p[1].strip(), 0)
                except Exception:
                    t = None
                if t is not None and not (IMG_LO <= t < IMG_HI):
                    invalid_edges += 1
                    t = None
                if rd == "ra":
                    if t is not None:
                        call_edges[t] += 1
                        if len(call_sites[t]) < 16:
                            call_sites[t].append(addr)
                    last_call = (addr, idx, t)
                elif rd in ("x0", "zero") and t is not None:
                    tail_edges[t] += 1
        elif m == "j":
            try:
                t = int(ops.strip(), 0)
                if IMG_LO <= t < IMG_HI:
                    tail_edges[t] += 1
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
                    if not (IMG_LO <= tgt < IMG_HI):
                        invalid_edges += 1
                        tgt = None
                if rd == "ra":
                    if tgt is not None:
                        call_edges[tgt] += 1
                        if len(call_sites[tgt]) < 16:
                            call_sites[tgt].append(addr)
                    else:
                        indirect_calls += 1
                    last_call = (addr, idx, tgt)
                elif tgt is not None:
                    tail_edges[tgt] += 1
                else:
                    indirect_tails += 1

        if m == "mv" and ", " in ops and last_call is not None:
            two = ops.split(", ")
            if len(two) == 2 and two[1].strip() in ("a0", "x10") and idx - last_call[1] <= 40:
                pool_raw.append((addr, last_call[0], last_call[2], two[0].strip()))

        if m in STORES:
            sp = mem_parts(ops)
            if sp:
                rs2, bas, off = sp
                if off == M588:
                    c588.append((addr, m, rs2, bas))
                elif off == M4000:
                    c4000.append((addr, m, rs2, bas))
                elif off == M3A78:
                    c3a78.append((addr, m, rs2, bas))
                elif off == -M588:
                    prov = resolve(1, bas)
                    if prov[0] == "static-plus-reg" and prov[1][0] == M4000 and \
                            str(prov[1][1]).rstrip("0123456789") in ("s", "fp"):
                        (alias_rel if rs2 in ("zero", "x0") else alias_inst).append((addr, m, rs2, bas))
                    else:
                        neg588_other.append((addr, m, rs2, bas, prov[0]))
                elif off == 0:
                    prov = resolve(1, bas)
                    if prov[0] == "derived-addi" and prov[1] and prov[1][1] in (M588, M4000, M3A78):
                        branchb.append((addr, m, rs2, bas, prov[1][1]))
                    elif prov[0] == "reg-base" and prov[1] and prov[1][1] in (M588, M4000, M3A78):
                        branchb.append((addr, m, rs2, bas, prov[1][1]))
        elif m in LOADS:
            lp = mem_parts(ops)
            if lp:
                rd, bas, off = lp
                if off in (-M588, M3A78):
                    prov = resolve(1, bas)
                    if prov[0] == "static-plus-reg" and prov[1][0] == M4000 and \
                            str(prov[1][1]).rstrip("0123456789") in ("s", "fp"):
                        readers_alias.append((addr, m, rd, bas))
                    else:
                        readers_other.append((addr, m, rd, bas, prov[0]))

        if idx % 1000000 == 0:
            print(f"  ... {idx} insns | 588={len(c588)} b-b={len(branchb)} alias_i={len(alias_inst)} "
                  f"alias_r={len(alias_rel)} readers_a={len(readers_alias)} pool={len(pool_raw)}", flush=True)

    starts_sorted = sorted(starts)

    def func_of(a):
        i = bisect.bisect_right(starts_sorted, a) - 1
        return starts_sorted[i] if i >= 0 else 0

    def fn_start(a):
        return func_of(a)

    # context windows for the probe sites
    def ctx_window(center, back, fwd):
        lo, hi = center - back, center + fwd
        seg = code[lo - 0x1000000:hi - 0x1000000]
        out = []
        for ins2 in md.disasm(seg, lo):
            mark = "  <<<" if ins2.address == center else ""
            out.append(f"{hex(ins2.address)}: {norm(ins2.mnemonic)} {ins2.op_str}{mark}")
        return out

    probes = {
        "gap_release_0x1326394": ctx_window(GAP_SITE, 0x40, 0x14),
        "twin_release_0x130b786": ctx_window(TWIN_RELEASE, 0x40, 0x14),
        "cluster_0x11dd146": ctx_window(CLUSTER[0], 0x50, 0x80),
    }
    probe_fns = {"gap": hex(fn_start(GAP_SITE)),
                 "twin": hex(fn_start(TWIN_RELEASE)),
                 "cluster": [hex(fn_start(c)) for c in CLUSTER]}

    def bstats(bucket):
        fns = sorted({func_of(a) for a, *_ in bucket})
        widths = defaultdict(int)
        for t in bucket:
            widths[t[1]] += 1
        return {"sites": len(bucket), "functions": len(fns), "widths": dict(widths)}

    census2 = {
        "pass": "4.15 — census v2 (aliased marker forms; sweep run 2, targets validated)",
        "substrate": SUBSTRATE,
        "linear_sweep": {"insns_streamed": idx, "prologue_starts": len(starts_sorted)},
        "fam588_direct": {**bstats(c588),
                          "null_stores": sum(1 for _, _, r, _ in c588 if r in ("zero", "x0")),
                          "first24": [[hex(a), m, r, b] for a, m, r, b in c588[:24]]},
        "fam4000_direct": bstats(c4000),
        "fam3A78_direct": bstats(c3a78),
        "branchb_slot": {**bstats(branchb),
                         "slot_dist": {hex(t[4]): sum(1 for x in branchb if x[4] == t[4]) for t in branchb},
                         "first16": [[hex(a), m, r, b, hex(s)] for a, m, r, b, s in branchb[:16]]},
        "alias3A78": {"install": {**bstats(alias_inst),
                                  "sites": [[hex(a), m, r, b] for a, m, r, b in alias_inst]},
                      "release": {**bstats(alias_rel),
                                  "sites": [[hex(a), m, r, b] for a, m, r, b in alias_rel]},
                      "gap_site_joins_release": any(t[0] == GAP_SITE for t in alias_rel)},
        "readers": {"alias_confirmed": {**bstats(readers_alias),
                                        "first24": [[hex(a), m, r, b] for a, m, r, b in readers_alias[:24]]},
                    "other_bases": {"sites": len(readers_other),
                                    "prov_dist": {p: sum(1 for t in readers_other if t[4] == p)
                                                  for p in {t[4] for t in readers_other}}}},
        "neg588_unresolved": {"sites": len(neg588_other),
                              "prov_dist": {p: sum(1 for t in neg588_other if t[4] == p)
                                            for p in {t[4] for t in neg588_other}},
                              "first16": [[hex(a), m, r, b, p] for a, m, r, b, p in neg588_other[:16]]},
        "probes": {"function_starts": probe_fns, "windows": probes},
        "banked_4_14": "87 sites / 29 functions (sd-only, markers {+0x588, +0x4000}, plus off==0 alias branch)",
    }
    union_sites = sorted({a for a, *_ in c588} | {a for a, *_ in c4000} | {a for a, *_ in c3a78}
                         | {a for a, *_ in alias_inst} | {a for a, *_ in alias_rel}
                         | {a for a, *_ in branchb})
    census2["union"] = {"sites": len(union_sites),
                        "functions": len({func_of(a) for a in union_sites})}
    with open(OUT_CENSUS, "w") as fh:
        json.dump(census2, fh, indent=1)

    # ============ O2 hunt (cleaned) ============
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

    INTEREST = {0x4000, 0x3A78, 0x588, 0x90, 0x10, 0xF, 0xFFF, 0x1000, 0x80}
    cands = []
    for tgt, n in top[:15]:
        ext = fn_extent(tgt)
        seg = code[tgt - 0x1000000:ext - 0x1000000]
        consts = defaultdict(int)
        calls_out = indirect_out = 0
        head = []
        for k, ins2 in enumerate(md.disasm(seg, tgt)):
            m2 = norm(ins2.mnemonic)
            o2 = ins2.op_str
            if k < 6:
                head.append(f"{hex(ins2.address)}: {m2} {o2}")
            if m2 in ("li", "addi", "lui", "andi", "ori"):
                p = [x.strip() for x in o2.split(",")]
                try:
                    v = int(p[-1], 0)
                    if m2 == "lui":
                        v = (v & IMM20) << 12
                    consts[v] += 1
                except Exception:
                    pass
            if m2 == "jalr" or m2 == "jal":
                if o2.split(",")[0].strip() == "ra":
                    calls_out += 1
                elif m2 == "jalr":
                    indirect_out += 1
        dominant = max(consts.values()) if consts else 0
        prologue = any(("ra," in h and "(sp)" in h) or h.split(": ", 1)[1].startswith("addi sp, sp, -")
                       for h in head)
        cands.append({"target": hex(tgt), "callers_mv_a0_save": n,
                      "fn_extent": f"{hex(tgt)}..{hex(ext)}", "fn_bytes": ext - tgt,
                      "head": head, "prologue_like": prologue,
                      "data_suspect": (dominant >= 4 and (ext - tgt) < 700),
                      "outgoing_ra_calls": calls_out, "indirect_jumps": indirect_out,
                      "interesting_constants": {hex(k): v for k, v in consts.items() if k in INTEREST},
                      "top_consts": {hex(k): v for k, v in sorted(consts.items(), key=lambda kv: -kv[1])[:12]}})

    o2 = {
        "pass": "4.15 — the O2 allocator hunt (cleaned call-graph pass)",
        "pool": {"raw_any_dst": len(pool_raw), "strict_sreg_dst": len(strict),
                 "resolved_targets": sum(1 for _, _, t, _ in strict if t is not None),
                 "unresolved_in_strict": sum(1 for _, _, t, _ in strict if t is None)},
        "call_graph": {"resolved_call_edges": sum(call_edges.values()),
                       "distinct_callees": len(call_edges),
                       "invalid_target_edges": invalid_edges,
                       "resolved_tail_edges": sum(tail_edges.values()),
                       "indirect_calls": indirect_calls, "indirect_tails": indirect_tails},
        "top_candidates": cands,
        "note": "rank = strict sites (a0 saved into a callee-saved reg within 40 insns of the call)",
    }
    with open(OUT_O2, "w") as fh:
        json.dump(o2, fh, indent=1)

    print(json.dumps({"union": census2["union"], "alias3A78": census2["alias3A78"],
                      "branchb": census2["branchb_slot"]["sites"],
                      "fam588": census2["fam588_direct"]["sites"],
                      "pool": o2["pool"], "invalid_edges": invalid_edges,
                      "top5": [{k: c[k] for k in ("target", "callers_mv_a0_save", "prologue_like",
                                                  "data_suspect", "fn_bytes")} for c in cands[:5]]},
                     indent=1))
    print(f"\nJSONs written:\n  {OUT_CENSUS}\n  {OUT_O2}")


if __name__ == "__main__":
    main()
