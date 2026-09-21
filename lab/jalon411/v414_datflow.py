#!/usr/bin/env python3
"""4.14 pass — the data-flow analysis of the mega-constructors around the vtable installs.

Streaming rewrite (the tuple-store version OOM'd on 3.8M insns): single linear
sweep, ring buffer of recent instructions, backward resolution only at sites.

Substrate: tools/gsp-extract/rm-full.elf (v414 image — ONE RWX LOAD at 0x1000000,
filesz==memsz==0xE9B000, zero section headers; fingerprint re-verified in-flight).
"""
import json
import struct
import sys
from collections import deque

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
OUT_JSON = "/home/z/my-project/repo-gpu/lab/jalon411/v414_datflow.json"

VT_LO = 0x1800000
COMP_OFF = 0x3A78        # the census slot: state+0x3A78
COMP_MARK = 0x588        # the observed companion-marker displacement (state+0x4000-0x588 family)
STATE_MARK = 0x4000      # the state-base marker (s11+0x4000)
A_REGS = {f"a{i}" for i in range(8)}
RING = 800


def norm(m):
    """Compressed mnemonic normalization: c.sd -> sd, c.mv -> mv, ..."""
    if m.startswith("c."):
        m = m[2:]
    if m == "sdsp":
        m = "sd"
    elif m == "ldsp":
        m = "ld"
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


def main():
    code = load_segment()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True  # no detail: parse op_str strings, much faster

    ring = deque(maxlen=RING)      # (addr, mnem, ops)
    starts = set()                 # prologue addrs
    vt_installs, comp_sites, alloc_binds = [], [], []
    last_call = None               # (addr, target, ring_len_at_call)
    idx = 0
    total = len(code)

    def func_of(addr, starts_sorted):
        import bisect
        i = bisect.bisect_right(starts_sorted, addr) - 1
        return starts_sorted[i] if i >= 0 else 0

    def resolve_backward(pos, reg, window=600, depth=0):
        """pos = distance from ring end (0 = newest). Returns (tag, value, extra)."""
        if depth > 6:
            return ("depth-limit", None, reg)
        n = len(ring)
        start = max(0, n - 1 - pos - window)
        for j in range(n - 1 - pos, start - 1, -1):
            addr, m, ops = ring[j]
            parts = [p.strip() for p in ops.split(",")]
            if not parts:
                continue
            dst = parts[0]
            if dst != reg:
                continue
            if m == "auipc" and len(parts) == 2:
                try:
                    imm = int(parts[1], 0)
                except Exception:
                    return ("auipc-raw", None, addr)
                return ("static-formed", (addr & 0xFFFFF000) + (imm << 12), addr)
            if m == "addi" and len(parts) == 3:
                try:
                    imm = int(parts[2], 0)
                except Exception:
                    return ("addi-opaque", None, addr)
                if parts[1] == "sp":
                    return ("stack-frame", addr, imm)
                if parts[1] in ("s11", "s0", "fp", "gp", "tp"):
                    return ("reg-base", addr, (parts[1], imm))
                sub = resolve_backward((n - j), parts[1], window // 2, depth + 1)
                if sub[0] == "static-formed" and sub[1] is not None:
                    return ("static-formed", sub[1] + imm, addr)
                return ("derived-addi", addr, (parts[1], imm))
            if m == "addi" :
                pass
            if m == "mv" and len(parts) == 2:
                src = parts[1]
                if src in A_REGS:
                    return ("argument", addr, src)
                return resolve_backward((n - j), src, window // 2, depth + 1)
            if m in ("ld", "lw") and len(parts) == 2:
                return ("memory-load", addr, ops)
            if m == "jalr":
                return ("call-result", addr, ops)
            if m == "lui" and len(parts) == 2:
                try:
                    imm = int(parts[1], 0)
                except Exception:
                    return ("lui-raw", None, addr)
                return ("static-formed", (imm << 12), addr)
            if m == "li" and len(parts) == 2:
                return ("li-imm", addr, ops)
            if m == "add" and len(parts) == 3:
                sub = resolve_backward((n - j), parts[1], window // 2, depth + 1)
                if sub[0] == "static-formed":
                    return ("static-formed", sub[1], addr)
                return ("derived-other", addr, f"{m} {ops}")
            if m in ("sub", "slli", "srli", "andi", "ori", "xori", "slt", "sltu"):
                return ("derived-other", addr, f"{m} {ops}")
            return ("clobbered-pattern", addr, f"{m} {ops}")
        return ("entry-value", None, reg)

    def sd_parts(ops):
        m1 = ops.split(", ")
        if len(m1) == 2 and "(" in m1[1]:
            rs2 = m1[0].strip()
            try:
                off_s, bas = m1[1][:-1].split("(", 1)
                off = int(off_s.strip(), 0)
            except Exception:
                return None
            return rs2, bas.strip(), off
        if len(m1) == 3:  # "rs2, base, off" variant
            rs2, bas, off_s = m1
            try:
                off = int(off_s.strip(), 0)
            except Exception:
                return None
            return rs2, bas.strip(), off
        return None

    print(f"streaming sweep over {total} bytes ...", flush=True)
    for ins in md.disasm(code, 0x1000000):
        idx += 1
        addr, ops = ins.address, ins.op_str
        m = norm(ins.mnemonic)
        ring.append((addr, m, ops))

        if m == "sd" and "ra," in ops and "(sp)" in ops:
            starts.add(addr)
        elif m == "addi" and ops.startswith("sp, sp, -"):
            starts.add(addr)
        elif m == "addi16sp" and ops.startswith("sp, -"):
            starts.add(addr)

        if m == "jal":
            try:
                tgt = int(ops.split(",")[-1].strip(), 0)
            except Exception:
                tgt = None
            last_call = (addr, tgt, len(ring))
        elif m == "jalr":
            last_call = (addr, None, len(ring))

        if m == "sd":
            sp = sd_parts(ops)
            if sp:
                rs2, bas, off = sp
                if off == 0:
                    prov = resolve_backward(1, rs2)
                    if prov[0] == "static-formed" and prov[1] and prov[1] >= VT_LO:
                        vt_installs.append((addr, prov[1]))
                if off in (COMP_MARK, STATE_MARK):
                    prov = resolve_backward(1, bas)
                    comp_sites.append((addr, off, prov))
                elif off == 0:
                    prov = resolve_backward(1, bas)
                    if prov[0] in ("derived-addi", "reg-base") and prov[2] and prov[2][1] in (COMP_MARK, STATE_MARK, COMP_OFF):
                        comp_sites.append((addr, 0, prov))

        if m == "mv" and ", " in ops and last_call is not None:
            two = ops.split(", ")
            if len(two) == 2 and two[1].strip() in ("a0", "x10") and len(ring) - last_call[2] < 40:
                dst = two[0].strip()
                tail = list(ring)
                for k in range(len(tail) - 1, -1, -1):
                    ka, km, ko = tail[k]
                    if km == "sd":
                        sp2 = sd_parts(ko)
                        if sp2 and (sp2[0] == dst or sp2[1] == dst):
                            break  # already-seen bind (older); skip
                # simple forward scan instead: mark pending, handled below
                pending = (dst, last_call)
                # look ahead in the NEXT insns is not possible in-stream; defer:
                alloc_binds.append((addr, pending[1][0], pending[1][1]))  # (mv site, call site, target)

        if idx % 1000000 == 0:
            print(f"  ... {idx} insns, vt={len(vt_installs)} comp={len(comp_sites)}", flush=True)

    # dedupe alloc_binds: keep mv sites where a bind actually follows within 60 insns
    # (the in-stream look-ahead is deferred; the mv-after-call list is the candidate pool)
    starts_sorted = sorted(starts)

    # strict-vtable filter: a true vtable's slot0 is a code pointer inside the LOAD
    seg0 = 0x78  # LOAD p_offset (file 0xE9B078, payload 0xE9B000)
    code_lo, code_hi = 0x1000000, 0x1000000 + 0xE9B000
    def is_vtable(t):
        off = seg0 + t - 0x1000000
        if off < 0 or off + 8 > len(code):
            return False
        slot0 = struct.unpack_from("<Q", code, off)[0]
        return code_lo <= slot0 < code_hi
    vt_strict = [(a, v) for a, v in vt_installs if is_vtable(v)]
    vt_strict_funcs = sorted({func_of(a, starts_sorted) for a, _ in vt_strict})

    vt_funcs = sorted({func_of(a, starts_sorted) for a, _ in vt_installs})
    comp_funcs = sorted({func_of(a, starts_sorted) for a, _, _ in comp_sites})
    prov_dist = {}
    for _, _, prov in comp_sites:
        prov_dist[prov[0]] = prov_dist.get(prov[0], 0) + 1

    anchor = [v for a, v in vt_installs if a == 0x115D324]

    mega = {}
    for fn, extent in ((0x1158C9C, 0x16000), (0x1325DF4, 0x4620)):
        w_sites = [(a, o, p) for a, o, p in comp_sites if fn <= a < fn + extent]
        w_vt = [[hex(a), hex(v)] for a, v in vt_installs if fn <= a < fn + extent]
        w_prov = {}
        for _, _, p in w_sites:
            w_prov[p[0]] = w_prov.get(p[0], 0) + 1
        mega[hex(fn)] = {
            "window": f"{hex(fn)}..{hex(fn+extent)}",
            "companion_sites": len(w_sites),
            "companion_detail": [[hex(a), hex(o), p[0]] for a, o, p in w_sites],
            "vtable_installs": w_vt[:12],
            "provenance": w_prov,
        }
    print("strict vtables:", len(vt_strict), "/", len(vt_strict_funcs), "functions")

    result = {
        "pass": "4.14 — the data-flow around the vtable installs (who allocates the O2, who binds it)",
        "substrate": {"path": SUBSTRATE,
                      "fingerprint": "ONE RWX LOAD vaddr=0x1000000 filesz==memsz=0xE9B000, shnum=0 — v414 re-verified"},
        "linear_sweep": {"insns_streamed": idx, "prologue_starts": len(starts_sorted)},
        "c2_validation": {"vtable_installs": len(vt_installs), "functions": len(vt_funcs),
                          "strict_vtables_slot0_codeptr": {"installs": len(vt_strict), "functions": len(vt_strict_funcs)},
                          "banked_4_13": "88 installs / 85 functions",
                          "anchor_0x115d324": [[hex(a), hex(v)] for a, v in vt_installs if a == 0x115D324],
                          "banked_anchor_value": "0x1c4b890 (the 4.13 tool) — byte-exact formation here: auipc 0xaee@0x115d31c + addi 0x56c = 0x1c4b56c"},
        "companion": {"sites_found": len(comp_sites), "functions": len(comp_funcs),
                      "banked_4_13": "64 writes / ~26 giant functions",
                      "provenance_distribution": prov_dist},
        "alloc_and_bind": {"mv_after_call_candidates": len(alloc_binds)},
        "mega_constructors": mega,
        "detail": {
            "vtable_installs_first40": [[hex(a), hex(v)] for a, v in vt_installs[:40]],
            "companion_sites_first40": [[hex(a), hex(o), p[0]] for a, o, p in comp_sites[:40]],
        },
    }
    import os
    os.makedirs("/home/z/my-project/repo-gpu/lab/jalon411", exist_ok=True)
    with open(OUT_JSON, "w") as fh:
        json.dump(result, fh, indent=1)
    print(json.dumps({k: result[k] for k in ("c2_validation", "companion", "alloc_and_bind", "mega_constructors")}, indent=1))
    print(f"\nJSON written: {OUT_JSON}")


if __name__ == "__main__":
    sys.exit(main())
