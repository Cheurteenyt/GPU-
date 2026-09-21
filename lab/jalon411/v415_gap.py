#!/usr/bin/env python3
"""4.15A pass — the honest gap: the companion write @0x1326394 (fn 0x1325df4)
that escapes the 4.14 marker set {0x588, 0x4000}.

Window-only instrument (no full sweep): linear disasm of the mega-constructor
window 0x1325df4..0x132a414, byte-exact read of the site, offset histogram of
every state-like store in the function, backward resolution of the base.

Outputs: lab/jalon411/v415_gap.json (+ stdout readout).
"""
import json
import struct

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
OUT_JSON = "/home/z/my-project/repo-gpu/lab/jalon411/v415_gap.json"

FN = 0x1325DF4
FN_END = 0x132A414          # the 4.14 mega window
SITE = 0x1326394            # the escaped write
CTX = 24                    # insns of context around the site

STORES = {"sd", "sw", "sh", "sb"}


def norm(m):
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


def store_parts(ops):
    """Parse 'rs2, off(base)' / 'rs2, base, off' -> (rs2, base, off) or None."""
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


def main():
    code = load_segment()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    lo, hi = FN, FN_END
    insns = []  # (addr, mnem, ops)
    for ins in md.disasm(code[lo - 0x1000000:hi - 0x1000000], lo):
        insns.append((ins.address, norm(ins.mnemonic), ins.op_str))
    print(f"window {hex(lo)}..{hex(hi)}: {len(insns)} insns", flush=True)

    # --- 1. byte-exact site context -----------------------------------------
    idx = next((i for i, t in enumerate(insns) if t[0] == SITE), None)
    site_ctx = []
    if idx is not None:
        for j in range(max(0, idx - CTX), min(len(insns), idx + CTX + 1)):
            a, m, ops = insns[j]
            mark = "  <<< SITE" if a == SITE else ""
            site_ctx.append(f"{hex(a)}: {m} {ops}{mark}")
    print("\n".join(site_ctx))

    # --- 2. every store in the function, offset histogram --------------------
    stores = []  # (addr, mnem, rs2, base, off)
    for a, m, ops in insns:
        if m in STORES:
            sp = store_parts(ops)
            if sp:
                stores.append((a, m) + sp)
    hist = {}
    for a, m, rs2, bas, off in stores:
        hist[hex(off)] = hist.get(hex(off), 0) + 1
    print("\nstore-offset histogram (top 30):")
    for off, n in sorted(hist.items(), key=lambda kv: -kv[1])[:30]:
        print(f"  {off}: {n}")

    # --- 3. the site store itself -------------------------------------------
    site_store = next(((a, m, rs2, bas, off) for a, m, rs2, bas, off in stores if a == SITE), None)

    # --- 4. backward resolution of the site's base + value (window-local) ----
    def resolve(pos, reg, window=400, depth=0):
        """pos = index in insns (search backwards from pos-1)."""
        if depth > 6 or pos <= 0:
            return ("limit", None)
        for j in range(pos - 1, max(0, pos - 1 - window), -1):
            a, m, ops = insns[j]
            parts = [p.strip() for p in ops.split(",")]
            if not parts or parts[0] != reg:
                continue
            if m == "auipc" and len(parts) == 2:
                try:
                    imm = int(parts[1], 0)
                    return ("static-formed", (a & 0xFFFFF000) + (imm << 12), a)
                except Exception:
                    return ("auipc-raw", a)
            if m == "addi" and len(parts) == 3:
                try:
                    imm = int(parts[2], 0)
                except Exception:
                    return ("addi-opaque", a)
                if parts[1] == "sp":
                    return ("stack-frame", (a, imm))
                if parts[1] in ("s11", "s0", "fp", "gp", "tp"):
                    return ("reg-base", (parts[1], imm), a)
                sub = resolve(j, parts[1], window // 2, depth + 1)
                if sub[0] == "static-formed" and sub[1] is not None:
                    return ("static-formed", sub[1] + imm, a)
                return ("derived-addi", (parts[1], imm), a)
            if m == "mv" and len(parts) == 2:
                return resolve(j, parts[1], window // 2, depth + 1)
            if m in ("ld", "lw"):
                return ("memory-load", (a, ops))
            if m == "jalr":
                return ("call-result", (a, ops))
            if m == "li" and len(parts) == 2:
                return ("li-imm", (a, ops))
            if m in ("add", "sub", "slli", "srli", "andi", "ori", "xori"):
                return ("derived-other", (a, f"{m} {ops}"))
            return ("clobbered-pattern", (a, f"{m} {ops}"))
        return ("entry-value", reg)

    base_prov = val_prov = None
    if site_store:
        a, m, rs2, bas, off = site_store
        pos = next(i for i, t in enumerate(insns) if t[0] == SITE)
        base_prov = resolve(pos, bas)
        val_prov = resolve(pos, rs2)

    # --- 5. state-like bases used in the fn (s-reg family) -------------------
    sreg_stores = [(a, m, rs2, bas, off) for a, m, rs2, bas, off in stores
                   if bas in ("s11", "s0", "fp", "gp") or bas.startswith("s")]
    sreg_hist = {}
    for a, m, rs2, bas, off in sreg_stores:
        sreg_hist[hex(off)] = sreg_hist.get(hex(off), 0) + 1

    result = {
        "pass": "4.15A — the honest gap: the write @0x1326394 (fn 0x1325df4) vs the {0x588, 0x4000} marker set",
        "substrate": SUBSTRATE,
        "window": f"{hex(FN)}..{hex(FN_END)}",
        "window_insns": len(insns),
        "site_context": site_ctx,
        "site_store": ([hex(a), m, "rs2=" + rs2, "base=" + bas, "off=" + hex(off)] for a, m, rs2, bas, off in [site_store]).__next__() if site_store else None,
        "site_base_provenance": [str(x) for x in base_prov] if base_prov else None,
        "site_value_provenance": [str(x) for x in val_prov] if val_prov else None,
        "fn_store_offset_histogram_top": dict(sorted(hist.items(), key=lambda kv: -kv[1])[:30]),
        "fn_sreg_store_offset_histogram": dict(sorted(sreg_hist.items(), key=lambda kv: -kv[1])[:40]),
        "fn_total_stores": len(stores),
        "fn_total_sreg_stores": len(sreg_stores),
    }
    with open(OUT_JSON, "w") as fh:
        json.dump(result, fh, indent=1)
    print(f"\nJSON written: {OUT_JSON}")


if __name__ == "__main__":
    main()
