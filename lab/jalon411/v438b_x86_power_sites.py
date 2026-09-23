#!/usr/bin/env python3
"""4.38 pass, TASK B instrument — the x86 power-site map of
`nv-kernel.o_binary` (19,233,368 B, sha256 48096db0…, the committed
kernel-open host RM core).

The mission question: WHERE does the closed x86 kernel store
{100000, 240000, 250000} (the {min, default, max} power triple in mW)?
For every site: the enclosing function (the nearest FUNC symbol — the
ET_REL symtab is complete, 22,685 symbols), the role (the -pl clamp?
the nvml report? the VBIOS parse?), and whether the -pl 280 clamp
passes there.

Method (all PROVEN-side, bytes cited):
  1. objdump -d (streaming) over the whole .text — the immediates are
     taken ONLY from decoded instructions (the 4.28 lesson: raw u32
     needles hit jcc disp32 / rip-rel disp32 / RELA addends — noise).
     Target values: 100000 0x186a0, 240000 0x3a980, 250000 0x3d090,
     280000 0x445c0, 500000 0x7a120 (the s4 clamp twin), 2400/2500/2800
     (the 0.1-W units of 240/250/280), and the f32s 100.0/240.0/250.0.
  2. data sections (.data, .rodata): u32 / u64 / f32 scans at EVERY
     offset; each hit gets the nearest symbol (nm -S) and an 8-dword
     window (the array/triple detector).
  3. the cross-check vs the 4.28 raw-u32 register (the 14 x 100000):
     which raw hits are REAL immediates, which are decoys — the honest
     classification closes the census.
  4. the power-function inventory: every FUNC matching
     pfm|perf|power|pmu|edp|vbios|bios (the clamp candidates), and the
     special check: does ANY power-family function carry one of the
     target immediates or data words?

Output: lab/jalon411/v438b_x86_power_sites.json
"""
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "tools", "analysis", "x86-rm", "binaries",
                   "nv-kernel.o_binary")
OUT = os.path.join(HERE, "v438b_x86_power_sites.json")
V428_REG = os.path.join(HERE, "v428_x86_substrate_census.json")

TARGETS_U32 = {
    "100000": 0x186A0,
    "240000": 0x3A980,
    "250000": 0x3D090,
    "280000": 0x445C0,
    "500000": 0x7A120,
    "2400": 0x960,
    "2500": 0x9C4,
    "2800": 0xAF0,
}
TARGETS_F32 = {"100.0": 100.0, "240.0": 240.0, "250.0": 250.0}

POWER_RE = re.compile(
    r"(pfm|perf|power|pmu|edp|vbios|bios|_BIT|Bmp|dcb|Dcb|Voltage"
    r"|Clk|RmFan|Thermal|Therm)", re.IGNORECASE)


def load_symbols():
    """nm -S: every defined symbol: (value, size, type, name)."""
    out = subprocess.run(
        ["nm", "--defined-only", "-S", BIN],
        capture_output=True, text=True, check=True).stdout
    syms = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 4:
            try:
                val, size = int(parts[0], 16), int(parts[1], 16)
            except ValueError:
                continue
            syms.append((val, size, parts[2], parts[3]))
        elif len(parts) == 3:
            try:
                val = int(parts[0], 16)
            except ValueError:
                continue
            syms.append((val, 0, parts[1], parts[2]))
    return syms


def load_sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
    raw = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        nameoff, sh_type, flags, addr, off, size, link, info, align, entsz = \
            struct.unpack_from("<IIQQQQIIQQ", buf, b)
        raw.append(dict(index=i, nameoff=nameoff, type=sh_type, flags=flags,
                        offset=off, size=size, link=link, info=info,
                        entsize=entsz))
    strtab_off = raw[e_shstrndx]["offset"]
    for s in raw:
        end = buf.index(b"\x00", strtab_off + s["nameoff"])
        s["name"] = buf[strtab_off + s["nameoff"]:end].decode("ascii", "replace")
    return raw


def sym_of(syms, off, kinds=None):
    """the nearest symbol with sym.value <= off < sym.value+max(size,1)."""
    best = None
    for val, size, typ, name in syms:
        if kinds and typ not in kinds:
            continue
        if val <= off:
            span = size if size else 1
            if val + span > off:
                return (name, val, size, typ, "exact")
            if best is None or val > best[1]:
                best = (name, val, size, typ, "nearest")
    return best


def scan_text():
    """stream objdump -d; collect target immediates with the fn label."""
    hits = []
    cur_fn, cur_addr = None, 0
    window = {}          # addr -> (fn, mnemonic-text)
    order = []
    p = subprocess.Popen(["objdump", "-d", "--no-show-raw-insn", BIN],
                         stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
    for line in p.stdout:
        m = re.match(r"^([0-9a-f]+) <([^>]+)>:\s*$", line)
        if m:
            cur_fn, cur_addr = m.group(2), int(m.group(1), 16)
            continue
        m = re.match(r"^\s+([0-9a-f]+):\t(.*)$", line)
        if not m:
            continue
        addr, text = int(m.group(1), 16), m.group(2).strip()
        window[addr] = (cur_fn, text)
        order.append(addr)
        for im in re.findall(r"\$(-?0x[0-9a-f]+)", text):
            try:
                v = int(im, 16)
            except ValueError:
                continue
            for name, tv in TARGETS_U32.items():
                if v == tv:
                    hits.append(dict(section=".text", addr=addr,
                                     fn=cur_fn, insn=text, imm=im,
                                     value=name, kind="imm"))
    p.wait()
    # f32 immediates never appear as such; x86 materializes f32 via .rodata
    return hits, window, order


def window_of(window, order, addr, n=6):
    try:
        i = order.index(addr)
    except ValueError:
        return []
    out = []
    for a in order[max(0, i - n): i + n + 1]:
        fn, txt = window[a]
        out.append({"addr": a, "fn": fn, "insn": txt})
    return out


def scan_data(secs, syms):
    """u32/u64/f32 scans over PROGBITS data sections."""
    buf = open(BIN, "rb").read()
    results = []
    for s in secs:
        if s["type"] != 1 or s["name"] not in (".data", ".rodata"):
            continue
        data = buf[s["offset"]: s["offset"] + s["size"]]
        base = s["offset"]
        for off in range(0, len(data) - 3):
            u32, = struct.unpack_from("<I", data, off)
            for name, tv in TARGETS_U32.items():
                if u32 == tv:
                    results.append(dict(section=s["name"], off=off,
                                        vaddr=base + off, value=name,
                                        kind="u32",
                                        ctx=[hex(x) for x in struct.unpack_from("<8I", data, max(0, off - 12))]))
        # u64 (imm64-shaped constants)
        for off in range(0, len(data) - 7):
            u64, = struct.unpack_from("<Q", data, off)
            for name, tv in TARGETS_U32.items():
                if u64 == tv:
                    results.append(dict(section=s["name"], off=off,
                                        vaddr=base + off, value=name,
                                        kind="u64-pos"))
        # f32
        for off in range(0, len(data) - 3):
            f, = struct.unpack_from("<f", data, off)
            for name, tv in TARGETS_F32.items():
                if f == tv:
                    results.append(dict(section=s["name"], off=off,
                                        vaddr=base + off, value=name,
                                        kind="f32",
                                        ctx=[hex(x) for x in struct.unpack_from("<4I", data, max(0, off - 8))]))
    # attribution
    for r in results:
        sm = sym_of(syms, r["vaddr"])
        r["symbol"] = {"name": sm[0], "value": sm[1], "size": sm[2],
                       "type": sm[3], "match": sm[4]} if sm else None
    return results


def main():
    buf = open(BIN, "rb").read()
    secs = load_sections(buf)
    syms = load_symbols()
    funcs = [(v, sz, t, n) for (v, sz, t, n) in syms if t in "Tt"]

    print(f"sections={len(secs)} symbols={len(syms)} funcs={len(funcs)}")

    hits, window, order = scan_text()
    print(f".text imm hits: {len(hits)}")
    for h in hits:
        h["win"] = window_of(window, order, h["addr"], 6)

    data_hits = scan_data(secs, syms)
    print(f"data hits: {len(data_hits)}")

    # the power-function inventory
    power_fns = sorted((v, sz, n) for (v, sz, t, n) in funcs if POWER_RE.search(n))
    print(f"power-family funcs: {len(power_fns)}")

    # does any power-family fn carry a target immediate?
    fn_names = {n: (v, sz) for (v, sz, t, n) in funcs}
    power_hits = [h for h in hits if POWER_RE.search(h["fn"] or "")]
    power_data = [r for r in data_hits
                  if r["symbol"] and POWER_RE.search(r["symbol"]["name"])]

    # the 4.28 cross-check: the 14 raw-u32 100000 sites — immediate or decoy?
    v428 = json.load(open(V428_REG))
    raw14 = [h["offset"] for h in v428["u32_scans"]["val_100000_0x186a0"]["hits"]]
    imm_addrs = {h["addr"] for h in hits if h["value"] == "100000"}
    # an immediate at addr covers bytes addr..addr+len; objdump addr = insn addr,
    # the imm32 sits in the tail. Real-immediate test: a raw offset falls in
    # [insn_addr, insn_addr + insn_len) of an immediate instruction. We do not
    # have insn lengths here (no-show-raw-insn) — re-derive with lengths:
    # simpler: for each raw offset, find the last instruction addr <= raw_off
    # and check it is an immediate-bearing instruction.
    import bisect
    order_sorted = sorted(order)
    cross = []
    for ro in raw14:
        i = bisect.bisect_right(order_sorted, ro) - 1
        if i < 0:
            cross.append({"raw": ro, "verdict": "NO-INSN (data or gap)"})
            continue
        a = order_sorted[i]
        fn, txt = window[a]
        is_imm = "$0x186a0" in txt
        cross.append({"raw": ro, "insn_addr": a, "fn": fn, "insn": txt,
                      "verdict": "IMMEDIATE" if is_imm else
                      ("same-insn-as-imm" if is_imm else
                       "DECOY (non-imm operand or mid-insn)")})
    print("cross-check vs the 4.28 raw 14:")
    for c in cross:
        print("  ", c)

    out = {
        "substrate": {"path": os.path.abspath(BIN), "size": len(buf),
                      "sha256": v428["identity"]["sha256"]},
        "targets_u32": TARGETS_U32,
        "text_imm_hits": hits,
        "data_hits": data_hits,
        "power_function_inventory": [
            {"addr": hex(v), "size": sz, "name": n} for (v, sz, n) in power_fns],
        "power_fn_imm_hits": power_hits,
        "power_fn_data_hits": power_data,
        "v428_raw14_crosscheck": cross,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print(f"written {OUT}")

    # verdict printout
    print("\n=== the verdict ===")
    for val in ("100000", "240000", "250000", "280000", "500000"):
        t = [h for h in hits if h["value"] == val]
        d = [r for r in data_hits if r["value"] == val]
        print(f"{val}: .text imm={len(t)}  data={len(d)}")
    for val in TARGETS_F32:
        d = [r for r in data_hits if r["value"] == val]
        print(f"f32 {val}: data={len(d)}")


if __name__ == "__main__":
    main()
