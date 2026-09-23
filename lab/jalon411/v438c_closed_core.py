#!/usr/bin/env python3
"""4.38 TASK B, instrument 2 — the CLOSED core census:
`kernel/nvidia/nv-kernel.o_binary` (120,980,872 B, sha256 c90f58d5…8cbf,
extracted from the official .run package sha b2e935c6…b116d — verified).

Same method as v438b (the open 19-MB core), plus:
  - the TRIPLE detector: {100000, 240000, 250000} within ±64 B in any
    data section (the v9 fingerprint of 4.23) — where does the closed
    core HOLD the reported limit?
  - the power-family function attribution for every .text immediate.

Output: /home/z/my-project/artifacts/v438c_closed_core.json (outside the
repo — the substrate is outside the repo too)
"""
import json
import os
import re
import struct
import subprocess

HERE = "/home/z/my-project/artifacts"
BIN = os.path.join(HERE, "pkg/kernel/nvidia/nv-kernel.o_binary")
OUT = os.path.join(HERE, "v438c_closed_core.json")

TARGETS_U32 = {
    "100000": 0x186A0, "240000": 0x3A980, "250000": 0x3D090,
    "280000": 0x445C0, "500000": 0x7A120,
    "2400": 0x960, "2500": 0x9C4, "2800": 0xAF0,
    "210000": 0x33510,  # the 4.23 -pl 210 capture value
    "200000": 0x30D40,  # a plausible -pl probe value
}
TARGETS_F32 = {"100.0": 100.0, "240.0": 240.0, "250.0": 250.0, "280.0": 280.0}

POWER_RE = re.compile(
    r"(pfm|perf|power|pmu|edp|vbios|bios|Bmp|dcb|Dcb|Voltage|Pmgr|Budget"
    r"|_BIT|Tgp|Limit)", re.IGNORECASE)


def load_symbols():
    out = subprocess.run(["nm", "--defined-only", "-S", BIN],
                         capture_output=True, text=True, check=True).stdout
    syms = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        try:
            if len(parts) == 4:
                syms.append((int(parts[0], 16), int(parts[1], 16), parts[2], parts[3]))
            elif len(parts) == 3:
                syms.append((int(parts[0], 16), 0, parts[1], parts[2]))
        except ValueError:
            continue
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
                        offset=off, size=size))
    strtab_off = raw[e_shstrndx]["offset"]
    for s in raw:
        end = buf.index(b"\x00", strtab_off + s["nameoff"])
        s["name"] = buf[strtab_off + s["nameoff"]:end].decode("ascii", "replace")
    return raw


def sym_of(syms, off):
    best = None
    for val, size, typ, name in syms:
        if val <= off:
            span = size if size else 1
            if val + span > off:
                return (name, val, size, typ, "exact")
            if best is None or val > best[1]:
                best = (name, val, size, typ, "nearest")
    return best


def scan_text():
    hits = []
    cur_fn = None
    window, order = {}, []
    p = subprocess.Popen(["objdump", "-d", "--no-show-raw-insn", BIN],
                         stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
    for line in p.stdout:
        m = re.match(r"^([0-9a-f]+) <([^>]+)>:\s*$", line)
        if m:
            cur_fn = m.group(2)
            continue
        m = re.match(r"^\s+([0-9a-f]+):\t(.*)$", line)
        if not m:
            continue
        addr, text = int(m.group(1), 16), m.group(2).strip()
        window[addr] = (cur_fn, text)
        order.append(addr)
        for im in re.findall(r"\$(-?0x[0-9a-f]+)", text):
            try:
                v = int(im, 16) & 0xFFFFFFFF
            except ValueError:
                continue
            for name, tv in TARGETS_U32.items():
                if v == tv:
                    hits.append(dict(section=".text", addr=addr, fn=cur_fn,
                                     insn=text, value=name, kind="imm"))
    p.wait()
    return hits, window, order


def needle_find(data, needle):
    """all offsets of needle in data (bytes.find loop — C speed)."""
    offs = []
    i = data.find(needle)
    while i != -1:
        offs.append(i)
        i = data.find(needle, i + 1)
    return offs


def scan_data(secs, syms):
    buf = open(BIN, "rb").read()
    results = []
    for s in secs:
        if s["type"] != 1 or s["name"] not in (".data", ".rodata"):
            continue
        data = buf[s["offset"]:s["offset"] + s["size"]]
        for name, tv in TARGETS_U32.items():
            needle = struct.pack("<I", tv)
            for off in needle_find(data, needle):
                results.append(dict(section=s["name"], off=off,
                                    value=name, kind="u32"))
        for name, tv in TARGETS_F32.items():
            needle = struct.pack("<f", tv)
            for off in needle_find(data, needle):
                results.append(dict(section=s["name"], off=off,
                                    value=name, kind="f32"))
    for r in results:
        sm = sym_of(syms, r["off"])
        r["symbol"] = {"name": sm[0], "value": sm[1], "size": sm[2],
                       "type": sm[3], "match": sm[4]} if sm else None
    return results


def triple_detector(secs):
    """{100000,240000,250000} within +/-64 B in any data section."""
    buf = open(BIN, "rb").read()
    needles = {"100000": struct.pack("<I", 0x186A0),
               "240000": struct.pack("<I", 0x3A980),
               "250000": struct.pack("<I", 0x3D090)}
    found = []
    for s in secs:
        if s["type"] != 1 or s["name"] not in (".data", ".rodata"):
            continue
        data = buf[s["offset"]:s["offset"] + s["size"]]
        for name, nd in needles.items():
            for off in needle_find(data, nd):
                lo, hi = max(0, off - 64), min(len(data) - 4, off + 64)
                win = data[lo:hi + 4]
                has = set()
                for n2, nd2 in needles.items():
                    if nd2 in win:
                        has.add(n2)
                if len(has) >= 2:
                    found.append(dict(section=s["name"], off=off,
                                      first=name, members=sorted(has)))
    return found


def main():
    buf = open(BIN, "rb").read()
    secs = load_sections(buf)
    syms = load_symbols()
    funcs = [(v, sz, n) for (v, sz, t, n) in syms if t in "Tt"]
    power_fns = sorted((v, sz, n) for (v, sz, n) in funcs if POWER_RE.search(n))
    print(f"sections={len(secs)} syms={len(syms)} funcs={len(funcs)} "
          f"power-fns={len(power_fns)}")

    hits, window, order = scan_text()
    print(f".text imm hits: {len(hits)}")
    for h in hits:
        print("   ", h["addr"], h["fn"], "::", h["insn"][:80])

    data_hits = scan_data(secs, syms)
    from collections import Counter
    c = Counter((r["value"], r["kind"]) for r in data_hits)
    print("data hits:", dict(c))

    triples = triple_detector(secs)
    print(f"TRIPLE hits (>=2 members within 64 B): {len(triples)}")
    for t in triples[:20]:
        sm = sym_of(syms, t["off"])
        print("   ", t["section"], hex(t["off"]), t["members"],
              "sym:", sm[0] if sm else None)

    power_hits = [h for h in hits if POWER_RE.search(h["fn"] or "")]

    out = {
        "substrate": {"path": BIN, "size": len(buf),
                      "sha256": "c90f58d59e8fef44fa07d057bd9ffb1e1b5ee38d3c51b35df71e05e0ad268cbf",
                      "package_sha256": "b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d"},
        "text_imm_hits": hits,
        "data_hits_count": {f"{k[0]}|{k[1]}": v for k, v in c.items()},
        "data_hits_sample": data_hits[:400],
        "triple_hits": triples,
        "power_fn_count": len(power_fns),
        "power_fn_imm_hits": power_hits,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
