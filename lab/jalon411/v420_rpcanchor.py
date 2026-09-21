#!/usr/bin/env python3
"""4.20 pass — the RPC anchor lane: the static ID->handler anchors of the
GSP-RM control interface.

The 4.19 wall: the dispatch graph is runtime-bound end to end (0 named
targets in 3,542 slot fills). But the RM implements a PROTOCOL: the host
driver sends control commands with PUBLIC ids (the open kernel modules
headers, FINN-generated, 610.57.04), and the RM must dispatch them by id —
an id-keyed structure is static and survives the runtime-bind.

The anchors (src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080internal.h):
  0x20800ad0 PMGR_PFM_REQ_HNDLR_UPDATE_EDPP_LIMIT   {bEnable, clientLimit}
  0x20800afd PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO {limitMin/Rated/Max/
               Curr/BattRated/BattMax}
  0x20800ad1 THERM_PFM_REQ_HNDLR_UPDATE_TGPU_LIMIT (the TGPU twin)
  0x20800112 GPU_SET_POWER
  0x2080205a/0x2080205b PERF GET/SET POWERSTATE
The INTERNAL interface family = 0x20800a00..0x20800aff (id low byte =
the FINN message id).

The three dispatch shapes a firmware can use, each scanned:
  A. key tables     — raw dwords equal to command ids (dense id runs)
  B. jump tables    — dense runs of in-image code pointers indexed by id
  C. compare chains — `li` of full ids via lui(HI)+addi in code, several
                      in one region = the switch; isolated = asserts

Layers:
  0. fingerprint (the 4.14+ invariant: ONE RWX LOAD, filesz==memsz, shnum=0)
  1. the id inventory from the headers of THIS driver (generated, not typed)
  2. data scan (shape A) + jump-table scan (shape B)
  3. code scan: lui fields 0x20800/0x20801 paired with the next-instruction
     addi/addiw — the full 0x20800000..0x20801fff constant population (shape C)
  4. every hit cross-checked against the 4.16 boundary-verified map

Output: lab/jalon411/v420_rpcanchor.json (+ the console summary)
"""
import json
import struct
import zlib
from bisect import bisect_right
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/analysis/gsp-extract/rm-full.elf"
MAP = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/lab/jalon411/v416_map.bin"
HEADERS = "/usr/src/nvidia-610.57.04/src/common/sdk/nvidia/inc/ctrl"
OUT = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/lab/jalon411/v420_rpcanchor.json"

IMG_LO = 0x1000000
INT_LO, INT_HI = 0x20800A00, 0x20800AFF          # the INTERNAL family
NAMED = {                                        # the header anchors
    0x20800AD0: "PMGR_PFM_REQ_HNDLR_UPDATE_EDPP_LIMIT",
    0x20800AFD: "PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO",
    0x20800AD1: "THERM_PFM_REQ_HNDLR_UPDATE_TGPU_LIMIT",
    0x20800112: "GPU_SET_POWER",
    0x2080205A: "PERF_GET_POWERSTATE",
    0x2080205B: "PERF_SET_POWERSTATE",
}
JUMPTABLE_MIN = 8                                # consecutive code dwords
CODE_L, CODE_H = IMG_LO, IMG_LO + 0xE9B000


def load():
    d = open(SUBSTRATE, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_shnum = struct.unpack_from("<H", d, 60)[0]
    fingerprint = {"size": len(d), "e_shnum": e_shnum, "loads": []}
    img = None
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if p_type == 1:
            fingerprint["loads"].append(
                {"off": p_off, "vaddr": p_vaddr, "filesz": p_filesz,
                 "memsz": p_memsz, "flags": p_flags})
            if p_filesz == p_memsz and (p_flags & 7) == 7:
                img = (d[p_off:p_off + p_filesz], p_vaddr)
    assert e_shnum == 0 and img and img[1] == IMG_LO, "fingerprint drift"
    return img[0], fingerprint


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


def inventory_ids():
    """The FINN command ids from THIS driver's headers (generated, exact)."""
    import os
    ids = {}
    for root, _, files in os.walk(HEADERS):
        for f in files:
            if not f.endswith(".h"):
                continue
            try:
                txt = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for line in txt.splitlines():
                if "#define NV2080_CTRL_CMD_" not in line or "(" not in line:
                    continue
                name = line.split("#define", 1)[1].split("(", 1)[0].strip()
                for tok in line.split():
                    tok = tok.strip(")")
                    if tok.startswith("0x2") and len(tok) == 10:
                        ids.setdefault(int(tok, 16), []).append(name)
    return ids


def main():
    code, fingerprint = load()
    n = len(code)
    seen, covered = load_map()
    reg_starts, reg_ends = build_regions(covered)

    def region_of(off):
        k = bisect_right(reg_starts, off) - 1
        if k >= 0 and reg_starts[k] <= off < reg_ends[k]:
            return (reg_starts[k], reg_ends[k])
        return None

    def verified(off):
        s = off >> 1
        return bool(seen[s]) if 0 <= s < len(seen) else False

    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    # ---- layer 1: the id inventory
    ids = inventory_ids()
    inv = {f"0x{k:08x}": (len(v), v[0]) for k, v in sorted(ids.items())
           if 0x20800000 <= k <= 0x2081FFFF}
    inv_named = {f"0x{k:08x}": v[0] for k, v in ids.items()
                 if k in NAMED and k in ids}

    # ---- layer 2: shape A (id key tables) + shape B (jump tables)
    ndw = n // 4
    words = struct.unpack_from(f"<{ndw}I", code, 0)

    key_hits = defaultdict(list)      # id -> [offsets]
    for i, w in enumerate(words):
        if INT_LO <= w <= INT_HI or w in NAMED:
            key_hits[w].append(i * 4)

    jt_runs = []                      # runs of consecutive code-point dwords
    i = 0
    while i < ndw:
        if CODE_L <= words[i] < CODE_H:
            j = i
            while j < ndw and CODE_L <= words[j] < CODE_H:
                j += 1
            if j - i >= JUMPTABLE_MIN:
                jt_runs.append((i * 4, j * 4, j - i))
            i = j
        else:
            i += 1

    # ---- layer 3: shape C (the li population 0x20800000..0x20801fff)
    li_hits = defaultdict(list)       # value -> [(off, hi, lo, reg)]
    for off in range(0, n - 6, 2):
        w = words[off >> 2] if (off & 3) == 0 else None
        if w is None:
            continue
        if (w & 0x7F) != 0x37:        # lui opcode
            continue
        hi = (w >> 12) & 0xFFFFF
        if hi not in (0x20800, 0x20801):
            continue
        rd = (w >> 7) & 0x1F
        # the paired addi/addiw: next 4 bytes
        w2 = struct.unpack_from("<I", code, off + 4)[0]
        lo = (w2 >> 20) - (1 << 12) if (w2 >> 20) >= 0x800 else (w2 >> 20)
        if (w2 & 0x7F) not in (0x13, 0x1B) or ((w2 >> 7) & 0x1F) != rd:
            continue
        val = (hi << 12) + lo
        if 0x20800000 <= val <= 0x20801FFF:
            li_hits[val].append({"off": off, "hi": hi, "lo": lo,
                                 "verified": verified(off)})

    # ---- assemble
    out = {
        "fingerprint": fingerprint,
        "inventory_2080_ids": {"count": len(inv), "named": inv_named,
                               "internal_family": {
                                   f"0x{v:08x}": (ids[v][0] if v in ids else "?")
                                   for v in range(INT_LO, INT_HI + 1) if v in ids}},
        "shapeA_key_tables": {
            f"0x{v:08x}": [{"off": o, "va": IMG_LO + o, "verified": verified(o),
                            "region": region_of(o) and [IMG_LO + region_of(o)[0],
                                                        IMG_LO + region_of(o)[1]]}
                           for o in offs[:64]]
            for v, offs in sorted(key_hits.items())},
        "shapeB_jump_tables": [
            {"off": a, "va": IMG_LO + a, "entries": c, "span_end": IMG_LO + b,
             "head": [hex(words[(a >> 2) + k]) for k in range(min(6, c))]}
            for a, b, c in jt_runs[:200]],
        "shapeC_li_population": {
            f"0x{v:08x}": {"sites": len(sites), "named": NAMED.get(v),
                           "all_verified": all(s["verified"] for s in sites),
                           "hits": sites[:32]}
            for v, sites in sorted(li_hits.items())},
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)

    # ---- summary
    print(f"fingerprint: {fingerprint['size']} B, shnum={fingerprint['e_shnum']}, "
          f"{len(fingerprint['loads'])} LOAD(s) {[hex(l['vaddr']) for l in fingerprint['loads']]}")
    print(f"inventory: {len(inv)} ids in the 0x2080 space "
          f"({sum(1 for k in ids if INT_LO <= k <= INT_HI)} INTERNAL family)")
    print(f"shape A (id key dwords): {len(key_hits)} distinct values, "
          f"{sum(len(v) for v in key_hits.values())} sites")
    for v, offs in sorted(key_hits.items()):
        tag = NAMED.get(v, ids.get(v, ["?"])[0])
        print(f"   0x{v:08x} {tag}: {len(offs)} site(s) at "
              f"{[hex(IMG_LO + o) for o in offs[:8]]}")
    print(f"shape B (jump tables >= {JUMPTABLE_MIN} code dwords): {len(jt_runs)} runs "
          f"(total {sum(c for _, _, c in jt_runs)} entries)")
    for a, b, c in jt_runs[:12]:
        print(f"   va 0x{IMG_LO + a:x}..0x{IMG_LO + b:x} ({c} entries)")
    print(f"shape C (li constants in 0x2080_0000..0x2081_ffff): "
          f"{len(li_hits)} values, {sum(len(s) for s in li_hits.values())} sites")
    for v, sites in sorted(li_hits.items()):
        tag = NAMED.get(v) or (ids.get(v, ["?"])[0] if v in ids else "?")
        va = f"all-verified" if all(s["verified"] for s in sites) else "partly-unverified"
        print(f"   0x{v:08x} {tag}: {len(sites)} site(s), {va}")


if __name__ == "__main__":
    main()
