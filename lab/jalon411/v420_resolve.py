#!/usr/bin/env python3
"""4.20 pass II — the RPC dispatch table resolver.

v420_rpcanchor.py found the shape-A table: dense id keys at 0x20 stride
(first entry 0x1c197b8, the INTERNAL family 0x20800aXX). Entry layout
(byte-exact from the dump):
  +0x00 u32 id          — the FINN command id (0x2080xxxx)
  +0x04 u32 tag         — varies (0x10c, 0x102, 0x101... = payload class?)
  +0x08 u64 pA          — COMMON across the family (a shared descriptor)
  +0x10 u64 pB          — VARIES per entry = the HANDLER
  +0x18 u32 sz0 / u32 sz1 — the payload sizes (0xc0/0x80...)

This script:
  1. finds every 0x20-stride id table (any 0x2080xxxx family, >= 4 entries)
  2. parses the entries; classifies the pointers (code/data, in-image)
  3. cross-checks every handler against the 4.16 boundary-verified map
  4. names the ids from THIS driver's FINN headers (exact regex)
  5. flags the EDPp handlers (0x20800ad0 / 0x20800afd) for the walk

Output: lab/jalon411/v420_resolve.json
"""
import json
import os
import re
import struct
import zlib
from bisect import bisect_right

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/tools/analysis/gsp-extract/rm-full.elf"
MAP = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/lab/jalon411/v416_map.bin"
HEADERS = "/usr/src/nvidia-610.57.04/src/common/sdk/nvidia/inc/ctrl"
OUT = "/run/media/cheurteen/Jeux SSD/Reverse Engenering/gpu-lab/lab/jalon411/v420_resolve.json"

IMG_LO = 0x1000000
STRIDE = 0x20
EDPP = {0x20800AD0: "UPDATE_EDPP_LIMIT", 0x20800AFD: "GET_EDPP_LIMIT_INFO"}


def load():
    d = open(SUBSTRATE, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", d, o)
        if p_type == 1:
            p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
            if p_filesz == p_memsz:
                return d[p_off:p_off + p_filesz]
    raise SystemExit("no image")


def load_map():
    blob = zlib.decompress(open(MAP, "rb").read())
    half = len(blob) // 2
    return blob[:half], blob[half:]


def build_regions(covered):
    starts, ends = [], []
    i, n = 0, len(covered)
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


def inventory():
    """name -> id, exact FINN defines from THIS driver."""
    pat = re.compile(r"#\s*define\s+(NV2080_CTRL_CMD_\w+)\s+\((0x[0-9A-Fa-f]+)U?\)")
    out = {}
    for root, _, files in os.walk(HEADERS):
        for f in files:
            if not f.endswith(".h"):
                continue
            try:
                txt = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for name, val in pat.findall(txt):
                out.setdefault(int(val, 16), name)
    return out


def main():
    img = load()
    n = len(img)
    ndw = n // 4
    words = struct.unpack_from(f"<{ndw}I", img, 0)
    seen, covered = load_map()
    reg_starts, reg_ends = build_regions(covered)
    names = inventory()

    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

    def verified(off):
        s = off >> 1
        return bool(seen[s]) if 0 <= s < len(seen) else False

    def region_of(off):
        k = bisect_right(reg_starts, off) - 1
        if k >= 0 and reg_starts[k] <= off < reg_ends[k]:
            return (reg_starts[k], reg_ends[k])
        return None

    def prologue_score(va):
        """Is the target a function prologue? (the 4.16 tier: addi sp / c.addi16sp + ra store)"""
        off = va - IMG_LO
        if off < 0 or off + 8 > n:
            return "out"
        try:
            ins = list(md.disasm(img[off:off + 16], va))
        except Exception:
            return "undecodable"
        if not ins:
            return "undecodable"
        m0 = ins[0].mnemonic
        ops0 = ins[0].op_str
        if m0 in ("addi",) and ops0.startswith("sp, sp, -"):
            return "prologue(addi-sp)"
        if m0 == "c.addi16sp":
            return "prologue(c.addi16sp)"
        return f"mid({m0} {ops0[:20]})"

    # ---- 1. the tables: every dword in [0x20800000,0x20810000) at a 0x20
    #         stride with >=4 consecutive matching ids at entry+0
    tables = []
    visited = set()
    for i in range(ndw):
        off = i * 4
        if off in visited:
            continue
        w = words[i]
        if not (0x20800000 <= w <= 0x20810000):
            continue
        # walk back to the table head
        head = off
        while head - STRIDE >= 0:
            prev = words[(head - STRIDE) >> 2]
            if 0x20800000 <= prev <= 0x20810000 and head - STRIDE not in visited:
                head -= STRIDE
            else:
                break
        if head in visited:
            continue
        # walk forward counting entries
        cnt = 0
        cur = head
        while cur + STRIDE <= n:
            v = words[cur >> 2]
            if not (0x20800000 <= v <= 0x20810000):
                break
            visited.add(cur)
            cur += STRIDE
            cnt += 1
        if cnt >= 4:
            tables.append((head, cur, cnt))
    tables.sort()

    # ---- 2/3/4. parse, verify, name
    result = []
    for head, end, cnt in tables:
        entries = []
        pA_hist = {}
        for cur in range(head, end, STRIDE):
            id_lo, tag = words[cur >> 2], words[(cur >> 2) + 1]
            pA, pB = struct.unpack_from("<QQ", img, cur + 8)
            sz0, sz1 = words[(cur >> 2) + 6], words[(cur >> 2) + 7]
            pA_hist[pA] = pA_hist.get(pA, 0) + 1
            h_va = pB
            h_off = h_va - IMG_LO if pB else -1
            in_img = IMG_LO <= h_va < IMG_LO + n if pB else False
            e = {
                "id": f"0x{id_lo:08x}",
                "name": names.get(id_lo),
                "edpp": EDPP.get(id_lo),
                "tag": f"0x{tag:x}",
                "pA": hex(pA),
                "handler_va": hex(h_va) if pB else None,
                "handler_verified": verified(h_off) if in_img else None,
                "handler_prologue": prologue_score(h_va) if in_img else "null/other",
                "handler_region": region_of(h_off) if in_img else None,
                "sz0": sz0, "sz1": sz1,
            }
            entries.append(e)
        result.append({
            "va": hex(IMG_LO + head), "end": hex(IMG_LO + end), "count": cnt,
            "id_range": [entries[0]["id"], entries[-1]["id"]],
            "entries": entries,
            "pA_common": {hex(k): v for k, v in pA_hist.items()},
            "named_count": sum(1 for e in entries if e["name"]),
            "verified_count": sum(1 for e in entries if e["handler_verified"]),
            "entries": entries,
        })

    with open(OUT, "w") as f:
        json.dump(result, f, indent=1)

    # ---- summary
    tot = sum(r["count"] for r in result)
    print(f"tables found: {len(result)}, total entries {tot}")
    for r in result:
        print(f"\n=== table @va {r['va']}..{r['end']} — {r['entries']} entries, "
              f"ids {r['id_range'][0]}..{r['id_range'][-1]} ===")
        print(f"    pA common: {r['pA_common']}; named {r['named_count']}/{r['entries']}; "
              f"handlers boundary-verified {r['verified_count']}/{r['entries']}")
        for e in r["entries"]:
            mark = ""
            if e["edpp"]:
                mark = "  <<< EDPp ANCHOR"
            elif e["name"]:
                mark = ""
            if e["edpp"] or (e["name"] and "EDPP" not in (e["name"] or "")):
                pass
            if e["edpp"]:
                print(f"    {e['id']} {e['name'] or e['edpp']} -> handler {e['handler_va']} "
                      f"[{e['handler_prologue']}] tag {e['tag']} sz0 {e['sz0']}{mark}")
        # the first few entries as a shape sample
        for e in r["entries"][:4]:
            print(f"    sample: {e['id']} ({e['name'] or '?'}) -> {e['handler_va']} "
                  f"[{e['handler_prologue']}] tag {e['tag']} sz0 {e['sz0']} sz1 {e['sz1']}")


if __name__ == "__main__":
    main()
