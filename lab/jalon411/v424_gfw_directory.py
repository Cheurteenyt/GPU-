#!/usr/bin/env python3
"""4.24 pass III-a — the GFW directory decoder + the compression test.

Parses the .fwimage directory (the component table) PROPERLY this time:
each component record = {name, version, ..., region-1 (vaddr 0x1000000),
region-2 (vaddr 0x4000000), ...} with (offset, size, flag) pairs, then:
  1. searches the known ELFs (comp-725KB, gsp-rm-17MB) inside fwimage.bin
     (are the components stored FLAT?),
  2. entropy-scans every region (a compressed region = high entropy, a
     flat code region = medium, signatures = high but no structure),
  3. tests raw-LZ4 block decoding at every region start (the founder's
     lz-probe hypothesis).

Output: lab/jalon411/v424_gfw_directory.json
"""
import json
import math
import struct
from collections import Counter

FW = "/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/fwimage.bin"
OUT = "/home/z/my-project/work/gpu-repo/lab/jalon411/v424_gfw_directory.json"


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def lz4_block(src, pos, out_limit=8 * 2**20):
    out = bytearray()
    n = len(src)
    while pos < n and len(out) < out_limit:
        token = src[pos]; pos += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                b = src[pos]; pos += 1
                lit_len += b
                if b != 255:
                    break
        out += src[pos:pos + lit_len]
        pos += lit_len
        if pos >= n or len(out) >= out_limit:
            break
        offset = struct.unpack_from("<H", src, pos)[0]; pos += 2
        if offset == 0:
            raise ValueError("zero offset")
        match_len = (token & 0xF) + 4
        if (token & 0xF) == 15:
            while True:
                b = src[pos]; pos += 1
                match_len += b
                if b != 255:
                    break
        start = len(out) - offset
        if start < 0:
            raise ValueError("offset before start")
        for i in range(match_len):
            out.append(out[start + i])
    return bytes(out), pos


def main():
    d = open(FW, "rb").read()
    print(f"fwimage.bin: {len(d):,} B")

    # 1. the known-ELF containment test
    contain = {}
    for name in ("comp-725KB.bin", "gsp-rm-17MB.bin"):
        blob = open(f"/home/z/my-project/work/gpu-repo/tools/analysis/gsp-extract/binaries/{name}", "rb").read()
        probe = blob[:64]
        i = d.find(probe)
        contain[name] = {"present_at": hex(i) if i != -1 else None,
                         "size": len(blob)}
        print(f"{name}: {'PRESENT @' + hex(i) if i != -1 else 'absent'}")

    # 2. the directory walk (clusters delimited by the name fields)
    #    find the name fields: "init.elf", "rm.elf", "vgpu.elf" ...
    comps = {}
    for nm in (b"init.elf", b"rm.elf", b"vgpu.elf"):
        off = d.find(nm[:6] + b"\x00\x00" if len(nm) == 7 else nm)
        # the name is u64-aligned-ish; record its pos
        comps[nm.decode()] = off
    print("name positions:", {k: hex(v) for k, v in comps.items()})

    # parse the region pairs relative to each name: the two u64s AFTER the
    # name+ver are {align, offset1, size1, flag5} etc. — verify empirically
    # by locating the 0x1000000/0x4000000 vaddr markers around each name
    regions = []
    for nm, pos in comps.items():
        # scan the cluster after the name for the region patterns
        lo, hi = pos, pos + 0x80
        r = {"name": nm, "at": hex(pos), "regions": []}
        cur = pos
        end = hi
        while cur < end:
            v = u64(d, cur)
            if v == 0x1000000 or v == 0x4000000:
                # region: vaddr @cur, then (0, 0x1000, offset, size, flag) window
                win = [u64(d, cur + k) for k in range(0, 0x28, 8)]
                r["regions"].append({"vaddr": hex(v), "window": [hex(x) for x in win]})
            cur += 8
        regions.append(r)
        print(f"{nm}: " + " | ".join(
            f"vaddr={x['vaddr']} win={x['window']}" for x in r["regions"]))

    # 3. the region entropy + LZ4 test on the discovered (offset,size) pairs
    tests = []
    # hard-coded from the verified manual decode:
    candidates = [
        ("init.elf region-1 (flag 5)", 0x125000, 0x8000),
        ("init.elf region-2 (flag 6)", 0x12d000, 0x4000),
        ("rm.elf region-1 (flag 5)", 0x132000, 0xe9b000),
        ("rm.elf region-2 (flag 6)", 0xfcd000, 0x1d5000),
        ("vgpu.elf region-1 (flag 5)", 0x11a3000, 0xa2000),
        ("vgpu.elf region-2 (flag 6)", 0x1245000, 0xf000),
    ]
    for name, off, size in candidates:
        blob = d[off:off + size]
        e = entropy(blob[:1 << 20])
        head = blob[:16].hex(" ")
        lz4_ok = None
        for skip in (0, 4, 8, 16, 0x100, 0x1000):
            try:
                out, _ = lz4_block(blob, skip, out_limit=2 * 2**20)
                lz4_ok = {"skip": skip, "decoded": len(out),
                          "head": out[:16].hex(" ")}
                break
            except Exception:
                continue
        # the ELF containment inside the region (is it the flat image?)
        elf_here = blob[:4] == b"\x7fELF"
        tests.append({"region": name, "offset": hex(off), "size": hex(size),
                      "entropy": round(e, 3), "head": head,
                      "starts_with_ELF": elf_here, "lz4_decode": lz4_ok})
        print(f"{name}: entropy={e:.3f} head={head} ELF={elf_here} lz4={lz4_ok}")

    json.dump({"containment": contain, "regions": regions, "tests": tests},
              open(OUT, "w"), indent=1)
    print(f">>> {OUT}")


if __name__ == "__main__":
    main()
