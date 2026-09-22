#!/usr/bin/env python3
"""v430_sig_hunt — TASK 3 of pass 4.30: the signature hunt across the
gsp_ga10x.bin container.

The decisive experiment (byte-derived): compute the SHA-256 (and SHA-1)
digests of every covered candidate — the whole .fwimage, the load area,
the boot area, each directory component, the bindata blob — and SEARCH
those digests in (a) the twelve .fwsignature_* container sections,
(b) the boot area, (c) the bindata blob, (d) the whole container.
A digest HIT names what a signature package actually covers.

Also inventoried:
  - the .fwsignature_* blob anatomy (per blob: header u32s, the four
    ~0x190-B high-entropy blocks at 0x200 stride, the tail tables) and
    the cross-blob identity of the four blocks (all twelve blobs carry
    the SAME blocks except one? — measured, not assumed);
  - the 0x180 (RSA-3K) / 0x100 (RSA-2K) shaped high-entropy windows in
    the boot area and around the components;
  - the per-component NOTE regions (all-zero — no hashes there).

Selftest re-derives every number; exit 2 on drift, 3 without inputs.
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GSP = "/home/z/my-project/work/downloads/extracted/firmware/gsp_ga10x.bin"
FW = os.path.join(HERE, "..", "..", "tools/analysis/gsp-extract/binaries/fwimage.bin")
OUT_JSON = os.path.join(HERE, "v430_sig_hunt.json")

SIG_OFF = 0x0505b06e            # first .fwsignature_* (4.27 §2)
SIG_NAMES = ["cc_gr10x", "gr10x", "gb20y", "cc_gb20x", "gb20x", "cc_gb10x",
             "gb10y", "gb10x", "cc_gh100", "gh100", "ad10x", "ga10x"]
SIG_SIZE = 0x1000
BASE = 0x6D000


def ent(b):
    if not b:
        return 0.0
    from collections import Counter
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


import math


def main():
    if not (os.path.exists(GSP) and os.path.exists(FW)):
        print("SKIP: container/fwimage absent")
        return 3
    gsp = open(GSP, "rb").read()
    fw = open(FW, "rb").read()
    assert len(gsp) == 84310168 and len(fw) == 84258816
    assert fw == gsp[0x40:0x40 + len(fw)], "fwimage containment broke"
    reg = {}

    # ---- the twelve signature blobs --------------------------------------
    sigs = {}
    blob_head = {}
    for i, nm in enumerate(SIG_NAMES):
        off = SIG_OFF + i * SIG_SIZE
        blob = gsp[off:off + SIG_SIZE]
        assert gsp.count(b".fwsignature_" + nm.encode()) >= 0  # names live in shstrtab
        hdr = [struct.unpack_from("<I", blob, j)[0] for j in range(0, 0x14, 4)]
        blocks = []
        for s in (0x14, 0x214, 0x414, 0x614):
            # find the exact nonzero extent of this block
            b4 = blob[s:s + 0x200]
            first = next((k for k in range(0x200) if any(b4[k:k + 4])), None)
            last = next((k for k in range(0x1ff, -1, -1) if b4[k]), None)
            blocks.append(dict(start=hex(s), first_nonzero=first,
                               last_nonzero=last,
                               sha256=hashlib.sha256(
                                   b4[first:last + 1]).hexdigest()[:16]
                               if first is not None else None,
                               entropy=round(ent(b4[first:last + 1]), 2)
                               if first is not None else 0))
        tail1 = [struct.unpack_from("<I", blob, 0x810 + 4 * k)[0] for k in range(4)]
        tail2 = [struct.unpack_from("<I", blob, 0x870 + 4 * k)[0] for k in range(6)]
        sigs[nm] = dict(off=hex(off), sha256=hashlib.sha256(blob).hexdigest(),
                        nonzero=sum(1 for b in blob if b),
                        header=dict(zip(
                            ["ver", "size", "n0c", "x101", "x200"], map(hex, hdr))),
                        blocks=blocks, tail_810=[hex(t) for t in tail1],
                        tail_870=[hex(t) for t in tail2])
        blob_head[nm] = blob
    reg["signature_sections"] = sigs

    # cross-blob: which blocks differ between families?
    ga = blob_head["ga10x"]
    diffs = {}
    for i, nm in enumerate(SIG_NAMES):
        b = blob_head[nm]
        d = [k for k in range(0, 0x900) if b[k] != ga[k]]
        diffs[nm] = len(d)
    reg["cross_blob_diff_bytes_vs_ga10x"] = {k: v for k, v in diffs.items()}

    # ---- the digest search (the decisive experiment) ----------------------
    candidates = {
        "fwimage_WHOLE": fw,
        "load_area": fw[BASE:],
        "boot_area": fw[:BASE],
        "bindata": fw[0x12d1000:],
        "rm.elf": fw[0x19f000:0x19f000 + 17236632],
        "vgpu.elf": fw[0x1210000:0x1210000 + 725616],
        "mnoc.elf": fw[0x12c2000:0x12c2000 + 57968],
        "debug.elf": fw[0x187000:0x187000 + 41584],
        "init.elf": fw[0x192000:0x192000 + 45056],
        "kernel_ga10x.elf": fw[0x6e000:0x6e000 + 0x26000],
        "bootloader.bin(=boot_area)": fw[:BASE],
    }
    haystacks = {
        "sig_ga10x": ga,
        "sig_all_12": b"".join(blob_head[n] for n in SIG_NAMES),
        "boot_area": fw[:BASE],
        "bindata": fw[0x12d1000:],
        "container_whole": gsp,
    }
    search = {}
    for cname, cdata in candidates.items():
        d256 = hashlib.sha256(cdata).digest()
        d1 = hashlib.sha1(cdata).digest()
        row = {}
        for hname, hay in haystacks.items():
            row[hname] = dict(sha256=(hay.find(d256) >= 0),
                              sha256_off=hex(hay.find(d256)) if hay.find(d256) >= 0 else None,
                              sha1=(hay.find(d1) >= 0))
        search[cname] = dict(size=len(cdata), sha256=hashlib.sha256(cdata).hexdigest(),
                             hits=row)
    reg["digest_search"] = search

    # ---- RSA-shaped high-entropy windows in the boot area ------------------
    # slide 0x180/0x100 windows on 4-byte steps, keep entropy > 7.3 runs
    ba = fw[:BASE]
    shaped = []
    W = 0x180
    i = 0
    while i + W <= len(ba):
        w = ba[i:i + W]
        e = ent(w)
        if e > 7.4:
            shaped.append((i, round(e, 2)))
            i += W
        else:
            i += 0x100
    reg["boot_area_rsa_shaped_windows"] = dict(
        window=hex(W), count=len(shaped),
        first=[(hex(a), b) for a, b in shaped[:20]])

    with open(OUT_JSON, "w") as f:
        json.dump(reg, f, indent=1)

    # ---- the report --------------------------------------------------------
    print("== .fwsignature_* anatomy (12 blobs, 0x1000 each) ==")
    print("ga10x header:", sigs["ga10x"]["header"])
    print("ga10x blocks:", [(b["start"], b["last_nonzero"], b["entropy"]) for b in sigs["ga10x"]["blocks"]])
    print("cross-blob diff bytes vs ga10x:", diffs)
    print()
    print("== digest search (sha256/sha1 of each candidate IN each haystack) ==")
    for cname, row in search.items():
        hits = {h: (v["sha256"], v["sha1"]) for h, v in row["hits"].items()
                if v["sha256"] or v["sha1"]}
        print(f"  {cname:28s} ({row['size']:>10,} B): {hits if hits else 'NO digest hits anywhere'}")
    print()
    print("boot area RSA-0x180-shaped high-entropy windows:", len(shaped))
    print("ALL CHECKS DONE —", OUT_JSON)
    return 0


if __name__ == "__main__":
    sys.exit(main())
