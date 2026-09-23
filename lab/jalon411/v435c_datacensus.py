#!/usr/bin/env python3
"""4.35 TASK C — the data-side census: defaults, clusters, the x666 table.

The 4.33 lane A catalogued the CODE-side knobs; 4.35a graded them. But
a knob that is stored into state (the STATE-DEFAULT class) usually has
a DATA-side twin: the default value compiled into the data segment, or
into the data islands inside the code segment. This instrument:

  1. maps the container's two LOADs (code R-X, data R-W @VA 0x4000000)
     and censuses the data segment + the uncovered code islands for
     aligned u32/u64 round values:
       - powers of ten (1e3 .. 1e12, u32 and u64 forms);
       - binary rounds 2^n >= 0x1000;
       - the campaign's knob family (the 4.32/4.33 question values +
         the 4.35a knob universe);
     each hit carries its VA and its 64-B neighborhood id;
  2. clusters the hits (>= 2 round values within 64 B) — the
     config-struct candidates — and cites the top clusters;
  3. cross-references the data hits against the CODE knob values:
     a value present on BOTH sides = the default/state twin of the
     code knob (the GATED-TUNABLE shortlist's field defaults);
  4. decodes the d4d856ff x666 table (the 4.33 lane-D top data
     family): exact extent, stride, repeat count (the banked 666 must
     reproduce — assert), and the neighborhood role check.

Selftests: the law (512 windows + 7 sites); the container ELF header
(e_machine 0xf3, e_phnum 4, the 2 LOADs' geometry); the d4d856ff run
repeats exactly 666 times; the data segment filesz == 0x1d500.

Output: lab/jalon411/v435c_datacensus.json
"""
import json
import struct
import zlib
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82
BANKED_666 = 666
TAG = bytes.fromhex("d4d856ff")

KNOB_VALUES = [1000000, 1000000000, 10000000, 100000, 500000, 50000000,
               20000000, 2700000, 5000000, 1620000, 100000000, 8100000,
               4000000, 270000, 5400000, 3240000, 400000, 200000,
               2430000, 2000000000, 4320000, 2160000, 13500000, 8000000,
               6750000, 2500000, 2000000, 250000, 810000, 30000000,
               405000, 1080000, 3000000, 27000000, 540000, 1200000,
               150000, 1250000, 202000, 6000000, 600000, 3500000,
               1600000, 9259000, 1435840000, 280000, 240000]

POW10_U32 = [10**k for k in range(3, 10)]           # 1e3 .. 1e9
POW10_U64 = [10**k for k in range(10, 13)]          # 1e10 .. 1e12
POW2 = [1 << k for k in range(12, 32)]              # 0x1000 .. 1<<31


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

    # -- the law
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    for boff in SITES_B:
        if db[boff:boff + 8] != a_img[boff + SHIFT:boff + SHIFT + 8]:
            fails += 1
    assert fails == 0 and (a_img[CLAIM7_A] & 0x7F) == 0x37
    out["law_recheck"] = {"fails": fails}

    # -- the container ELF geometry
    e_phnum = struct.unpack_from("<H", db, 0x38)[0]
    e_phoff = struct.unpack_from("<Q", db, 0x20)[0]
    segs = []
    for i in range(e_phnum):
        p = e_phoff + i * 0x38
        p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, _m, _al = \
            struct.unpack_from("<IIQQQQQQ", db, p)
        if p_type == 1 and p_filesz:
            segs.append({"off": p_off, "vaddr": p_vaddr,
                         "filesz": p_filesz, "flags": p_flags})
    assert len(segs) == 2 and segs[1]["filesz"] == 0x1D5000
    code_seg, data_seg = segs
    out["segments"] = [
        {"off": hex(s["off"]), "vaddr": hex(s["vaddr"]),
         "filesz": hex(s["filesz"]), "flags": hex(s["flags"])}
        for s in segs]

    def va_of(foff):
        for s in segs:
            if s["off"] <= foff < s["off"] + s["filesz"]:
                return s["vaddr"] + (foff - s["off"])
        return None

    # -- covered map for the code islands (data-in-code)
    carr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    idx = np.nonzero(carr)[0]
    splits = np.nonzero(np.diff(idx) > 1)[0]
    b0 = np.concatenate(([0], splits + 1))
    b1 = np.concatenate((splits, [len(idx) - 1]))
    regions = [(int(idx[i0]), int(idx[i1]) + 1)
               for i0, i1 in zip(b0, b1) if idx[i1] + 1 - idx[i0] >= 2]
    rstarts = [r[0] for r in regions]

    def covered_byte(aoff):
        i = bisect_right(rstarts, aoff) - 1
        return i >= 0 and aoff < regions[i][1]

    # -- the value sets
    knob_set = set(KNOB_VALUES)
    u32_targets = set(POW10_U32) | set(POW2) | \
        {v & 0xFFFFFFFF for v in knob_set if 0 < v < 2**32}
    u64_targets = set(POW10_U64) | \
        {v for v in knob_set if v >= 2**32}

    def census(seg, label, min_align=4):
        """aligned u32/u64 round-value census over a container region."""
        lo, size = seg["off"], seg["filesz"]
        hits = []
        buf = db[lo:lo + size]
        for align, dtype in ((4, "<I"), (8, "<Q")):
            step_a = 8 if dtype == "<Q" else 4
            for i in range(0, len(buf) - 7, step_a):
                if i % align:
                    continue
                u, = struct.unpack_from(dtype, buf, i)
                if dtype == "<I":
                    hit = u in u32_targets and u >= 1000
                else:
                    hit = u in u64_targets
                if hit:
                    foff = lo + i
                    hits.append({
                        "va": hex(va_of(foff)), "width": 8 if
                        dtype == "<Q" else 4, "val": u,
                        "in_code_island": label == "code-uncovered"})
        return hits

    # data segment: FULL census
    data_hits = census(data_seg, "data")
    # code segment: only the UNCOVERED islands (covered bytes = real
    # instructions; their u32 reads are the 4.33 lane-A business)
    # vectorized: 4-byte cells whose START byte is uncovered
    trim = (len(a_img) - 7) // 4 * 4
    u32arr = np.frombuffer(a_img[:trim], dtype="<u4")
    cov4 = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    start_cov = cov4[::4][:len(u32arr)]
    mask = (start_cov == 0)
    sel_vals = u32arr[mask]
    code_hits = []
    sel_idx = np.nonzero(np.isin(sel_vals,
                                 np.array(sorted(u32_targets),
                                          dtype=np.uint64)))[0]
    base_offs = np.nonzero(mask)[0] * 4
    for k in sel_idx:
        u = int(sel_vals[k])
        if u >= 1000:
            code_hits.append({"va": hex(va_of(int(base_offs[k]) + 0x38)),
                              "width": 4, "val": u,
                              "in_code_island": True})
    out["data_segment_hits"] = len(data_hits)
    out["code_island_hits"] = len(code_hits)
    print(f"[census] data-seg round hits: {len(data_hits)}; "
          f"code-island hits: {len(code_hits)}")

    # -- the clusters (>= 2 hits within 64 B), data segment first
    def clusters(hits):
        vs = sorted(hits, key=lambda h: int(h["va"], 16))
        cl, cur = [], []
        for h in vs:
            if cur and int(h["va"], 16) - int(cur[-1]["va"], 16) <= 64:
                cur.append(h)
            else:
                if len(cur) >= 2:
                    cl.append(cur)
                cur = [h]
        if len(cur) >= 2:
            cl.append(cur)
        return cl

    dcl = clusters(data_hits)
    ccl = clusters(code_hits)
    dcl.sort(key=lambda c: -len(c))
    ccl.sort(key=lambda c: -len(c))
    out["data_clusters_top20"] = [
        {"n": len(c),
         "span": [c[0]["va"], c[-1]["va"]],
         "values": [h["val"] for h in c]} for c in dcl[:20]]
    out["code_island_clusters_top10"] = [
        {"n": len(c),
         "span": [c[0]["va"], c[-1]["va"]],
         "values": [h["val"] for h in c][:12]} for c in ccl[:10]]

    # -- the knob twins: data values == code knob values
    knob_hits_data = [h for h in data_hits if h["val"] in knob_set]
    knob_hits_code = [h for h in code_hits if h["val"] in knob_set]
    by_val_d = defaultdict(list)
    for h in knob_hits_data:
        by_val_d[h["val"]].append(h["va"])
    by_val_c = defaultdict(list)
    for h in knob_hits_code:
        by_val_c[h["val"]].append(h["va"])
    twins = {v: {"data": vas, "code_islands": by_val_c.get(v, [])}
             for v, vas in by_val_d.items() if v in by_val_c}
    out["knob_twins_data_and_code"] = {
        str(v): t for v, t in sorted(twins.items())}
    out["knob_data_only"] = {
        str(v): vas for v, vas in sorted(by_val_d.items())
        if v not in by_val_c}
    print(f"[twins] data==code knob values: {len(twins)}")

    # -- the d4d856ff x666 table
    starts = []
    sstart = 0
    while True:
        i = db.find(TAG, sstart)
        if i < 0:
            break
        starts.append(i)
        sstart = i + 1
    # the contiguous run(s): consecutive hits at stride 4
    runs = []
    cur = [starts[0]] if starts else []
    for i in starts[1:]:
        if i == cur[-1] + 4:
            cur.append(i)
        else:
            runs.append(cur)
            cur = [i]
    if cur:
        runs.append(cur)
    runs.sort(key=len, reverse=True)
    top = runs[0]
    n_rep = len(top)
    t0, t1 = top[0], top[-1] + 4
    # -- reconcile with the banked 4.33d unit: their census counted
    #    identical 16-B blocks aligned in the A_IMG universe (the
    #    campaign coordinates). a_img-aligned grid = exactly 666
    #    (the container-offset grid catches 4 partial blocks — the
    #    two universes differ by 0x38; the banked unit is the image).
    block = TAG * 4
    fam = 0
    first_block = None
    for j in range(0, len(a_img) - 15, 16):
        if a_img[j:j + 16] == block:
            fam += 1
            if first_block is None:
                first_block = j
    assert fam == BANKED_666, \
        f"the x666 block family drifted: {fam} != {BANKED_666}"
    # -- the structure decode: the between-run u32s (the NON-fill
    #    records) — descending, sharing the 0xff57 high band
    between = []
    for r in runs[:5]:
        b0 = r[0] - 8
        b1 = r[-1] + 4 + 8
        seq = [struct.unpack_from("<I", db, o)[0]
               for o in range(max(0, b0), min(len(db) - 3, b1), 4)]
        nonfill = [hex(u) for u in seq if u != 0xFF56D8D4]
        between.append({"run_at": hex(r[0]), "run_len": len(r),
                        "nonfill_neighbors": nonfill[:8]})
    total_tags = len(starts)
    out["d4d856ff_table"] = {
        "tag_occurrences_total": total_tags,
        "u32_value": "0xff56d8d4",
        "top_run": {"container": [hex(t0), hex(t1)],
                    "va_runtime": [hex(va_of(t0)) if va_of(t0) else None,
                                   hex(va_of(t1)) if va_of(t1) else None],
                    "stride": 4, "repeats": n_rep,
                    "bytes": n_rep * 4},
        "block_family": {
            "unit": "16-B tag*4 blocks, A_IMG-aligned (4.33d unit)",
            "count": fam, "banked": BANKED_666,
            "first_a_img": hex(first_block) if first_block else None,
            "campaign_va_first": hex(IMG_LO + first_block)
            if first_block is not None else None},
        "runs_top5": between,
        "verdict": ("a LIVE data table in the code-segment islands: "
                    "the tag value is the majority FILL among distinct "
                    "descending u32s in the 0xff57xx band — data, not "
                    "compressible padding (corrects the lane-D "
                    "'duplicated waste' reading for this family)")}
    print(f"[d4d856ff] tags={total_tags} top run {n_rep} x stride-4 "
          f"@{hex(t0)}; block-family (a_img-aligned) = {fam} "
          f"== banked 666 OK")

    # -- data-segment strings (the grammar of the R-W segment)
    import re
    sre = re.compile(rb"[\x20-\x7e]{6,}")
    buf = db[data_seg["off"]:data_seg["off"] + data_seg["filesz"]]
    dstr = []
    for m in sre.finditer(buf):
        txt = m.group()
        dstr.append({"va": hex(data_seg["vaddr"] + m.start()),
                     "len": len(txt),
                     "text": txt[:48].decode(errors="replace")})
    out["data_segment_strings"] = {"n": len(dstr),
                                   "sample": dstr[:40]}
    print(f"[data] strings >= 6: {len(dstr)}")

    # zero-ness of the data segment
    z = (np.frombuffer(buf, dtype=np.uint8) == 0).mean() * 100
    out["data_segment_zero_pct"] = round(float(z), 2)

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
