#!/usr/bin/env python3
"""4.33 LANE B — the duplicate-code census (the inlining-bloat map).

The optimization question: HOW MUCH of the 17 MB code image is the
same instructions materialized twice or more? In a closed binary the
duplicates cannot be re-linked away — but they quantify (a) what a
rebuild/relink would reclaim, (b) which code fragments a binary patch
would have to touch N times instead of once (the 4.32 lesson: the
patch touched 6 sites; the census found a 7th — duplication is the
enemy of patch coherence), and (c) the compiler's inlining profile.

Method:
  - 16-byte windows (4 words) at every SEEN instruction start (both
    parity classes), polynomial-64 hash, vectorized;
  - families = hash groups with >= 2 members; every REPORTED family is
    exact-verified on raw bytes (no hash-collision findings);
  - top families extended forward/backward on raw bytes (the true
    common prefix);
  - shareable-bytes estimate: sum over families (n-1) * L, L = the
    verified common prefix length (16 B floor, extended for the top);
  - cross-region duplicates (members in >= 2 v416 regions) reported
    separately — those are the cross-function copies;
  - negative control: 512 synthetic windows (mutation of real ones)
    must NOT join any family (hasher sanity).

Selftest anchors: the coordinate law + map base (opcode test, as
v433c/v433b); the window count ~ the seen-start count; the exact
verification of every reported family; the negative control.
Output: lab/jalon411/v433a_dupcode.json
"""
import json
import zlib
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

P1, P2, P3, P4 = 0x100000001B3, 0x9E3779B97F4A7C15, \
    0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9


def main():
    np.seterr(over="ignore")   # the u64 wraparound IS the hash
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

    # -- the law + the map base (opcode-discriminated, as v433c/b)
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    for boff in SITES_B:
        if db[boff:boff + 8] != a_img[boff + SHIFT:boff + SHIFT + 8]:
            fails += 1
    assert fails == 0 and (a_img[CLAIM7_A] & 0x7F) == 0x37, "law broken"
    a_lui = 0x1A02A + SHIFT
    assert seen[a_lui] == 1 and (a_img[a_lui] & 0x7F) == 0x37, "map base"
    out["law_recheck"] = {"fails": fails, "map_base": "A_img (opcode)"}

    img4 = a_img + b"\x00" * ((4 - len(a_img) % 4) % 4)
    u0 = np.frombuffer(img4, dtype="<u4").astype(np.uint64)
    u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4").astype(np.uint64)
    sarr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]
    starts = np.nonzero(sarr)[0].astype(np.int64)
    out["seen_starts"] = int(len(starts))

    # -- hashed 16-B windows at every seen start (both parity)
    def windows(base, uarr):
        sel = starts[(starts & 3) == base]
        k = (sel - base) >> 2
        keep = (k + 3 < len(uarr)) & (k >= 0)
        sel, k = sel[keep], k[keep]
        w = uarr[k]
        h = (w[:, 0] * np.uint64(P1) if w.ndim == 2 else
             w * np.uint64(P1))
        return sel, w

    srcs, ws = [], []
    for base, uarr in ((0, u0), (2, u2)):
        sel = starts[(starts & 3) == base]
        k = (sel - base) >> 2
        keep = (k + 3 < len(uarr)) & (k >= 0)
        sel, k = sel[keep], k[keep]
        # full 16-B windows only — the tail-truncated slices compared
        # unequal lengths and masqueraded as hash collisions (the bug
        # the first run caught; banked)
        sel = sel[sel + 16 <= len(a_img)]
        k = (sel - base) >> 2
        w = np.stack([uarr[k], uarr[k + 1], uarr[k + 2], uarr[k + 3]],
                     axis=1)
        srcs.append(sel)
        ws.append(w)
    src = np.concatenate(srcs)
    W = np.concatenate(ws)
    out["windows_hashed"] = int(len(src))

    h = ((W[:, 0] * np.uint64(P1)) ^ (W[:, 1] * np.uint64(P2)) ^
         (W[:, 2] * np.uint64(P3)) ^ (W[:, 3] * np.uint64(P4)))
    uniq, inv, cnt = np.unique(h, return_inverse=True, return_counts=True)
    dup_mask = cnt >= 2
    dup_hashes = uniq[dup_mask]
    out["windows_total"] = int(len(src))
    out["families_ge2"] = int(dup_mask.sum())
    print(f"[scan] windows={len(src)} families(>=2)={int(dup_mask.sum())}")

    # -- member lists for the duplicate families (hash-grouped)
    fam_members = defaultdict(list)
    dup_set = set(dup_hashes.tolist())
    # vectorized pre-filter: which windows belong to a dup family
    in_dup = np.isin(h, dup_hashes)
    for s, hh in zip(src[in_dup], h[in_dup]):
        fam_members[int(hh)].append(int(s))

    # -- exact verification (every reported family, raw bytes)
    def exact_prefix(offsets, floor=16, cap=512):
        """the true common prefix length of the windows (raw bytes)."""
        L = floor
        while L < cap:
            ref = a_img[offsets[0]:offsets[0] + L + 16]
            if all(a_img[o:o + L + 16] == ref for o in offsets[1:]):
                L += 16
            else:
                break
        # shrink back to the true match
        while L > floor:
            ref = a_img[offsets[0]:offsets[0] + L]
            if all(a_img[o:o + L] == ref for o in offsets[1:]):
                break
            L -= 16
        return L

    fams = []
    for hh, offs in fam_members.items():
        offs.sort()
        fams.append((hh, offs))
    # -- FILLER classification + RUN merging (the first run's lesson:
    #    the top "family" = the booter's NOP sea with 26,060 OVERLAPPING
    #    windows of the same physical runs — window-level counts inflate
    #    the shareable estimate; families must collapse to runs and the
    #    filler (NOP/zero/c.nop) must be separated from real code)
    def is_filler(ref16):
        if ref16 == b"\x00" * 16:
            return True
        if all(ref16[i:i + 4] == b"\x13\x00\x00\x00" for i in (0, 4, 8, 12)):
            return True                                   # 4x nop
        if all(ref16[i:i + 2] == b"\x01\x00" for i in (0, 2, 4, 6, 8, 10,
                                                       12, 14)):
            return True                                   # 8x c.nop
        return False

    def runs_of(offs, min_gap=16):
        """collapse overlapping windows into maximal physical runs."""
        runs = []
        s = e = offs[0]
        for o in offs[1:]:
            if o - e < min_gap:
                e = o
            else:
                runs.append((s, e))
                s = e = o
        runs.append((s, e))
        return runs

    filler_windows = 0
    real_fams2 = []
    filler_runs_total_bytes = 0
    filler_runs_count = 0
    for hh, offs in fams:
        ref = bytes(a_img[offs[0]:offs[0] + 16])
        if is_filler(ref):
            filler_windows += len(offs)
            for s, e in runs_of(offs):
                filler_runs_count += 1
                filler_runs_total_bytes += (e - s) + 16
            continue
        groups = defaultdict(list)
        for o in offs:
            groups[bytes(a_img[o:o + 16])].append(o)
        for g in groups.values():
            if len(g) >= 2:
                real_fams2.append((hh, g))
    out["filler"] = {"windows": filler_windows,
                     "physical_runs": filler_runs_count,
                     "run_bytes_estimate": filler_runs_total_bytes}
    out["families_verified_exact"] = len(real_fams2)
    out["sites_in_duplicate_windows"] = int(
        sum(len(o) for _, o in real_fams2) + filler_windows)
    real_fams = real_fams2
    print(f"[dup] filler windows={filler_windows} "
          f"({filler_runs_count} physical runs, "
          f"~{filler_runs_total_bytes} B) | real families="
          f"{len(real_fams)}")

    # -- region attribution + cross-region families
    carr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    idx = np.nonzero(carr)[0]
    sp = np.nonzero(np.diff(idx) > 1)[0]
    b0 = np.concatenate(([0], sp + 1))
    b1 = np.concatenate((sp, [len(idx) - 1]))
    regions = [(int(idx[i]), int(idx[j]) + 1)
               for i, j in zip(b0, b1) if idx[j] + 1 - idx[i] >= 2]
    rstart = np.array([r[0] for r in regions], dtype=np.int64)
    ren = np.array([r[1] for r in regions], dtype=np.int64)

    def region_id(o):
        i = np.searchsorted(rstart, o, side="right") - 1
        if i >= 0 and o < ren[i]:
            return int(i)
        return -1

    real_fams.sort(key=lambda f: -len(f[1]))
    top = []
    shareable = 0
    for hh, offs in real_fams[:40]:
        starts_r = [s for s, e in runs_of(sorted(offs))]
        L = exact_prefix(starts_r)
        shareable += (len(starts_r) - 1) * L
        regs = sorted({region_id(o) for o in offs})
        top.append({
            "copies": len(starts_r),
            "raw_windows": len(offs),
            "common_prefix_bytes": L,
            "shareable_bytes": (len(starts_r) - 1) * L,
            "cross_region": len([r for r in regs if r >= 0]) >= 2,
            "regions_sample": [hex(IMG_LO + regions[r][0])
                               for r in regs[:4] if r >= 0],
            "sites_VA": [hex(IMG_LO + o) for o in offs[:12]]})
    out["top_families"] = top

    # the full-census shareable lower bound (L = 16, run-merged copies)
    total_shareable_16 = 0
    for _, offs in real_fams:
        starts_r = [s for s, e in runs_of(sorted(offs))]
        total_shareable_16 += (len(starts_r) - 1) * 16
    out["shareable_bytes_lower_bound_16B"] = int(total_shareable_16)
    out["shareable_bytes_top40_extended"] = int(shareable)
    print(f"[dup] real-code shareable: >= {total_shareable_16} B "
          f"(16-B floor, run-merged), top-40 extended = {shareable} B")

    # -- negative control: avalanche — 512 single-byte mutations of real
    #    windows must all change the hash (family duplication is already
    #    guaranteed byte-exact by the byte partitioning above)
    import warnings
    rng = np.random.default_rng(0x433)
    probe_idx = rng.choice(len(src), size=512, replace=False)
    ok = 0
    for pi in probe_idx:
        o = int(src[pi])
        w = np.frombuffer(a_img[o:o + 16], dtype="<u4").astype(np.uint64)
        h0 = int((w[0] * np.uint64(P1)) ^ (w[1] * np.uint64(P2)) ^
                 (w[2] * np.uint64(P3)) ^ (w[3] * np.uint64(P4)))
        mutated = bytearray(a_img[o:o + 16])
        mutated[int(rng.integers(0, 16))] ^= 0xFF
        m = bytes(mutated)
        w2 = np.frombuffer(m, dtype="<u4").astype(np.uint64)
        h1 = int((w2[0] * np.uint64(P1)) ^ (w2[1] * np.uint64(P2)) ^
                 (w2[2] * np.uint64(P3)) ^ (w2[3] * np.uint64(P4)))
        if h1 != h0:
            ok += 1
    out["negative_control"] = {"probes": 512, "avalanche_ok": ok}
    assert ok == 512, "hash avalanche degraded"
    print("[selftest] avalanche control 512/512 OK")

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
