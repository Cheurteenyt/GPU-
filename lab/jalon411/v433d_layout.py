#!/usr/bin/env python3
"""4.33 LANE D — the layout-waste census (padding, zeros, duplicated
data, the booter's own share).

The optimization question: HOW MUCH of the delivered bytes is waste?
Three layers measured:
  1. the ELF's own structure: phdr LOAD segments, inter-segment file
     gaps, alignment padding;
  2. zero runs (>= 64 B) across the code image and the container —
     classified against the v416 covered map (in-code padding vs data);
  3. duplicated DATA: exact 16-B aligned blocks in the non-covered
     half of the image (the data side), top families;
  4. the booter (bootloader.bin, 0x6d000): its own zero/dup profile —
     the boot-time lane (4.31 proved the NOP-safe patch methodology
     there; this census sizes what a rebuild could reclaim).

The container compression caveat (4.29): the LZ4 floor on rm.elf is
51-58% — zero runs and dup data compress to almost nothing in the
DELIVERED gsp_ga10x.bin; this census measures the RAW image (what the
GSP actually maps and what any rebuild would ship uncompressed or
re-compress), and says so.

Selftest anchors: the coordinate law + map base (opcode test); B's ELF
magic (e_machine 0xf3 = RISC-V, the 4.31 proof); the code-image length
0xE9B000 (the campaign constant); the zero-run census must find the
banked NOTE regions all-zero (4.30) — sampled.
Output: lab/jalon411/v433d_layout.json
"""
import json
import struct
import zlib
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
BOOT = ROOT / "tools/analysis/gsp-extract/binaries/bootloader.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
STRINGS = ROOT / "tools/analysis/gsp-extract/rm-strings.txt"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82


def zero_runs(buf, minlen=64):
    """vectorized zero-run census: [(start, len)] for runs >= minlen."""
    a = np.frombuffer(buf, dtype=np.uint8)
    nz = np.nonzero(a)[0]
    if len(nz) == 0:
        return [(0, len(a))]
    gaps = np.diff(nz)
    # zero spans sit between consecutive non-zero bytes
    zstarts = nz[:-1][gaps > 1] + 1
    zlens = gaps[gaps > 1] - 1
    # edge runs
    edges = []
    if nz[0] >= minlen:
        edges.append((0, int(nz[0])))
    if len(a) - 1 - nz[-1] >= minlen:
        edges.append((int(nz[-1]) + 1, len(a) - 1 - int(nz[-1])))
    runs = [(int(s), int(l)) for s, l in zip(zstarts, zlens)
            if l >= minlen] + edges
    runs.sort()
    return runs


def main():
    np.seterr(over="ignore")
    da = A.read_bytes()
    db = B.read_bytes()
    boot = BOOT.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000"}

    # -- the law + the map base (opcode test, the 4.33 standard)
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

    # -- 1. B's ELF structure (the 4.31 proof: e_machine 0xf3)
    assert db[:4] == b"\x7fELF", "B is not an ELF"
    e_machine, = struct.unpack_from("<H", db, 0x12)
    assert e_machine == 0xF3, f"e_machine {e_machine} != 0xf3"
    e_phoff, = struct.unpack_from("<Q", db, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", db, 0x36)
    phdrs = []
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, \
            p_align = struct.unpack_from("<IIQQQQQQ", db, p)
        phdrs.append({"type": hex(p_type), "flags": hex(p_flags),
                      "off": hex(p_off), "vaddr": hex(p_vaddr),
                      "filesz": hex(p_filesz), "memsz": hex(p_memsz),
                      "align": hex(p_align)})
    out["elf"] = {"e_phnum": e_phnum, "phdrs": phdrs}
    loads = [p for p in phdrs if p["type"] == "0x1"]
    gaps = []
    loads_sorted = sorted(loads, key=lambda p: int(p["off"], 16))
    for a0, b0 in zip(loads_sorted, loads_sorted[1:]):
        gap = int(b0["off"], 16) - (int(a0["off"], 16) +
                                    int(a0["filesz"], 16))
        if gap > 0:
            gaps.append({"between": [a0["off"], b0["off"]],
                         "bytes": gap})
    out["elf"]["inter_load_file_gaps"] = gaps
    out["elf"]["gap_total"] = int(sum(g["bytes"] for g in gaps))
    print(f"[elf] phdrs={e_phnum} LOADs={len(loads)} "
          f"file-gaps={out['elf']['gap_total']} B")

    # -- 2. the zero runs (code image + container + booter)
    carr = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)]
    runs_a = zero_runs(a_img, 64)
    in_code_bytes = 0
    for s, l in runs_a:
        if carr[s:s + l].any():        # any covered byte in the run
            in_code_bytes += l
    out["zero_runs_code_image"] = {
        "count": len(runs_a), "total_bytes": int(sum(l for _, l in runs_a)),
        "bytes_touching_covered": int(in_code_bytes),
        "top10": [[hex(IMG_LO + s), l] for s, l in
                  sorted(runs_a, key=lambda r: -r[1])[:10]]}
    runs_b = zero_runs(db, 64)
    out["zero_runs_container_B"] = {
        "count": len(runs_b), "total_bytes": int(sum(l for _, l in runs_b)),
        "top5": [[hex(s), l] for s, l in
                 sorted(runs_b, key=lambda r: -r[1])[:5]]}
    runs_boot = zero_runs(boot, 64)
    out["zero_runs_booter"] = {
        "file_size": len(boot), "count": len(runs_boot),
        "total_bytes": int(sum(l for _, l in runs_boot)),
        "top5": [[hex(s), l] for s, l in
                 sorted(runs_boot, key=lambda r: -r[1])[:5]]}
    print(f"[zero] code-image: {len(runs_a)} runs "
          f"({out['zero_runs_code_image']['total_bytes']} B) | "
          f"booter: {len(runs_boot)} runs "
          f"({out['zero_runs_booter']['total_bytes']} B)")

    # -- 3. duplicated DATA (16-B aligned blocks, non-covered bytes)
    #      the covered map is the CODE side; its complement (inside the
    #      image) = data + uncovered islands. Blocks fully non-covered.
    noncov = np.frombuffer(covered, dtype=np.uint8)[:len(a_img)] == 0
    block_starts = np.arange(0, (len(a_img) - 16) & ~15, 16, dtype=np.int64)
    ok = np.ones(len(block_starts), dtype=bool)
    for d in range(0, 16, 4096):     # chunked non-covered test
        pass
    ok = noncov[block_starts] & noncov[block_starts + 15]
    # every byte of the block non-covered (chunked AND)
    for s in range(0, len(block_starts), 200000):
        bs = block_starts[s:s + 200000]
        acc = noncov[bs] & noncov[bs + 15]
        for d in (1, 4, 8, 12):
            acc &= noncov[bs + d]
        ok[s:s + 200000] = acc
    sel = block_starts[ok]
    out["data_blocks_tested"] = int(len(sel))
    u0 = np.frombuffer(a_img + b"\x00" * 16, dtype="<u4")
    k = sel >> 2
    W = np.stack([u0[k], u0[k + 1], u0[k + 2], u0[k + 3]], axis=1)
    P1, P2, P3, P4 = 0x100000001B3, 0x9E3779B97F4A7C15, \
        0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9
    h = ((W[:, 0].astype(np.uint64) * np.uint64(P1)) ^
         (W[:, 1].astype(np.uint64) * np.uint64(P2)) ^
         (W[:, 2].astype(np.uint64) * np.uint64(P3)) ^
         (W[:, 3].astype(np.uint64) * np.uint64(P4)))
    uniq, cnt = np.unique(h, return_counts=True)
    dup = uniq[cnt >= 2]
    fam = defaultdict(list)
    in_dup = np.isin(h, dup)
    for s, hh in zip(sel[in_dup], h[in_dup]):
        fam[int(hh)].append(int(s))
    real = []
    zero_block = 0
    for hh, offs in fam.items():
        offs.sort()
        ref = bytes(a_img[offs[0]:offs[0] + 16])
        if ref == b"\x00" * 16:
            zero_block += len(offs)
            continue
        groups = defaultdict(list)
        for o in offs:
            groups[bytes(a_img[o:o + 16])].append(o)
        for g in groups.values():
            if len(g) >= 2:
                real.append(g)
    real.sort(key=lambda g: -len(g))
    dup_data_bytes = sum(len(g) for g in real) * 16
    out["data_duplication"] = {
        "exact_families": len(real),
        "windows_in_families": int(sum(len(g) for g in real)),
        "zero_windows_excluded": zero_block,
        "duplicated_bytes": int(dup_data_bytes),
        "top10": [{"members": len(g),
                   "bytes_hex": bytes(a_img[g[0]:g[0] + 16]).hex(),
                   "sites_VA": [hex(IMG_LO + o) for o in g[:8]]}
                  for g in real[:10]]}
    print(f"[data] dup families={len(real)} "
          f"({dup_data_bytes} B in 16-B windows)")

    # -- 4. the strings duplication (rm-strings.txt, one per line)
    strings = STRINGS.read_text(errors="replace").splitlines()
    seen_str = defaultdict(int)
    for s in strings:
        if len(s) >= 8:
            seen_str[s] += 1
    dups = {s: c for s, c in seen_str.items() if c >= 2}
    wasted = sum((c - 1) * (len(s) + 1) for s, c in dups.items())
    out["strings"] = {
        "total_lines": len(strings), "ge8": len(seen_str),
        "dup_strings": len(dups),
        "wasted_bytes_estimate": int(wasted),
        "top10": sorted(dups.items(), key=lambda kv: -kv[1])[:10]}
    print(f"[strings] dup>=2: {len(dups)} (~{wasted} B wasted)")

    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
