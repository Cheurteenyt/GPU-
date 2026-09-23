#!/usr/bin/env python3
"""4.32 pass, instrument 0 — the coordinate law between the two rm.elf
substrates, PROVEN before any disassembly rides on it.

Two substrates carry the same RISC-V GSP-RM code:
  A = tools/analysis/gsp-extract/rm-full.elf      (the 4.14-4.21 map coords:
      ONE RWX LOAD vaddr=0x1000000, p_offset=0x40; the v416 map and the
      v420 census are indexed in IMAGE coordinates = VA - 0x1000000)
  B = tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin (the mission's
      substrate: VA = file + 0x1000000, the 4.30 patch ran on it)

The 4.30 register gives the six 250000 sites in BOTH coordinates; their
difference is the claimed uniform shift. This instrument:
  1. parses both phdr tables and prints the facts (no assumption);
  2. re-decodes the six sites on B (lui+addi/addiw == 250000, rd per the
     4.30 register {15,12,12,15,15,18});
  3. byte-compares windows around the six sites and the 17 v420 census
     sites under the candidate law  B_file = A_img - 0x38;
  4. samples the whole code image (every 0x1000) for the same equality,
     so the law is proven image-wide, not just at the sites we use.

Output: lab/jalon411/v432_coord_check.json
"""
import json
import struct
import sys
from pathlib import Path

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
OUT = Path(__file__).with_suffix(".json")

IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]  # 4.30
RDS_430 = [15, 12, 12, 15, 15, 18]
ADDIW_SITE = 3  # the 0x7c467c site uses addiw (4.30)

V420 = ROOT / "lab/jalon411/v420_edpp.json"


def phdrs(d):
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_vaddr, p_paddr, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        out.append({"type": p_type, "flags": p_flags, "off": p_off,
                    "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz})
    return out


def riscv_split(v):
    lo = v & 0xFFF
    if lo >= 0x800:
        lo -= 0x1000
    hi = (v - lo) >> 12
    return hi, lo


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    pa, pb = phdrs(da), phdrs(db)
    print(f"A rm-full.elf    {len(da)} B, {len(pa)} phdrs")
    for p in pa:
        print(f"  type={p['type']} flags={p['flags']:#x} off={p['off']:#x} "
              f"vaddr={p['vaddr']:#x} filesz={p['filesz']:#x}")
    print(f"B gsp-rm-17MB    {len(db)} B, {len(pb)} phdrs")
    for p in pb:
        print(f"  type={p['type']} flags={p['flags']:#x} off={p['off']:#x} "
              f"vaddr={p['vaddr']:#x} filesz={p['filesz']:#x}")

    a_load = next(p for p in pa if p["type"] == 1 and p["filesz"] == p["memsz"])
    a_img = da[a_load["off"]:a_load["off"] + a_load["filesz"]]
    assert a_load["vaddr"] == IMG_LO, "A base unexpected"

    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)

    # --- 2. re-decode the six sites on B -----------------------------------
    sites = []
    for k, off in enumerate(SITES_B):
        w1 = struct.unpack_from("<I", db, off)[0]
        w2 = struct.unpack_from("<I", db, off + 4)[0]
        ok1 = (w1 >> 7) & 0x1F and (w1 & 0x7F) == 0x37  # lui rd!=0
        hi = w1 >> 12
        ok2 = ((w2 & 0x7F) == 0x13 or (w2 & 0x7F) == 0x1B)  # addi/addiw
        lo = (w2 >> 20) & 0xFFF
        if lo >= 0x800:
            lo -= 0x1000
        val = ((hi << 12) + lo) & 0xFFFFFFFF
        val_s = ((hi << 12) + lo) & 0xFFFFFFFFFFFFFFFF if False else (hi << 12) + lo
        rd1 = (w1 >> 7) & 0x1F
        rd2 = (w2 >> 7) & 0x1F
        rs1 = (w2 >> 15) & 0x1F
        ops = []
        for i in md.disasm(db[off:off + 8], IMG_LO + off):
            ops.append(f"{i.mnemonic} {i.op_str}")
        rec = {
            "idx": k, "file_off_B": hex(off), "va_B": hex(IMG_LO + off),
            "va_A_expected": hex(IMG_LO + off + 0x38),
            "words": [hex(w1), hex(w2)],
            "decoded": ops,
            "value": val_s, "value_ok": val_s == 250000,
            "rd": rd1, "rd_ok_vs_430": rd1 == RDS_430[k],
            "pair_ok": bool(ok1 and ok2 and rd1 == rd2 == rs1),
            "op2": "addiw" if (w2 & 0x7F) == 0x1B else "addi",
        }
        sites.append(rec)
        print(f"site {k}: B@{off:#x} val={val_s} rd=x{rd1} "
              f"{' | '.join(ops)}  val_ok={rec['value_ok']} rd_ok={rec['rd_ok_vs_430']}")

    # --- 3. the -0x38 law at the used sites --------------------------------
    shift = 0x38
    cmp_windows = []
    for k, off in enumerate(SITES_B):
        a_off = off + shift
        n = 0x200
        eq = a_off >= 0 and a_off + n <= len(a_img) and off + n <= len(db)
        if eq:
            eq = db[off:off + n] == a_img[a_off:a_off + n]
        cmp_windows.append({"site": k, "B_file": hex(off), "A_img": hex(a_off),
                            "window": n, "bytes_equal": bool(eq)})
        print(f"window cmp site {k}: B@{off:#x} vs A_img@{a_off:#x} equal={eq}")

    v420_sites = []
    if V420.exists():
        j = json.load(open(V420))
        for s in j["sites"]:
            va = int(s["va"], 16)
            a_off = va - IMG_LO
            b_off = a_off - shift
            n = 0x80
            eq = b_off >= 0 and b_off + n <= len(db) and a_off + n <= len(a_img)
            if eq:
                eq = db[b_off:b_off + n] == a_img[a_off:a_off + n]
            v420_sites.append({"va": s["va"], "A_img": hex(a_off),
                               "B_file": hex(b_off), "bytes_equal": bool(eq)})
        neq = [v for v in v420_sites if not v["bytes_equal"]]
        print(f"v420 census sites re-mapped: {len(v420_sites)}, "
              f"non-equal: {len(neq)}")

    # --- 4. image-wide sample ----------------------------------------------
    mism = []
    n_sample = 0
    # law: B file X == A img X + 0x38  (B_file = A_img - 0x38)
    limit = min(len(a_img) - 0x38, len(db))
    for off in range(0, limit - 0x100, 0x1000):
        n_sample += 1
        if db[off:off + 0x100] != a_img[off + 0x38:off + 0x38 + 0x100]:
            mism.append(hex(off))
    print(f"image-wide sample: {n_sample} windows of 0x100 at stride 0x1000, "
          f"mismatches: {len(mism)} {mism[:8]}")

    # first divergence point (fine-grained around the first mismatch if any)
    first_div = None
    if mism:
        m0 = int(mism[0], 16)
        for off in range(max(0, m0 - 0x1000), m0 + 0x2000):
            if off < len(db) and off + 0x38 + 1 < len(a_img):
                if db[off] != a_img[off + 0x38]:
                    first_div = hex(off)
                    break
        print(f"first divergent B_file offset: {first_div}")

    out = {
        "substrates": {
            "A_rm_full_elf": {"path": str(A.relative_to(ROOT)), "size": len(da),
                              "phdrs": pa, "img_offset": a_load["off"],
                              "img_size": a_load["filesz"]},
            "B_gsp_rm_17MB": {"path": str(B.relative_to(ROOT)), "size": len(db),
                              "phdrs": pb},
        },
        "sites_B": sites,
        "window_cmp": cmp_windows,
        "v420_census_remapped": v420_sites,
        "image_wide": {"stride": 0x1000, "windows": n_sample,
                       "mismatches": mism, "first_divergence_A_img": first_div},
        "law": "B_file = A_img - 0x38 (VA_common = A_img + 0x1000000 = B_file + 0x38 + 0x1000000)",
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
