#!/usr/bin/env python3
"""4.37 TASK A — the data-twin xref probe: who REFERENCES the banked data
tables?  (the one reachability probe the campaign never ran)

The 4.36 verdict: three probes (regkey co-residency, RPC anchors,
function fan-in) returned ZERO — the knob VALUES are not reached by any
static nameable path.  But 4.35c proved the DATA TWINS exist (the
22x1000000 compiled-default table, the 2^n ladders, the 16-entry clock
twin, the duplicated config blocks).  Nobody has ever asked: which CODE
references those tables?  A code site that materializes the table's
address (lui+addi or auipc+partner) is the LOADER — the init path that
copies compiled defaults into runtime state, or the reader that walks
the table.  Finding them names the runtime entry points the 4.26
capture must watch.

Targets (all banked 4.35c, re-derived from the bytes in the selftests):
  T1  the 22x1000000 table        @VA 0x404b4b0-0x404b7f8  (data LOAD)
  T2  the 8000000 data-only pair  @VA 0x41904c0-0x41904d0  (data LOAD)
  T3  the 2^n size-class ladders  @0x1c4ab68 / @0x1c4ad68  (code island)
  T4  the duplicated config blocks @0x1d85e04/0x1de0c4c/0x1de185c
  T5  the 16-entry 1435840000 twin @0x1c0d38c-0x1c0d404   (code island)
  T6  the d4d856ff fill-value top run @0x1c51f04-0x1c52ef0 (code island)

Universes: the JSONs cite VA = B_off + 0x1000000 for code islands, and
the phdr VA for the data LOAD.  The two differ by the 0x38 shift, so
every window is probed with BOTH bases and the selftest settles which
universe each target really lives in (the lesson: the byte-probe before
the bit-layout faith).

Method (all re-derived, banked rules):
  - the coordinate law re-asserted (512 windows + 7 sites + claim7);
  - the map base re-proven (opcode-discriminated, as v433c/v435a/v436a);
  - the full-form lui+addi pair census re-run (gaps {2,4}+{6,8},
    clobber checks) — the banked 4.32 counts must reproduce EXACTLY;
  - the c.lui-100000 compressed census re-run (36 sites, = v434b);
  - DATA-XREF probe 1 (absolute): pair values landing inside any target
    window (both universes) — the lui+addi materializations of a table
    address;
  - DATA-XREF probe 2 (PIC): auipc + {addi|add|ld} partners, tgt = pc +
    (hi20<<12) + lo12 landing inside any target window — the PC-relative
    addressings AND the GOT-entry loads;
  - DATA-XREF probe 3 (data pointers): u64s inside the data LOAD whose
    value lands inside a code-island window — data->data pointer tables;
  - every hit: seen-check, cited +-24-insn window, the consumer
    instruction (what reads the address register), func window, and the
    cross vs the 4.35a owner regions + the 4.35b regkey xref windows.

Selftests: the law; the map base; the banked pair counts; the 36 c.lui;
the T1 table bytes (22 u32 = 1000000); the d4d856ff tag at the cited
run; the 2^n ladder re-derivation.

Output: lab/jalon411/v437a_data_twin_xrefs.json
"""
import json
import struct
import zlib
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

import numpy as np
import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

ROOT = Path(__file__).resolve().parents[2]
A = ROOT / "tools/analysis/gsp-extract/rm-full.elf"
B = ROOT / "tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin"
MAP = ROOT / "lab/jalon411/v416_map.bin"
V435A = ROOT / "lab/jalon411/v435a_knobcards.json"
V435B = ROOT / "lab/jalon411/v435b_regkeys.json"
V434B = ROOT / "lab/jalon411/v434b_cl100_bodies.json"
OUT = Path(__file__).with_suffix(".json")

SHIFT = 0x38
IMG_LO = 0x1000000
SITES_B = [0x190C6, 0x1A02A, 0x1F09A8, 0x7C467C, 0xB99BB4, 0xB99C90]
CLAIM7_A = 0xB99C82
BANKED_COUNTS = {250000: 6, 500000: 25, 1000000: 123, 4000000: 15,
                 100000000: 17, -250000: 1, -1000000: 3, -500000: 5,
                 100000: 0, 240000: 0, 280000: 0}
N_CLUI_100000 = 36

# data LOAD phdr: off 0xE9B000, vaddr 0x4000000, filesz 0x1D5000
DATA_OFF = 0xE9B000
DATA_VA = 0x4000000
DATA_FILESZ = 0x1D5000

# target windows (VA as cited by 4.35c; both universes probed per target)
TARGETS = [
    {"id": "T1", "desc": "22x1000000 compiled-default table",
     "lo": 0x404B4B0, "hi": 0x404B7F8, "seg": "data"},
    {"id": "T2", "desc": "8000000 data-only pair",
     "lo": 0x41904C0, "hi": 0x41904D0, "seg": "data"},
    {"id": "T3a", "desc": "2^n size-class ladder x60",
     "lo": 0x1C4AB68, "hi": 0x1C4ACA4, "seg": "island"},
    {"id": "T3b", "desc": "2^n size-class ladder x63",
     "lo": 0x1C4AD68, "hi": 0x1C4AEB4, "seg": "island"},
    {"id": "T4a", "desc": "duplicated config block A",
     "lo": 0x1D85E04, "hi": 0x1D85F48, "seg": "island"},
    {"id": "T4b", "desc": "duplicated config block B",
     "lo": 0x1DE0C4C, "hi": 0x1DE0E10, "seg": "island"},
    {"id": "T4c", "desc": "duplicated config block C",
     "lo": 0x1DE185C, "hi": 0x1DE19A0, "seg": "island"},
    {"id": "T5", "desc": "16-entry 1435840000 clock-threshold twin",
     "lo": 0x1C0D38C, "hi": 0x1C0D404, "seg": "island"},
    {"id": "T6", "desc": "d4d856ff fill-value top run",
     "lo": 0x1C51F04, "hi": 0x1C52EF0, "seg": "island"},
]
PAD = 0x40   # both-universe tolerance (the 0x38 shift + slack)

REGS = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6"]

md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
md.detail = True


def dis1(buf, off, va=None):
    if off + 2 > len(buf):
        return None
    if buf[off] & 3 == 3:
        if off + 4 > len(buf):
            return None
        return next(md.disasm(buf[off:off + 4], (va or off)), None)
    return next(md.disasm(buf[off:off + 2], (va or off)), None)


def writes_reg(ins, rd_name):
    if ins is None:
        return False
    m = ins.mnemonic
    if m in ("sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp", "c.sdsp",
             "beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
             "bltz", "bgez", "blez", "bgtz", "c.beqz", "c.bnez",
             "j", "c.j", "ret", "c.ret", "c.jr", "ecall", "ebreak",
             "fence", "fence.i", "nop", "c.nop", "wfi", "mret", "sret",
             "uret", "sfence.vma", "rdtime", "rdcycle", "rdinstret"):
        return False
    return ins.op_str.split(",")[0].strip() == rd_name


def is_retlike(ins):
    if ins is None:
        return False
    m, ops = ins.mnemonic, ins.op_str
    if m in ("ret", "c.ret"):
        return True
    if m == "jalr" and ops.startswith("zero,"):
        return True
    if m == "c.jr" and ops.strip() == "ra":
        return True
    return False


def reads_reg(ins, rd_name):
    if ins is None:
        return False
    try:
        m = ins.mnemonic
        ops = ins.op_str.split(", ")
        if m in ("sd", "sw", "sh", "sb", "c.sd", "c.sw", "c.swsp",
                 "c.sdsp"):
            mem = ops[1] if len(ops) > 1 else ""
            return "(" in mem and \
                mem.split("(")[1].rstrip(")") == rd_name
        if m.startswith(("b", "c.b")):
            return rd_name in [x.strip() for x in ops]
        dest = ops[0].strip() if ops else ""
        for k, x in enumerate(ops):
            x = x.strip()
            if x == rd_name and not (k == 0 and x == dest):
                return True
        return False
    except Exception:
        return False


def func_window(img, aoff, limit=0x4000):
    fs = None
    off = aoff
    chain = []
    while aoff - off < limit and off >= 2:
        p2 = off - 2
        if p2 >= 0 and img[p2] & 3 != 3:
            ins = dis1(img, p2)
            if ins is not None and ins.size == 2:
                chain.append((p2, ins))
                off = p2
                continue
            break
        p4 = off - 4
        if p4 >= 0 and img[p4] & 3 == 3:
            ins = dis1(img, p4)
            if ins is not None and ins.size == 4:
                chain.append((p4, ins))
                off = p4
                continue
        break
    for o, ins in chain:
        if is_retlike(ins):
            fs = o + ins.size
            break
    fe = None
    off = aoff
    for _ in range(limit):
        ins = dis1(img, off)
        if ins is None:
            break
        off += ins.size
        if is_retlike(ins):
            fe = off
            break
    return fs, fe


def window_text(img, aoff, back=24, fwd=24, va_base=IMG_LO):
    lines = []
    off = aoff
    for _ in range(back):
        p2 = off - 2
        if p2 >= 0 and img[p2] & 3 != 3:
            ins = dis1(img, p2, va_base + p2)
            if ins is not None and ins.size == 2:
                lines.append((p2, ins))
                off = p2
                continue
            break
        p4 = off - 4
        if p4 >= 0 and img[p4] & 3 == 3:
            ins = dis1(img, p4, va_base + p4)
            if ins is not None and ins.size == 4:
                lines.append((p4, ins))
                off = p4
                continue
        break
    lines.reverse()
    off = aoff
    for _ in range(fwd):
        ins = dis1(img, off, va_base + off)
        if ins is None:
            break
        lines.append((off, ins))
        off += ins.size
    out = []
    for o, ins in lines:
        mark = " <== HIT" if o == aoff else ""
        out.append(f"  0x{o + IMG_LO:x}: {ins.mnemonic} {ins.op_str}{mark}")
    return out


def full_pass(a_img, cands, gaps):
    by_value = defaultdict(list)
    for off, w1 in cands:
        rd = (w1 >> 7) & 0x1F
        if rd == 0:
            continue
        hi_s = (w1 >> 12) - (1 << 20) if (w1 >> 12) >= 0x80000 \
            else (w1 >> 12)
        for d in gaps:
            if off + d + 4 > len(a_img):
                continue
            w2 = struct.unpack_from("<I", a_img, off + d)[0]
            if (w2 & 0x7F) not in (0x13, 0x1B):
                continue
            if ((w2 >> 12) & 7) != 0:
                continue
            if ((w2 >> 15) & 0x1F) != rd or ((w2 >> 7) & 0x1F) != rd:
                continue
            if d > 4:
                ins = dis1(a_img, off + 4)
                if ins is not None and writes_reg(ins, REGS[rd]):
                    continue
            lo_f = (w2 >> 20) & 0xFFF
            if lo_f >= 0x800:
                lo_f -= 0x1000
            by_value[(hi_s << 12) + lo_f].append(
                {"A_img": off, "gap": d, "rd": REGS[rd]})
            break
    return by_value


def clui_100000_scan(img, starts):
    hits = []
    for off in starts.tolist():
        if img[off] & 3 == 3:
            continue
        w16 = img[off] | (img[off + 1] << 8)
        if (w16 & 0xE003) != 0x6001:
            continue
        if (w16 >> 12) & 1:
            continue
        rd = (w16 >> 7) & 0x1F
        if rd == 0:
            continue
        imm52 = (w16 >> 2) & 0x1F
        if imm52 != 0b11000:
            continue
        for d in (2, 4):
            ins = dis1(img, off + d)
            if ins is None:
                continue
            if ins.mnemonic == "addi":
                try:
                    ops = [x.strip() for x in ins.op_str.split(",")]
                    if REGS[rd] not in (ops[0], ops[1]):
                        continue
                    if int(ops[2], 0) != 0x6A0:
                        continue
                except Exception:
                    continue
                hits.append({"A_img": off, "gap": d, "rd": REGS[rd]})
                break
    return hits


def in_window(v):
    """returns (target_id, target, rel) when v lands in a padded window."""
    for t in TARGETS:
        if t["lo"] - PAD <= v < t["hi"] + PAD:
            return t, v - t["lo"]
    return None, None


def main():
    da = A.read_bytes()
    db = B.read_bytes()
    a_img = da[0x40:0x40 + 0xE9B000]
    blob = zlib.decompress(MAP.read_bytes())
    half = len(blob) // 2
    seen, covered = blob[:half], blob[half:]
    out = {"law": "B_file = A_img - 0x38; VA_A = A_img + 0x1000000",
           "img_len": hex(len(a_img))}

    # -- the law re-asserted
    fails = 0
    step = len(a_img) // 512
    for i in range(512):
        o = 0x38 + i * step
        if a_img[o:o + 16] != db[o - SHIFT:o - SHIFT + 16]:
            fails += 1
    for boff in SITES_B:
        if db[boff:boff + 8] != a_img[boff + SHIFT:boff + SHIFT + 8]:
            fails += 1
    if db[CLAIM7_A - SHIFT:CLAIM7_A - SHIFT + 8] != \
            a_img[CLAIM7_A:CLAIM7_A + 8]:
        fails += 1
    out["law_recheck"] = {"windows": 512 + 7, "fails": fails}
    assert fails == 0, "coordinate law broken"
    print("[selftest] coordinate law: 519 windows, 0 fails")

    # -- the map base
    a_lui, b_lui = 0x1A02A + SHIFT, 0x1A02A
    base_a = seen[a_lui] == 1 and seen[a_lui + 2] == 0 \
        and covered[a_lui + 2] == 1 and (a_img[a_lui] & 0x7F) == 0x37
    base_b = seen[b_lui] == 1 and seen[b_lui + 2] == 0 \
        and covered[b_lui + 2] == 1 and (a_img[b_lui] & 0x7F) == 0x37
    assert base_a != base_b and base_a, "map base ambiguous"
    out["map_semantics"] = {"base": "A_img", "seen": "instruction starts"}

    sarr = np.frombuffer(seen, dtype=np.uint8)[:len(a_img)]
    starts = np.nonzero(sarr)[0]

    # -- the full-form census (banked rules)
    img4 = a_img + b"\x00" * ((4 - len(a_img) % 4) % 4)
    u0 = np.frombuffer(img4, dtype="<u4")
    u2 = np.frombuffer(img4[2:] + b"\x00\x00", dtype="<u4")
    cands = []
    for base_off, uarr in ((0, u0), (2, u2)):
        kmax = (len(img4) - 4 - base_off) >> 2
        k = np.arange(kmax, dtype=np.int64)
        mask = (uarr[k] & 0x7F) == 0x37
        for kk in k[mask]:
            cands.append((int(base_off + (kk << 2)), int(uarr[kk])))
    cands.sort()

    p24 = full_pass(a_img, cands, (2, 4))
    p68 = full_pass(a_img, cands, (6, 8))
    allpairs = defaultdict(list)
    for v, lst in p24.items():
        allpairs[v].extend(lst)
    drift = {v: (len(p24.get(v, [])), want) for v, want in
             BANKED_COUNTS.items() if len(p24.get(v, [])) != want}
    assert not drift, f"banked pair counts drifted: {drift}"
    print("[selftest] banked 4.32 pair counts reproduced exactly")

    # -- the c.lui census (banked 36)
    clui = clui_100000_scan(a_img, starts)
    assert len(clui) == N_CLUI_100000, \
        f"c.lui count {len(clui)} != banked {N_CLUI_100000}"
    v434b = json.loads(V434B.read_text())
    v434b_sites = sorted(s["A_img"] for s in v434b["sites"]) \
        if isinstance(v434b.get("sites"), list) else None
    print(f"[selftest] c.lui-100000 census: {len(clui)} sites (banked 36)")

    # -- SELFTEST T1: the u32 = 1000000 at EVERY cited VA (the 4.35c
    #    census lists the hit positions, not a dense array — the region
    #    holds records of varying stride; verified position by position)
    t1 = next(t for t in TARGETS if t["id"] == "T1")
    cited = json.loads((ROOT / "lab/jalon411/v435c_datacensus.json")
                       .read_text())["knob_twins_data_and_code"]["1000000"]
    ok_t1 = 0
    for va_s in cited["data"]:
        va = int(va_s, 16)
        off_t1 = DATA_OFF + (va - DATA_VA)
        v = struct.unpack_from("<I", db, off_t1)[0]
        if v == 1000000:
            ok_t1 += 1
    assert ok_t1 == len(cited["data"]), \
        f"T1 positions agree on {ok_t1}/{len(cited['data'])} only"
    out["selftest_t1"] = {"n_cited": len(cited["data"]),
                          "positions_1000000": ok_t1}
    print(f"[selftest] T1: {ok_t1}/{len(cited['data'])} cited VAs hold "
          "u32 1000000 (record layout, not dense)")

    # -- SELFTEST T6: the d4d856ff tag at the cited run
    run_off = 0xC51F04                     # B_off (container coords)
    tag = bytes.fromhex("d4d856ff")
    n_tag = 0
    while db[run_off + n_tag * 4:run_off + n_tag * 4 + 4] == tag:
        n_tag += 1
    assert n_tag >= 1000, f"T6 tag run too short: {n_tag}"
    out["selftest_t6"] = {"run_at": hex(run_off), "tag_repeats": n_tag,
                          "banked": 1019}
    print(f"[selftest] T6: d4d856ff run at 0xc51f04 = {n_tag} repeats")

    # -- SELFTEST T3: the 2^n ladder re-derivation
    lad = [struct.unpack_from("<I", db, 0xC4AD68 + i * 4)[0]
           for i in range(24)]
    ladder_ok = all(
        lad[i] == lad[i + 1] or (lad[i + 1] in
                                 (lad[i] * 2, lad[i]))
        for i in range(23))
    out["selftest_t3b"] = {"first_24": lad[:8],
                           "monotone_nondec_2n_pairs": ladder_ok}
    print(f"[selftest] T3b ladder head: {lad[:8]}")

    # =========================================================
    # PROBE 1 — absolute lui+addi pairs landing in target windows
    # =========================================================
    probe1 = []
    for v, lst in sorted(allpairs.items()):
        t, rel = in_window(v)
        if t is None:
            continue
        for h in lst:
            probe1.append({"target": t["id"], "value": hex(v & 0xFFFFFFFF),
                           "rel_to_lo": hex(rel), "seg": t["seg"],
                           **h})
    out["probe1_absolute_pairs"] = probe1
    print(f"[probe1] absolute lui+addi pairs in windows: {len(probe1)}")

    # =========================================================
    # PROBE 1b — lui + {load|store|addi} DIRECT: the dominant RV64
    # global idiom (%hi materialized by lui, the %lo carried by the
    # access itself — no addi partner, invisible to probe1).  The
    # pre-filter keeps only lui values whose 12-bit reach could touch
    # a padded window (a tiny union), so the 8-insn scan stays cheap.
    # =========================================================
    reach = []
    for t in TARGETS:
        reach.append((t["lo"] - 0x840, t["hi"] + 0x7FF + PAD))
    probe1b = []
    page_bases = []
    for off, w1 in cands:
        rd = (w1 >> 7) & 0x1F
        if rd == 0 or (w1 & 0x7F) != 0x37:
            continue
        hi_s = (w1 >> 12) - (1 << 20) if (w1 >> 12) >= 0x80000 \
            else (w1 >> 12)
        lui_val = hi_s << 12
        if not any(lo <= lui_val <= hi for lo, hi in reach):
            continue
        page_bases.append({"A_img": off, "lui_val": hex(lui_val & 0xFFFFFFFF)})
        poff = off + 4
        hit = None
        for _ in range(8):
            ins = dis1(a_img, poff, IMG_LO + poff)
            if ins is None or is_retlike(ins):
                break
            if ins.size == 4 and (a_img[poff] & 0x7F) == 0x37:
                break
            m = ins.mnemonic
            try:
                ops = [x.strip() for x in ins.op_str.split(",")]
            except Exception:
                poff += ins.size
                continue
            if m in ("ld", "lw", "sd", "sw") and len(ops) == 2 and \
                    "(" in ops[1]:
                bas = ops[1].split("(")[1].rstrip(")")
                try:
                    lo = int(ops[1].split("(")[0], 0)
                except Exception:
                    lo = None
                if bas == REGS[rd] and lo is not None:
                    tgt = lui_val + lo
                    t, rel = in_window(tgt)
                    if t is not None:
                        hit = {"target": t["id"],
                               "value": hex(tgt & 0xFFFFFFFF),
                               "rel_to_lo": hex(rel),
                               "A_img": off, "rd": REGS[rd],
                               "access_at": poff,
                               "access": f"{m} {ins.op_str}",
                               "kind": "lui-access"}
                        break
            elif m in ("addi", "c.addi") and len(ops) >= 3 and \
                    ops[1] == REGS[rd]:
                try:
                    lo = int(ops[2], 0)
                    tgt = lui_val + lo
                    t, rel = in_window(tgt)
                    if t is not None:
                        hit = {"target": t["id"],
                               "value": hex(tgt & 0xFFFFFFFF),
                               "rel_to_lo": hex(rel),
                               "A_img": off, "rd": REGS[rd],
                               "access_at": poff,
                               "access": f"{m} {ins.op_str}",
                               "kind": "lui-addi-form"}
                        break
                except Exception:
                    pass
            if writes_reg(ins, REGS[rd]):
                break
            poff += ins.size
        if hit:
            probe1b.append(hit)
    out["probe1b_lui_access"] = probe1b
    out["page_base_lui_in_reach"] = len(page_bases)
    print(f"[probe1b] lui+access refs in windows: {len(probe1b)} "
          f"(page-bases in reach: {len(page_bases)})")

    # =========================================================
    # PROBE 2 — auipc + {addi|add|ld} PIC data-refs landing in windows
    # =========================================================
    probe2 = []
    for base_off in (0, 2):
        uarr = u0 if base_off == 0 else u2
        sel = starts[(starts & 3) == base_off]
        k = (sel - base_off) >> 2
        keep = (k + 1 < len(u0)) & (k >= 0)
        sel, k = sel[keep], k[keep]
        mask = (uarr[k] & 0x7F) == 0x17          # auipc
        sel, k = sel[mask], k[mask]
        if len(sel) == 0:
            continue
        w_a = uarr[k]
        rd_a = ((w_a >> 7) & 0x1F).astype(np.int64)
        hi20 = (w_a >> 12).astype(np.int64)
        hi20[hi20 >= 0x80000] -= 0x100000
        for j, soff in enumerate(sel.tolist()):
            rd = int(rd_a[j])
            if rd == 0:
                continue
            base_val = soff + (int(hi20[j]) << 12)
            # partner scan: the next 8 insns, first consumer wins
            poff = soff + 4
            for _ in range(8):
                ins = dis1(a_img, poff, IMG_LO + poff)
                if ins is None:
                    break
                if is_retlike(ins):
                    break
                if ins.size == 4 and (a_img[poff] & 0x7F) == 0x37:
                    break                          # a new auipc kills it
                m = ins.mnemonic
                try:
                    ops = [x.strip() for x in ins.op_str.split(",")]
                except Exception:
                    poff += ins.size
                    continue
                tgt = None
                if m in ("addi", "c.addi") and rd != 0:
                    if len(ops) >= 3 and ops[1] == REGS[rd]:
                        lo = int(ops[2], 0)
                        tgt = base_val + lo
                elif m == "add" and len(ops) >= 3 and \
                        ops[1] == REGS[rd]:
                    tgt = None                      # reg+reg: unknown
                elif m in ("ld", "lw") and len(ops) == 2 and \
                        "(" in ops[1]:
                    bas = ops[1].split("(")[1].rstrip(")")
                    try:
                        lo = int(ops[1].split("(")[0], 0)
                    except Exception:
                        lo = None
                    if bas == REGS[rd] and lo is not None:
                        tgt = base_val + lo         # the GOT-entry load
                if tgt is not None:
                    t, rel = in_window(tgt)
                    if t is not None:
                        probe2.append({
                            "target": t["id"], "value": hex(tgt & 0xFFFFFFFF),
                            "rel_to_lo": hex(rel), "seg": t["seg"],
                            "A_img": soff, "partner_at": poff,
                            "partner": f"{m} {ins.op_str}",
                            "kind": "got-load" if m in ("ld", "lw")
                            else "addr-form"})
                    break                           # first consumer wins
                if writes_reg(ins, REGS[rd]):
                    break                           # clobbered
                poff += ins.size
    out["probe2_pic_refs"] = probe2
    print(f"[probe2] auipc PIC data-refs in windows: {len(probe2)}")

    # =========================================================
    # PROBE 3 — data pointers: u64s inside the data LOAD pointing at
    # the target windows (code-island AND data), full segment scan.
    # (the widened diagnostic: 784 u64s point at code VAs, 2,086 at
    # data VAs — the question is whether ANY land in OUR windows)
    # =========================================================
    probe3 = []
    for i in range(DATA_FILESZ - 8):
        off = DATA_OFF + i
        v = struct.unpack_from("<Q", db, off)[0]
        t, rel = in_window(v)
        if t is None:
            continue
        # the 0x38 universe tolerance is inside in_window (PAD);
        # record which universe fits exactly
        univ = "cited" if any(
            t["lo"] <= v < t["hi"] for t in TARGETS if t["id"] == t["id"]
        ) else "shifted(0x38)"
        probe3.append({"target": t["id"],
                       "ptr_va": hex(DATA_VA + i),
                       "value": hex(v),
                       "rel_to_lo": hex(rel), "universe": univ})
    out["probe3_data_ptrs"] = probe3
    print(f"[probe3] data u64 pointers into windows: {len(probe3)}")

    # =========================================================
    # PROBE 5 — indexed access to data pages: lui <data-page> followed
    # (within 8 insns) by an access through the base reg OR through a
    # third reg (add rd3,rd,rs2 then access).  The diag census: 24 lui
    # values land in the data segment (0x4000000 x180 = the segment
    # base; 0x4040000 x2 = T1's 4KB page; 0x4090000 x14...).  For the
    # add-form the offset is dynamic — the SITE is the result.
    # =========================================================
    DATA_LO, DATA_HI = DATA_VA, DATA_VA + DATA_FILESZ
    probe5 = []
    for off, w1 in cands:
        rd = (w1 >> 7) & 0x1F
        if rd == 0 or (w1 & 0x7F) != 0x37:
            continue
        hi_s = (w1 >> 12) - (1 << 20) if (w1 >> 12) >= 0x80000 \
            else (w1 >> 12)
        lui_val = hi_s << 12
        if not (DATA_LO <= lui_val < DATA_HI):
            continue
        poff = off + 4
        for _ in range(8):
            ins = dis1(a_img, poff, IMG_LO + poff)
            if ins is None or is_retlike(ins):
                break
            if ins.size == 4 and (a_img[poff] & 0x7F) == 0x37:
                break
            m = ins.mnemonic
            try:
                ops = [x.strip() for x in ins.op_str.split(",")]
            except Exception:
                poff += ins.size
                continue
            rec = None
            if m in ("ld", "lw", "sd", "sw") and len(ops) == 2 and \
                    "(" in ops[1]:
                bas = ops[1].split("(")[1].rstrip(")")
                if bas == REGS[rd]:
                    rec = {"via": "base", "access": f"{m} {ins.op_str}",
                           "access_at": poff}
            elif m == "add" and len(ops) >= 3:
                if ops[1] == REGS[rd] or ops[2] == REGS[rd]:
                    # the sum reg becomes a base — find its first access
                    rd3 = ops[0]
                    p2 = poff + ins.size
                    for _ in range(6):
                        i2 = dis1(a_img, p2, IMG_LO + p2)
                        if i2 is None or is_retlike(i2):
                            break
                        if i2.mnemonic in ("ld", "lw", "sd", "sw") and \
                                "(" in i2.op_str.split(", ", 1)[1]:
                            bas2 = i2.op_str.split(", ", 1)[1].split(
                                "(")[1].rstrip(")")
                            if bas2 == rd3:
                                rec = {"via": "add-index",
                                       "access": f"{i2.mnemonic} {i2.op_str}",
                                       "access_at": p2}
                                break
                        if writes_reg(i2, rd3):
                            break
                        p2 += i2.size
            if rec is not None:
                rec.update({"A_img": off, "rd": REGS[rd],
                            "page": hex(lui_val)})
                probe5.append(rec)
                break
            if writes_reg(ins, REGS[rd]):
                break
            poff += ins.size
    out["probe5_indexed_pages"] = probe5
    pages_seen = sorted({p["page"] for p in probe5})
    out["probe5_pages"] = pages_seen
    print(f"[probe5] indexed/base accesses to data pages: {len(probe5)} "
          f"across pages {pages_seen}")

    # -- the data-page lui census (positions, no access requirement):
    #    the widened diag proved 24 lui values land in the data LOAD
    #    (0x4000000 x180 = the segment base, 0x4040000 x2 = T1's page).
    #    Bank their positions so the findings can cite them.
    dp = defaultdict(list)
    for off, w1 in cands:
        rd = (w1 >> 7) & 0x1F
        if rd == 0 or (w1 & 0x7F) != 0x37:
            continue
        hi_s = (w1 >> 12) - (1 << 20) if (w1 >> 12) >= 0x80000 \
            else (w1 >> 12)
        v = hi_s << 12
        if DATA_VA <= v < DATA_VA + DATA_FILESZ:
            dp[hex(v)].append(hex(off + IMG_LO))
    out["data_page_lui_census"] = {
        k: {"n": len(lst), "sites_first5": lst[:5]} for k, lst in
        sorted(dp.items())}
    print(f"[census] lui data-page values: {len(dp)}, "
          f"total sites: {sum(len(v) for v in dp.values())}")

    # =========================================================
    # The hit dossiers: seen-check, cited window, consumer, cross
    # =========================================================
    v435a = json.loads(V435A.read_text())
    knob_owners = []
    for k in v435a["knobs"]:
        for o in k.get("owners", []):
            knob_owners.append(int(o, 16) - IMG_LO)
    for s in v435a["shortlist_gated_tunable"]:
        for o in s.get("owners", []):
            knob_owners.append(int(o, 16) - IMG_LO)
    knob_owners = sorted(set(knob_owners))

    v435b = json.loads(V435B.read_text())
    regkey_xref_sites = []
    for c in v435b["regkey_cards"]:
        for x in c.get("xref_detail", []):
            try:
                regkey_xref_sites.append(
                    (int(x["va"], 16) - IMG_LO, c["name"]))
            except Exception:
                pass
    regkey_xref_sites.sort()

    def nearest(anchors, aoff):
        if not anchors:
            return None
        i = bisect_right(anchors, aoff) - 1
        best = None
        for j in (i, i + 1):
            if 0 <= j < len(anchors):
                d = abs(anchors[j] - aoff)
                if best is None or d < best[1]:
                    best = (j, d)
        return best

    dossiers = []
    for kind, plist in (("probe1", probe1), ("probe2", probe2)):
        for h in plist:
            aoff = h["A_img"]
            is_seen = bool(sarr[aoff]) if aoff < len(sarr) else False
            fs, fe = func_window(a_img, aoff)
            win = window_text(a_img, aoff)
            consumer = None
            rd = h.get("rd")
            if rd is None:
                rd = None
            off = aoff
            for _ in range(16):
                ins = dis1(a_img, off, IMG_LO + off)
                if ins is None:
                    break
                if off != aoff and reads_reg(ins, REGS[rd] if rd else ""):
                    consumer = f"{ins.mnemonic} {ins.op_str} @0x{off + IMG_LO:x}"
                    break
                if off != aoff and is_retlike(ins):
                    break
                off += ins.size
            ko = nearest(knob_owners, aoff)
            rk = nearest([s for s, _ in regkey_xref_sites], aoff)
            rk_name = None
            if rk is not None:
                rk_name = regkey_xref_sites[rk[0]][1]
            dossiers.append({
                "kind": kind, **{k2: h[k2] for k2 in
                                 ("target", "value", "rel_to_lo", "seg")},
                "A_img": aoff, "VA_A": hex(aoff + IMG_LO),
                "seen": is_seen, "func": [hex(fs) if fs is not None else None,
                                          hex(fe) if fe is not None else None],
                "consumer": consumer,
                "nearest_knob_owner": (hex(knob_owners[ko[0]]), ko[1])
                if ko else None,
                "nearest_regkey_xref": (rk_name, rk[1]) if rk else None,
                "window": win,
            })
    out["dossiers"] = dossiers

    # the probe5 dossiers: the data-page access sites (the real ref mass)
    p5_dossiers = []
    for h in probe5:
        aoff = h["A_img"]
        is_seen = bool(sarr[aoff]) if aoff < len(sarr) else False
        fs, fe = func_window(a_img, aoff)
        ko = nearest(knob_owners, aoff)
        rk = nearest([s for s, _ in regkey_xref_sites], aoff)
        p5_dossiers.append({
            "A_img": aoff, "VA_A": hex(aoff + IMG_LO), "seen": is_seen,
            "page": h["page"], "rd": h["rd"], "via": h["via"],
            "access": h["access"],
            "access_VA": hex(h["access_at"] + IMG_LO),
            "func": [hex(fs) if fs is not None else None,
                     hex(fe) if fe is not None else None],
            "nearest_knob_owner": (hex(knob_owners[ko[0]]), ko[1])
            if ko else None,
            "nearest_regkey_xref": (regkey_xref_sites[rk[0]][1], rk[1])
            if rk else None,
        })
    out["probe5_dossiers"] = p5_dossiers

    # the per-target roll-up
    roll = {}
    for t in TARGETS:
        hits = [d for d in dossiers if d["target"] == t["id"]]
        roll[t["id"]] = {
            "desc": t["desc"], "seg": t["seg"],
            "window_cited": [hex(t["lo"]), hex(t["hi"])],
            "n_code_refs": len(hits),
            "seen_verified": sum(1 for d in hits if d["seen"]),
            "consumers": [d["consumer"] for d in hits if d["consumer"]][:8],
        }
    out["rollup"] = roll
    n_total = sum(r["n_code_refs"] for r in roll.values())
    out["total_code_refs"] = n_total
    print(f"[rollup] total code refs into the banked tables: {n_total}")
    for tid, r in roll.items():
        if r["n_code_refs"]:
            print(f"  {tid}: {r['n_code_refs']} refs, consumers={r['consumers'][:2]}")

    OUT.write_text(json.dumps(out, indent=1))
    print(f"[out] {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
