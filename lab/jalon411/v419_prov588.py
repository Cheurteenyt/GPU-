#!/usr/bin/env python3
"""4.19 pass — the full provenance table of the -0x588 family.

Queue item 1 of 4.18: re-apply the 4.18 provenance machine (ret-frontiere +
c.lui/merge chase + slot capture) to ALL -0x588 stores — one merged table
for the whole family, classified by SEMANTICS (the 4.18 finding that the
family mixes state slots, local frame fields, and data pages):

  state-slot  : base handed down and page-merged or carried — the store
                writes a state structure's -0x588 field (slot = base +
                (X<<12) - 0x588 when X resolved)
  frame       : base = addi s0, sp, imm — the store writes a LOCAL FRAME
  data        : base absolute (auipc/lui/c.lui with NO carried merge) — the
                store writes a data page, not a structure
  no-trail    : no verified trail exists (4.17 verdict final by construction)
  indeterminate / trail-short / other-def : honest buckets

Layers (byte-exact cross-checks first):
  1. inventory: every store sd/sw/sh/sb with literal offset -0x588 — the
     flat 4.16 formation walk re-derived and compared to the FULL REF_416
     family table (48 X=? + 1 X=?+s3 + 15 resolved = 64 sites);
  2. the 4.17 verdicts (from v417_xresolve.json) merged per site;
  3. the 4.18 upstream provenance (from v418_upstream.json, 15 sites)
     merged per site — then the 4.18 machine re-run FRESH on all 64:
     every site in both scopes must classify identically (machine
     reproducibility is asserted);
  4. the 4.19 semantic axis per site — the full table.

Output: lab/jalon411/v419_prov588.json
"""
import json
import struct
import zlib
from bisect import bisect_right
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
XRES = "/home/z/my-project/repo-gpu/lab/jalon411/v417_xresolve.json"
UPST = "/home/z/my-project/repo-gpu/lab/jalon411/v418_upstream.json"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v419_prov588.json"

IMG_LO = 0x1000000
STORES = {"sd", "sw", "sh", "sb"}
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
TRAIL_LIMIT = 4096
TRAIL_MIN = 8
TARGET = -0x588
BACK = 260  # flat 4.16 window — cross-check only

REF_416 = {"X=?": 48, "X=0x1+s1": 3, "X=0x8+s1": 2, "X=0x5+s1": 2,
           "X=0x3+s1": 2, "X=0x8+s2": 1, "X=0x4+s1": 1, "X=0x4+s2": 1,
           "X=0x4+s11": 1, "X=0x1+s9": 1, "X=0x8+s6": 1, "X=?+s3": 1}


def load():
    d = open(SUBSTRATE, "rb").read()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize = struct.unpack_from("<H", d, 54)[0]
    e_phnum = struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
        if p_type == 1:
            return d[p_off:p_off + p_filesz]


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


def norm(m):
    return m[2:] if m.startswith("c.") else m


def sign_ext(v, bits):
    return v - (1 << bits) if v > (1 << (bits - 1)) - 1 else v


def decode_at(md, code, pc):
    try:
        return next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
    except StopIteration:
        return None


def back_trail(md, code, seen, site_off, limit=TRAIL_LIMIT):
    """EXACT 4.17/4.18 backstep: candidates skipped, not fatal."""
    trail = []
    pc = site_off
    reason = "trail-limit"
    while len(trail) < limit:
        cands = []
        for s in (pc - 2, pc - 4):
            if s < 0 or not seen[s]:
                continue
            ins = decode_at(md, code, s)
            if ins is None or ins.size != pc - s or ins.mnemonic in (".byte", "(bad)"):
                continue
            cands.append((s, ins))
        if len(cands) == 1:
            s, ins = cands[0]
            trail.append((ins.mnemonic, ins.op_str, s, ins.size))
            pc = s
        elif len(cands) > 1:
            reason = "ambiguous-backstep"
            break
        else:
            reason = "unverified-edge"
            break
    trail.reverse()
    return trail, reason


BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez",
            "c.beqz", "c.bnez", "j", "c.j"}


def classify_418(trail, bas):
    """The 4.18 machine: stop at first return; chase merges to the page const."""
    rets = 0
    hops = []
    merges = []
    other_def = None
    for jm, jops, jpc, jsize in reversed(trail[:-1]):
        jn = norm(jm)
        if (jn == "ret" or (jn == "jr" and jops.strip() == "ra")
                or (jn == "c.jr" and jops.strip() == "ra")):
            rets += 1
            if rets == 1:
                if merges:
                    return "abi-carried-plus-reg", hops, rets, ",".join(merges)
                return "ABI-carried", hops, rets, None
        if jn in BRANCHES:
            continue
        jp = [t.strip() for t in jops.split(",")]
        wr = jp[0] if jp else None
        if wr != bas:
            continue
        if jn == "mv" and len(jp) == 2:
            src = jp[1]
            if src in A_REGS:
                return "entry-arg", hops, rets, None
            if src in S_REGS:
                hops.append(f"={src}")
                merges.append(f"={src}")
                bas = src
                continue
            other_def = f"mv {jops}"
            break
        if jn in ("ld", "lw") and len(jp) == 2 and "(" in jp[1]:
            try:
                off_s, b2 = jp[1][:-1].split("(", 1)
                if b2.strip() == "sp":
                    return "restored", hops, rets, None
                if b2.strip() in A_REGS:
                    return "loaded-from-arg", hops, rets, f"{jn} {jops}"
                return "loaded-from-carried", hops, rets, f"{jn} {jops}"
            except Exception:
                pass
            other_def = f"{jn} {jops}"
            break
        if jn == "auipc" and len(jp) == 2:
            try:
                X = sign_ext(int(jp[1], 0) & 0xFFFFF, 20)
            except Exception:
                X = None
            return f"static-formed({'auipc+merge' if merges else 'auipc'})", hops, rets, X
        if jn == "lui" and len(jp) == 2 and jsize == 4:
            try:
                X = sign_ext(int(jp[1], 0) & 0xFFFFF, 20)
            except Exception:
                X = None
            return f"static-formed({'lui+merge' if merges else 'lui'})", hops, rets, X
        if jn == "lui" and len(jp) == 2 and jsize == 2:
            try:
                X = int(jp[1], 0)
            except Exception:
                X = None
            return f"static-formed({'c.lui+merge' if merges else 'c.lui'})", hops, rets, X
        if jn == "addi" and len(jp) == 3 and jp[1] == bas:
            continue
        if jn == "addi" and len(jp) == 3 and jp[1] == "sp":
            return "sp-derived-frame", hops, rets, jp[2]
        if jn in ("addiw", "addw") and len(jp) == 3 and jp[1] == bas:
            continue
        if jn == "add" and len(jp) == 3:
            if jp[1] == bas:
                if jp[2] in S_REGS or jp[2] in A_REGS:
                    hops.append(f"+{jp[2]}")
                    merges.append(f"+{jp[2]}")
                    continue
                other_def = f"add {jops}"
                break
            if jp[1] == bas:
                continue
            if jp[1] in S_REGS and jp[2] in S_REGS:
                return "sum-of-carried", hops, rets, f"{jp[1]}+{jp[2]}"
            if (jp[1] in S_REGS and jp[2] in A_REGS) or (jp[1] in A_REGS and jp[2] in S_REGS):
                return "sum-of-carried-and-arg", hops, rets, f"{jp[1]}+{jp[2]}"
            other_def = f"add {jops}"
            break
        if jn == "add" and len(jp) == 2:
            if jp[1] in A_REGS:
                hops.append(f"+{jp[1]}")
                merges.append(f"+{jp[1]}")
                continue
            if jp[1] in S_REGS and jp[1] != bas:
                hops.append(f"={jp[1]}")
                merges.append(f"={jp[1]}")
                bas = jp[1]
                continue
            other_def = f"add {jops}"
            break
        other_def = f"{jn} {jops}"
        break
    if merges and other_def:
        return "merge-then-other-def", hops, rets, other_def
    if other_def:
        return "other-def", hops, rets, other_def
    return "no-def-before-trail-end", hops, rets, None


def flat_X(win, bas, site_pc):
    """EXACT 4.16 flat formation walk — cross-check only."""
    X = None
    sreg = None
    for jm, jops, jpc, jsize in reversed(win):
        if jpc == site_pc:
            continue
        jn = norm(jm)
        jp = [t.strip() for t in jops.split(",")]
        wr = jp[0] if jp else None
        if wr != bas:
            continue
        if jn == "lui" and len(jp) == 2:
            try:
                imm = int(jp[1], 0)
            except Exception:
                return None, None
            X = imm if jsize == 2 else sign_ext(imm & 0xFFFFF, 20)
            break
        if jn == "add" and len(jp) == 2 and jp[0] == bas:
            if jp[1] in S_REGS:
                sreg = jp[1]
                continue
            break
        if jn == "add" and len(jp) == 3 and jp[1] == bas:
            if jp[2] in S_REGS:
                sreg = jp[2]
            continue
        if jn == "addi" and len(jp) == 3 and jp[1] == bas:
            continue
        break
    return X, sreg


def semantics(prov):
    """4.19 semantic axis: what DOES the -0x588 store hit?"""
    if prov == "no-trail" or prov == "trail-short":
        return prov
    if prov in ("static-formed(auipc)", "static-formed(lui)", "static-formed(c.lui)"):
        return "data"
    if prov == "sp-derived-frame":
        return "frame"
    if prov in ("static-formed(c.lui+merge)", "static-formed(lui+merge)",
                "entry-arg", "ABI-carried", "abi-carried-plus-reg", "restored",
                "sum-of-carried", "sum-of-carried-and-arg",
                "loaded-from-arg", "loaded-from-carried"):
        return "state-slot"
    if prov == "static-formed(auipc+merge)":
        return "hybrid-data-carried"
    return "indeterminate"


def main():
    code = load()
    n = len(code)
    seen, covered = load_map()
    reg_starts, reg_ends = build_regions(covered)

    def region_of(pc):
        k = bisect_right(reg_starts, pc) - 1
        if k >= 0 and reg_starts[k] <= pc < reg_ends[k]:
            return k
        return None

    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    # ---- layer 1: inventory + EXACT flat 4.16 cross-check ----
    inv = []
    flat = defaultdict(int)
    pc = 0
    win = []
    while pc < n - 2:
        try:
            insn = next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
        except StopIteration:
            win.clear()
            pc += 2
            continue
        m, ops = insn.mnemonic, insn.op_str
        size = insn.size
        if m not in (".byte", "(bad)"):
            win.append((m, ops, pc, size))
            if len(win) > BACK + 2:
                win.pop(0)
        mn = norm(m)
        if mn in STORES:
            p1 = ops.split(", ")
            if len(p1) == 2 and "(" in p1[1]:
                try:
                    off_s, bas = p1[1][:-1].split("(", 1)
                    off = int(off_s.strip(), 0)
                except Exception:
                    off = None
                if off == TARGET:
                    bas = bas.strip()
                    X, sreg = flat_X(win, bas, pc)
                    key = f"X={hex(X) if X is not None else '?'}" + (f"+{sreg}" if sreg else "")
                    flat[key] += 1
                    inv.append({"pc": pc, "width": mn, "base": bas,
                                "X_flat": X, "sreg_flat": sreg})
        pc += size

    flat_dict = dict(flat)
    repro = flat_dict == REF_416
    print("inventory:", len(inv), "-0x588 stores | flat table reproduced 4.16:", repro)
    assert repro, f"4.16 cross-check FAILED: {flat_dict}"

    # ---- prior verdicts to merge ----
    xres = json.load(open(XRES))
    v417 = {r["site"]: r for r in xres["results"]}
    upst = json.load(open(UPST))
    v418 = {r["site"]: r for r in upst["results"]}

    # ---- layers 2-4: the merged provenance table ----
    results = []
    sem_count = defaultdict(int)
    prov_count = defaultdict(int)
    mismatch = 0
    for s in inv:
        site_hex = hex(IMG_LO + s["pc"])
        bas = s["base"]
        r = region_of(s["pc"])
        rname = (hex(IMG_LO + reg_starts[r]) + "-" + hex(IMG_LO + reg_ends[r])
                 if r is not None else "UNCOVERED")
        row = {"site": site_hex, "width": s["width"], "base": bas,
               "verified": bool(seen[s["pc"]]), "region": rname,
               "family_416": f"X={hex(s['X_flat']) if s['X_flat'] is not None else '?'}"
                             + (f"+{s['sreg_flat']}" if s["sreg_flat"] else "")}
        if site_hex in v417:
            row["verdict_417"] = v417[site_hex].get("verdict")
            row["trail_len_417"] = v417[site_hex].get("trail_len")
        if site_hex in v418:
            row["provenance_418_upstream"] = v418[site_hex].get("provenance")

        trail, reason = back_trail(md, code, seen, s["pc"])
        row["trail_len_419"] = len(trail)
        row["trail_stop_419"] = reason
        if len(trail) < TRAIL_MIN:
            row["provenance_419"] = "trail-short" if trail else "no-trail"
        else:
            prov, hops, rets, extra = classify_418(trail, bas)
            row["rets_crossed"] = rets
            row["hops"] = hops
            row["provenance_419"] = prov
            if prov.startswith("static-formed") and isinstance(extra, int):
                row["X_resolved_419"] = hex(extra)
                row["slot_off_419"] = hex((extra << 12) - 0x588)
                for hh in hops:
                    if hh.startswith("+"):
                        row["merge_reg"] = hh[1:]
            elif isinstance(extra, str):
                row["detail"] = extra
        # reproducibility: where 4.18 also classified this site, agree
        if "provenance_418_upstream" in row and "provenance_419" in row:
            if row["provenance_418_upstream"] != row["provenance_419"]:
                mismatch += 1
                row["MISMATCH_418_419"] = True
        row["semantics_419"] = semantics(row["provenance_419"])
        prov_count[row["provenance_419"]] += 1
        sem_count[row["semantics_419"]] += 1
        results.append(row)
        print(f"  {site_hex} base={bas} fam={row['family_416']} "
              f"trail={row['trail_len_419']} prov={row['provenance_419']} "
              f"sem={row['semantics_419']} X={row.get('X_resolved_419')} "
              f"slot={row.get('slot_off_419')}")

    assert mismatch == 0, f"4.18/4.19 machine mismatch on {mismatch} sites"
    out = {
        "pass": "4.19-prov588",
        "substrate": SUBSTRATE,
        "inventory": len(inv),
        "flat_crosscheck_reproduced_416": repro,
        "flat_table": flat_dict,
        "machine_reproducibility_418_vs_419": "mismatch-free on all shared sites",
        "provenance_419": dict(prov_count),
        "semantics_419": dict(sem_count),
        "results": results,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("provenance:", dict(prov_count))
    print("semantics:", dict(sem_count))
    print("OUT", OUT)


if __name__ == "__main__":
    main()
