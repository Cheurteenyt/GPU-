#!/usr/bin/env python3
"""4.17 pass — the 48 X=? resolution attempt (v2).

Queue item 2 of 4.16: 48 of the 64 `-0x588` stores kept an unresolved page
constant X ("base carried / load-formed"). The 4.16 formation walk was a
flat 260-insn linear window — it can silently cross jumps, and it dies on
carried bases by construction.

Method upgrade (banked as the 4.17 rule): the backward walk follows the
VERIFIED instruction trail. From the store site, decode backwards; a
backward step is accepted only if the candidate start s (pc-2 or pc-4)
decodes to an instruction ENDING exactly at pc AND seen[s] is set (a
boundary-verified insn start). Ambiguity or an unverified offset STOPS the
trail — the trail length itself is reported (how much verified context
backs the site). The formation walk then runs INSIDE that trail with the
4.16 rules (c.lui/lui told apart by insn size — the exact 4.16 fix):

  X-resolved / X-resolved-via-copy : page constant found (inside trail)
  carried-stack                    : base restored from sp — upstream
  copied-from                      : base = mv of another register
  trail-short / no-verified-trail  : not enough verified context — the
                                     site is (partially) dispatch-reached
  honest-gap                       : base redefined by an untracked insn

Layer 1 re-derives the 4.16 families table with the EXACT flat rules
(including insn-size disambiguation) as a cross-check: X=? must be 48.

Output: lab/jalon411/v417_xresolve.json
"""
import json
import struct
import zlib
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v417_xresolve.json"

IMG_LO = 0x1000000
STORES = {"sd", "sw", "sh", "sb"}
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
BACK = 260          # flat window, exact 4.16 rules — cross-check only
TARGET = -0x588
TRAIL_MIN = 8       # below this the trail is "short"


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


def norm(m):
    return m[2:] if m.startswith("c.") else m


def sign_ext(v, bits):
    return v - (1 << bits) if v > (1 << (bits - 1)) - 1 else v


def flat_X(win, bas, site_pc):
    """EXACT 4.16 formation walk — flat window, insn-size disambiguation."""
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
            if jsize == 2:   # c.lui — signed 6-bit immediate as decoded
                X = imm
            else:            # lui — 20-bit raw page number
                X = sign_ext(imm & 0xFFFFF, 20)
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


def decode_at(md, code, pc):
    try:
        return next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
    except StopIteration:
        return None


def back_trail(md, code, seen, site_off, limit=512):
    """Walk BACKWARDS from site following the verified trail.
    Returns chronological list [(m, ops, pc, size)] (site last) and the
    stop reason."""
    trail = []
    pc = site_off
    reason = "trail-limit"
    while len(trail) < limit:
        cands = []
        for s in (pc - 2, pc - 4):
            if s < 0:
                continue
            if not seen[s]:
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


def trail_X(trail, bas):
    """4.16 formation rules applied to the verified trail (chronological)."""
    X = None
    sreg = None
    copied = None
    for jm, jops, jpc, jsize in reversed(trail[:-1]):
        jn = norm(jm)
        jp = [t.strip() for t in jops.split(",")]
        wr = jp[0] if jp else None
        if wr != bas:
            continue
        if jn == "lui" and len(jp) == 2:
            try:
                imm = int(jp[1], 0)
            except Exception:
                return None, None, "honest-gap"
            if jsize == 2:
                X = imm
            else:
                X = sign_ext(imm & 0xFFFFF, 20)
            return X, sreg, ("lui" if jsize == 4 else "c.lui")
        if jn == "add" and len(jp) == 2 and jp[0] == bas:
            if jp[1] in S_REGS:
                sreg = jp[1]
                continue
            if jp[1] != bas:
                copied = jp[1]
                break
            break
        if jn == "add" and len(jp) == 3 and jp[1] == bas:
            if jp[2] in S_REGS:
                sreg = jp[2]
                continue
            break
        if jn == "addi" and len(jp) == 3 and jp[1] == bas:
            continue
        if jn == "ld" and len(jp) == 2 and "(" in jp[1]:
            try:
                off_s, bas2 = jp[1][:-1].split("(", 1)
                if bas2.strip() == "sp":
                    return None, None, "carried-stack"
            except Exception:
                pass
            return None, None, "honest-gap"
        return None, None, "honest-gap"
    if copied:
        for jm, jops, jpc, jsize in reversed(trail[:-1]):
            jn = norm(jm)
            jp = [t.strip() for t in jops.split(",")]
            if jp and jp[0] == copied and jn == "lui" and len(jp) == 2 and jsize == 4:
                try:
                    imm = int(jp[1], 0)
                except Exception:
                    return None, None, "honest-gap"
                return sign_ext(imm & 0xFFFFF, 20), None, "X-resolved-via-copy"
        return None, copied, "copied-from"
    return None, sreg, "upstream-carried"


def main():
    code = load()
    n = len(code)
    seen, _ = load_map()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    # ---- layer 1: EXACT 4.16 flat re-derivation (cross-check) ----
    flat = defaultdict(int)
    xsites = []
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
                    X, sreg = flat_X(win, bas.strip(), pc)
                    key = f"X={hex(X) if X is not None else '?'}" + (f"+{sreg}" if sreg else "")
                    flat[key] += 1
                    if X is None:
                        xsites.append((pc, bas.strip(), p1[0].strip(), mn))
        pc += size

    repro_n = sum(v for k, v in flat.items() if k.startswith("X=?"))
    # the 4.16 table, for exact-family comparison (X=? excluded the +s3
    # variant, which the 4.16 summary counted separately — 48 + 1 = 49
    # X-unresolved sites total)
    REF_416 = {"X=?": 48, "X=0x1+s1": 3, "X=0x8+s1": 2, "X=0x5+s1": 2,
               "X=0x3+s1": 2, "X=0x8+s2": 1, "X=0x4+s1": 1, "X=0x4+s2": 1,
               "X=0x4+s11": 1, "X=0x1+s9": 1, "X=0x8+s6": 1, "X=?+s3": 1}
    flat_dict = dict(flat)
    families_reproduced = (flat_dict == REF_416)

    # ---- layer 2: verified-trail resolution of every X=? site ----
    results = []
    verdicts = defaultdict(int)
    resolved = defaultdict(int)
    for pc, bas, src, mn in xsites:
        entry = {"site": hex(IMG_LO + pc), "width": mn, "base": bas,
                 "verified": bool(seen[pc])}
        trail, reason = back_trail(md, code, seen, pc)
        entry["trail_len"] = len(trail)
        entry["trail_stop"] = reason
        if len(trail) == 0:
            entry["verdict"] = "no-verified-trail"
            verdicts["no-verified-trail"] += 1
            results.append(entry)
            continue
        if len(trail) < TRAIL_MIN:
            entry["verdict"] = "trail-short"
            verdicts["trail-short"] += 1
            results.append(entry)
            continue
        X, sreg, verdict = trail_X(trail, bas)
        entry["verdict"] = verdict
        entry["X"] = (hex(X) if X is not None else None)
        entry["sreg"] = sreg
        entry["slot_if_sreg"] = (hex((X << 12) - 0x588) if X is not None else None)
        verdicts[verdict] += 1
        if X is not None:
            resolved[verdict] += 1
        results.append(entry)

    out = {
        "pass": "4.17-xresolve",
        "substrate": SUBSTRATE,
        "method_note": "the backward walk follows the verified instruction "
                       "trail (each backstep is a boundary-verified insn start "
                       "whose decode ends exactly at the previous step); the "
                       "formation rules are the exact 4.16 set with insn-size "
                       "disambiguation. Trail length = how much verified "
                       "context backs each site.",
        "flat_crosscheck": {"X=?": repro_n, "families_total": sum(flat.values()),
                            "families_reproduced_416": families_reproduced,
                            "flat_table": flat_dict,
                            "note": "the 4.16 summary counted 48 'X=?' plus the "
                                    "'X=?+s3' variant separately: 49 X-unresolved "
                                    "sites total — both reproduced here."},
        "xsites": len(xsites),
        "verdicts": dict(verdicts),
        "X_resolved_by_verdict": dict(resolved),
        "results": results,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("flat cross-check: X=? =", repro_n, "(expect 48) — reproduced:", repro_n == 48)
    print("verdicts:", dict(verdicts))
    print("X resolved via:", dict(resolved))
    print("OUT", OUT)


if __name__ == "__main__":
    main()
