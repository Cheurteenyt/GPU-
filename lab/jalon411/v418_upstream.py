#!/usr/bin/env python3
"""4.18 pass — the upstream formation pass (who forms the state pointers?).

Queue item 3 of 4.17: the 4.14 entry-value instrument re-run over the
verified map, aimed at the 15 long-trail X=? sites (11 honest-gap + 4
copied-from in 4.17) — the bases whose formation was beyond 512 verified
insns.

The 4.18 rule upgrade: the backward verified-trail walk now stops at the
FIRST RETURN crossed (ret / c.jr ra) — a function boundary the walk must
never cross. Within the site's own function, the base register's defining
event classifies the pointer's provenance:

  entry-arg      : mv base, aX — the state pointer is a FUNCTION ARGUMENT
                   (the caller hands it down — and per 4.16 the callers are
                   themselves dispatch targets: the pointer circulates in
                   the dispatch graph)
  ABI-carried    : no def before the ret — the register arrived holding the
                   pointer through the callee-saved ABI (handed down, the
                   strongest form)
  restored       : ld base, off(sp) mid-function (a non-ABI spill restore)
  static-formed  : auipc / lui (the pointer is formed locally — would
                   contradict the carried model; checked honestly)
  copied-carried : mv base, sY (one hop chased inside the same function)
  mv-other/ld-other/other-def / no-def-in-trail : honest buckets

Sites: the 15 verdict-bearing entries of v417_xresolve.json (honest-gap,
copied-from). The 34 no-verified-trail hosts stay dispatch-reached — no
trail exists to walk; that verdict is final by construction.

Output: lab/jalon411/v418_upstream.json
"""
import json
import struct
import zlib
from collections import defaultdict

import capstone
from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC

SUBSTRATE = "/home/z/my-project/repo-gpu/tools/gsp-extract/rm-full.elf"
MAP = "/home/z/my-project/repo-gpu/lab/jalon411/v416_map.bin"
XRES = "/home/z/my-project/repo-gpu/lab/jalon411/v417_xresolve.json"
OUT = "/home/z/my-project/repo-gpu/lab/jalon411/v418_upstream.json"

IMG_LO = 0x1000000
S_REGS = {f"s{i}" for i in range(12)} | {"fp"}
A_REGS = {f"a{i}" for i in range(8)}
TRAIL_LIMIT = 4096


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


def decode_at(md, code, pc):
    try:
        return next(md.disasm(code[pc:pc + 16], IMG_LO + pc))
    except StopIteration:
        return None


def back_trail(md, code, seen, site_off, limit=TRAIL_LIMIT):
    """EXACT 4.17 backstep logic: invalid candidates are SKIPPED, not fatal."""
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


def classify(trail, bas):
    rets = 0
    hops = []
    merges = []          # carried regs merged into the base (4.16 `add bas, sY`)
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
        # branches READ regs, they never write — skip before the writer test
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
            tag = "auipc+merge" if merges else "auipc"
            return f"static-formed({tag})", hops, rets, X
        if jn == "lui" and len(jp) == 2 and jsize == 4:
            try:
                X = sign_ext(int(jp[1], 0) & 0xFFFFF, 20)
            except Exception:
                X = None
            tag = "lui+merge" if merges else "lui"
            return f"static-formed({tag})", hops, rets, X
        if jn == "lui" and len(jp) == 2 and jsize == 2:
            try:
                X = int(jp[1], 0)          # c.lui — signed 6-bit, as decoded
            except Exception:
                X = None
            tag = "c.lui+merge" if merges else "c.lui"
            return f"static-formed({tag})", hops, rets, X
        if jn == "addi" and len(jp) == 3 and jp[1] == bas:
            continue                       # bas += imm — keep walking
        if jn == "addi" and len(jp) == 3 and jp[1] == "sp":
            return "sp-derived-frame", hops, rets, jp[2]
        if jn in ("addiw", "addw") and len(jp) == 3 and jp[1] == bas:
            continue                       # bas += imm (32-bit) — keep walking
        if jn == "add" and len(jp) == 3:
            if jp[1] == bas:
                if jp[2] in S_REGS or jp[2] in A_REGS:
                    hops.append(f"+{jp[2]}")
                    merges.append(f"+{jp[2]}")
                    continue               # the lui/page may still follow
                other_def = f"add {jops}"
                break
            if jp[1] == bas:               # add bas2, bas, sY — bas reused
                continue
            if jp[1] in S_REGS and jp[2] in S_REGS:
                # bas = sA + sB — sum of two carried pointers, no page const
                return "sum-of-carried", hops, rets, f"{jp[1]}+{jp[2]}"
            if jp[1] in S_REGS and jp[2] in A_REGS:
                return "sum-of-carried-and-arg", hops, rets, f"{jp[1]}+{jp[2]}"
            if jp[1] in A_REGS and jp[2] in S_REGS:
                return "sum-of-carried-and-arg", hops, rets, f"{jp[1]}+{jp[2]}"
            other_def = f"add {jops}"
            break
        if jn == "add" and len(jp) == 2:
            if jp[1] in A_REGS:
                hops.append(f"+{jp[1]}")
                merges.append(f"+{jp[1]}")
                continue                   # merge with an argument reg
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


def main():
    code = load()
    seen, _ = load_map()
    md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
    md.skipdata = True

    xres = json.load(open(XRES))
    targets = [r for r in xres["results"]
               if r.get("verdict") in ("honest-gap", "copied-from")]
    print("4.17 long-trail sites:", len(targets))

    results = []
    provs = defaultdict(int)
    for t in targets:
        site = int(t["site"], 16) - IMG_LO
        bas = t["base"]
        trail, reason = back_trail(md, code, seen, site)
        if not trail:
            provs["no-trail"] += 1
            results.append({"site": t["site"], "base": bas,
                            "verdict_417": t.get("verdict"),
                            "trail": 0, "stop": reason,
                            "provenance": "no-trail"})
            continue
        prov, hops, rets, extra = classify(trail, bas)
        slot = None
        merge_reg = None
        if prov.startswith("static-formed") and extra is not None:
            slot = hex((extra << 12) - 0x588)
            for hh in hops:
                if hh.startswith("+"):
                    merge_reg = hh[1:]
        provs[prov] += 1
        results.append({
            "site": t["site"], "width": t.get("width"), "base": bas,
            "verdict_417": t.get("verdict"),
            "trail_len": len(trail), "trail_stop": reason,
            "rets_crossed": rets, "hops": hops,
            "provenance": prov, "X": extra,
            "slot_off": slot, "merge_reg": merge_reg,
        })
        print(f"  {t['site']} base={bas} trail={len(trail)} rets={rets} prov={prov} "
              f"X={extra} slot={slot} merge={merge_reg}")

    out = {
        "pass": "4.18-upstream",
        "substrate": SUBSTRATE,
        "rule": "the backward verified-trail walk stops at the first return "
                "crossed (a function boundary); the base register's defining "
                "event inside the site's own function classifies its "
                "provenance.",
        "sites": len(targets),
        "provenance": dict(provs),
        "results": results,
    }
    json.dump(out, open(OUT, "w"), indent=1)
    print("provenance:", dict(provs))
    print("OUT", OUT)


if __name__ == "__main__":
    main()
