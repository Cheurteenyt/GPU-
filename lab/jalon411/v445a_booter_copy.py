#!/usr/bin/env python3
"""4.45 TÂCHE A — the memdesc→stack copy hunt in OUR bootloader.asm.

The paper's claim (Zenodo 20916112, silicon-proven on THIS card, the
spin 0x4a7): the memdesc signature = copied ONTO THE Booter's OWN
STACK via an UNBOUNDED DMA → the overflow → the canary defeated by
uniformity → the return hijacked → the ROP. This instrument proves or
refutes, ON OUR BYTES, each link:

  A1. the copy site: every store whose base = sp or an sp-derived
      register (the stack writes), classified:
        - the frame saves (the prologue/epilogue: ra + s-regs)
        - the data writes (the candidate buffer fills), and among
          them, those inside LOOPS (the copy candidates) with the
          bound source (a literal? a register? from where?);
      PLUS the "stack address escapes" — every point where an
      sp-derived address is passed OUT of the function (an SBI call
      arg, a memcpy arg): THE ROM-side DMA onto our stack = through
      these calls. The bound = the size arg paired at the same call.
  A2. the canary: the stack-protector patterns (a guard global stored
      adjacent to ra, compared in the epilogue), and any fixed-magic
      store in the frames.
  A3. the SBI service table: fn-ids, arg blocks, the output checks —
      the booter's privileged surface (the copy/hash/verify services
      live in the ROM, not here — the 4.31 verdict re-tested).

The banked counts re-asserted first: 84 c.ret (0x8082 bytes), 515
auipc lines in bootloader.asm, the image sha.

Output: lab/jalon411/v445a_booter_copy.json
"""
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASM = ROOT / "tools/analysis/gsp-extract/bootloader.asm"
BIN = ROOT / "tools/analysis/gsp-extract/binaries/bootloader.bin"
OUT = Path(__file__).with_suffix(".json")

INSN_RE = re.compile(
    r"^\s+([0-9a-f]+):\s+([0-9a-f ]+?)\s+(\S+)(?:\s+(.*?))?(?:\s*<[^>]*>)?\s*$"
)
FRAME_RE = re.compile(r"addi(?:16sp)?\s+sp,\s*sp,\s*(-0x[0-9a-f]+)$")
RET_RE = re.compile(r"^(ret|c\.ret)$")
STORE_RE = re.compile(r"^(sd|sw|sh|sb|c\.sd|c\.sw|c\.sdsp|c\.swsp)\s+(\S+),\s*(-?0x[0-9a-f]+)?\(?(\w+)\)?$")
LOAD_RE = re.compile(r"^(ld|lw|lwu|lb|lbu|lh|lhu|c\.ld|c\.lw|c\.ldsp)\s+(\S+),\s*(-?0x[0-9a-f]+)?\(?(\w+)\)?$")
SPDERIV_RE = re.compile(r"^(addi|c\.addi|mv|c\.mv|add)\s+(\w+),\s*(\w+)(?:,\s*(-?0x[0-9a-f]+))?$")


def parse():
    insns = []
    for line in ASM.read_text().splitlines():
        m = INSN_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        words = m.group(2).split()
        mn = m.group(3)
        ops = (m.group(4) or "").strip()
        insns.append({"addr": addr, "n": len(words) * 2, "mn": mn, "ops": ops,
                      "raw": line.strip()})
    return insns


def main():
    insns = parse()
    by_addr = {i["addr"]: i for i in insns}
    addrs = sorted(by_addr)

    # ---------- banked counts ----------
    blob = BIN.read_bytes()
    cret_bytes = sum(1 for k in range(len(blob) - 1)
                     if blob[k] == 0x82 and blob[k + 1] == 0x80)
    auipc_lines = sum(1 for i in insns if i["mn"] == "auipc")
    sha = hashlib.sha256(blob).hexdigest()

    # ---------- function segmentation ----------
    # a function = a frame-setup insn (addi sp,sp,-N / c.addi16sp) .. the
    # next frame-setup OR a leaf boundary. We keep the classic prologues.
    prologues = []
    for idx, i in enumerate(insns):
        if i["mn"] in ("addi", "c.addi16sp"):
            m = FRAME_RE.match(i["mn"] + " " + i["ops"])
            if m:
                prologues.append({"idx": idx, "addr": i["addr"],
                                  "frame": int(m.group(1), 16)})
    funcs = []
    for k, p in enumerate(prologues):
        end = prologues[k + 1]["idx"] if k + 1 < len(prologues) else len(insns)
        funcs.append({"addr": p["addr"], "frame": p["frame"],
                      "start_idx": p["idx"], "end_idx": end})

    def func_of(addr):
        for f in funcs:
            if f["addr"] <= addr < insns[f["end_idx"] - 1]["addr"] if f["end_idx"] > 0 else False:
                pass
        # simple linear scan
        lo = 0
        for f in funcs:
            if f["addr"] <= addr:
                lo = f
            else:
                break
        return lo if lo else None

    # ---------- per-function analysis ----------
    results = []
    for f in funcs:
        body = insns[f["start_idx"]:f["end_idx"]]
        faddr = f["addr"]
        # the ra save slot + the s-reg saves (the prologue stores to sp)
        ra_slot = None
        saves = []
        for i in body[:40]:
            m = STORE_RE.match(i["mn"] + " " + i["ops"])
            if m and m.group(4) == "sp":
                off = int(m.group(3), 16) if m.group(3) else 0
                if m.group(2) == "ra":
                    ra_slot = off
                saves.append((m.group(2), off))
        # sp-derived registers (data pointers into the frame)
        spderiv = {}  # reg -> offset
        for i in body:
            m = SPDERIV_RE.match(i["mn"] + " " + i["ops"])
            if m:
                dst, src, imm = m.group(2), m.group(3), m.group(4)
                if src == "sp":
                    spderiv[dst] = int(imm, 16) if imm else 0
                elif src in spderiv:
                    base = spderiv[src]
                    step = int(imm, 16) if imm else 0
                    spderiv[dst] = (base + step) & 0xFFFFFFFFFFFFFFFF
        # the data writes with sp/sp-derived bases
        writes = []
        for j, i in enumerate(body):
            m = STORE_RE.match(i["mn"] + " " + i["ops"])
            if not m:
                continue
            val, off, base = m.group(2), m.group(3), m.group(4)
            if base == "sp":
                o = int(off, 16) if off else 0
                kind = "frame_save" if (val in ("ra", "s0", "s1", "s2", "s3",
                                                "s4", "s5", "s6", "s7", "s8",
                                                "s9", "s10", "s11", "sp")
                                        and o >= 0
                                        and (ra_slot is not None and o >= min(
                                            [s[1] for s in saves] or [0]))) \
                    else "data"
                writes.append({"addr": i["addr"], "reg": val, "off": o,
                               "base": "sp", "kind": kind})
            elif base in spderiv:
                o = spderiv[base] + (int(off, 16) if off else 0)
                writes.append({"addr": i["addr"], "reg": val, "off": o & 0xFFFFFFFFFFFFFFFF,
                               "base": base, "kind": "via_ptr"})
        # the loops (backward branches) within the function
        loops = []
        for j, i in enumerate(body):
            if i["mn"] in ("bltu", "bgeu", "bne", "blt", "bge", "beq", "bltu",
                           "c.bnez", "c.beqz", "bnez", "beqz", "bltz", "bgez"):
                toks = i["ops"].split(", ")
                tgt = toks[-1]
                try:
                    t = (i["addr"] + int(tgt, 16)) & 0xFFFFFFFFFFFFFFFF
                except ValueError:
                    continue
                if t < i["addr"]:
                    loops.append({"site": i["addr"], "to": t})
        # the stack-address escapes: sp-derived regs passed as call args
        escapes = []
        for j, i in enumerate(body):
            if i["mn"] in ("jalr", "c.jalr", "jal", "ecall"):
                pass
            m = SPDERIV_RE.match(i["mn"] + " " + i["ops"])
            # escape = an sp-derived value moved into an A-register
            if m and m.group(2) in ("a0", "a1", "a2", "a3", "a4", "a5",
                                    "a6", "a7") and (m.group(3) == "sp"
                                                     or m.group(3) in spderiv):
                imm = m.group(4)
                escapes.append({"addr": i["addr"], "areg": m.group(2),
                                "src": m.group(3),
                                "off": int(imm, 16) if imm else 0})
        if writes or escapes or ra_slot is not None:
            results.append({
                "func": faddr, "frame": f["frame"], "ra_slot": ra_slot,
                "saves": saves, "sp_derived": {k: v for k, v in spderiv.items()
                                               if k not in ("sp",)},
                "stack_writes": writes, "loops": loops, "escapes": escapes,
            })

    # ---------- the SBI wrapper call table ----------
    # the wrapper @0x10045e: a5 = the fn-id (the caller's a0), a1 = the
    # block. The block = {fn, arg1..arg4}; the outputs = [block+8] status,
    # [block+0x10], [block+0x18].
    WRAP = 0x10045E
    sbi_calls = []
    for idx, i in enumerate(insns):
        if i["mn"] != "jalr":
            continue
        toks = [t.strip() for t in i["ops"].split(",")]
        # form A: 'jalr off(ra)' (rd=ra implicit); form B: 'jalr rd, rs, off'
        if len(toks) == 1 and "(" in toks[0]:
            off_s, rs = toks[0].split("(")
            rs = rs.rstrip(")")
            rd, off = "ra", int(off_s, 16)
        elif len(toks) == 3:
            rd, rs = toks[0], toks[1]
            off = int(toks[2], 16)
        else:
            continue
        if idx == 0 or insns[idx - 1]["mn"] != "auipc":
            continue
        au = insns[idx - 1]
        auops = [t.strip() for t in au["ops"].split(",")]
        if auops[0] != rs:
            continue
        try:
            auimm = int(auops[1], 16)
        except ValueError:
            continue
        tgt = (au["addr"] + (sx20(auimm) << 12) + off) & 0xFFFFFFFFFFFFFFFF
        if tgt != WRAP:
            continue
        # walk back up to 26 insns: the fn-id = the nearest li into a5/t1
        # BEFORE the block-store; the block base = addi a1/a0, sp, N
        fnid = None
        block = None
        block_stores = []
        for k in range(idx - 1, max(0, idx - 30), -1):
            t = insns[k]
            if block is None and t["mn"] in ("addi", "c.addi"):
                p = [x.strip() for x in t["ops"].split(",")]
                if len(p) == 3 and p[1] == "sp" and p[0] in ("a1", "a0"):
                    block = (p[0], int(p[2], 16))
            m = STORE_RE.match(t["mn"] + " " + t["ops"])
            if m and m.group(4) == "sp" and m.group(2) != "ra":
                off = int(m.group(3), 16) if m.group(3) else 0
                block_stores.append({"addr": t["addr"], "off": off,
                                     "reg": m.group(2)})
            if fnid is None and t["mn"] in ("li", "c.li"):
                p = [x.strip() for x in t["ops"].split(",")]
                if len(p) == 2 and p[0] in ("a5", "t1", "a4", "a3", "a2"):
                    fnid = int(p[1], 16)
        sbi_calls.append({"site": i["addr"], "fnid": fnid,
                          "block": block, "auipc": au["addr"],
                          "block_stores": block_stores})

    # ---------- canary (stack-protector) scan ----------
    # the pattern: in the prologue, a value loaded from a GLOBAL and stored
    # adjacent to ra; in the epilogue, a reload + a compare (bne) before ret.
    canary_hits = []
    for f in funcs:
        body = insns[f["start_idx"]:f["end_idx"]]
        ra_slot = None
        for i in body[:40]:
            m = STORE_RE.match(i["mn"] + " " + i["ops"])
            if m and m.group(4) == "sp" and m.group(2) == "ra":
                ra_slot = int(m.group(3), 16) if m.group(3) else 0
        if ra_slot is None:
            continue
        # prologue: ld X, off(g) ; sd X, ra_slot±0x10(sp)
        prot = []
        for i in body[:24]:
            m = STORE_RE.match(i["mn"] + " " + i["ops"])
            if m and m.group(4) == "sp":
                off = int(m.group(3), 16) if m.group(3) else 0
                if abs(off - ra_slot) <= 0x10 and m.group(2) not in (
                        "ra", "sp") and not m.group(2).startswith("s"):
                    # the saved reg = an a/t reg holding a canary? trace its def
                    prot.append({"store": i["raw"], "reg": m.group(2),
                                 "off": off})
        # epilogue: ld X, off(sp) then a compare against another reg
        cmps = []
        for j, i in enumerate(body):
            m = LOAD_RE.match(i["mn"] + " " + i["ops"])
            if m and m.group(4) == "sp":
                off = int(m.group(2 - 1), 16) if False else None
            if i["mn"] in ("bne", "c.bne", "beq", "c.beq") and j > len(body) - 40:
                cmps.append(i["raw"])
        if prot:
            canary_hits.append({"func": f["addr"], "ra_slot": ra_slot,
                                "suspect_stores": prot})
    # the booter = compiled without the stack protector IF canary_hits = []
    # with only ra/s-reg saves. The a/t-reg stores near ra = the suspects.

    # ---------- write x loop cross: the stack writes inside loops ----------
    write_loops = []
    for r in results:
        for w in r["stack_writes"]:
            for lp in r["loops"]:
                if lp["to"] <= w["addr"] < lp["site"] + 0x10 or \
                        (lp["to"] <= w["addr"] <= lp["site"]):
                    write_loops.append({"func": r["func"], "write": w,
                                        "loop": lp})
    # the strict form: the write lies between the loop target and the
    # branch (the loop body)
    write_loops = []
    for r in results:
        for w in r["stack_writes"]:
            for lp in r["loops"]:
                if lp["to"] <= w["addr"] <= lp["site"]:
                    write_loops.append({"func": r["func"],
                                        "write_addr": w["addr"],
                                        "write": w["reg"] + "," + hex(w["off"]),
                                        "base": w["base"], "kind": w["kind"],
                                        "loop_to": lp["to"],
                                        "loop_site": lp["site"]})

    out = {
        "image": {"sha256": sha, "bytes": len(blob)},
        "banked": {"c_ret_byte_0x8082": cret_bytes, "auipc_asm_lines": auipc_lines,
                   "banked_c_ret": 84, "banked_auipc": 515},
        "functions": len(funcs),
        "frames": [{"func": f["addr"], "frame": f["frame"]} for f in funcs],
        "stack_analysis": results,
        "sbi_wrapper_calls": sbi_calls,
        "canary_scan": {"suspect_functions": canary_hits,
                        "verdict_booter_stack_protector":
                            "PRESENT" if canary_hits else "ABSENT"},
        "stack_write_loops": write_loops,
    }
    OUT.write_text(json.dumps(out, indent=1))
    # the console digest
    print(f"image sha256 {sha[:16]}…  ({len(blob)} B)")
    print(f"banked re-assert: c.ret bytes 0x8082 = {cret_bytes} (banked 84) "
          f"-> {'MATCH' if cret_bytes == 84 else 'MISMATCH'}")
    print(f"banked re-assert: auipc asm lines = {auipc_lines} (banked 515) "
          f"-> {'MATCH' if auipc_lines == 515 else 'MISMATCH'}")
    print(f"functions with frames: {len(funcs)}")
    big = [f for f in funcs if -f['frame'] >= 0xa0]
    print("frames >= 0xa0:", [(hex(f['addr']), hex(-f['frame'])) for f in big])
    n_data = sum(1 for r in results
                 for w in r["stack_writes"] if w["kind"] != "frame_save")
    n_esc = sum(len(r["escapes"]) for r in results)
    print(f"stack data-writes (non frame-save): {n_data}")
    print(f"sp-derived A-register escapes: {n_esc}")
    print(f"SBI wrapper call sites: {len(sbi_calls)} "
          f"fn-ids: {[hex(c['fnid']) if c['fnid'] is not None else '?' for c in sbi_calls]}")
    print(f"canary (stack-protector) suspects: {len(canary_hits)} "
          f"-> verdict {out['canary_scan']['verdict_booter_stack_protector']}")
    print(f"stack writes INSIDE loops: {len(write_loops)}")
    for wl in write_loops[:12]:
        print(f"   func {wl['func']:#x} write {wl['write']} base={wl['base']}"
              f" kind={wl['kind']} loop {wl['loop_to']:#x}..{wl['loop_site']:#x}")


def sx20(v):
    v &= 0xFFFFF
    return v - (1 << 20) if v >> 19 else v


if __name__ == "__main__":
    main()
