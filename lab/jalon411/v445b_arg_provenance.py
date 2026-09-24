#!/usr/bin/env python3
"""4.45 TÂCHE A — the argument PROVENANCE of every privileged call in the
booter's main flow (the SBI wrapper services + the internal memcpy).

Method: for each call site, walk BACKWARD from the site and build the
def-chain of every register that feeds the call:
  - the SBI wrapper @0x10045e consumes: a1 = the block base (addi a1, sp, N)
    and a0 = the token; the block words [0..0x20] = the stores
    (sd reg, N+off(sp)) immediately before; each source register is
    traced backward to its def (li/lui/auipc/addi/ld/mv) and CLASSIFIED:
      LIT  = a literal constant
      SP   = an sp-derived address (STACK ADDRESS ESCAPE — the decisive
             class: the ROM-side service writes our stack)
      OBJ  = loaded from an object/global (the runtime value)
      ARG  = the function's own incoming register
  - the memcpy @0x1029f6 consumes (a0=dst, a1=src, a2=n) — the same trace.

The classes answer TÂCHE A1: is there a copy onto the booter's stack
with a param-fed size? The answer = the byte table here.

Output: lab/jalon411/v445b_arg_provenance.json + the annotated windows
on stdout.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASM = ROOT / "tools/analysis/gsp-extract/bootloader.asm"
OUT = Path(__file__).with_suffix(".json")

INSN_RE = re.compile(
    r"^\s+([0-9a-f]+):\s+([0-9a-f ]+?)\s+(\S+)(?:\s+(.*?))?(?:\s*<[^>]*>)?\s*$"
)
AREGS = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
SREGS = ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
         "s10", "s11"]
TREGS = ["t0", "t1", "t2", "t3", "t4", "t5", "t6"]


def parse():
    insns = []
    for line in ASM.read_text().splitlines():
        m = INSN_RE.match(line)
        if m:
            insns.append({"addr": int(m.group(1), 16), "mn": m.group(3),
                          "ops": (m.group(4) or "").strip(),
                          "raw": line.strip()})
    return insns


def opsplit(s):
    return [x.strip() for x in s.split(",")] if s else []


def main():
    insns = parse()
    idx_of = {i["addr"]: k for k, i in enumerate(insns)}

    # ---------- locate the call sites ----------
    sites = []  # (kind, idx, target)
    for k, i in enumerate(insns):
        if i["mn"] != "jalr" or k == 0:
            continue
        toks = opsplit(i["ops"])
        prev = insns[k - 1]
        if prev["mn"] != "auipc":
            continue
        ptoks = opsplit(prev["ops"])
        if len(ptoks) != 2:
            continue
        # form A: jalr off(ra) ; form B: jalr rd, rs, off
        if len(toks) == 1 and "(" in toks[0]:
            off_s, rs = toks[0].split("(")
            rs = rs.rstrip(")")
            off = int(off_s, 16)
        elif len(toks) == 3:
            rs = toks[1]
            off = int(toks[2], 16)
        else:
            continue
        if ptoks[0] != rs:
            continue
        imm = int(ptoks[1], 16) & 0xFFFFF
        imm = imm - (1 << 20) if imm >> 19 else imm
        tgt = (prev["addr"] + (imm << 12) + off) & 0xFFFFFFFFFFFFFFFF
        if tgt in (0x10045E, 0x1029F6):
            sites.append({"idx": k, "addr": i["addr"], "kind": (
                "sbi" if tgt == 0x10045E else "memcpy"), "target": tgt})

    # ---------- the backward def-trace ----------
    WRITER = {"li", "c.li", "lui", "auipc", "addi", "c.addi", "mv", "c.mv",
              "add", "sub", "ld", "lw", "lwu", "lb", "lbu", "lh", "lhu",
              "c.ld", "c.lw", "c.ldsp", "slli", "srli", "srai", "andi",
              "ori", "xori", "sext.w", "zext.b", "addiw", "c.addiw",
              "slli64", "neg", "seqz", "snez", "c.slli", "c.srli"}

    def classify(def_insn, reg):
        mn, ops = def_insn["mn"], def_insn["ops"]
        p = opsplit(ops)
        if mn in ("li", "c.li"):
            return ("LIT", int(p[1], 16), def_insn)
        if mn == "lui":
            v = int(p[1], 16) & 0xFFFFF
            v = v - (1 << 20) if v >> 19 else v
            return ("LIT", (v << 12) & 0xFFFFFFFFFFFFFFFF, def_insn)
        if mn == "auipc":
            imm = int(p[1], 16) & 0xFFFFF
            imm = imm - (1 << 20) if imm >> 19 else imm
            return ("LIT", (def_insn["addr"] + (imm << 12)) & 0xFFFFFFFFFFFFFFFF,
                    def_insn)
        if mn in ("addi", "c.addi", "add"):
            src = p[1]
            off = 0
            if len(p) > 2:
                try:
                    off = int(p[2], 16)
                except ValueError:
                    off = 0
            if src == "sp":
                return ("SP", off, def_insn)
            if src == "zero":
                return ("LIT", off, def_insn)
            return ("DERIV", (src, off), def_insn)
        if mn in ("mv", "c.mv"):
            return ("COPY", p[1], def_insn)
        if mn in ("ld", "lw", "lwu", "lb", "lbu", "lh", "lhu", "c.ld",
                  "c.lw", "c.ldsp"):
            base = p[1].split("(")[1][:-1]
            off = int(p[1].split("(")[0] or "0", 16)
            return ("LOAD", (base, off), def_insn)
        if mn in ("addiw", "c.addiw"):
            return ("DERIV", (p[1], int(p[2], 16)), def_insn)
        if mn in ("slli", "srli", "srai", "c.slli", "c.srli", "slli64",
                  "srli64"):
            return ("SHIFT", (p[1], int(p[1] if len(p) == 2 else p[-1], 16)),
                    def_insn)
        if mn in ("andi", "ori", "xori"):
            return ("DERIV", (p[1], int(p[2], 16)), def_insn)
        return ("OTHER", ops, def_insn)

    def trace_back(reg, start_idx, depth=0):
        """walk backward to the nearest def of reg; return (class, val,
        insn, path) — the path = the defs of the SOURCES (depth 1)."""
        for k in range(start_idx - 1, max(0, start_idx - 400), -1):
            i = insns[k]
            p = opsplit(i["ops"])
            if not p:
                continue
            dst = p[0]
            if i["mn"] in ("sd", "sw", "sb", "sh", "c.sd", "c.sw", "c.sdsp"):
                continue
            if i["mn"] in ("jal", "jalr", "ecall", "ret", "c.jr", "c.jalr",
                           "c.j", "j"):
                # a call clobbers the caller-saved a-regs; the s-regs survive
                if dst == reg and reg in AREGS:
                    return ("ARG", None, i, [])
                continue
            if dst == reg and i["mn"] in WRITER:
                cls, val, di = classify(i, reg)
                subs = []
                if depth < 2 and cls in ("DERIV", "COPY", "SHIFT"):
                    src = val[0] if isinstance(val, tuple) else val
                    if src and src != "sp" and src != "zero":
                        subs = [trace_back(src, k, depth + 1)]
                elif depth < 2 and cls == "LOAD":
                    base, off = val
                    if base != "sp" and base != "zero":
                        subs = [trace_back(base, k, depth + 1)]
                return (cls, val, i, subs)
        return ("NONE", None, None, [])

    reports = []
    for s in sites:
        k = s["idx"]
        rep = {"addr": s["addr"], "kind": s["kind"],
               "window": [insns[j]["raw"] for j in
                          range(max(0, k - 30), min(len(insns), k + 3))]}
        if s["kind"] == "sbi":
            # the block base = the nearest backward addi a1, sp, N (or a0)
            blk = None
            for j in range(k - 1, max(0, k - 30), -1):
                i = insns[j]
                p = opsplit(i["ops"])
                if i["mn"] in ("addi", "c.addi") and len(p) == 3 and \
                        p[0] in ("a1", "a0") and p[1] == "sp":
                    blk = (p[0], int(p[2], 16), j)
                    break
            rep["block"] = None
            if blk:
                rep["block"] = {"base_reg": blk[0], "off": blk[1]}
                words = {}
                for j in range(k - 1, max(0, blk[2] - 40), -1):
                    i = insns[j]
                    p = opsplit(i["ops"])
                    if i["mn"] in ("sd", "sw", "c.sd", "c.sw") and len(p) == 2:
                        m2 = re.match(r"(-?0x[0-9a-f]+)?\((\w+)\)", p[1])
                        if m2 and m2.group(2) == "sp":
                            off = int(m2.group(1) or "0", 16)
                            if blk[1] <= off <= blk[1] + 0x20:
                                t = trace_back(p[0], j)
                                words[hex(off - blk[1])] = {
                                    "class": t[0],
                                    "val": (hex(t[1]) if isinstance(t[1], int)
                                            else t[1]),
                                    "def": t[2]["raw"] if t[2] else None,
                                    "subs": [
                                        {"class": u[0],
                                         "val": (hex(u[1]) if isinstance(u[1], int)
                                                 else u[1]),
                                         "def": u[2]["raw"] if u[2] else None}
                                        for u in t[3] if u[0] != "NONE"],
                                }
                rep["block"]["words"] = words
        else:  # memcpy: a0=dst, a1=src, a2=n
            args = {}
            for areg in ("a0", "a1", "a2"):
                t = trace_back(areg, k)
                args[areg] = {"class": t[0],
                              "val": (hex(t[1]) if isinstance(t[1], int) else t[1]),
                              "def": t[2]["raw"] if t[2] else None,
                              "subs": [{"class": u[0],
                                        "val": (hex(u[1]) if isinstance(u[1], int)
                                                else u[1]),
                                        "def": u[2]["raw"] if u[2] else None}
                                       for u in t[3] if u[0] != "NONE"]}
            rep["args"] = args
        reports.append(rep)

    OUT.write_text(json.dumps(reports, indent=1))
    for r in reports:
        print("=" * 78)
        print(f"{r['kind'].upper()} call @ {r['addr']:#x}")
        if r["kind"] == "sbi" and r["block"]:
            print(f"  block @sp{r['block']['off']:#x}:")
            for off, w in sorted(r["block"]["words"].items()):
                subs = " <- " + "; ".join(f"{u['class']} {u['val']}"
                                          for u in w["subs"]) if w["subs"] else ""
                print(f"    [+{off}] {w['class']:6} {str(w['val']):>18}"
                      f"  ({w['def']}){subs}")
        if r["kind"] == "memcpy":
            for a, w in r["args"].items():
                subs = " <- " + "; ".join(f"{u['class']} {u['val']}"
                                          for u in w["subs"]) if w["subs"] else ""
                print(f"  {a}: {w['class']:6} {str(w['val']):>18}"
                      f"  ({w['def']}){subs}")
    print(f"\nsites: {len(reports)} -> {OUT}")


if __name__ == "__main__":
    main()
