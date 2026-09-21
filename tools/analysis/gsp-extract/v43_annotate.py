#!/usr/bin/env python3
"""v43-annotate — ré-émet une fenêtre win-*.txt avec annotations:
  - auipc/addi résolus → nom de string si l'adresse cible est dans strings.json
  - jal/c.jal résolus → CALL <VA>
  - branches beq/bne/blt... → cible VA
Usage: python3 v43_annotate.py <win-file> [start_line] [end_line]
"""
import json
import re
import sys
from pathlib import Path

OUT = Path("/home/z/my-project/scratch-gsp/v42")
strings = {int(k, 16): v for k, v in
           json.loads((OUT / "strings.json").read_text()).items()}

BRANCH = re.compile(r"^\s*0x([0-9a-f]+):\s+(b(?:eq|ne|lt|ge|ltu|geu|nez|eqz)w?|c\.bnez|c\.beqz|beqz|bnez|c\.b?)(?:\s+(\S+))?\s+(.*)$")
AUIPC = re.compile(r"^\s*0x([0-9a-f]+):\s+auipc\s+(\S+),\s*(-?0x[0-9a-f]+|\d+)")
ADDI = re.compile(r"^\s*0x([0-9a-f]+):\s+c\.addi|addi\s+(\S+),\s*(\S+),\s*(-?0x[0-9a-f]+|-?\d+)$")


def parse_int(s):
    s = s.strip()
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    v = int(s, 0)
    return -v if neg else v


def annotate(path, lo=None, hi=None):
    lines = Path(path).read_text().splitlines()
    # registres: dernier auipc par registre
    auipc = {}
    out = []
    for idx, l in enumerate(lines):
        if not (lo is None or lo <= idx < hi):
            out.append(l)
            continue
        m = re.match(r"\s*0x([0-9a-f]+):\s+(\S+)\s*(.*)", l)
        if not m:
            out.append(l)
            continue
        pc = int(m.group(1), 16)
        mn = m.group(2)
        ops = m.group(3) or ""
        note = ""
        # auipc: target page
        am = re.match(r"^(\S+),\s*(-?0x[0-9a-f]+|\d+)$", ops)
        if mn == "auipc" and am:
            rd = am.group(1)
            imm = parse_int(am.group(2))
            auipc[rd] = pc + (imm << 12)
            out.append(l)
            continue
        # addi rd, rd, imm où rd provient d'un auipc
        if mn in ("addi", "c.addi"):
            pm = re.match(r"^(\S+),\s*(\S+),\s*(-?0x[0-9a-f]+|-?\d+)$", ops) if mn == "addi" \
                else re.match(r"^(\S+),\s*(-?0x[0-9a-f]+|-?\d+)$", ops)
            if pm:
                if mn == "addi":
                    rd, rs, imm = pm.group(1), pm.group(2), parse_int(pm.group(3))
                else:
                    rd, rs, imm = pm.group(1), pm.group(1), parse_int(pm.group(2))
                if rs in auipc:
                    tgt = auipc[rs] + imm
                    if tgt in strings:
                        s = strings[tgt]
                        note = f'  ;; STR {tgt:#x}: "{s}"'
                    else:
                        note = f"  ;; -> {tgt:#x}"
                    auipc.pop(rs, None)
                out.append(l + note)
                continue
        # jal
        if mn in ("jal", "c.jal") :
            jm = re.match(r"^(\S+),\s*(-?0x[0-9a-f]+|-?\d+)$", ops) or re.match(r"^(-?0x[0-9a-f]+|-?\d+)$", ops)
            if jm:
                tgt = jm.group(1)
                off = parse_int(tgt) if not re.match(r"^\S+,", ops) else parse_int(jm.group(2))
                out.append(l + f"  ;; CALL {pc+off:#x}")
                continue
        if mn == "jalr":
            out.append(l + f"  ;; CALL indirect")
            continue
        # branches: cible
        if mn.startswith("b") and not mn.startswith("binv"):
            bm = re.match(r"^(.*?)\s*,\s*(-?0x[0-9a-f]+|-?\d+)$", ops)
            if bm:
                try:
                    off = parse_int(bm.group(2))
                    out.append(l + f"  ;; BR -> {pc+off:#x}")
                    continue
                except Exception:
                    pass
        if mn in ("c.bnez", "c.beqz", "j", "c.j") and ops and re.match(r"^-?0x[0-9a-f]+$|^-?\d+$", ops.strip()):
            off = parse_int(ops.strip())
            out.append(l + f"  ;; BR -> {pc+off:#x}")
            continue
        out.append(l)
    return "\n".join(out)


if __name__ == "__main__":
    path = sys.argv[1]
    lo = int(sys.argv[2]) - 1 if len(sys.argv) > 2 else None
    hi = int(sys.argv[3]) if len(sys.argv) > 3 else None
    print(annotate(path, lo, hi))
