#!/usr/bin/env python3
"""
4.42 TASK 1 — the callers of the transfer-list function 0x100aec.

The booter calls in auipc+jalr PIC pairs (the 4.33 census law). The
bootloader.asm = the objdump plaintext of PT_LOAD#0 (base 0x100000).
This scan finds every auipc ra,hi / jalr lo(ra) pair whose composed
target = 0x100aec (the transfer function entry), and every direct
jal/pc-relative branch into [0x100aec, 0x100ba6).

Rule banked (4.31 L7): capstone/objdump prints branch targets RELATIVE
(pc+imm); jalr = 3 tokens [rd, rs1, imm]; auipc imm20 = SIGNED in RV64.
"""
import re, json, sys

ASM = "tools/analysis/gsp-extract/bootloader.asm"
TARGET = 0x100AEC

insn_re = re.compile(
    r"^\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*?)\s*$")

insns = []
with open(ASM) as f:
    for line in f:
        m = insn_re.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        words = m.group(2)
        mnem = m.group(3)
        ops = m.group(4).split("#")[0].split("<")[0].strip()
        insns.append((addr, words, mnem, ops))

print(f"[+] {len(insns)} instructions parsed")

def parse_imm(tok):
    if tok is None:
        return None
    tok = tok.strip().replace("<PT_LOAD#0+0x", "P").rstrip(">")
    return tok

# --- auipc ra, imm / jalr imm2(ra) pairs ---
auipc_re = re.compile(r"^ra,\s*(-?0x[0-9a-f]+|-?\d+)$")
jalr_re  = re.compile(r"^(-?0x[0-9a-f]+|-?\d+)?\(ra\)$")

pairs = []
for i, (addr, w, mn, ops) in enumerate(insns):
    if mn != "auipc":
        continue
    m = auipc_re.match(ops)
    if not m:
        continue
    hi = int(m.group(1), 0)
    # next non-announced insn (allow the exact next slot)
    if i + 1 >= len(insns):
        continue
    a2, w2, mn2, ops2 = insns[i + 1]
    if mn2 != "jalr":
        continue
    m2 = jalr_re.match(ops2)
    if not m2:
        continue
    lo = int(m2.group(1), 0) if m2.group(1) else 0
    # RV64 auipc imm20 = SIGNED (lesson 4.31-L7); objdump prints hex
    # like 0xffffe = -2 semantically. Sign-extend from 20 bits.
    hi_s = hi if hi < 0x80000 else hi - 0x100000
    target = (addr + (hi_s << 12) + lo) & 0xFFFFFFFFFFFFFFFF
    pairs.append((addr, a2, target))

callers = [p for p in pairs if p[2] == TARGET]
print(f"[+] auipc+jalr pairs total: {len(pairs)}")
print(f"[+] calls targeting 0x100aec: {len(callers)}")
for addr, a2, t in callers:
    print(f"    call site 0x{addr:x} (jalr @0x{a2:x})")

# --- direct jal into the function range ---
direct = []
jal_re = re.compile(r"^0x([0-9a-f]+)")
for addr, w, mn, ops in insns:
    if mn in ("jal", "j"):
        m = jal_re.match(ops)
        if m:
            t = int(m.group(1), 16)
            if 0x100AEC <= t < 0x100BA6:
                direct.append((addr, mn, t))
print(f"[+] direct j/jal into [0x100aec,0x100ba6): {len(direct)}")
for addr, mn, t in direct:
    print(f"    0x{addr:x}: {mn} 0x{t:x}")

# --- also: any auipc+addi building the address 0x100aec into a register (call-via-reg) ---
out = {
    "target": TARGET,
    "auipc_jalr_pairs_total": len(pairs),
    "callers_of_0x100aec": [
        {"auipc": f"0x{a:x}", "jalr": f"0x{b:x}"} for a, b, t in callers
    ],
    "direct_jumps_into_range": [
        {"site": f"0x{a:x}", "mnem": mn, "target": f"0x{t:x}"} for a, mn, t in direct
    ],
}
with open("lab/jalon411/v442a_callers.json", "w") as f:
    json.dump(out, f, indent=2)
print("[+] wrote lab/jalon411/v442a_callers.json")
