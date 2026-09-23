#!/usr/bin/env python3
"""
4.42 TASK 1d — WHO initializes the ring-config globals 0x124488/90/98/4a0?

Scan the plaintext asm for every auipc-composed address landing in the
window [0x124400, 0x124500) and classify: STORE (the writer = the
setup) / LOAD (the reader). The auipc imm20 = SIGNED in RV64 (lesson
4.31 L7); objdump prints the resolved auipc+addi pair as two insns.
"""
import re, json

ASM = "tools/analysis/gsp-extract/bootloader.asm"
insn_re = re.compile(r"^\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*?)\s*$")
insns = []
for line in open(ASM):
    m = insn_re.match(line)
    if m:
        insns.append((int(m.group(1), 16), m.group(2), m.group(3),
                      m.group(4).split("#")[0].split("<")[0].strip()))

auipc_re = re.compile(r"^(\w+),\s*(-?0x[0-9a-f]+|-?\d+)$")
add_re   = re.compile(r"^(\w+),\s*(\w+),\s*(-?0x[0-9a-f]+|-?\d+)$")
LO_RE    = re.compile(r"^(\w+),\s*(-?0x[0-9a-f]+|-?\d+)?\((\w+)\)$")

WINDOW_LO, WINDOW_HI = 0x124400, 0x124500
regs = {}   # reg -> composed address (best effort: auipc value alone or +addi)
events = []

# pass 1: auipc rx, imm and the IMMEDIATE next addi/add/ld/store with
# %lo — the canonical composition.
i = 0
while i < len(insns):
    addr, w, mn, ops = insns[i]
    if mn == "auipc":
        m = auipc_re.match(ops)
        if m:
            rd_, hi = m.group(1), int(m.group(2), 0)
            base = (addr + (hi << 12)) & 0xFFFFFFFFFFFFFFFF
            # look ahead up to 3 insns for addi rd, rd, lo
            composed = base
            used = 0
            for k in range(1, 4):
                if i + k >= len(insns):
                    break
                a2, w2, mn2, ops2 = insns[i + k]
                m2 = add_re.match(ops2)
                if m2 and m2.group(1) == rd_ and m2.group(2) == rd_:
                    lo = int(m2.group(3), 0)
                    # RV %lo is sign-extended 12-bit
                    if lo >= 0x800:
                        lo -= 0x1000
                    composed = (base + lo) & 0xFFFFFFFFFFFFFFFF
                    used = k
                    break
            regs[rd_] = (composed, addr, used)
    i += 1

# pass 2: every memory op with an offset(reg) — resolve reg from the
# LAST composed value (linear scan, per function window this is exact
# enough for a census).
cur = {}
for addr, w, mn, ops in insns:
    if mn == "auipc":
        m = auipc_re.match(ops)
        if m:
            rd_, hi = m.group(1), int(m.group(2), 0)
            cur[rd_] = ((addr + (hi << 12)) & 0xFFFFFFFFFFFFFFFF, addr)
        continue
    m2 = add_re.match(ops)
    if m2 and m2.group(1) == m2.group(2) and m2.group(1) in cur:
        base, baddr = cur[m2.group(1)]
        lo = int(m2.group(3), 0)
        if lo >= 0x800:
            lo -= 0x1000
        cur[m2.group(1)] = ((base + lo) & 0xFFFFFFFFFFFFFFFF, baddr)
        continue
    m3 = LO_RE.match(ops)
    if m3 and m3.group(3) in cur:
        base, baddr = cur[m3.group(3)]
        disp = int(m3.group(2), 0) if m3.group(2) and re.match(r'^-?(0x[0-9a-f]+|\d+)$', m3.group(2)) else 0
        if disp >= 0x800:
            disp -= 0x1000
        eff = (base + disp) & 0xFFFFFFFFFFFFFFFF
        if WINDOW_LO <= eff < WINDOW_HI:
            events.append((addr, mn, m3.group(1), eff, baddr))
    # also plain moves clobber: mv rd, rs (cheap model)
    mm = re.match(r"^(\w+),\s*(\w+)$", ops)
    if mn in ("mv",) and mm and mm.group(2) in cur:
        cur[mm.group(1)] = cur[mm.group(2)]

print(f"[+] memory ops landing in [0x{WINDOW_LO:x},0x{WINDOW_HI:x}): {len(events)}")
for addr, mn, rd_, eff, baddr in events:
    print(f"  0x{addr:x}: {mn} {rd_}, -> 0x{eff:x}   (base auipc @0x{baddr:x})")

json.dump([{"site": f"0x{a:x}", "mnem": mn, "reg": r, "eff": f"0x{e:x}"}
           for a, mn, r, e, b in events],
          open("lab/jalon411/v442d_ring_setup.json", "w"), indent=2)
print("[+] wrote lab/jalon411/v442d_ring_setup.json")
