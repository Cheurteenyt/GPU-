#!/usr/bin/env python3
"""
4.42 TASK 1b — how does the booter REACH 0x100aec?

Lanes:
  L1 — ALL jalr (any rs1) at seen starts: compose targets where the
       register was auipc-composed in the preceding window (window 4).
  L2 — auipc rx + jalr rx pairs NON-adjacent (gap <= 3 insns).
  L3 — u64 data words == 0x100aec / 0x100aec-relative pointers in the
       BOOTER BINARY (function-pointer tables). The binary = the
       container's booter (load_off law 4.33: true = load_off + 0x6d000
       is for the GFW BOOT AREA — the plaintext bootloader.elf is the
       reference here, VA = file offset + 0x100000 for PT_LOAD#0).
  L4 — the REACHED-BY-FALLTHROUGH check: is 0x100aec the target of any
       pc-relative branch with a WIDER range (c.j, beq/bne 8-bit...)?
       (objdump already resolves those — the v442a direct-j scan covered
       j/jal only; here we cover ALL conditional/compressed branches.)

The asm = the only substrate (PROVEN bytes). The binary = for the u64
pointer census.
"""
import re, struct, json

ASM = "tools/analysis/gsp-extract/bootloader.asm"
ELF = "tools/analysis/gsp-extract/bootloader.elf"
TARGET = 0x100AEC

insn_re = re.compile(r"^\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*?)\s*$")
insns = []
for line in open(ASM):
    m = insn_re.match(line)
    if m:
        insns.append((int(m.group(1), 16), m.group(2), m.group(3),
                      m.group(4).split("#")[0].split("<")[0].strip()))

print(f"[+] {len(insns)} insns")

def imm(tok):
    try:
        return int(tok, 0)
    except Exception:
        return None

# L1/L2: auipc rx,hi ... jalr [imm](rx)  within a 4-insn window
auipc_re = re.compile(r"^(r[ast]\d|ra|sp|gp|tp|t\d|s\d|a\d|zero),\s*(-?0x[0-9a-f]+|-?\d+)$")
jalr_any = re.compile(r"^(-?0x[0-9a-f]+|-?\d+)?\((\w+)\)$")

hits = []
for i, (addr, w, mn, ops) in enumerate(insns):
    if mn != "jalr":
        continue
    m = jalr_any.match(ops)
    if not m:
        continue
    lo = imm(m.group(1)) if m.group(1) else 0
    rs1 = m.group(2)
    if rs1 == "ra":
        continue  # covered by v442a
    # look back up to 4 insns for auipc rs1
    for back in range(1, 5):
        if i - back < 0:
            break
        a0, w0, mn0, ops0 = insns[i - back]
        if mn0 != "auipc":
            continue
        m0 = auipc_re.match(ops0)
        if m0 and m0.group(1) == rs1:
            hi = imm(m0.group(2))
            tgt = (a0 + (hi << 12) + lo) & 0xFFFFFFFFFFFFFFFF
            hits.append((addr, a0, rs1, tgt))
            break

print(f"[+] L1/L2 jalr-rx-with-auipc-base pairs: {len(hits)}")
for addr, a0, rs1, tgt in hits:
    mark = "  <<== TARGETS THE TRANSFER FN" if tgt == TARGET else ""
    print(f"    jalr @0x{addr:x} (base auipc @0x{a0:x} {rs1}) -> 0x{tgt:x}{mark}")

# L4: every branch whose RESOLVED target (objdump prints pc+imm) == in-range
br = re.compile(r"^0x([0-9a-f]+)$")
br_hits = []
for addr, w, mn, ops in insns:
    if mn in ("j", "jal"):
        continue
    m = br.match(ops.split(",")[-1].strip())
    if m:
        t = int(m.group(1), 16)
        if 0x100AEC <= t < 0x100BA6:
            br_hits.append((addr, mn, t))
print(f"[+] L4 branches into the transfer-fn range: {len(br_hits)}")
for addr, mn, t in br_hits[:10]:
    print(f"    0x{addr:x}: {mn} -> 0x{t:x}")

# L3: u64 words in the binary
data = open(ELF, "rb").read()
print(f"[+] bootloader.elf = {len(data)} B")
words = []
for off in range(0, len(data) - 8, 4):
    v = struct.unpack_from("<Q", data, off)[0]
    if v == TARGET:
        words.append(off)
print(f"[+] L3 u64 == 0x100aec in the ELF: {len(words)} at {['0x%x'%o for o in words[:10]]}")
# also the little-endian u32 halves (RV64 auipc-composed, but data tables hold full u64)
w32 = []
for off in range(0, len(data) - 4, 4):
    v = struct.unpack_from("<I", data, off)[0]
    if v == (TARGET & 0xFFFFFFFF):
        w32.append(off)
print(f"[+] L3b u32 == 0x00100aec: {len(w32)} at {['0x%x'%o for o in w32[:10]]}")

json.dump({
    "jalr_rx_pairs": [f"0x{a:x}->0x{t:x}" for a, _, r, t in hits],
    "jalr_rx_targeting_transfer_fn": [f"0x{a:x}" for a, _, _, t in hits if t == TARGET],
    "branches_into_range": [f"0x{a:x}:{mn}->0x{t:x}" for a, mn, t in br_hits],
    "u64_ptr_hits": [f"0x{o:x}" for o in words],
    "u32_half_hits": [f"0x{o:x}" for o in w32],
}, open("lab/jalon411/v442b_indirect.json", "w"), indent=2)
print("[+] wrote lab/jalon411/v442b_indirect.json")
