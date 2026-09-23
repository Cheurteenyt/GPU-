# 4.40 — the ROP gadget hunt in OUR bootloader (the runtime-lane preparation)

Substrate: tools/analysis/gsp-extract/bootloader.asm (5,370 instructions,
the plaintext libos booter — OUR build). The tools: the gadget scan
(the custom python, this pass) + tools/booter_emu.py (the RV64IMC
emulator, the 4.31 pass — the directed patch = the FAIL/PASS oracle
5/5).

## The runtime-lane context

Every static lane = closed (the INDEX, the 4.38 verdict): the power
never travels the transport, the rm.elf = booter-verified (the error
0xb, the empirical boot test), the kernel RAM copies = dead. The ONLY
proven-on-this-card execution lane = the RUNTIME ROP (the pass III:
the spin at 0x4a7 = the PC hijack confirmed in silicon). This pass =
the gadget inventory for that lane.

## The gadgets found (byte-cited)

**The WRITE-PRIMITIVE pair @0x100b3e+0x100b48** (the transfer gadget,
the transfer-list processor):
```
0x100b3e: ld   a5, 0x8(sp)      # la valeur = NOTRE pile (le memdesc 0xF800!)
0x100b40: addi a6, a5, 0x8      # le pointeur avance
0x100b44: ld   a5, 0x0(a5)      # la donnée = la charge utile
0x100b46: sd   a6, 0x8(sp)      # le pointeur sauvegardé (la boucle!)
0x100b48: sd   a5, 0x0(a1)      # L'ÉCRITURE : [a1] = la charge utile
```
= **a SELF-ADVANCING TRANSFER-LIST gadget**: the pointer at sp+8 walks
the list, each entry = [a1] ← the payload — the loop = BUILT INTO the
gadget (the bgeu a5, a0 @0x100b3a = the bounds vs a0 = the end marker).
The a1 = the caller's context register = OUR control via the ROP stack.

**The emulator = the gadget run = 39 steps, NO fault** (the budget
39 = the entry loop = the model = partial but the gadget = the live
flow = in-boot code, the 4.31's bounds demo = the same region).

## The gadgets for the FEAT write (the remaining hunt)

The FEAT PLM 0x00823804 = not materialized in the booter (the 0 lui
0x823/0x824). The chain = ours to build: the memdesc 0xF800 = OUR
bytes = the values at sp+8 = the transfer-list entries = the
{payload, target} pairs — the a1 = the base = the chain = via the ROP
stack = the addresses = ours to place. The paper's = "write_value @
f754, write_addr @f76c" = THEIR slots — OURS = this transfer-list
gadget = the SAME mechanism (the list = the entries {value,
next-ptr}).

## The next steps (the lane plan)

1. The transfer-list gadget = the base a1 = the control study (the
   callers of 0x100b48 = the contexts = the a1 sources).
2. The FEAT write = the entry {0x00823804-target, value} = via the
   transfer list = the emulation test (the risk-free).
3. The power-limit register = the write after the PLM open (the
   paper's sequence = the 4 writes = the 4 PLMs = OUR gadgets).

## The discipline

No machine writes. The emulator = the validation lane. The findings =
the banked evidence; the gadget scan = the tool committed (the custom
python, this pass).
