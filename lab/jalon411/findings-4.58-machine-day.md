# 4.58 MACHINE DAY — THE SYNTHESIS: the stock signature INTACT + the tail chain, the frame math, the clean negative

**The date: 2026-09-26 (the evening). 2 boots (the v448a + the v448b),
zero Xid, the rollback clean.**

## THE SYNTHESIS DESIGN (the machine-day insight chain)

The 4.44 = the signature replaced → the verify fails → 0x1d. The 4.45 =
the signature replaced → the spin. THE CONTRADICTION SOLVED BY THE
DESIGN: **the memdesc = ENLARGED to 0xf800 (the 4.57's creation mod),
the STOCK SIGNATURE = UNTOUCHED (the verify = passes by construction!),
the cmpunlocker ROP chain = written at the 0xf754+ TAIL** — the booter's
unbounded DMA copies the whole memdesc onto its small stack → the
overflow fires the chain DURING the copy → the write {0x001fa7c4 WPR ←
0xffffffff} → **the verify STILL passes → the boot proceeds with the
PLM OPEN.**

## v448a — the WPR_META miss (the boot: the same spin)

The v448a = the tail write + the flush ×2, BUT: **the WPR_META was NOT
re-pointed** — the booter reads `sysmemAddrOfSignature` +
`sizeOfSignature` FROM THE WPR META: without the re-point, the DMA
copies ONLY 0x1000 (the old size) — **the tail = NEVER DMA-éd**. The
probe post-mortem: WPR = 0x4cb8f = the stock = the write did not fire.
**The fix (v448b): the re-point = the cmpunlocker's critical lines
(decoded 2026-09-25) — `sysmemAddrOfSignature =
memdescGetPhysAddr(pMemdesc, AT_GPU, 0); sizeOfSignature =
memdescGetSize(pMemdesc);` + the WPR-meta descriptor flush.**

## v448b — the math of the frame: the chain was in the WRONG MILLENNIUM

The v448b = the WPR meta re-pointed + the flush + the chain at 0xf754.
The boot: the spin (the same) — **the probe post-mortem: WPR =
0x4cb8f = the write did NOT fire.**

**THE MATH THAT EXPLAINS EVERYTHING** (our own 4.45a inventory): the
copy's stack frame = **≤ 0x620 bytes = the word 196** — the return
address of the ROM's copy routine = within the words 0-196. **OUR chain
was at 0xf754 = the word 790 — TWO MILLENNIA PAST the frame.** The
return landed ON THE FILL (the value 0x4a7) → the jump to 0x4a7 = the
invalid address → **the trap loop = the spin.** At every boot. The
fill value, the canaries, the flush, the WPR re-point = all irrelevant
while the chain = beyond the frame.

**The cmpunlocker's 0xf754 = THEIR frame** (the CMP 170HX = the deeper
booter stack) — the position = per-architecture, not transferable.

## THE POST-MORTEM METHOD — the clean observable (the day's gift)

**The falcon = PLM-sealed** (the reads @0x110100 = 0xbadf5620 — the
driver itself cannot read the falcon CPUCTL): the spin = unobservable
directly. BUT **the PLM registers = host-readable post-boot** — **the
probe post-mortem = the CLEAN BINARY OBSERVABLE**: after each sweep
boot, WPR = 0xffffffff (the write fired!) or 0x4cb8f (the miss). The
falcon-spin interpretive quagmire = replaced by the binary read.

## THE NEXT WAVE — the position sweep

The cmpunlocker chain = SELF-CONTAINED (the parameters inline — no ctx
dependency) → **the position = free to relocate**. The sweep: the chain
relocated to {0x300, 0x400, 0x480, 0x500, 0x580} (the within-frame
positions), one boot per position, the PLM post-mortem per boot. **The
position that fires (the WPR = 0xffffffff) = the GA104's return slot =
THE CONTROL ACHIEVED** → the power-base write → nvidia-smi -pl 280.

## The arsenal

- v448_tail_write.c (tools/booter-patch/): the tail-write drop-in (the
  fill + the chain + the flush + the WPR meta re-point);
- patch448.py (~/dmem-451/ → the repo): the exact-anchor patcher (the
  include + the memdescCreate 0xf800 + the call);
- pgc6_probe.py: the PGC6 pair probe (the trajectory service pattern).

## The rollback

Proven 2× today (~2 commands): 0 v448 strings in the stock module, the
firmware sha = c0156954 = untouched. The machine = production clean.
