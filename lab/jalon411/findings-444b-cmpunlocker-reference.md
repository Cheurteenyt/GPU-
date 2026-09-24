# 4.44b-machine — THE PUBLIC REFERENCE FOUND: cmpunlocker = the working
# implementation of the SAME bug class; the 4.45 lane = fully specified

Date: 2026-09-24, 02h46. Source: the internet research (the user's
directive) + the local repos (the data disk) + the GitHub.

## The discovery chain

1. **Jon Pry = at Arizona State University**; the follow-up paper
   « Defeating Stack Protection in a GPU Secure Coprocessor » (June
   2026, ResearchGate). The Yahoo Tech coverage (Aug 18, 2026) = the
   blueprint for bypassing the Falcon security microprocessor.
2. **cmpunlocker = the WORKING public tool** (amoghmunikote/cmpunlocker
   on GitHub; the d3dx9 fork = also on our data disk) unlocking the
   CMP 170HX (the GA100 silicon) to the A100 level — the Tom's
   Hardware coverage (Aug 2026): 64 GB VRAM + the SMs restored,
   independently replicated, the prices exploded.
3. **The mechanism (the README + build.py + pipeline.py)**: the
   BootROM loads the `.fwsignature_ga100` ELF section into the DMEM
   BEFORE verifying the signature (the bug) → the section = replaced
   with the ROP payload → the chain runs in HS mode regardless of the
   signature validity.
4. **The driver fork = open-gpu-kernel-modules-610.43.03** — the patch
   file = in the repo:
   `driver/patches/sec2-postbl-plm-ss-cfg.patch` (470 lines; the copy
   = in OUR repo at imports/cmpunlocker/sec2-postbl.patch).

## The reference implementation (the patch, decoded)

`_kgspSec2PostblTimingFillPayload(pSignatureVa, signatureSize,
writeAddr, writeValue)` — the EXACT same injection point we used in
the 4.44-machine boot (the signature memdesc!):

1. **The uniform fill = SEC2_POSTBL_TIMING_FILL_DWORD = 0x000004a7**
   over the ENTIRE signature — **the "spin 0x4a7" from our own
   campaign memory = the canary-defeat fill of the paper**. The
   uniformity defeats the stack canary (the 4.42-bank finding).
2. The markers: @0x1100 = 0x7, the canary magic **0xc0deca7e**
   interleaved at the chain boundaries (@0x5b40, 0xf758, 0xf794,
   0xf7a0, 0xf7c4).
3. The parameterized ROP: writeValue @0xf754, writeAddr @0xf76c, the
   BROM gadget chain (0x0cbd, 0x1fbd, 0x10aa, 0x815a, 0x8e18, 0xffbc,
   0x582d, 0x0ccb, 0x7f2f — ALL ODD = the BROM thumb-like encoding,
   all < 0x8000 = BROM-resident, per our 4.31 note).
4. The refill = memdescMapInternal → the fill → memdescUnmapInternal →
   **memdescFlushCpuCaches** (the step OUR 4.44 drop-in MISSED) → the
   WPR_META sysmemAddrOfSignature/sizeOfSignature re-pointed.
5. The chain = performs ONE BAR0 write (writeAddr ← writeValue); the
   pipeline runs it ×4 = the PLM registers (WPR_CFG, FBPA, WPR, FEAT)
   = the Platform Lock Manager opened → the HOST writes the unlock
   values (CFG1/LMR/SS0/SS1) via BAR0 with the STOCK signature
   restored on disk → the clean reload.

## The deltas for OUR GA104 (the 4.45 work items)

| theirs (CMP 170HX / GA100) | ours (RTX 3070 / GA104) |
|---|---|
| gsp_tu10x.bin (the TU10x/GA100 family) | gsp_ga10x.bin (our family) |
| `.fwsignature_ga100` = ~63 KB (the chain at 0xf754 = in-range) | `.fwsignature_ga10x` = **0x1000 = 4 KB measured** — the chain must be COMPACT (the 24-DWORD = 96 B = fits) |
| the BROM gadgets < 0x8000 | our libos booter = the 4.40 inventory (0x100b3e/0x100b48 etc.) — the ROP = executes in the BOOTER's stack, not the BROM's |
| the canary magic 0xc0deca7e, the offsets 0xf7xx | our stack layout = to re-derive from bootloader.asm (the 4.45 TÂCHE A) |
| the PLM target (the OTP caps) | the f18 route (the 4.44: 100 → 112 = 280 W, PERSISTANT) — the same write primitive, a different target |

**The open question = unchanged (the 4.45 TÂCHE A)**: does OUR libos
booter copy the memdesc to its stack UNBOUNDED (the bug) or parse it
strictly? The cmpunlocker = the proof the bug EXISTS in the
TU10x/GA100 booters; the 0x1d = proves our booter = consumes the
memdesc strictly when it contains garbage — BUT the 0x1d = also
consistent with the verify reading a corrupted-but-copied payload (the
copy happened, the verify failed on the content, no ROP = because OUR
payload = dest=0 inert = no chain executed!). **The 0x1d boot = does
NOT falsify the overflow lane** — it only falsifies the free-replacement
lane. The overflow lane = EXACTLY what the reference implements.

## The operational model (the better one, from the reference)

Patch the firmware FILE on disk (the .fwsignature section = the ROP)
→ modprobe (the exploit boot) → restore the stock file → modprobe
(the clean boot, the effects latched). **The driver stays STOCK** — no
DKMS, no UKI ritual, the rollback = the file restore. Our 4.44
driver-side refill = the alternative (the proven injection point) but
the file patch = simpler.

## The tooling cross-check

The cmpunlocker's own `tools/booter_emu.py` = the SAME instrument
family as ours (the independent convergence). Their
docs/emulator_validation.md = the validation methodology = cross-
referenceable for our 4.45.

## Sources

- The cmpunlocker README (the local d3dx9 fork + the amoghmunikote
  upstream): https://github.com/amoghmunikote/cmpunlocker
- The driver patch: driver/patches/sec2-postbl-plm-ss-cfg.patch (the
  copy = imports/cmpunlocker/sec2-postbl.patch)
- The Consensus-Protocol/cmp170hx docs (how-it-works.md, rop-chain.md)
- The ResearchGate: « Defeating Stack Protection in a GPU Secure
  Coprocessor » (Jon Pry, ASU, June 2026)
- The coverage: the Tom's Hardware (Aug 2026), the Yahoo Tech
  (Aug 18, 2026), the HPC.social thread (July 16, 2026)
