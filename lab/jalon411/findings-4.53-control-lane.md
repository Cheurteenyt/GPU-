# 4.53 — THE CONTROL LANE: the relocatable layout, the carpet, the
# a4-conjugation discovery, the O5 MMIO scatter design, the debts

**The date: 2026-09-25. The branch pass/4.53-control-lane, PR-only,
no merge. The order: T1 → T4 → T2 → T3 → T5 (the founder's order).
Nothing ran on the GPU — the machine execution = the gated r2a/r2b.**

## 0. The baseline gate (the batteries reproduced FIRST)

auipc **416,206** (v4440, match=True) · the law **512/512** (v450b) ·
census **17/17** (v431) · 84 c.ret / 24 chainable / 0 work-gadgets
(v444e) · selftest **5/5** · TT **11/11** · TR **18/18** · TF **9/9** ·
TT-T **5/5** · v451a **4/4+4/4** · v452a **27/27** / v452b **23/23** /
v452c **18/18**. ALL GREEN before the first line of the new code.

## 1. T1 — the builder v446: the FULLY RELOCATABLE layout + the carpet

`v446_rop_payload_build.py` — the constants IMPORTED from the v445
builder (zero re-transcription: G40 = 0x10022A, TERMINAL = 0x100B3E,
SIZE = 0x1000). The two machine-day levers, both implemented:

- **L1 THE RELOCATION** (mode `chain`): the ctx {slot0, cap, dest,
  magic} and the list = placeable at ANY word of the 512-word window;
  the chain = extendable across the WHOLE window (fill_len = 200 = the
  r1 zone works identically — the TR2-C proof). The collisions =
  REFUSED (LayoutError — the 4.52 selector discipline), never silently
  resolved.
- **L2 THE CARPET** (mode `carpet`): the zone [fill_len, 512) = the
  LIVE entries, whatever word the ROM's return pops:
  - `pair` = the spec's cell {entrée-spine, terminal} repeated
    (zone-relative: the even = G40, the odd = TERMINAL) — 200 + 200 on
    the default fill_len=112;
  - `aligned` = the pop-aligned variant: the G40 every 9th zone word,
    the TERMINAL elsewhere — the G40's pop ([sp+0x38] = the word +8)
    ALWAYS hits a terminal (the +8 pop = the SAME parity kills the
    pair carpet's even class — the property SELF-ASSERTED at build
    time, the builder refuses the violating geometry).

**Selftest 28/28 — 3 bugs caught BEFORE the founder**: (1) the
relocation diff = missing the walk cell (its VALUE = &list[0] — it
re-targets when the list moves); (2) the aligned carpet placed a G40
at the zone word 508 whose +8 pop = OUTSIDE the window (the builder
now pins the last 8 zone words = TERMINAL); (3) the tree guard: BOTH
entries = **c.ldsp** (RVC quadrant 2 — the mask 0xE003/0x6002, NOT the
32-bit ld) distinguished by the exact rd member (G40 = ra/x1
0x38(sp)@0x10022a; TERMINAL = a5/x15 0x8(sp)@0x100b3e) — the "exact
tree members, not the plausible names" lesson, executed against the
LIVE image bytes.

## 2. THE DISCOVERY OF THE PASS — the ctx = a4-RELATIVE (TR2-B)

The TT-A note ("the scatter = [a4+0x498] + [a4+0x488]*8") was never
DECOUPLED from the v445 layout: every prior test had the ctx @word
0x91 = the byte 0x488 AND a4 = PAY — the two models coincide. The
TR2-B relocation DECOUPLED them (the ctx words @word 0x100, a4 = PAY)
and the primitive IGNORED the placed ctx: the write log (the wmem
trace): the slot write-back @PAY+**0x488** (the FILL area!), the
scatter @address **0x8** (the dest loaded = 0). Re-run with the
CONJUGATED a4 = PAY + 0x100·8 − 0x488: everything lands.

⇒ **The primitive's ctx = a4-RELATIVE with the BYTE-FIXED offsets:
the slot @a4+0x488, the dest @a4+0x498.** The v445's ctx @0x488 =
NOT a free choice — it = the CONJUGATION a4 = PAY. Consequences:

- The ctx relocation = the **(ctx_off, a4) PAIR** — the builder
  relocates the words, the consumer conjugates a4. ON THE BOOT: the
  ctx placement = a BET on the a4 residue — INDECIDABLE-BY-BYTES (the
  R2 experiment row, the runbook-453).
- The **walk cell + the list = FREE** ([sp+8] = the chain-controlled
  word; TR2-B: the pre = &list[0] @word 0x110, the post = &list[2]
  advanced 2 loads = the walk-pointer write-back mechanics).
- The invocation semantics (the refined mechanics): the iter 1 = the
  wild [a1] = list[0] + the slot increment (the write-back); the
  iters 2..a3 = the ring [dest + slot·8] = list[k] + the increment.
  ONE invocation a3=8 = 8 u64 writes (the wild + 7 ring — the
  4.44 D-list formula, byte-confirmed).

## 3. The carpet classes MEASURED (TR2-D/E, the real image)

The sweep = 29 RA positions over the zone [112, 512) (every 17th word
+ the boundaries), the modeled favorable residue (a1 = the scratch, a4
= the modeled ctx block @CTX2+0x488 — the A3 discipline), the
counter-bump = the capture oracle:

| class | pair carpet | aligned carpet |
|---|---|---|
| the zone-odd (the terminal first) | **the IMMEDIATE capture** — the counter [dest] = 1, the wild = the image bytes @the walk pointer (the walk cell = the word **w+2**, [sp+8] at sp = w+1 — the mechanics check byte-exact) | the immediate capture |
| the zone-even (the spine first) | the **G40 march** — 5 full 0x40 hops, write-free, the stop pc = the entry or its ret 0x10023a | **the ONE-STEP capture** — the +8 pop = a terminal (the builder property) |
| the tail {510, 511} | the NAMED class — the walk cell (w+2) = beyond the 4 KB | the NAMED class — the same |

TR2-D: 14/14 odd captured, 11 marched + 2 zone-exited + 2 tail-named
evens, ZERO strays. TR2-E: 27/27 in-window captured + 2 named tails,
ZERO strays. **The aligned carpet = the 100% one-step capture — the
anti-strategy made exact; the pair carpet = the honest 50/50 with the
march class.** The r2a boot = ONE unknown RA — the outcome = the class
of that RA; the pair→aligned comparison = the traverse that maps it.

## 4. T2 — the runbook-453: the r2a carpet probe (GATED)

`tools/edpp/runbook-453.sh` — the 4.45 gating pattern: **RUNBOOK_453_ACK=1**
(the machine execution = the founder's explicit ACK, per boot), the 9/9
checks gate (the 6 batteries incl. TR2 21/21 + the v446 selftest 28/28 +
the payload byte-exact + the stock firmware sha), the chain r2b REFUSED
without the r2a map file. The steps: prereq → build (the carpet + the C
header, the r1point pattern) → patch (the 4.44 anchor drop-in + the dkms
+ the UKI ritual — the embedded-module lesson) → **r2a** (the boot, the
MAP) → r2b (CARPET_MODE=aligned, the traverse) → observe → restore.
**THE MAP (the decision mode)**: `progress` (≠ 0xff or an unseen dmesg
stage = the flow moved FURTHER than the r1 spin — the capture state) /
`boot` (the completion — the unexpected rejoin, documented as-is) /
`hang` (0xff + the timeout — the march class or the unknown RA,
INCONCLUSIVE for the capture, still ≠ the r1 garbage-trap IF the
pattern differs). The rollback = **the driver alone** (~2 commands from
the stocks, proven 3× on the machine days; 0 v445/v446 strings in the
stock module; the firmware sha c0156954 untouched).

## 5. T3 — the chain r2 = the MMIO scatter (the O5 class, the DESIGN)

The only byte-coherent survivor of the 4.45 option analysis (O1 f18 =
DEAD — the object allocated BY the RM post-boot; O2/O3/O4 = dead or
refused). The cmpunlocker reference (imports/cmpunlocker/
sec2-postbl.patch, the GA100/CMP-170HX silicon-proven pipeline): the
chain performs ONE register write (writeAddr ← writeValue), the
pipeline runs it ×11 (the PLM table), the HOST writes the config with
the stock signature restored. OUR transfer to GA104:

**The candidate register table (theirs GA100 → ours GA104 = INDECIDABLE-BY-BYTES):**

| name | addr (GA100) | open value |
|---|---|---|
| WPR_CFG | 0x001fa7cc | 0xfffff0ff |
| WPR | 0x001fa7c4 | 0xffffffff |
| FBPA | 0x009a0148 | 0xffffffff |
| FEAT | 0x00823804 | 0xffffffff |
| FEAT2 | 0x00823b00 | 0xffffffff |
| OPT_PLM | 0x008200fc | 0xffffffff |
| XVE / XVE_B / XVE_C | 0x00088ff4 / 0x00088ab4 / 0x00088ff8 | 0xffffffff |
| PJTAG_PLM / PJTAG_SEC_PLM | 0x0000c840 / 0x0000c848 | 0xffffffff |
| (the WPR2 window, saved/restored) | 0x001fa824 / 0x001fa828 | — |
| (the host config, post-open) | SS0 0x0082381c, SS1 0x00823820, CFG1 0x009a0204, LMR 0x00100ce0 | 0x88888888 / 0x8 / 0x02779000 / 0x20B (the CMP devID forms) |

**THE READ PROBE = THE FIRST GESTURE, NON-NEGOTIABLE** (the write-test
= REFUSED without the read-test):
1. The host Bar0 read (READ-ONLY, the stock driver, no patch): the
   mmap of /sys/bus/pci/devices/<gpu>/resource0 + the u32 reads at
   every candidate offset. A read = the safe gesture by construction.
2. **The shape-match scan**: our card = 250 W stock ⇒ a u32 register
   reading **0x0EE6B280 = 250000000 µW** = the POWER-BASE register
   DECODED on GA104 — the read probe's decision criterion, byte-grounded
   (the 4.44 formula: limit = base·f18/100000).
3. The all-0xFFFFFFFF reads = the decode absent/masked ⇒ the candidates
   DEAD (the honest negative); the plausible values = the decode
   present ⇒ the transferability = STILL INDECIDABLE (the read ≠ the
   write semantics — the WPR_CFG bit map = GA100-specific until the
   bytes say otherwise).

**The write mechanics (the proven primitive, the refined form)**:
ONE invocation a3=1, a1 = the register address, the walk list = [the
value] = ONE SURGICAL MMIO write per hijack cycle (the wild #1 IS the
write; the scatter ring = untouched) — the cmpunlocker-equivalent
pipeline, N registers = N cycles (their ×4 = the same model). The
a3=8 block form = only IF a consecutive register block decodes. The
a1 = the RAW register offset (the GSP data space decodes the MMIO at
the BAR0 offsets — the cmpunlocker's writeAddr = the raw form).

**The 280 W values (the 4.44 pairs, THROUGH the MMIO door — the f18
object route stays dead)**: the base = **0x10B07600** (280000000 µW);
the stock read-shape = 0x0EE6B280 (250 W) = the probe's marker. The
values enter the walk list; the register = the read probe's finding.
NOTHING writes before a read-test row exists for that exact register.

## 6. T5 — THE DEBTS (named, on the shelf)

- **gsp_hpoke.c:79 = THE TRAP, the 3rd occurrence**: `#include
  <linux/workqueue.h>` in a file INCLUDED BY kernel_gsp.c — the TU RM
  = OS-abstract, ZERO linux headers. The fail = identical to the prior
  two; the conversion = the **two-sided pattern (patch_nv_451.py)**:
  the RM side = the RM-portable state + the function pointers (the
  gc-sections law), the nv.c side = the workqueue + the debugfs (the
  layout MIRROR structs). STATUS: the debt NAMED, the conversion = the
  pre-machine-day work item — the writer waits for the future dumps.
- **pillarB-sysmem v452 = the runbook-452 §1 = the calibration on the
  REAL machine** — the ways-day cold baseline stays HONEST only after
  it (the 8.3/8.8/57.7 GB/s = the launch-overhead floor diagnosis,
  waiting for the measured link state).

## 7. THE LEDGER

- **PROUVÉ**: the relocation (the chain anywhere in 0-511, the walk
  cell/list free, TR2-B/C); the ctx = a4-relative byte-fixed (the
  write-log trace + the conjugated re-run); the carpet classes (the
  pair = the immediate/march/named-tail, the aligned = 100% one-step,
  21/21 TR2 on the real image); the c.ldsp tree guard (the live bytes,
  the exact rd members); the byte-exact C (3/3 plans, gcc); the
  baseline gate (all green, reproduced first).
- **HYPOTHÈSE**: the r1 inference (the RA = a fixed word > 145) — the
  r2a decides; the carpet capture = the observable ≠ spin — the map
  decides; the a4 residue on the real boot = the R2 row.
- **INDECIDABLE-BY-BYTES**: the RA position (the ROM closed); the
  residue block (a1/a3/a4 at the capture); the GA104 decode of the
  PLM candidates; the power-base register address (the shape-match
  probe finds it or nothing); the WPR_CFG bit semantics on GA104.
- **REFUSÉ**: any write before a read-test row (the O5 discipline);
  the ctx relocation without the a4 conjugation (the TR2-B lesson);
  the pair carpet as the 100% claim (the even class = the march — the
  aligned = the exact form); the machine execution without the ACK;
  the rollback = anything but the driver alone.
