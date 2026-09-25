# 4.56 — THE R2B LANE: the day of writing, PREPARED — the progression
# decoder, the O5 map, the v447 write-chain builder, the gated runbook

**The date: 2026-09-25. The branch pass/4.56-r2b-lane (stacked on main,
post-4.55), PR-only, no merge. Nothing ran on the GPU — the payloads
this pass commits = ZERO (the v447 emits at the runbook day, from the
REAL verdict, ACK-gated); the emulator + the file arithmetic = the only
executors.**

**THE CONTAINER RESET, DOCUMENTED (the 2nd)**: the working tree and the
worklog were lost between the passes (the environment rebuilt). NOTHING
was at risk: everything lives in the pushed commits (main @97c152b =
the 4.55, verified BEFORE the re-clone). The re-clone from origin, the
branch created, the batteries re-run, the `.ogkm-610-cache` re-fetched
from the 610.57.04 tag (BOTH guard locations — the repo root for
v452a/v456a/v456c, `lab/jalon411/` for v424). The lesson holds: the
worklog + the state live in the PUSHED commits.

## 0. The baseline gate (the batteries reproduced FIRST — on the
## recovered clone, BEFORE the first line of new code)

auipc **416,206** class · selftest **5/5** · TT **11/11** · test-444
**9/9** · TT-T **5/5** · TR **18/18** · TR2 **21/21** · v446 selftest
**28/28** · v451a **4/4+4/4** · v452a **27/27** (the tree guard
RESTORED — the cache re-fetched) · v452b **23/23** · v452c **18/18** ·
v454a **22/22** · v454b **22/22** · v454c **24/24** · v454d **16/16** ·
v455a **44/44**. ALL GREEN.

## 1. T3 — v456a: the progression decoder (THE judge of tonight's r2a)

`v456a_progress_decode.py` — **28/28, the tree guard GREEN** (the
sources re-read live from the cache). The order T3-first = the founder's
mandate: the decoder = the reading of the boot map BEFORE the day.

**THE DISCOVERY OF THE PASS — 0xFF = _COMPLETED.** The register =
`NV_PGC6_AON_SECURE_SCRATCH_GROUP_05_0_GFW_BOOT` (0x00118234), the
field `_PROGRESS` 7:0, and `..._PROGRESS_COMPLETED = 0x000000FF`
(`dev_gc6_island_addendum.h:32`, the tu102 AND ga102 headers
IDENTICAL — the addresses too: `_PRIV_LEVEL_MASK` = 0x00118128 at
tu102:28 = ga102:27, `GROUP_05(i)` = 0x00118234+(i)*4 at tu102:34 =
ga102:33). **The machine-day r0 line `progress 0xff` = NOT a failure
code**: the GFW boot reached its TERMINAL marker; the reported failure =
`kflcnWaitForHalt_HAL` timing out (2,050,000 µs scaled,
kern_gpu_tu102.c:403-406) — the falcon NEVER halted, the progress read
REGARDLESS of the halt status (:456-460). The r0 spin = POST-COMPLETION
(the marker written, the core spinning — the hijack state the paper
predicted, now phase-located). The two dmesg lines of the r0 day = ONE
root: `gpuWaitForGfwBootComplete` prints the halt-timeout + the progress
(:468), `kgspWaitForGfwBootOk` propagates the 0x65 =
NV_ERR_TIMEOUT (kernel_gsp_tu102.c:1195, nvstatuscodes.h:130).

**The PLM artifact**: `_gpuIsGfwBootCompleted_TU102` reads the PLM
FIRST (:409-419) — if FWSEC has not lowered `_READ_PROTECTION_LEVEL0`
(bit 0:0), the code reports `*gfwBootProgressVal = 0x0` WITHOUT reading
the status register. **A reported 0x0 = the artifact OR a genuine early
stage — the value alone CANNOT decide; the PLM register read (0x00118128)
decides** (the decoder carries `--plm`; the pair = the NEW probe
candidates, §2). The stages 0x01..0xfe = INTERMEDIATE-UNNAMED: the open
tree has NO stage table, the booter plaintext carries NO GFW writes
(grep-verified this pass on bootloader.asm — the "GFW" string count = 0)
— the closed ROM writes them; the values = the map coordinates, the
monotone order NEVER assumed (INDECIDABLE-BY-BYTES).

The verdict matrix (the (line, progress) → the map): HALT-TIMEOUT+0xff =
**HANG-POST-COMPLETION** (the r0/r1 spin class); HALT-TIMEOUT+0x0 =
HANG-PRE-START-or-PLM; HALT-TIMEOUT+0x01..0xfe = **HANG-AT-STAGE** (the
coordinate for the next probe); NOT-COMPLETED-HALTED = EARLY-HALT; the
wrapper = STATUS-PROPAGATION. The `--dmesg` mode = the scan of a capture
(the real r0 lines = the selftest fixtures).

## 2. T3 — v456b: the boot timeline (the timestamps dmesg → the map)

`v456b_boot_timeline.py` — **13/13**. The v456a classifier IMPORTED
(zero re-transcription); the kernel timestamps `[  123.456789]` parsed,
the deltas computed (`dt_first`, `dt_prev`), the cycles split on the
MODULE-LOAD anchors (the kernel loader's own printk; the PROBE
error-path anchors = nv.c:937,959 — the SUCCESSFUL probe line of the
older drivers does NOT exist in the 610 tree, grep-verified, the map
labels the first NVRM/nvidia line AS the practical anchor). **The
level-gate lesson baked in**: the failure lines = LEVEL_ERROR only — a
QUIET capture is NOT a health proof (the summary note says so, verbatim).
One test-model bug caught BEFORE the founder: the cycle lengths = the
anchor INCLUSIVE ([2,2], not [2,1] — the model was wrong, the code was
right).

## 3. T1 — v456c: the O5 map (the GA104 candidates, the honest cross)

`v456c_o5_map.py` (+ `v456c_o5_map.json`) — **18/18, the tree guard
GREEN**. The 215 v454a offsets IMPORTED (zero re-transcription) and
CROSSED against the 610.57.04 published swref headers — the exact
addresses grepped across EVERY family (ga100, ga102, tu102, gp102,
ad10x, gb100):

**The 3 EXACT-PUBLIC crosses** (the address named in a public family
header):

| offset | the patch's name | the PUBLIC name | source |
|---|---|---|---|
| 0x00100ce0 | LMR | **NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE** | pascal/gp102/dev_fb.h:26 |
| 0x001fa7c4 | WPR | **NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE__PRIV_LEVEL_MASK** | blackwell/gb100/dev_fb.h:28 |
| 0x00823814 | NB(+0x10@FEAT) — a v454a RISK row | **NV_FUSE_FEATURE_READOUT** | ampere/ga100/dev_fuse.h:26 |

**The coherence finding**: the cmpunlocker's own GA100-era names = the
registers' real meanings — "LMR" = the WPR range register ITSELF, "WPR"
= the PLM OF that range register. The patch's model = coherent with the
public tree across THREE families (the Pascal register, the Blackwell
PLM, the Ampere block).

**The blocks**: the 0x0082xxxx = the **FUSE block** (ga100/dev_fuse.h
defines span 0x00820378..0x00824118 — 106 of our rows); the
0x001fa7xx/0x001fa8xx = the **PFB PRI MMU cluster** (ga100/dev_fb.h:36-46:
LOCK_CFG PLM @0x001FA7C8, LOCK_ADDR_LO/HI @0x001FA82C/30 — the patch's
WPR2 window @0x001fa824/28 sits INSIDE, unnamed; 37 rows); the
0x00088xxx = **PCFG/XVE** (tu102/dev_nv_xve.h:26, 3 rows); 0x00100ce0 =
PFB (1 row). 68 rows = PATCH-ONLY (the 0x009a block = ZERO public
attribution anywhere — the FBPA name = the patch's own; the PJTAG, the
exact FEAT/FEAT2/OPT_PLM/SS0/SS1 roles). The published swref = heavily
redacted (the tu102 dev_fbpa.h = 29 lines) — the negative named.

**The 4.56 additions = the PGC6 pair ONLY** {0x00118128
GFW_BOOT_STATUS_PLM, 0x00118234 GFW_BOOT_PROGRESS} — EXACT-PUBLIC in
BOTH tu102 AND ga102, the r2a/r2b judge registers (the v456a decoder's
own). Flagged `CANDIDATE-NOT-IN-454`: candidates for the NEXT probe-table
revision, **NOT silently injected into the committed 215** (the
frozen-register discipline — the corrections land as new rings that name
the old).

**Every row = verdict `GA104-DECODE-INDECIDABLE-BY-BYTES`** — even the
EXACT-PUBLIC crosses: the address plausible (the NVIDIA PRI stability
across families) ≠ the behavior on OUR card. The confidence = the
ADDRESS plausibility only. The map names ZERO write targets; the gate
text = carried in the JSON itself.

## 4. T2 — v447: the r2b write-chain builder (the gate IN CODE)

`v447_rop_write_build.py` — **17/17**. Imports v446 (the relocatable
layout) + v454a (the shapes) + v456c (the map) — zero re-transcription.

**THE REAL SCATTER SEMANTICS re-decoded** (bootloader.asm re-read this
pass, 0x100b00-0x100ba4 — the definitive loop decode, correcting the
TR-C/D shorthand):
- the hijack enters at the TERMINAL 0x100b3e = the loop BODY (the head
  skipped): **write #1 = [a1] = the ROM RESIDUE** (W1/W2) ← list[0];
- the loop head (0x100b2e-b38) recomputes a1 EVERY iteration:
  `a1 = ctx.dest + ctx.slot*8`; the write (0x100b48); the slot advance
  (0x100b4a-5a) with the **wrap to 1, never 0**; the bound check
  neutralized by a0 = ~0;
- **the counter [ctx.dest] += a3 AT THE EXIT ONLY** (0x100b6e-76) — one
  u64 RMW of the slot-0 cell, the read side effect INCLUDED;
- the exit ret (0x100b7a) = W3 (the re-entry, the spin).

**The scatter geometry** (the mission's "8 writes à a1+8k", the 4.44
D-list conjugated): the targets = {B+8k, k=0..7}; `slot0=1, cap=0x40,
dest=B-8`; the ring = [B+8..B+56] ← V1..V7 (the slots 2..8); the wild
[a1-residue] ← V0; the counter [B-8] += 8 (the named clobber BELOW the
block — an RMW: it READS too). **The slot-1 hole = named**: [B] = skipped
by the ring — covered ONLY IF the a1-residue = B (the A3-favorable
assumption, the 4.44 a1 = dest+8 conjugation). TR3-B demonstrates the
hole (the pre-existing value SURVIVES); TR3-C demonstrates the
A3-favorable full block. The surgical form = the v454d continuity (a3=1,
a1 = the RAW offset, the counter home = REQUIRED, never silent).

**THE GATE (the mission's wording, in code)**: `check_gate()` consumes
the v454c verdict doc — `write_target: null` or `write_lane = REFUSED*`
→ **BuildRefused, exit 2, machine-readable** (TR3-E demonstrates the CLI
refusal). The synthetic verdict fixture = the SAME code path, tagged
`synthetic` in every doc. **This pass commits NO .bin** — the payloads =
emitted at the runbook-456 day, from the REAL verdict, ACK-gated.

**The honesty rows** (every build doc carries them): the +4 neighbors
(8 u32 zeroed per the scatter — 16 u32 touched), the counter RMW, the
wild, the slot-1 hole, the (ctx_off, a4) conjugation (the TR-2 law,
self-asserted = `PAY + ctx_off*8 - 0x488`), align8 = INDECIDABLE-BY-BYTES
(the STORE width itself — the u64 vs 2×u32 decode on the GSP data
space), the map cross per-address (the touched rows = the map candidates
or NOT-IN-MAP flagged). The refusals: the misaligned B, the wrong value
count, the out-of-BAR0, the counter-home unset, the gate — 7/7 tested.

**TR-3 (`booter_emu.py --test-rop3`) = 15/15 on the REAL image**: the
guards (TR3-A the v447 selftest, TR3-F the v446 freshness); the scatter
E2E (TR3-B: the wild, the ring slots 2..8, THE HOLE, the counter, the
ctx slot → 9, the walk cell → &list[8]); the A3-favorable full block
(TR3-C); the surgical (TR3-D); the gate refusal (TR3-E). The modeled
window (B = 0x164000 in the emulator RAM, pre-zeroed) = the A3
discipline — the builder is ADDRESS-AGNOSTIC (the raw-vs-modeled
conjugation = the test's, the decode = INDECIDABLE, the day decides).
The full non-regression battery re-run green (5/5, 11/11, 9/9, 5/5,
18/18, 21/21).

## 5. T4 — runbook-456: the gated r2b day

`tools/edpp/runbook-456.sh` (bash -n clean; the lab exercise: the prereq
9/11-green + the honest firmware refusal; the observables, the map, the
gate stages exercised end-to-end; the v447 CLI full chain with the
planted verdict → the scatter payload built; the REFUSED verdict → exit
2). The stages {prereq 11 checks, observables, map, **gate**, payload,
patch, r2b, observe, restore}:

- **THE DECISION (the gate stage)**: the verdict 454 absent/REFUSED →
  CONTINGENCE-VERDICT (the read day = runbook-454 first — the read probe
  = the non-negotiable prerequisite); the r2a map absent/hang →
  **CONTINGENCE-CARTE with the next probe variants NAMED** ((1) the
  aligned carpet — the runbook-453 r2b, the pair/aligned traverse;
  (2) the fill_len × fill_value re-sweep WITH the v456a decoder = the
  named coordinates instead of the uniform spin; (3) the PGC6 pair in
  the next probe revision = the live progress WITHOUT the dmesg);
  the verdict = POWER-BASE-MATCH AND the map = non-hang → **WRITE**.
- **r2b = the write boot, DOUBLE-gated**: `RUNBOOK_456_ACK=1` (per boot
  — one invocation = one fresh ACK) AND the decision file = WRITE. The
  ledger = the boot log with the timestamps.
- **observe = the decoder judges**: the v456a `--dmesg` (the verdict
  classes) + the v456b timeline (the deltas) + nvidia-smi (the 280 W
  cross-check) + the copy-out ritual (the /tmp = volatile, the 4.51
  lesson).
- **restore = the driver alone** (the proven ~2-command revert; 0
  v447 strings in the stock module; the firmware sha intact; the write =
  one-shot by design — the next boot = the memdesc rewritten STOCK by
  the driver).

## 6. THE LEDGER

- **PROUVÉ**: 0xFF = _COMPLETED (the public headers, tu102 = ga102,
  file+line cited); the PLM artifact path (the code, :409-419); the
  cross-family coherence of the patch's names (3 EXACT crosses); the
  block attributions (the grep evidence); the REAL scatter semantics
  (the disassembly, instruction-by-instruction) + the TR3 15/15 on the
  real image; the gate in code (the refusals 7/7 + TR3-E); the map =
  215 annotated + the 2 candidates, zero rows lost; the timeline
  (13/13, the r0 fixture); the runbook chain exercised in the lab.
- **HYPOTHÈSE**: the A3-favorable residue (a1 = B — the 4.44 conjugation;
  the day's R0/R2 decides); the decode of the GSP data-space u64 store
  to the MMIO pair (the +4 = zeroed — the plausible form, the day reads
  it back); the power-base register = one of the 3 EXACT/block
  candidates (the 454 probe decides).
- **INDECIDABLE-BY-BYTES**: the GA104 decode of EVERY candidate (even
  the EXACT-PUBLIC — the address ≠ the behavior); the GFW boot stages
  0x01..0xfe (the closed ROM — no public table, no booter writes); the
  monotone order of the stages; the a1/a4/a3 residue values at the
  capture; the misaligned/width semantics of the u64 store on the GSP
  data space.
- **REFUSÉ**: any write without the POWER-BASE-MATCH row (the gate IN
  CODE, exit 2, demonstrated); any payload committed by this pass (zero
  .bin); the a3=8 block on an unverified decode (the map = the
  candidates, the sonde = the prerequisite); the machine gesture without
  the ACK (the double gate: the ACK per boot + the decision file).
- **THE DEBTS**: pillarB = runbook-452 §1 = the machine calibration
  (unchanged). The gsp_hpoke two-sided = PAID (4.55). NEW: the next
  probe-table revision = the v454a successor carrying the PGC6 pair
  (the map names it, the pass does NOT rewrite the committed 215).

## 7. The lessons

1. **The failure code was a success marker** — the r0 "progress 0xff"
   read as the failure code for two passes; the public header names 0xFF
   = COMPLETED. The value semantics live in the HEADERS, not in the
   intuition: grep the defines BEFORE interpreting the dmesg.
2. **The reported zero can be an artifact** — the decoder that reads the
   status register CONDITIONALLY (the PLM gate first) manufactures 0x0;
   a zero = ambiguous BY CONSTRUCTION, the PLM read = the disambiguator.
3. **The shorthand vs the bytes** — "the counter [dest] += 1 per write"
   (the TR-C shorthand) = actually ONE bump of a3 at the exit (the
   disassembly); the emulator tests pass EITHER way (the oracle = the
   final state) but the day's read-back expectations differ. Re-read the
   bytes when a NEW composition (the v447 block) depends on the ORDER.
4. **The patch's names were honest** — the cmpunlocker's "LMR"/"WPR"
   = the real register names in the public tree (3 families agree). The
   external tooling = a source like any other: cross it, don't dismiss
   it.
5. **The published swref = a curated subset** — the absence of a define
   = the redaction, not the absence of the register. The negative =
   bounded (the block-level attributions stand, the exact roles =
   PATCH-ONLY).
