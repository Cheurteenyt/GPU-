# 4.57 — THE TRANSPOSE: the cmpunlocker mechanism ported to OUR GA104
# — the POSTBL lane, the write day PREPARED RIGHT (the order T1→T3→T2→T4)

**The date: 2026-09-26. The branch pass/4.57-cmpunlocker-transpose
(STACKED on main @89bb464 = post-4.56-machine-day — the founder MERGED
#53 and #54 mid-pass and deleted the branches; the 4.57 commit REBASED
onto main per the 4.55 precedent; the battery re-run after the
rebase), PR-only, no merge. Nothing ran on the GPU — the executors =
the anchor-exact transposer, the emulator, the file arithmetic. The
committed payload bytes = ZERO (the fill = C CODE in the patch; the
firmware = NEVER touched).**

**THE MACHINE-DAY CONTEXT (main @89bb464 — the founder's #54, READ
BEFORE the transpose landed):** the trajectory captured to the
register — the PGC6 pair {0x00118128, 0x00118234} = HOST-READABLE
(pgc6_probe.py, the PLM 0x8b8f = no lock on these); the carpet boot =
the progress 0xff CONSTANT over 180 s (36 snapshots) = **the GFW boot
COMPLETES with the payload resident — the signature verification =
bypassed-or-neutral on OUR silicon** (THE POSITIVE SIGNAL for the
transpose: the 0xf800 memdesc = tolerated by the boot flow); the spin
= the falcon-handoff post-completion. **THE STRUCTURAL NEGATIVE**:
the copy's return address = NOT controllable by the memdesc content
(6 variants = the same spin) — **the OLD portMemCopy lane CLOSED**.
THE TRANSPOSE = the DIFFERENT execution context (the booter
RE-EXECUTED, the POSTBL pass — not the copy overflow): the negative
does NOT transfer automatically (named, INDECIDABLE for the POSTBL
context) — this is exactly WHY the mission ordered the transpose lane
NOW. The machine day also re-banked the verification law (the nm
inline false-zero, the 4th occurrence) and committed the judge
instruments (pgc6-traj.service + pgc6_probe.py) — the sweep's judge =
THE COMMITTED service, not a name on paper.

**THE REFERENCE**: `imports/cmpunlocker/sec2-postbl.patch` — 470 lines,
read and decoded (2026-09-25, the review done). The mechanism: the SEC2
POSTBL timing lane — the signature memdesc ENLARGED (0xf800), FILLED
with the 0x4a7 field + the 0xc0deca7e canaries + the ROP chain tail at
0xf754..0xf7f8, the Booter RE-EXECUTED per PLM target
(kgspExecuteBooterLoad_HAL = the write primitive), the WPR2 re-write
per attempt, the read-back verdict, the stock signature REBUILT for the
clean final boot. The hook = after kgspPrepareForBootstrap_HAL — NOT
our 4.45 portMemCopy lane (the timing = post-boot-loader).

## 0. The baseline gate (the batteries reproduced FIRST)

selftest **5/5** · TT **11/11** · test-444 **9/9** · TT-T **5/5** · TR
**18/18** · TR2 **21/21** · TR3 **15/15** (incl. the v446 selftest
28/28 inside TR2-F). ALL GREEN — before the first line of new code.
RE-RUN after the rebase onto main (the 4.56 machine-day merged
mid-pass): ALL GREEN AGAIN.

## 1. T1 — v457a: the anchor-exact transpose (71 checks, TOUT VERT)

`v457a_sec2_postbl_transpose.py` + the emitted
`sec2-postbl-ga104-610.57.04.patch` (**436 lines**, -p1 style like the
reference). The method: **no offsets, no fuzz** — TEN ops, each on an
anchor asserted `count == 1` in the pristine 610.57.04 tree (the
transpose DIES LOUDLY if the tree drifts). The verification suite:

- **V1** the anchors unique (10/10);
- **V2** the emitted patch applies with `patch(1) --dry-run`, ZERO
  fuzz, on a pristine mock tree;
- **V3** the value invariants: the device gate **0x2488** alone (the
  CMP 0x20C2/0x2082 NOT ported), the memdesc **0xf800**, the fill
  **0x4a7**, the canaries **0xc0deca7e ×5**, the PLM table **11
  entries byte-exact** (WPR_CFG 0xfffff0ff + the ten 0xffffffff), the
  WPR2 save/re-write pair {0x001fa824/28}, the booter re-executed with
  `memdescGetPhysAddr(WPR_META_DESC, AT_GPU, 0)` (the EXACT
  `_kgspGetBooterLoadArgs` NORMAL conjugation), **2 attempts**, the
  LMR/CFG1 else-branch values {0x02669000, 0x28A} + SS0/SS1
  {0x88888888, 0x8}, **THE REFILL ORDER** map→fill→unmap→flush(sig)→
  re-point→flush(desc) verified IN THE TRANSPOSED C, the rebuild
  (the stock guard, the 256 align, the re-point, the flushes), THE
  HOOK POSITION (after PrepareForBootstrap, before the relaxed
  locking, the rebuild + the PopulateWprMeta re-call inside);
- **V4** ZERO linux headers in the added text (the TU RM law);
- **V5** THE 4.44 LAW: the C `_kgspSec2PostblTimingFillPayload` =
  **byte-exact** vs the python builder model over 0xf800 (the PutU32
  calls parsed from the transposed source and replayed — the chain
  slots, the parameters, the 0x4a7 field, the 0x1100=7 and 0x5b40
  canari specials);
- **V6** determinism (two builds = identical patch bytes).

**THE 610.57.04 GROUND TRUTH CHECKED BY HAND** (the transpose's
invisible work): `_kgspBootGspRm` = the reference's structure (the
WPR2-up check, PopulateWprMeta, the scrubber, PrepareForBootstrap, the
relaxed locking); `_kgspCreateSignatureMemdesc` = the portMemCopy shape
IDENTICAL; `g_kernel_gsp_nvoc.h:545-546` = the exact anchor pair
(pGspUCodeRadix3Descriptor / pSignatureMemdesc); the GspFwWprMeta
fields {sysmemAddrOfSignature, sizeOfSignature} = the union's anonymous
struct; `kgspExecuteBooterLoad_TU102` = OUR HAL path (GA104 → turing);
**the GPU_REG_RD32/WR32 visibility PROVED through the include chain**
(kernel_gsp.c has ZERO occurrences — the macro rides
g_kernel_gsp_nvoc.h → gsp_static_config.h:40 → gpu.h → g_gpu_nvoc.h →
gpu_access.h → g_gpu_access_nvoc.h:237/252; the OBJGPU completeness
cross-checked at kernel_gsp.c:4498 `pGpu->idInfo.PCIDeviceID`) — the
include-chain trap caught BEFORE the DKMS (the sibling of the
zero-linux-headers law).

**THE DOCUMENTED DEVIATIONS (the founder reviews)**:
- **D1** the rebuild ALSO flushes the signature memdesc after the stock
  copy (the reference flushes the WPR_META desc only) — the 4.45
  stale-cache lesson applies to the FINAL booter run too;
- **D2** the dmem.bin loader NOT ported — `os_open_and_read_file` does
  not exist in 610.57.04 (grep: absent); the built-in fill = the only
  path (also the safer: no runtime file dependency);
- **D3** the device gate = 0x2488 alone; the LMR/CFG1 = the
  else-branch values {0x02669000, 0x28A} per the mission (g) — the 8GB
  GA104 encoding = **INDECIDABLE-BY-BYTES** (the read-back = the
  ledger; the runbook §2 records what sticks);
- **D4** the static-info FB remap hunk NOT ported (CMP-specific,
  outside the mission's (a)-(g)).

## 2. T3 — TR-4: the transpose sequence emulated (15/15)

`tools/booter_emu.py --test-sec2` — the NEW battery on the REAL image,
the existing batteries REPRODUCED FIRST (the discipline):

- **TR4-A** the v457a selftest via subprocess (TOUT VERT);
- **TR4-B** the memdesc 0xf800 model: the ROP tail lands at
  0xf754..0xf7f8; the refill = the SAME layout re-laid, EVERY word
  outside the two parameterized slots byte-identical;
- **TR4-C** **THE STALE-CACHE MODEL** — the r0/r1 lesson REPLICATED at
  the model level: without the flush the DMA consumes the PREVIOUS
  pair; with memdescFlushCpuCaches the DMA consumes the CURRENT pair;
  stale ≠ fresh (the difference between the 4.45 dead lane and the
  transpose);
- **TR4-D** **the PLM loop E2E on the real image**: the 11 pairs =
  THE SAME table as the C patch (imported from v457a — the
  cross-instrument guard); per iteration: the surgical payload
  re-laid (the refill), the chain walk on the REAL booter bytes (the
  booter RE-EXECUTED), the write lands at the modeled PLM window slot,
  the read-back = opened; **11/11 opens**, the ledger accumulated
  across the iterations; the stop = the EXIT bump (the 4.56
  semantics — the write lands BEFORE the counter);
- **TR4-E** the rebuild: the tail = the stock content (the model =
  zeros — the real stock signature = the firmware blob, never
  committed); the final run WITHOUT the payload = **ZERO writes** at
  the modeled window (the clean boot);
- **TR4-F** the INDECIDABLES byte-proof: the GA100 BROM gadgets
  {0x0cbd, 0x1fbd, 0x7f2f, 0x0ccb} = sub-0x10000 (the OTHER ROM);
  the v444e strict work-gadgets = 0 + the rets = 84; OUR write
  primitive = the transfer-list pair @0x100b3e/0x100b48 (the sd
  byte-cited in OUR build).

**3 test-model bugs caught before the founder** (the WPR2 re-write
count 3→2; the refill/rebuild anchors matching the K1 PROTOTYPE instead
of the definition; the PLM-loop stop on the write instead of the exit
bump + the ledger read from the last Emu instead of accumulated). The
non-regression re-run AFTER the TR-4 insertion: **5/5 … 15/15 ALL
GREEN.**

## 3. T2 — v457b: the named indecidables + the sweep design (TOUT VERT)

`v457b_gadget_cross_sweep.py` (+JSON). The C byte-exact selftest of the
mission's (c) = ALREADY BANKED (v457a V5 + TR4-A/B — the 4.44 law).
This instrument names what the bytes cannot decide:

- **the CROSS TABLE**: the 4 GA100 gadget slots — the positional roles
  = HYPOTHESES (the load link after {writeValue, canari}; the repeated
  spine ×3; the terminal pair) — each **INDECIDABLE-BY-BYTES** for the
  GA104 (the BROM-relative sub-0x10000 offsets of the OTHER ROM, our
  booter VMA base = 0x100000);
- **the byte-level re-derivation of the 4.40 facts FROM OUR IMAGE**
  (not from the asm text): the c.sd @0x100b48 = **0xe19c**, the c.ld
  @0x100b3e, the rets = **84** re-counted;
- **OUR equivalents = PROVEN** (not hypothetical): the write = the
  transfer-list pair @0x100b3e/0x100b48 (the TR/TR3/TR4 writes land
  through it); the spine = the G40 epilogue (the REAL bytes, the
  TR-B/TR2/TR3 walks); the terminal = the v445/447 TERMINAL; the
  chainable inventory = the v444e 24 sites; the loader-link gap = NAMED
  (the v444e strict work-gadgets = 0);
- **THE SWEEP MATRIX P0..P5** (the design, NOT the execution): P0 the
  reference identity (the byte-exact tail — the falsification of "the
  offsets transfer"); P1..P3 the fill_len {64, 96, 112} with the
  reference tail (NAMED CAVEAT: the fill_len axis was EXHAUSTED in the
  OLD lane — the machine-day negative; here it re-runs in the NEW
  execution context only); **P4 the OUR-TAIL variant** (the
  v447 surgical chain in the 0xf800 buffer at 0xf754 — the hypothesis:
  the POSTBL can reach the booter's own code, the booter = EXECUTING
  when the verify runs); P5 the control (the pure 0x4a7 field, no
  tail — the r0 uniform spin baseline). ONE boot per point; the ACK =
  `RUNBOOK_457_ACK=1;RUNBOOK_457_POINT=<id>` (the semicolon form — the
  4.51 lesson); the judge = **pgc6-traj.service + pgc6_probe.py** (the
  machine-day's COMMITTED automatic trajectory unit — the PGC6 pair
  read LIVE, 60 × 5 s, the JSON per snapshot) + the dmesg SEC2_DEBUG
  ledger; the verdicts {OPENED, NO-EFFECT, SPIN, HANG, FAULT}; the
  rollback = driver-only.

## 4. T4/T5 — runbook-457.sh: the gated transpose day

`tools/edpp/runbook-457.sh` (bash -n OK) — the mission's §0..§5:

- **§0 prereq** the 9/9 checks (the 8 emulator batteries incl. TR-4 +
  the v457a/v457b guards + the firmware stock + the device 0x2488 on
  the bus) — the automatic refusal;
- **§1 patch** the dry-run + the application + **THE RITUAL = dkms
  remove + install --force** (the stale build-dir lesson — NOT a plain
  build) + limine-mkinitcpio (the UKI = the module EMBARQUÉ) +
  **THE VERIFICATION LAW**: nm the .ko (the 2 global transpose
  functions + the plmTable data symbol, the fold-tolerant NOTE) +
  the bytes (the SEC2_DEBUG strings, the canari at od) — NEVER the
  function name alone;
- **§2 boot** the ACK gate PER BOOT (`RUNBOOK_457_ACK=1`, the ledger
  with the point ID) — the expected SEC2_DEBUG ledger documented line
  by line (the saved stock signature → the 11×2 PLM lines → the
  POST-WRITE SS0/SS1/CFG1/LMR stick → the WPR meta updated);
- **§3 plm** the LEDGER PARSER (the embedded python): per PLM row, the
  LAST attempt's `reg` vs the table value → the verdict {OPEN 11/11,
  PARTIAL, NOT-OPEN}; the POST-WRITE line = the D3 honesty (what
  sticks); the NOT-OPEN contingence = the named hypotheses (the bypass
  not taken / the POSTBL no-hijack on GA104 = the expected P0 / the
  stale DMA);
- **§4 write** GATED ON OPEN: the power-base write (the 4.53 pair) —
  the target = the POWER-BASE-MATCH row of the v454c verdict (the
  v447 gate IN CODE = exit 2 without it);
- **§5 verify** `nvidia-smi -pl 280` + THE LOAD (pillarB/Q2RTX, the
  télémétrie) = the tenue à 280 W = **THE BREAK** (the doctrine 4.47);
  the refus = the contingence named (the sweep P0..P5, the PGC6 probe
  revision, the r2b lane);
- **restore** the rollback = **THE DRIVER ALONE** (~10 min, éprouvé
  4×) + the verifications (0 Sec2Postbl in the stock module; the
  firmware sha intact — the firmware = NEVER touched, the law).

## 5. The ledger

- **PROUVÉ** (the emulators + the anchors): the transpose = the anchor-
  exact byte-exact artifact, patch(1)-applicable zero-fuzz, the C fill
  byte-exact vs the builder, the refill ORDER in the C, the sequence
  E2E on the real image 15/15, the 11 opens modeled, the stale-cache
  model, the GA100 gadgets = the OTHER ROM (the byte status);
- **INDECIDABLE-BY-BYTES** (named, never invented): the 4 gadget slot
  VALUES on GA104; the PLM addresses' BEHAVIOR on our silicon (the O5
  law — the plausible address ≠ the behavior; the read-back = the
  judge); the LMR/CFG1 8GB encoding (D3); the POSTBL's reach into the
  booter's code (P4's hypothesis);
- **REFUSÉ** (nothing ran): the machine boots (the runbook = the day,
  ACK-gated per boot); the firmware writes (NEVER); the payload .bin
  commits (ZERO — the fill = C code; the sweep = PARAMETERS).

## 6. The next (the runbook day, the founder at the helm)

1. `runbook-457.sh prereq` → `patch` → the §1 ritual + the module
   verify → `boot` (the ACK) → `plm` → the gate decides (OPEN →
   `write` → `verify`; else the sweep P0..P5).
2. The PAT rotation = STILL DUE (the 3rd — the token crossed the chat
   in the 4.52 session; this session added none).
3. The stacked PRs: #53 (4.56) → the 4.57 PR on top — the founder
   reviews both, no merge by the agent.
