# 4.54 — THE READ LANE: the probe table, the READ-ONLY Bar0 probe, the
# shape-match gate, the surgical write-plan skeleton

**The date: 2026-09-25. The branch pass/4.54-read-probe (stacked on
pass/4.53-control-lane, 95d02f9), PR-only, no merge. Nothing ran on
the GPU — this lane CANNOT: the probe tool contains no write path at
all (the code = the guarantee, self-asserted). The machine execution
= the gated runbook-454 (PROBE_454_ACK=1, PROBE_454_NB=1).**

**THE CONTAINER RESET, DOCUMENTED**: the working tree and the worklog
were lost between the passes (the environment rebuilt). NOTHING was
at risk: everything lives in the pushed branches (95d02f9 confirmed
via ls-remote BEFORE the re-clone). The re-clone from origin, the
branch restored, the batteries re-run. ONE casualty: the
`.ogkm-610-cache` tree-guard header — re-fetched from the 610.57.04
tag (raw.githubusercontent), the guard GREEN again. The lesson: the
worklog + the state live in the PUSHED commits; the local-only assets
(the cache) = re-derivable by design.

## 0. The baseline gate (the batteries reproduced FIRST — on the
## recovered clone, BEFORE the first line of new code)

auipc **416,206** (v4440, match=True) · the law **512/512**
(law_fails=0) · census **17/17** (v431) · 84 c.ret / 0 work-gadgets
(v444e) · selftest **5/5** · TT **11/11** · TR **18/18** · test-444
**9/9** · TR2 **21/21** · TT-T **5/5** · v446 selftest **28/28** ·
v451a **4/4+4/4** · v452a **27/27** (the tree guard RESTORED) ·
v452b **23/23** · v452c **18/18**. ALL GREEN.

## 1. T1 — v454a: the candidate table (every row SOURCED, never
## invented)

`v454a_probe_table.py` — **215 offsets** (17 SAFE + 198 RISK), the
provenance carried per row:

- **SRC-PATCH** (SAFE-PROBE): parsed FROM the cmpunlocker patch bytes
  (`imports/cmpunlocker/sec2-postbl.patch` — the exact members, not
  plausible names): the 11 PLM registers (the plmTable[] C array, the
  patch's own order preserved), the WPR2 save/restore window (2), the
  host config writes (4: SS0/SS1/CFG1/LMR — the WR32 parse accepts
  the VARIABLE forms: cfg1Value/lmrValue are NOT hex constants — the
  selftest's first catch). The addresses = the tree guard against the
  committed constants (EXPECT_PLM/EXPECT_WPR2/EXPECT_CFG asserted in
  the selftest).
- **SRC-NB** (RISK-PROBE): the bounded neighborhoods ±0x40 (stride 4)
  around the 9 power-domain anchors — IN SCOPE = the blocks where the
  patch's own power/PLM registers cluster {0x0082xxxx, 0x001fa7xx,
  0x009axxxx}. **OUT OF SCOPE, named**: the XVE/PJTAG/LMR
  neighborhoods (the security-adjacent blocks — the scope
  discipline). The anchors themselves excluded, the SAFE rows
  excluded, the cross-anchor overlaps deduped (FEAT/SS0/SS1 windows
  overlap — one offset = ONE row named by the FIRST anchor claiming
  it; the selftest checks the COVERAGE (nothing lost) + the
  ATTRIBUTION (offset == anchor + delta) against the independent
  EXPECT_* constants, not the builder's own code path).

**Selftest 22/22 — 3 builder bugs + 1 test-model bug caught BEFORE
the founder**: (1) the WR32 regex = the constant-only form — CFG1/LMR
are written through VARIABLES (2 != 4 caught); (2) the PLM count
guard hardcoded at 11 blocked the format synthesis (parameterized
`expect_plm`); (3) **the quantifier bug**: `any(not (lo <= off < hi))`
skipped EVERYTHING (an offset in ONE block is absent from the OTHER
two — 0 NB rows caught by the "RISK > 0" check); (4) the geometry
test modeled the dedup naively — replaced by the coverage +
attribution invariants.

**The shapes = the single source, computed EXACT here** (v454b/v454c
import them — zero re-transcription): 250000000 = **0x0EE6B280**,
240000000 = **0x0E4E1C00**, 280000000 = **0x10B07600** (asserted in
the selftest, µW per the 4.44 formula).

## 2. T2 — v454b: the READ-ONLY probe (the code IS the guarantee)

`v454b_bar0_probe.py` — mmap `/sys/bus/pci/devices/<gpu>/resource0`,
ONE u32 LE read per candidate offset. **NO WRITE PATH EXISTS**: the
machinery (everything before the selftest) contains no WR32/poke/
PROT_WRITE — the selftest asserts its own source (the machinery
region only — the check's own literals live in the selftest; the
self-reference = the trap the first run caught).

- **The two-tier ACK** (the machine discipline, applied even to
  reads): `PROBE_454_ACK=1` → the 17 SAFE rows; `+ PROBE_454_NB=1` →
  the 198 RISK rows (the opt-in — the unknown registers CAN be
  read-sensitive: FIFO pops, R1C forms; the honest exposure named).
  Without the ACK: exit 2, tested.
- **The read-once discipline**: each offset = exactly one read, NO
  polling, NO repeat (the selftest asserts the count and the
  uniqueness).
- **The synthetic mode = the SAME code path**: the selftest plants
  the known values in a regular file (the marker 250 W at a RISK
  offset, DEAD-FF/DEAD-ZERO/plausible-µW at others), runs the same
  mmap+read loop, asserts the values byte-exact, the skip counts,
  the ERROR-OOR refusal (an offset beyond the BAR = a named error,
  never a crash), the JSON round-trip. **22/22.**
- The discovery: the sysfs walk (vendor 10de, class 03xxxx), the
  multi-GPU = the explicit --pci refusal, the missing resource0 = the
  clean refusal.

## 3. T3 — v454c: the shape-match analyzer (the O5 gate IN CODE)

`v454c_shape_match.py` — the dump → the verdicts. **The precedence:
the exact markers FIRST** (a marker inside the plausible µW range
still = POWER-BASE-MATCH):

| verdict | form | the write target? |
|---|---|---|
| POWER-BASE-MATCH | the EXACT 0x0EE6B280 / 0x0E4E1C00 / 0x10B07600 | **the ONLY rows that name one** |
| POWER-FORM | the plausible µW [1e8, 6e8], no exact marker | NEVER (a LEAD for the re-probe) |
| POWER-MW | the mW family [1e5, 6e5] (the 4.44 dual hypothesis) | NEVER (the secondary form) |
| DEAD-FF | 0xFFFFFFFF | — (the decode absent — the honest negative) |
| DEAD-ZERO | 0x00000000 | — (unnamed) |
| ERROR | the read failed | — |
| UNPLAUSIBLE | everything else | — |

**THE GATE**: no POWER-BASE-MATCH row ⇒ `write_target: null` AND
`write_lane: "REFUSED — no POWER-BASE-MATCH row"` (machine-readable —
v454d and the runbook consume it). A marker row ⇒ `write_target`
NAMED with its provenance (the found_via = SAFE/RISK kept) — the
WRITE ITSELF stays a LATER ACK-gated machine day; naming ≠ writing.
**Selftest 24/24** (every class + both gate states + the precedence +
the round-trip; the case-normalization catch: the dump's value_hex =
lowercase, the test compared uppercase).

## 4. T4 — v454d: the surgical write-plan skeleton (the honesty rows)

`v454d_write_plan.py` — the verdict → the PLAN (the parameter
document, NOT a payload, NOT a write):

- **a1 = the RAW register offset** (the GSP data space decodes the
  MMIO at the BAR0 offsets — the cmpunlocker's writeAddr = the raw
  form; the plan refuses any a1 beyond the BAR0 span).
- **a3 = 1, the walk list = [280000000]** (µW) — ONE invocation =
  ONE surgical write per hijack cycle (the wild #1 IS the write; the
  scatter ring untouched — the 4.53 §2 refined semantics). N
  registers = N cycles. **The a3=8 block form = REFUSED here** —
  only IF a consecutive register block decodes (the read evidence,
  absent today).
- **The u64 honesty**: the value = the ZERO-EXTENDED 280 W
  (0x0000000010B07600) — the u64 store ⇒ **the +4 NEIGHBOR register
  receives 0x00000000** (the upper dword). DOCUMENTED in the plan,
  never hidden — the write-day runbook read-tests it.
- **align8 = (a1 % 8 == 0)** — the misaligned u64 store on the GSP
  data space = **INDECIDABLE-BY-BYTES** (the R2 emulation row
  decides; the plan flags it, never assumes).
- **The (ctx_off, a4) PAIR law** (the TR2-B discovery) named in the
  builder command; the payload = the NEXT pass (v446), emulated
  (--test-rop2) BEFORE any boot, ACK-gated on the machine day.
- The refusals: no verdict / no target / a REFUSED lane / an
  out-of-BAR0 a1 → exit 2. **Selftest 16/16.**

## 5. T5 — runbook-454: the read day (ZERO-patch by construction)

`tools/edpp/runbook-454.sh` — prereq (the 6/6 checks: the 4 v454
selftests + the table + the sysfs) → table (v454a) → **probe**
(PROBE_454_ACK=1, + PROBE_454_NB=1 opt-in) → match (v454c, the gate
displayed) → plan (v454d; the REFUSED lane = a RESULT, displayed
honestly, not a runbook failure) → observe (the verdict summary +
nvidia-smi, the 250 W cross-check) → restore (**NOTHING TO RESTORE —
no module, no firmware, no boot was touched**; the lane's defining
property). The outputs land in $RUN454_DIR (default /tmp/runbook454
— the 4.51 VOLATILE lesson: copy the evidence out). bash -n clean;
the ACK refusal + the no-GPU refusal tested in the lab; the full
chain (probe-synthetic → match → plan → observe) exercised
end-to-end with a planted marker @0x001fa798 (a WPR-neighborhood
RISK row) → the gate NAMED → the plan emitted.

## 6. THE LEDGER

- **PROUVÉ**: the table = 215 sourced offsets (the patch bytes the
  guard); the probe = read-only (the machinery self-asserted), the
  read-once, the synthetic = the same code path; the analyzer = the
  7 classes + the exact-first precedence + the gate in code; the
  plan = the honesty rows (the raw a1, the +4 side effect, the
  align8 flag, the a3=8 refusal); the chain exercised end-to-end in
  the lab; the baseline gate reproduced on the recovered clone.
- **HYPOTHÈSE**: the power-base register DECODES on GA104 (the
  marker hunt finds it — the r-day probe decides); the PLM
  candidates read plausibly (the SAFE tier answers).
- **INDECIDABLE-BY-BYTES**: the GA104 decode of every candidate
  (the patch's addresses = GA100); the read vs write semantics (a
  plausible read NEVER proves a writable register); the misaligned
  u64 store behavior; the +4 neighbor's identity (per-target, the
  write-day read-test).
- **REFUSÉ**: any write before a read-test row (the O5 gate IN
  CODE); any fuzzy POWER-FORM as a write target (the leads, never
  the targets); the a3=8 block without the decode evidence; the
  machine gesture without the ACK; the payload from THIS pass (the
  v446 build = the next pass, emulated first).
- **THE DEBTS (unchanged, still named)**: gsp_hpoke.c:79 (the
  linux-header-in-RM-TU trap, the 3rd occurrence — the two-sided
  conversion = the patch_nv_451.py pattern, shelved); pillarB v452 =
  runbook-452 §1 = the machine calibration.
