# 4.50 — the 600 GB/s roadmap, the G5x bit1 verdict, the FB/L2 ingestion
map, and the machine instruments (the TT-T scenario, the nvcc battery)

Pass: 4.50 (stacked on 4.49 `39c7881`). Date: 2026-09-24.
Trigger: the founder's planning request — « je me lance pas tout de
suite — prévoie une grosse tâche … vise la possibilité d'avoir 600 gb/s
voir + », then « continue prévois de grosses tâches pour la prochaine PR ».
Deliverables: `lab/jalon411/ROADMAP-600GBs.md` (the escalation plan, in
French for the founder), `v450a_g5x_bit1` (+JSON), `v450b_fb_l2_map`
(+JSON), `tools/booter_emu.py --test-timings` (TT-T),
`tools/edpp/build_timing_payload.py`, `tools/edpp/pillarB.cu`,
`tools/edpp/pillarB-driver.sh`, runbook-447 §6.
Baseline gate: ALL banked counts reproduced on this machine before
production — auipc 416,206 (byte census, both alignments) ✓, the
coordinate law 512/512 ✓; and after the tool changes: TT 11/11 ✓,
TF 9/9 ✓, TR 18/18 ✓, selftest 5/5 ✓ (the new batteries added, none
broken).

## §1 The roadmap (the founder-facing plan)

`ROADMAP-600GBs.md` decodes the FOUR meanings of « 600 GB/s » and
sequences the escalation: **M1** the 0xSero metric (91.3 % of 448 =
~409 effective, pure software), **M2** the mclk OC (~440-485 effective,
the sweep decides), **M3** the 600+ L2-resident lane (guaranteed for
L2-fitting footprints), **M4** the 600-streaming wall (~20.5-21.5
Gbps/pin = hardware, documented, OUT OF SCOPE per the 2026-09-21
PC-only decision). Five TIERs with quad gates (battery ×3 + memtest +
zero-Xid + confirmed rollback), the ingenious parking lot (tagged),
the J1-J5 machine-day calendar, the honesty ledger. THIS pass executes
the machine-free half of TIER 0-2 preparation.

## §2 THE TÂCHE A ANSWER (v450a): the consumer tests bit0 ONLY; the
G5x bit1 has NO reader in the flag-word class (PROUVÉ)

The v449a `the_consumer` decode started at 0x1318d46 — a FALSE
prologue: its func_bounds test `(hw & 3) == 1 and (hw >> 13) == 3`
matches BOTH c.addi16sp AND c.lui (the discriminator is rd == x2).
v450a corrects the test and walks back to the TRUE prologue:

- **The function**: prologue `c.addi16sp sp, -0x180` @0x1318cc0, first
  ret @0x131aac8 — 2296 insns, ~7.5 KB. The ways flow (gate byte
  config+0x67f, the flag load @0x1318d4a, the ways value @0x1318d52,
  the 0x2ac/0x2bc register programming) sits INSIDE, exactly as 4.49
  banked.
- **The census inside the whole 2296-insn function**: flag-word
  (-0x298) loads = 1 (the bit0 one), ways (-0x27c) accesses = 2, bit
  tests = 12 — **ZERO of them test mask 2**. The ways consumer never
  reads bit1.
- **The image-wide fallback**: a bit1 test within ±0x40 of any of the
  251 raw flag-word sites — exactly ONE candidate @0x12aa87a
  (`andi s5, s5, 2` near the -0x298 load @0x12aa862). Decoded: the
  -0x298 load there reaches cfg+0x3D68 through a DIFFERENT carried
  base (s2+0x2000), and the flag word is the MULTIPLICAND of a time
  computation (`mulw a2, a5, a2` after the 1e9-ns rounding chain);
  the `andi 2` tests bit1 of an **MMIO register read** (vtable+0x28),
  NOT of the flag word. **Classified: false positive.**
- **The verdict**: within the flag-word displacement class, bit1
  (config+0x3D68) is SET by the ingestion but read by NOTHING in this
  image. The G5x promote experiment's observable CANNOT be the flag
  word (see §3 — the real G5x mechanism is elsewhere anyway).

## §3 THE TÂCHE B MAP (v450b): the 24-key FB/L2 ingestion carded —
and the 4.49 bit1 reading CORRECTED (PROUVÉ)

v450b decodes the ingestion [0x1307AFC, 0x1308800) as: a fetch WALK
(24 named `0x103c08c` calls, 0x1307b3e-0x1307f28, each preceded by the
interned name materialization), per-key success stubs (dense-packed,
4-12 B apart, 0x130815e-0x13082f8), and per-key APPLY BLOCKS right
after each fetch (the stubs jump BACKWARD into them; the cfg bases =
the `c.lui N; c.add rX, s3` idiom, N=4 for the +0x4000 page, N=8 for
the +0x8000 page).

**The 4.49 correction**: the « neighbor handler sets bit 1 for
RMG5xL2VidmemPromote » reading was a dense-packing artifact (the 4.49
0x140 B handler window swallowed the neighbors). The mask-2 ori
belongs to **RMFermiL2CacheBypass**'s handler (@0x130829e: the value
store is absent, `sw` of the flag word @0x13082aa, `ori a4, a4, 2`
@0x13082a6 — mask 2 = bit 1). The corrected flag-word map
(config+0x3D68):

| Bit | Owner | Evidence |
|---|---|---|
| bit0 (mask 1) | RML2MaxWaysSysmem-was-set | the ways handler @0x130822c (`sw@0x3d84`, `sw@0x3d68`, `ori 1`) — the 4.49 anchor, re-proven |
| bit1 (mask 2) | RMFermiL2CacheBypass-was-set | @0x130829e/0x13082a6/0x13082aa — NEW |
| G5xPromote | NO flag bit | see below |

**The G5x chain, corrected and PROVEN**:
`RMG5xL2VidmemPromote` = a u32 regkey whose value lands in **TWO
config words**: config+0x85C4 AND config+0x85E4 (the apply block
@0x1307d88-0x1307db6: `lw a5, -0x70(s0)` → `sw a5, 0x5c4(s4)` and
again → `sw a5, 0x5e4(s4)`, s4 = c.lui 8 + c.add s3 = cfg+0x8000, each
store followed by its trace push). On regkey MISS, the failure stub
@0x130816a loads the constant **0x15511554** and jumps back INTO the
apply block — **0x15511554 = the DEFAULT value of the G5x promote
word when the key is unset** (a packed-field-looking magic). The G5x
experiment card is therefore: a u32 key with a NAMED default, TWO
named landing words, and NO flag bit.

**The per-key card (the walk order, the named landing zones)**:
byte-flag zone config+0x86xx: RMAssertOnEccErrors→0x86B4,
RmOrigFbReqSize→0x8678/0x8679, RMDisableZBCDefaultLoad→0x8679 (stub
forces 0), RMAsrEnable→0x867D, RMAsrWakeup→0x867D (stub FORCES the
local to 1 — the wakeup semantics), RMAltL2ArbCYA→0x86A5
(`snez` of the value → the byte), RmAllowComptagZero→0x86AA,
RMAERRForceDisable→0x86AD/0x86B0, RMIsoCommitUnallocate→0x86B0,
RMDisableWarBug1761410→0x8686 (stub zero) + word→0x85D8,
RMDisableFbAddressRetraining→0x869B, RMDisableIntrIllegalCompstatAccess→0x8687,
RMBug1790718War→0x8688, RMDisablePostL2Compression→0x86B9,
RMDisableLRCCoalescing→0x86BA, RML2PreFill→0x86B6 (stub writes 1),
RMDisableRCOnDBE→0x86B3 + word→0x3D80, RmEnableL2CohErrorIntr→0x85E8
+ byte→0xFBE, RMSysmemSelectAtomicsConfigNcoh→word 0x85DC + byte 0xFB9,
RMROPL2FuseMaskForFModel→word 0x3D80 + the flag word,
NvLinkPeerThroughL2→no store in the window (honest). The u32 page:
RML2MaxWaysSysmem→0x3D84 (the anchor), G5x→0x85C4+0x85E4 (above).

**The parked hunt**: who READS config+0x85C4/0x85E4? The
displacement-class scan (imm 0x5c4/0x5e4, both alignments) = 96 raw
sites, ZERO carrying the `c.lui 8; c.add rX, s3` base idiom within the
±26 B lookback — the readers either construct their base differently
or sit outside the class. INDECIDABLE-BY-BYTES; the runtime trace-ring
or a targeted A/B decides (the runbook §3 card update comes with the
G5x experiment day).

## §4 The machine instruments (all validated WITHOUT the GPU)

- **`--test-timings` (TT-T 5/5 PASS)**: the timing SCENARIO on the
  proven 4.42 transfer-list machinery: TT-T1 the LHR 5-field table
  (70/175/44/20/5) byte-exact to the scatter dest; TT-T2 the A/B swap
  (launch 78/210/52/26/24 → LHR); TT-T3 the rollback (LHR → launch);
  TT-T4 the slot 2→7, clean ret, zero deviation. The honest boundary:
  the byte-LANE layout of the parsed records stays INDECIDABLE until
  the §5 dump — TT-T validates the machinery, not the final layout.
  ALL previous batteries stay green (TT 11/11, TF 9/9, TR 18/18,
  selftest 5/5).
- **`build_timing_payload.py` (8/8 PASS)**: reproduces the four
  banked fingerprint representations of BOTH records (u8/u16le/u32le/
  the (rc,rfc) pair) BEFORE emitting anything; emits the u64 tables
  (lane width parameterized u8/u16/u32) and the C block with the
  TARGETS placeholder (the dump §5 supplies the real addresses; the
  {value,target} assembly then follows the 4.42 gabarit).
- **`pillarB.cu` + `pillarB-driver.sh`**: the 0xSero-method battery —
  float4 grid-stride unrolled copy/read/write, the streaming-hint
  variants (__ldcs/__stcs evict-first — the D2D L2-thrash fix), the
  copy-engine mode, the CE+SM overlap mode, and the `persist` mode
  (the accessPolicyWindow persisting window = the M3 lane, with the
  footprint sweep 256 KB-4 MB and the cudaCtxResetPersistingL2Cache
  leak guard). JSON verdicts, % of CEILING (env-overridden after an
  mclk offset). Compiled on the machine day (sm_86 probed).
- **runbook-447 §6**: (a) the nvcc battery integration (CEILING must
  match the applied offset), (b) the THERMAL probe (the battery cold
  vs hot — the GDDR6 refresh doubling shows as the effective-BW
  delta), (c) the ncu probe (dram__throughput % of peak — the direct
  % instrument).

## §5 Honesty ledger

- PROUVÉ: the true consumer-function bounds (0x1318cc0-0x131aac8,
  2296 insns) and its bit0-only reading; the false-positive
  classification of 0x12aa87a; the 24-key fetch walk; the ways anchor
  re-proof; the bit1 = RMFermiL2CacheBypass correction; the G5x
  two-word mechanism + the 0x15511554 default; the TT-T 5/5 and the
  8/8 fingerprint reproduction; all previous batteries green.
- CORRECTED: the 4.49 « the neighbor handler sets bit 1 for
  RMG5xL2VidmemPromote » — a dense-packing artifact; bit1 belongs to
  RMFermiL2CacheBypass; G5x sets NO flag bit.
- HYPOTHÈSE: the byte-flag zone semantics (the per-key 0x86xx bytes
  are ENABLE flags by shape, the exact runtime consumer of each stays
  open); the 0x15511554 field packing.
- INDECIDABLE-BY-BYTES: the byte-lane layout of the parsed timing
  records (the §5 dump); the readers of cfg+0x85C4/0x85E4 (96 raw
  sites, no CFG8 idiom in the class); the stock % of the ceiling (the
  battery day); NvLinkPeerThroughL2's landing (no store in window).
- REFUSED: nothing turned, nothing flashed, no machine action; the
  day-1 SAFE pack unchanged; the M4 hardware tier stays out of scope
  (the 2026-09-21 PC-only decision).

## §6 Instrument lessons (banked)

- **The prologue discriminator**: quadrant-1 funct3-011 covers BOTH
  c.lui and c.addi16sp — rd==x2 is the difference. The v449a bounds
  test missed it and started a 7.5 KB function mid-body (any bit test
  BEFORE the false start was invisible).
- **Dense-packed handler stubs**: per-key stubs 4-12 B apart defeat
  fixed-window extraction — slice by the SORTED branch-target list,
  carry the cfg-base idiom across slices, and cut at the first
  unconditional jump (the shared tail pollutes otherwise).
- **The stubs jump BACKWARD**: the per-key stores live in the apply
  blocks AFTER each fetch, not in the stubs — a linear walk finds
  them, a stub-window extraction does not.
- **Capstone compressed-branch operands**: this build prints the
  RELATIVE immediate (not an absolute target) — validated by the
  v450b branch-target collection landing exactly on the banked
  0x130822c site; verify the convention per build before trusting it.
- The bit-mask vs bit-index trap: `ori a4, a4, 2` = BIT 1 (mask 2),
  not bit 2 — one wrong name and the whole flag-word map shifts.
