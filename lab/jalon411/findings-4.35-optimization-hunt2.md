# 4.35 — the optimization hunt, round 2: the knob cards, the regkey
# lane, and the data twins

The 4.33 verdict was "the closed GSP-RM is optimizable ONLY through the
knob table, every turn gated by its semantics". Round 2 pays that gate:
every knob gets a CARD (unit hypothesis, risk class, leverage), and the
one surface DESIGNED for tuning — the host-facing registry-key (regkey)
machinery — is mapped end to end. The data side is censused for the
defaults behind the code knobs. No boot, no hardware write (law 2);
PR-only, no merge.

## Verdict first

1. **The SAFE optimization lane EXISTS and is now PROVEN: the regkey
   surface.** The firmware carries **864 `Rm*`/`RM*` name strings**
   (the anchor `RMEnableEventTracer` banked), with **251 names holding
   ≥ 1 direct PIC code xref** (366 xrefs total; **291 of the 366
   classify PASS-TO-CALL** — the name is handed to a lookup function as
   an ABI argument and the returned status is branched on). The
   consumed-by-name machinery is joined by **name-pointer tables** (the
   `RmVgpcSkyline` family — 27 names + 4 `SingletonMask` variants laid
   out as u64 pointer arrays @0x1d858b8-0x1d85a28; the `RmCePceMap`
   family @0x1c492e0) and by an **FNV-1a-32 hash machinery** (the
   basis 0x811C9DC5 materialized at 3 sites; one window shows the
   hash-context init stored into a state struct at +0x5c). Host-side
   regkeys reach these WITHOUT any firmware patch — the lever the
   4.34 verdict asked for ("the host-side limit API is the lever").
2. **The knob cards (TASK A) turn the 4.33 table into a decision
   tool.** 60 knobs re-censused (the banked 4.32 counts reproduce
   exactly), each with an extended CFG-following classifier, an
   rdtime/co-constant body scan, owner regions and a recomputed PIC
   fan-in. Headlines: **1000000 = TIME-CONVERSION, DO-NOT-TOUCH-BLIND**
   (the 1e9/1e6 chain in-body); **10000000 = TIME-QUANTA** (rdtime in
   the same body — 10 ms against the 1-ns tick); a **coherent
   CLK-270k-FAMILY of 14 knobs** (270000 × {1,2,3,6,8,9,10,12,16,20,
   25,30,50,100}); and a **GATED-TUNABLE shortlist** ranked by leverage
   (top: 500000, 100000000 THRESHOLD and 4000000 STATE-DEFAULT in the
   fan-in-794 region 0x10844a4).
3. **1435840000 = a clock threshold with a data twin.** The knob card
   (3 COMPARE sites, THRESHOLD/POLICY) is joined by a **16-entry u32
   table of the same value** in a code island
   (@0x1c0d38c-0x1c0d404) — 1.43584 GHz materialized on BOTH sides.
4. **The data census (TASK C) finds the defaults table of the top
   knob:** a tight region of the data segment (0x404b4b0-0x404b7e8)
   holding **22 u32 copies of 1000000** — the compiled default block
   twin of the most frequent code knob (123 sites). Plus the 2^n
   size-class ladders (@0x1c4ad68, 0x1c4ab68), duplicated config
   blocks (the data twin of 4.33's clone mass), and the
   `NVDUMPCONFIGSIG` signature at the data-segment base.
5. **A lane-D correction:** the top "duplicated data" family of 4.33
   (the `d4d856ff` ×666) is NOT waste — it is the FILL VALUE of a live
   table in the code-segment islands: u32 0xff56d8d4 repeated 2,688
   times across runs (top run 1,019 @container 0xc51f04) interspersed
   with DISTINCT descending values in the 0xff57xx band
   (…0xff570536, 0xff570512, 0xff5704ee — step ≈ −0x24). The banked
   666 reproduces EXACTLY in the a_img-aligned 16-B-block unit (first
   block @a_img 0xc50130 = the cited VA 0x1c50130); the raw
   container-aligned grid catches 670 (the 0x38 universe shift). Data
   with structure, not compressible padding.

## 1. The method (what round 2 adds)

Round 1 (4.33) enumerated; round 2 attributes. Three instruments, all
rebuilt on the banked discipline (the coordinate law re-checked at 512
windows + 7 sites before any claim; the map base proven by opcode;
every count asserted against the 4.32/4.33/4.34 banked values):

- **v435a_knobcards** — the 60 knobs re-censused with the exact
  banked rules (full24/full68/c.lui, selftest = the 11 pair counts +
  the 36 c.lui-100000), then per site: the extended classifier
  (80 insns, CFG-follow through unconditional jumps — the 4.34
  value-block shapes re-attacked), the body scan for
  rdtime/rdcycle and for co-constant round pairs, the owner region
  (the v416 covered map), and the owner fan-in from the PIC call
  census recomputed in-instrument (148,848 edges; the banked callee
  0x188EF44 fan-in = 50 reproduced).
- **v435b_regkeys** — the whole-container string census (5,269 runs
  ≥ 8 printable chars), the `Rm*`/`RM*` candidate filter (864), and
  TWO independent reference mechanisms per name: the PIC data-xref
  (auipc+addi composed EXACTLY on the string VA — the auipc census
  runs over ALL 416,206 even-offset words in the code segment, each
  hit verified against its immediate) and the raw-u64 pointer-table
  probe. Consumer classification with the ABI-honest rules (a call
  CONSUMES the a-regs as arguments; MEM-base reads are derefs). Plus
  the hash-alternative census (FNV-1a/DJB2/CRC32 constants).
- **v435c_datacensus** — the container's real ELF geometry (the
  container = the 2-LOAD ELF: code R-X [0, 0xe9b000) @0x1000000, data
  R-W [0xe9b000, 0x1070000) @0x4000000, filesz 0x1d5000), the aligned
  u32/u64 round-value census over the data segment AND the uncovered
  code islands, the cluster finder (≥ 2 round values within 64 B),
  the code-knob ↔ data-value twin cross-reference, and the d4d856ff
  structure decode with the banked-666 reconciliation.

**The two VA universes, formalized.** The campaign's VA convention
(VA_A = A_img + 0x1000000) is the rm-full.elf universe — the code-only
1-LOAD re-wrap. The RUNTIME addresses come from the CONTAINER's own
phdrs (the loader's ground truth): runtime VA = campaign VA + 0x38 for
every code byte (the same 0x38 as the B_file = A_img − 0x38 law). The
xref composition MUST run in one universe on both sides (the constant
shift cancels) — v435b composes auipc PCs and string targets in the
runtime universe and reports both coordinates.

## 2. TASK A — the knob cards (v435a_knobcards)

The card = value + site classes (extended classifier) + body evidence
(rdtime, co-constants) + owner regions with fan-in + unit hypothesis
(ordered rules R1-R7, cited in the docstring) + risk class.

### 2.1 The risk taxonomy

| risk class | rule | meaning |
|---|---|---|
| DO-NOT-TOUCH-BLIND | rdtime-in-body (TIME-QUANTA) or the 1e9/1e6 conversion chain in-body | the value IS the time math — turning it corrupts every delta |
| PROTOCOL-RISK | CALL-ARG sites | the value enters RM internals / RPC semantics |
| GATED-TUNABLE | STATE-DEFAULT or THRESHOLD dominant | turnable, but the field consumer must be NAMED first |
| CONTEXT-DEPENDENT | else | evidence insufficient — no verdict |

### 2.2 The headlines

- **1000000 (123 sites): TIME-CONVERSION, DO-NOT-TOUCH-BLIND.** The
  1e9/1e6 chain lives in the same bodies (the 4.34 tick=1-ns proof);
  1e6 in a body = the µs multiplier. Turning any of the 123 sites is
  refused by the card.
- **10000000 (40 sites): TIME-QUANTA, DO-NOT-TOUCH-BLIND.** rdtime in
  the body of a COMPARE-classified site — 10,000,000 ns = 10 ms against
  raw ticks. The 4.34 µs-ladder picture extended one rung up.
- **The CLK-270k-FAMILY: 14 knobs** = 270000 × {1, 2, 3, 6, 8, 9, 10,
  12, 16, 20, 25, 30, 50, 100} — 270000, 540000, 810000, 1620000,
  2160000, 2430000, 2700000, 3240000, 4320000, 5400000, 6750000,
  8100000, 13500000, 27000000. COMPARE-dominant across the family
  (e.g. 1620000: 10 of 16 sites COMPARE). A coherent frequency-plan
  family (the multiples are exact, not coincidental); the SEMANTIC
  stays HYPOTHESIS (4.34 proved 27 MHz is not the tick domain). The
  family clusters in regions of fan-in 112 (0x12bf874's neighborhood).
- **The GATED-TUNABLE shortlist (ranked by owner fan-in):**

| value | unit | risk | max owner fan-in | owner regions (campaign VA) |
|---|---|---|---|---|
| 500000 | THRESHOLD/POLICY | GATED-TUNABLE | 794 | 0x10844a4, 0x10d93a0, 0x133cd26 |
| 100000000 | THRESHOLD/POLICY | GATED-TUNABLE | 794 | 0x10844a4, 0x11d28a8, 0x10661dc, 0x1288c80 |
| 4000000 | STATE-DEFAULT | GATED-TUNABLE | 794 | 0x10844a4, 0x14f5c98, 0x15e4cf4, 0x15c253c |
| 400000 | STATE-DEFAULT | GATED-TUNABLE | 213 | 0x17d8344, 0x17c09b8, 0x12afc8c, 0x15c253c |
| 1435840000 | THRESHOLD/POLICY | GATED-TUNABLE | 169 | 0x14131aa, 0x144a0c8 |
| 50000000 | THRESHOLD/POLICY | GATED-TUNABLE | 112 | 0x12bf874, 0x14f5c98, 0x11e8498, 0x1288c80 |
| 20000000 | THRESHOLD/POLICY | GATED-TUNABLE | 82 | 0x129c214, 0x1225000, 0x12afc8c, 0x11f3508 |
| 1250000 | STATE-DEFAULT | GATED-TUNABLE | 52 | 0x1161c64 |
| 600000 | THRESHOLD/POLICY | GATED-TUNABLE | 39 | 0x16e2f28, 0x1270c34 |
| 340000 | THRESHOLD/POLICY | GATED-TUNABLE | 35 | 0x1242e44, 0x1270c34 |
| 202000 | THRESHOLD/POLICY | GATED-TUNABLE | 33 | 0x16f8034 |

  (the owner = the v416 covered REGION — coarse by construction; the
  per-function attribution is the queue item, not a done deal.)

### 2.3 The 1435840000 card (the cross-instrument case)

3 COMPARE sites (owner regions 0x14131aa, 0x144a0c8 — fan-in 169),
zero STORE-DATA, no rdtime in-body — a pure threshold. TASK C then
finds **16 consecutive u32s = 1435840000 in the code island
0x1c0d38c-0x1c0d404**. One value, two materials, both censused:
1.43584 GHz is a clock PLANE the RM compares against. Any "raise the
clock" idea must quote this card: the value is compared (code) AND
tabulated (data) — a patch must be consistent across BOTH, or use the
host lane.

## 3. TASK B — the regkey lane (v435b_regkeys): the safe lever, proven

### 3.1 The surface

- 5,269 printable strings (whole container); the strings live in the
  rodata islands at the END of the code segment (the anchor
  `RMEnableEventTracer` @runtime 0x1e27b20 = container 0xe27b20) and
  in the data segment (2,350 runs ≥ 6 there).
- **864 `Rm*`/`RM*` candidates**; **251 with ≥ 1 direct PIC xref**
  (366 xrefs total).
- The consumer classes of the 366: **PASS-TO-CALL (ABI arg) 291**,
  PTR-CLOBBERED 19, REG-READ 16, DEREF-LOAD (byte-walk) 5,
  UNRESOLVED-in-24 2.

### 3.2 The lookup-by-name pattern (the proof)

The canonical window (`RmValidateClientData`, runtime 0x1e27b58, 4
xrefs — cited at the campaign VAs):

```
0x1bf47fa: addi     a1, a1, 0x32a     # a1 = the name string (pair tail)
0x1bf47fe: auipc    ra, 2
0x1bf4802: jalr     ra, ra, -0x4c     # call lookup(obj?, a1=name)
0x1bf4806: sext.w   s0, a0            # status
0x1bf480c: bne      s0, s5, 0x5a      # the status gate
```

The same shape at distance (`RmClk2Enable`, 8 xrefs, sites in far
regions 0x1bb4864 AND 0x11819ca): the name-lookup API is called from
many subsystems. `RMForcePcieConfigSave` (19 xrefs — the most
referenced name) shows the string-address LADDER shape: several
`auipc a1/addi a1` blocks branching to each other = a name-match
chain. `RML2MaxWaysSysmem` shows a byte-copy walk (the name being
copied into a buffer). The pattern is not one call site — it is the
firmware's param machinery.

### 3.3 The name-pointer tables

The u64 probe finds the pointer-array grammar in the wild:

- **`RmVgpcSkyline` family @0x1d858b8-0x1d85a28** (runtime):
  `RmVgpcSkyline{,1-5}`, `RmVgpcSingletonMask`,
  `RmVgpcSkylineHalf{,1-5}` + `…SingletonMaskHalf`, MiniHalf, Quarter,
  MiniQuarter, Eighth variants — **27 names + masks** laid out as
  consecutive u64 pointers: the per-GPC skyline config name table.
- **`RmCePceMap` family @0x1c492e0-0x1c49340**: `RmCePceMap{,1-3}`,
  `RmCe1PceMap{,1-3}` (the CE→PCE mapping config names), followed by
  the contiguous `LAUNCHERR_REPORT_*` string-pointer array (a second,
  tighter grammar: 8-byte stride, no padding).

### 3.4 The hash alternative

FNV-1a-32 basis 0x811C9DC5 materialized at 3 sites (campaign VAs
0x19f80f8, 0x1aeeaa4, 0x103be86). The cited window: the basis built
into a5 (`lui a5, 0x811ca; addi a5, a5, -0x23b`) and STORED into a
state struct (c.sw a5, 0x5c(s1)) with an enabled flag byte (+0x58 = 1)
and a function pointer (+0x60) — an initialized hash context. The
prime 16777619 does NOT appear as a full pair (it is shift-built or
folded) — the basis alone names the algorithm (FNV-1a-32), the
window names the consumer shape. DJB2/CRC32/Knuth: ZERO hits.

### 3.5 The top of the tunable surface (the name cards)

| name | xrefs | table refs | reading (HYPOTHESIS where marked) |
|---|---|---|---|
| RMForcePcieConfigSave | 19 | 0 | the PCIE config-save trigger (the ladder shape) |
| RmDisableDecompOnlyLce | 9 | 0 | the LCE decomp-only disable |
| RmClk2Enable | 8 | 0 | the second clock domain enable |
| RMUseTc0NonCoherent | 7 | 0 | the TC0 coherency mode |
| RmClockUprocSecurityCheck | 7 | 0 | the clock uproc security gate |
| RmAllowChannelCreationOnPendingReset | 7 | 0 | the reset-window channel policy |
| RmValidateClientData | 4 | 0 | the client validation toggle |
| RML2MaxWaysSysmem | 4 | 0 | **the L2 ways for sysmem — a cache-partitioning tunable** |
| RMEnableQoSRunlistIntr | 4 | 0 | the runlist QoS interrupt |
| RMNvLinkMinionControl | 4 | 0 | the NVLink minion control |
| RmLpwrCacheStatsOnD3 | 4 | 0 | the D3 cache-stats policy |
| RMAcrUseCeForShadowCopy | 4 | 0 | the CE-for-shadow-copy ACR policy |
| RmDisableFbflcnDevinitBoot | 4 | 0 | the FB FLCN devinit-boot disable |
| RmVgpcSkyline family | — | 27+4 | the per-GPC skyline config (pointer table) |
| RmCePceMap family | — | 8 | the CE→PCE map config (pointer table) |

**The lane verdict: the regkey surface is the optimization road that
requires NO firmware patch.** Every turn is a host-side registry
value; the firmware-side machinery (name lookup + tables + hash) is
mapped. The next step on this lane is EXPERIMENTAL, not static: log
which regkeys the driver actually sends (the 4.26 capture answers it
on the same boot).

## 4. TASK C — the data twins (v435c_datacensus)

### 4.1 The geometry

The data segment = [0xe9b000, 0x1070000) @VA 0x4000000, 0x1d5000 B
(1.83 MB), **58.11% zeros**, opening with the `NVDUMPCONFIGSIG`
signature (twice, @0x4000000 and 0x4000038), 2,350 printable runs
≥ 6 (mostly high-entropy — compressed/obfuscated blobs).

### 4.2 The round-value census and the twins

839 aligned round hits in the data segment + 1,014 in the uncovered
code islands. The cross-reference against the 47-value knob family:

- **The 1000000 default table (THE twin):** 22 u32 copies of 1e6 in
  0x404b4b0-0x404b7e8 (a record region: pairs at +0/+0xC spacing,
  0x28-0x30 record pitch) — the compiled default block of the top
  code knob (123 sites). The 1e6 card says DO-NOT-TOUCH for the CODE
  sites (time math); this DATA table is the same value as a DEFAULT —
  the config-struct twin the knob cards predicted.
- **1435840000 ×16** in the code island 0x1c0d38c-0x1c0d404 (see
  §2.3).
- **8000000 ×2** adjacent (0x41904c0/0x41904c8) — a data-only pair.
- **The 0x80000000 fill clusters**: 131- and 129-member runs
  (@0x4099ff8, 0x409abe8) + smaller — the sign-bit constant as the
  table fill (mask/invalid markers), NOT knobs.
- **The 2^n size-class ladders** in the code islands:
  4096→8192→16384→32768… ×63 @0x1c4ad68 and ×60 @0x1c4ab68 — the
  allocator size-class tables; and the repeated config blocks
  (32768, 131072, 536870912, 524288×3, 67108864, 2097152×2) at
  0x1de0c4c, 0x1d85e04, 0x1de185c — **the data twin of the 4.33
  clone mass** (the duplicated functions carry duplicated tables).

### 4.3 The d4d856ff decode (the lane-D correction)

- 2,688 tag occurrences total (u32 0xff56d8d4); runs at stride 4:
  **1,019 @container 0xc51f04**, 753 @0xc5132c, 385 @0xc500ec,
  377 @0xc5090c, 154 @0xc5108c.
- The between-run records are DISTINCT descending u32s in the
  0xff57xx band: …0xff570536, 0xff570512, 0xff5704ee, 0xff5704ca,
  0xff5704a2… (step ≈ −0x24) — a structured table where the tag is
  the majority FILL value among real entries.
- The banked ×666 = the a_img-aligned 16-B-block unit (tag×4 per
  block), reproduced EXACTLY (first block @a_img 0xc50130 = the cited
  VA 0x1c50130); the container-offset grid counts 670 (the 0x38
  universe shift, now formalized).
- **The correction to 4.33 lane D:** this family is live data with
  structure (a fill-value table), not "wasted" duplication. The
  OTHER dup families (the ×350/×348/×341 idiom blocks) remain the
  code-clone mass — unchanged verdict. The 815,552-B "duplicated
  data" total needs the same per-family semantics gate before any
  rebuild claim.

## 5. The optimization plan, updated (round 2)

1. **The SAFE lane (no patch): host regkeys.** Proven machinery:
   864 names, 251 with direct code consumers (291 PASS-TO-CALL xrefs),
   name-pointer tables (RmVgpcSkyline, RmCePceMap), FNV-1a-32 hashed
   contexts. The named shortlist for experiments: RML2MaxWaysSysmem
   (cache partitioning), RmClk2Enable (clock domain),
   RMUseTc0NonCoherent (coherency mode), RmDisableDecompOnlyLce
   (LCE path). Every experiment = one regkey, one boot, one counter
   delta — on the STOCK firmware.
2. **The GATED lane (patch): the knob shortlist** (§2.2), each turn
   gated by the card: name the field owner first (the +0x5d0 owner
   queue item from 4.34), produce the 7/7-equivalent consistency
   proof (code + data twins TOGETHER — the 1435840000 lesson), and
   the gspbuild split-form rules apply.
3. **The REFUSED lane: the time math.** 1e6 (123 sites) and 1e7 (40
   sites) are DO-NOT-TOUCH-BLIND — the cards refuse them by rule.
4. **The queue (honest):** the per-function (CFG) attribution of the
   knob owner regions; the regkey→state-field flow for the shortlist
   names; the 4.26 capture (which regkeys the host really sends + the
   EDPp object's live values in one boot); the 7 slice-interrupted
   bodies of 4.34 (unchanged, low value).

## 6. The instrument ledger and the lessons banked

- v435a_knobcards (+json): the knob cards; the CFG-follow classifier;
  the PIC edge recomputation; selftests = the banked pair counts, the
  36 c.lui, the callee fan-in 50.
- v435b_regkeys (+json): the regkey surface; the PIC data-xref
  verifier; the pointer-table probe; the hash census; the VA-universe
  formalization (runtime = campaign + 0x38, from the container phdrs).
- v435c_datacensus (+json): the data geometry + round census +
  clusters + twins; the d4d856ff structure decode; the banked-666
  reconciliation in the a_img-aligned unit.
- Lessons: (1) the campaign VA and the runtime VA differ by +0x38 —
  the container phdrs are the loader truth; compose PIC in ONE
  universe; (2) the a-reg call rule: a call CONSUMES its ABI args
  before clobbering them — classify PASS-TO-CALL, not clobber; (3)
  the pair's own addi reads its own rd — exclude it before classifying
  (the REG-READ trap that ate the first run); (4) the 4.33d "×666"
  unit was the a_img-aligned 16-B block — reconciled exactly, the
  container grid counts 670; (5) the data segment is 0x1d5000 (1.83
  MB), not the 0x1d500 misread — re-read the phdr before asserting
  geometry; (6) a "duplicated data" family is guilty until PROVEN
  padding — the fill-value table decode flips the lane-D reading.
