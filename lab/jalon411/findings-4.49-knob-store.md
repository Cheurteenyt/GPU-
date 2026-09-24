# 4.49 — the knob store named: the L2 ways chain end-to-end, the MclkProg
latch loop, and the timing walker's static exhaustion

Pass: 4.49 (stacked on 4.48 `4ed4c42`). Date: 2026-09-24.
Trigger: the 4.48 re-scoped queue — TÂCHE C (name the RML2MaxWaysSysmem
store + the RmClkMprog semantics, OUTSIDE the trace window) and the
static half of TÂCHE B (the 0x4C-candidate narrowing).
Instruments: `v449a_knob_store` (+JSON), `v449b_stride_narrow` (+JSON),
the runbook-447 §3 card update.
Baseline gate: ALL banked counts reproduced on this machine before
production — auipc 416,206 (byte census, both alignments) ✓, the
coordinate law 512/512 ✓, the 4.48 stride totals 349/185/15 re-derived
exactly ✓.

## §1 THE TÂCHE C ANSWER: the RML2MaxWaysSysmem chain, named end-to-end (PROUVÉ)

The 4.47 card read the window @0x130697e-0x1306aec as a "pointer-range
switch"; 4.48 re-scoped it to a name dispatch inside a trace window and
left the store unnamed. 4.49 names the WHOLE chain:

**The ingestion function @0x1307AFC.** Prologue `c.addi16sp sp,-0x80`
@0x1307afc; signature `f(a0, a1, a2)` with **s3 = a1 = the config base**
(the destination struct is the SECOND argument). The body walks a
registry-key sequence @0x1307b20-0x1307f1a: for EVERY key of the
FB/L2 family it materializes the interned name pointer
(auipc+addi, both in the 0x1e343xx-0x1e345xx data-LOAD block), sets
`a2 = s0-0x70` (the frame output slot), calls **0x103c08c(s2_obj,
NAME, &local)**, then reads the local and stores the value into the
config struct at a per-key offset. The family (the interned run from
GC6_CTX_HDR @0x1e343c0 through RmEnableL2CohErrorIntr): RMAssertOnEccErrors,
RmOrigFbReqSize, RMDisableZBCDefaultLoad, RMAsrEnable, RMAsrWakeup,
**RML2MaxWaysSysmem**, RML2PreFill, RMFermiL2CacheBypass, RMAltL2ArbCYA,
RMDisableRCOnDBE, RMROPL2FuseMaskForFModel, RmAllowComptagZero,
RMAERRForceDisable, RMIsoCommitUnallocate, RMG5xL2VidmemPromote,
NvLinkPeerThroughL2, RMDisableWarBug1761410,
RMSysmemSelectAtomicsConfigNcoh, RMDisableFbAddressRetraining,
RMDisableIntrIllegalCompstatAccess, RMBug1790718War,
RMDisablePostL2Compression, RMDisableLRCCoalescing,
RmEnableL2CohErrorIntr — the FB/L2 module's regkey ingestion, ~24 keys
in one straight-line block.

**The fetch primitive 0x103c08c = the u32 regkey getter (120 B,
PROUVÉ).** Guards (name != 0, out != 0), the stack-canary dance against
the global @**0x418ffa0** (load-compare-xor at exit — see §3), the
global enable byte @**0x41d3fdc** (0 = skip the lookup), then
**0x1a93218(name, 1)** = the lookup; on hit: `lw a5, 0x10(row)` —
the value u32 at row+0x10 — `sw a5, 0(out)`, return 0.

**The registry 0x1a93218 = a runtime LINKED LIST (158 B, PROUVÉ).**
Head global @**0x40d1220**; walk `next = *(row+0)`; per node: the state
byte @+0x18 (compared against the caller's a1 = 1 = in-use), the name
@+0x19 compared CASE-INSENSITIVELY (the ±0x20 fold dance), the value
u32 @+0x10. This is the RM-side registry the host's regkey writes land
in — the same mechanism class 4.35 named "lookup-by-name", now with the
exact row layout.

**THE STORE @0x130822c (the RML2MaxWaysSysmem success handler).**
`lw a1, -0x70(s0)` (the fetched value) → **`sw a1, [config+0x3D84]`**
(base `c.lui a5,4; c.add a5,s3` = config+0x4000, displacement -0x27c);
the presence flag: `lw a4, [config+0x3D68]; ori a4, a4, 1; sw` —
**bit 0 of the flag word @config+0x3D68 = "the ways key was set"**
(the neighbor handler sets bit 1 for RMG5xL2VidmemPromote — the word
is the per-key bitmap). Then the trace push (tag a0=2, the value as
the vararg, format @0x200b4518 in the opaque rodata).

**THE CONSUMER (the reader hunt).** The displacement scan (-0x27c /
-0x298 image-wide, 251 raw hits) filtered by the `c.lui 4 + c.add`
base idiom → 5 sites: 3 are the ingestion's own handlers, and
**@0x1318d4a/0x1318d52 = a DIFFERENT function reading BOTH the flag
word AND the ways value**:

```
0x1318d34: a5 = frame-0x140            (the config base)
0x1318d38: gate = lbu 0x67f(a5)        (the feature gate byte)
0x1318d3c: beqz gate -> skip           (feature off -> nothing)
0x1318d40: s2 = 7                      (the DEFAULT ways)
0x1318d4a: flags = lw -0x298(a5)       (config+0x3D68)
0x1318d4e: flags & 1 == 0 ? -> store s2 (=7) to config+0x3D84, program
0x1318d52: value = lw -0x27c(a5)       (config+0x3D84 = the regkey value)
           value == 0 -> s2 = 0, rejoin at 0x1318d6c (config untouched)
           value == 7 -> s2 = 7, rejoin at 0x1318d6c (config untouched)
           else       -> config+0x3D84 = 7 (the [1,6] CLAMP), program
0x1318d6c: the register programming:
           a0 = *(s1+0x50)             (the MMIO-window object)
           a1 = 0x2ac                  (the register OFFSET)
           read via vtable+0x28; a2 = (val & 0xffffe0ff) | (s2 << 8)
           a2 &= 0xe0e10fff; a2 |= 0x10100000
           write via vtable+0x40 (offset 0x2ac)
           ... then the same treatment for offset 0x2bc
```

**The verdict:** RML2MaxWaysSysmem is a REAL u32 regkey whose value
reaches an MMIO register write (offset **0x2ac**, the ways at
**bits [15:8]** via `<<8`, with the 0xffffe0ff / 0xe0e10fff /
0x10100000 mask dance, then 0x2bc) through a vtable-windowed object —
the L2 partition programming. The absolute MMIO address stays
INDECIDABLE-BY-BYTES (the window base lives in runtime state), but the
knob's semantics are named: **the effective domain = {0} ∪ {7}** —
unset or 1-6 → 7 (the clamp PROVEN by the `sw s2` fall-through),
0 → honored (the ways field zeroed), 7 → the default. The day-1 SAFE
pack is UNCHANGED (observe-only — the sysmem-L2 coherency surface is
not a stock-day experiment), and the runbook §3 card now carries the
named mechanism plus the NAMED FUTURE EXPERIMENT: RML2MaxWaysSysmem=0
judged by the §1 battery on its OWN day.

## §2 The RmClkMprog window closed: a per-entry latch/trace loop (PROUVÉ)

The 4.48 note ("the value byte has no write site in ±0x400") resolves
with the wider decode: the window's caller is a LOOP over entries
(s8 = the item): per entry — the method `*(s8+0x68)` called via
`c.jalr`, then the latch byte `lbu 0x38(s8)` tested against 1; if
latched: the trace push (a0=3: the name "RmClkMclkProg", the value
`lbu 0x34(s8)`, s7, + the packed format id + rdtime), then
**`sb zero, 0x38(s8)` = the latch RESET**; loop count `lbu 0x170(s1)`.
So the "knob window" = the per-entry notify/latch handler of an object
table; the VALUE's producer = the entry's own vtable method (+0x68) —
INDECIDABLE-BY-BYTES statically (the vtable is runtime state); the
named disambiguator = a runtime trace dump of the push stream (the
values appear in the ring per §4.48's API decode).

## §3 The re-scopes

- **0x418ffa0 = the STACK-CANARY global** (for 0x103c08c and the
  ingestion function: load at entry, xor-check at exit). The 4.46
  citation of "the static {ptr,size} config @data 0x418ffa0" shares the
  ADDRESS; the canary reading is byte-proven for the 4.49 consumers.
  The dual citation is kept honestly: two readers, one address, two
  roles banked — the 4.46 dispatcher-table reading keeps its own
  evidence chain.
- **The dispatcher window family card**: the 4.47 "pointer-range
  switch" compares = the bounds of the interned-name run
  (GC6_CTX_HDR @0x1e343c0 …), now superseded by the §1 ingestion
  reading (the real dispatch = the straight-line per-key sequence, not
  a switch).
- The data census for the family: exactly ONE u64-in-range hit
  (@0x193fc54 → 0x1e34585, the NUL tail of RMDisableFbAddressRetraining
  — noise). **The MCLK_LIMIT ×4 {name-ptr} pattern does NOT extend to
  the L2 family** — the L2 keys are consumed by the code path only.

## §4 The timing walker: the static half EXHAUSTED (INDECIDABLE-BY-BYTES, with proof)

v449b narrowed the 4.48 census with four independent angles; ALL came
back negative or non-discriminating, and one negative is itself PROVEN:

1. **The feature scoring is DEAD as a discriminator (PROVEN).** Scoring
   179 candidates on (loads-from-one-base, bit-extract density, a
   second 0x4c, li-65, the LHR constants) against a 40-sample random
   noise floor: the floor's max (113) BEATS the best candidate (88).
   Stack-heavy code dominates every feature — no cheap static score
   separates a record walker.
2. **No LHR constant co-location**: zero li-210/li-175 within ±0x200 of
   ANY 0x4c site. If the RM compared the vendor's tightened timing
   values, the constants do not appear — consistent with the records
   being BIT-PACKED (the gx5 grammar six-u32→18-fields never reached
   the repo) and/or the parse not living in the RM at all.
3. **The memcpy-size signature** (`li a2, 0x4c` = a whole-record
   copy-out): 42 sites, 37 followed by a direct call — banked in the
   JSON, non-disambiguating (76-byte structs are common).
4. **The density map**: the densest 0x800-bin (9× addi-0x4c + the
   mul76 @0x122001c) decodes to a static record-table lookup — 60
   records × 76 B @0x1c57390, linear-scanned by a u32 key @+0
   (compare `lw 0(a5)` vs the key), fields at +0x18/+0x4. The table's
   keys = high-entropy u32s (hash/fuse-like), NOT monotonic, 60 ≠ 65
   (gx5), ZERO in-image pointer fields → **NAMED: not the timing
   table** — but the mechanism class exists in the RM (static 76-B
   record tables with key scans) and stays banked.

**The verdict:** the RM-side timing-walker question is now exhausted
at reasonable static depth. The census (4.48), the features, the
density, the signatures (4.49) — all non-discriminating or negative.
The runbook-447 **§5 DMEM fingerprint dump remains THE deciding
experiment** for TÂCHE B: a hit in the post-boot dump opens the
f18-analog lane (TÂCHE D); no hit (with no FB-Falcon consumer named)
closes the lane honestly.

## §5 Honesty ledger

- PROUVÉ: the ingestion function (bounds, s3=a1=config, the per-key
  sequence, the family list); 0x103c08c's body (guards, canary, enable
  byte, the lookup call, value@row+0x10 → *out, return 0); the registry
  linked-list layout (head 0x40d1220, next, value@0x10, state@0x18,
  name@0x19, the case-fold); the L2 ways store (config+0x3D84 + the
  bit0 flag @config+0x3D68); the consumer's flow (the gate byte, the
  default 7, the 0/7/1-6 branches, the clamp store, the register
  programming @0x2ac ways<<8 + the masks, then 0x2bc); the MclkProg
  latch loop (method@+0x68, latch@+0x38, value@+0x34, the reset, the
  count@0x170); the 60×76 static table decode; the noise-floor
  measurements; all baseline counts.
- HYPOTHÈSE: the 0x2ac register = the L2 partition/way programming
  surface (the reading is the parsimonious one given the knob, the
  ways<<8 field and the gate byte; the absolute register name needs
  the runtime window base); the canary dual-citation of 0x418ffa0.
- INDECIDABLE-BY-BTES: the absolute MMIO address behind the 0x2ac
  offset (the runtime window base); the MclkProg value's producer
  (the vtable method); which 0x4c walker (if any) parses the timing
  records (the §5 dump decides); the true TLS offset T (4.48's).
- REFUSED: nothing turned, nothing flashed, no machine action — the
  day-1 SAFE pack unchanged (RmClk2Enable=1 + the mclk sweep judged by
  the §1 battery), RML2MaxWaysSysmem still observe-only on the stock
  day with the named future experiment.

## §6 Instrument lessons (banked)

- An undecodable byte MUST advance the walk (`sz or 2`) — a missing
  guard turned the first v449a run into an OOM loop (the environment
  caps at 4 GB; 420-insn windows die fast and silently).
- capstone with detail=False RAISES on `.operands` (CS_ERR_DETAIL) —
  parse op_str instead.
- The displacement scan (-0x27c/-0x298) needs the BASE-IDIOm filter
  (`c.lui r,4; c.add r,base` on the SAME register): 251 raw sites →
  5 after filtering → the consumer.
- Measure the NOISE FLOOR before trusting any feature score (the
  40-random-site protocol): without it, a top-score-88 looks like a
  signal; with it, it is PROVEN noise.
- The family range must be bounded by the OBSERVED run (the first
  wide range swallowed the HUBCLIENT id tables — 354 fake consumers).
