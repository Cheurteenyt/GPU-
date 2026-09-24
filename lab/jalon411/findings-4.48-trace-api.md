# 4.48 — the trace API decoded: the 61,339-call discovery, the knob cards re-scoped, the timing census

Pass: 4.48 (stacked on 4.47 `f9f2397`). Date: 2026-09-24.
Trigger: the 4.47 queue — TÂCHE C (name the L2 knob store target + the
RmClkMprog call semantics) and the static half of TÂCHE B (where the
VBIOS DRAM timing records are parsed at runtime).
Instruments: `v448a_trace_api` (+JSON), `v448b_trace_world` (+JSON),
`v448c_stride_timing` (+JSON), the runbook-447 §5 amendment.
Baseline gate: ALL banked counts reproduced on this machine before
production — auipc 416,206 (byte census, both alignments) ✓, the
coordinate law 512/512 ✓, map 670 covered regions ✓, selftest 5/5 ✓,
TT 11/11 ✓, TF 9/9 ✓, TR 18/18 ✓.

## §1 THE DISCOVERY: the most-called function in the image is a trace logger (PROUVÉ)

The two 4.47 "lookup-by-name knob" windows call EXACTLY `0x1a9e624`
(byte-exact at both sites: the RmClkMprog window `auipc ra,0x9b5 +
jalr 0x696` @0x10e8f8e, and the L2-switch window `auipc ra,0x798 +
jalr -0x4dc` @0x1306b00). Before any knob story could stand, the API
itself had to be decoded. The result re-scopes the cards:

**The census.** Scanning every `auipc ra` + `jalr ra,ra,imm` pair at
BOTH 2-byte alignments (compressed code — the 4-byte-only scan misses
every site): 173,433 direct-call pairs → 6,941 distinct targets.
**0x1a9e624 = 61,339 sites (35.4 %) — the #1 called function in the
RM by a factor 1.7.** #2 = `0x1b4da4c` (35,225 sites) — and the dense
caller blocks call the two IN SEQUENCE (push, then act).

**The body** (204 B, `[0x1a9e624, 0x1a9e6f0)`; the `c.jr ra` @0x1a9e6c2
is a MID-function fast-path return — the cold tail 0x1a9e6c4..0x1a9e6ee
belongs to the function; all branch targets resolved with a manual RVC
decoder cross-checked 4/4 against capstone — the first decoder pass
dropped imm[5]@hw[2] and capstone was right):

- the ring header lives at the TASK pointer: `{count @tp+T+0x88, cap
  @+0x90, base @+0x98, flag @+0xA0}` (the tp-relative `lui rd,0; add
  rd,rd,tp` idiom; the TLS relocation is link-time info not present in
  the image — the true T offset = INDECIDABLE-BY-BYTES);
- if count==0 or base==0 → silent return (the un-initialized ring);
- else push N = a0+1 words at consecutive 8-byte slots (cursor =
  base + count·8, recomputed per iteration):
  - `i < a0-1` → the RAW caller args (a1..a7), up to a0-1 of them;
  - `i == a0-1` → the PACKED word: `((arg[a0-1] − 0x20000038) & 0xFFFF)
    | flag<<56 | N<<48` (the cold tail 0x1a9e6c8..0x1a9e6e4);
  - `i == a0` → **rdtime** — the 1-ns timestamp (the 4.34 proof reused);
- count wraps to **1 at cap (never 0)** — the exact fingerprint of the
  booter's transfer-loop counter (4.42: `(count % (cap-1))+1`);
- after the push: `[base] += N` (a running word counter at the base).

**The classification.** The a1-argument resolution over the callers
settles it: the labels are the RM's own trace-message fragments —
'Read'/'Write'/'disabling'/'enabling'/'ASSERTED'/'DEASSERTED'/'TRUE'/
'NV_FALSE'/'Restore'/'Enable', the inforom and gpio HAL function names
('_inforomFsWriteFile', 'gpioReadInput_v05_01', …), the severity
classes 'MISSIONERR' (×22)/'LATENTERR' (×19), and — the point — **the
registry/config names themselves**: RMPcieLinkSpeed (×46),
RmIsoHubMCLKSwitch, RMROPL2FuseMaskForFModel, RMFermiBigPageSize,
RmEngineContextSwitchTimeoutUs, RmPmgrIsenseCheckIgnore,
RmSramVminCheckIgnore, RMIncreaseRsvdMemorySizeMB, RMAsrEnable,
RMGpcTileMap, RmGlobalPoisonOverride, RMIntrLockingMode, …

`0x1a9e624` = **the RM's per-task debug/trace/event push** (the RM-side
analog of the booter's step-logger array, 4.42): tag a0 = the vararg
count + 1 (tags {1: 33,515, 2: 22,321, 3: 3,058, 4: 629, 0: 242, …}),
the packed word carries the FORMAT-STRING id (the 16-bit offset from
0x20000038) + the arg count + the flag byte, the raw args precede it,
the 1-ns timestamp follows it. It is **NOT a knob setter** — it stores
the value only in the log ring.

## §2 The knob cards re-scoped (the 4.47 correction)

- **RmClkMprog**: the banked "lookup-by-name window" = a trace push
  (a0=3 → 2 varargs: the name pointer + the value byte `lbu a2,0x34(s8)`
  + the packed format-id + the rdtime). The value byte has **no write
  site** inside the ret-bounded 222 B caller NOR anywhere in ±0x400 —
  the value comes from an outer frame; the real parse sits elsewhere.
  The site stays a consumption MARKER (the knob is handled there and
  its value flows into the log), but the state-consumption mechanism
  is NOT in the site.
- **RML2MaxWaysSysmem**: the "pointer-range switch" = the NAME dispatch
  (the `bgeu/bltu s5` compares against the interned-name VAs — the
  name string itself @0x13063c4, siblings @0x13063d0), the matched
  name copied into a local buffer (the `lbu/sb` loops), per-branch
  trace messages (distinct opaque format ids: 0x202B42F0 @0x1306af8,
  0x202B5B05-family @0x1306b58), and `c.ebreak` assert guards
  (`lbu a5,0(s1); bnez; c.ebreak`). **No store of a ways-count is
  visible in the window.** The store target stays unnamed — the 4.47
  TÂCHE C question remains OPEN, re-scoped: the consumer sits outside
  the trace/switch window entirely.
- The MCLK_LIMIT ×4 pointer-records, the 11 regkey candidates, the
  soft-floor presence strings: unchanged as DATA — every mechanism
  reading that leaned on the 4.47 window pattern inherits this re-scope.
- **The day-1 SAFE pack is UNCHANGED**: RmClk2Enable=1 + the mclk sweep
  judged by the §1 battery never depended on the window mechanism.

## §3 The opaque region: the consumption mechanism PROVEN (the 4.46 cross-link)

4.46 quantified the 0x20000000 region (71,541 refs → 65,060 targets,
3.95 MB) and closed it INDECIDABLE-BY-BYTES (the identity mapping
fails on `rm.bindata.bin`). 4.48 adds the mechanism:

- the trace pack base **0x20000038 sits 0x2C bytes from the region
  start** — the trace system anchors INSIDE the opaque rodata;
- **37,031 resolved trace sites pass pointers into the region** (the
  format strings); the a1 label pointers walk the region in 0x30–0x48
  strides (the record families);
- ⇒ the region's ROLE is now proven: the RM's rodata — the trace
  string/format table first among its tenants. The byte-level mapping
  stays INDECIDABLE (4.46's bound holds); the consumption is no longer
  a mystery.

## §4 The timing-parse hunt — the static half of TÂCHE B (INDECIDABLE-BY-BYTES, the test sharpened)

- **The stride census**: the gx5 timing table = 65 records × 76 B; any
  RM-side walker advances by 76. The image-wide census: **349
  `addi x,x,0x4c` sites, 185 li-76 constants (`addi rT,zero,0x4c` —
  c.li cannot carry 76, the 4.46 lesson), 15 mul-by-76 consumers**.
  76 is a common stride: no static anchor isolates THE timing walker.
  The candidates + their neighborhoods are banked in the JSON for the
  next pass.
- **The strings**: no 'MemTiming'/'TimingTable' anywhere; DRAMCLK
  confirmed @0x1E34B20 (the data LOAD — the v447b probe, re-cited);
  the retraining regkeys (RMDisableFbAddressRetraining,
  RmDisableGen2LinkRetraining) and SlideMCLK noted nearby in kind.
- **The deciding experiment is now CHEAP**: the dump fingerprints are
  built (`v448c_stride_timing.json → dmem_fingerprints`) — the gx5
  top-bin field vectors (launch id 6 {78,210,52,26,24}; LHR id 26
  {70,175,44,20,5}) rendered as u8/u16/u32-LE contiguous patterns plus
  the (rc,rfc) pair. The runbook-447 gained a §5: the post-boot DMEM
  dump (shared with the 4.44/4.45 machine day) is searched for them.
  A hit → the records live in RM-reachable state → the f18-analog
  timing lane OPENS (TÂCHE D). No hit (+ no FB-Falcon consumer named)
  → the lane closes honestly.
- The caveat stands: the gx5 bit grammar (six u32 → 18 fields) never
  made it into the repo (pre-repo instrument on the founder's machine)
  — the fingerprints use the five banked field values; the grammar
  should be re-banked on the next ROM pass.

## §5 Honesty ledger

- PROUVÉ: the call-target identity at both 4.47 windows (byte-exact);
  the 61,339-site census + the target distribution (173,433 pairs,
  6,941 targets); the API body decode (the ring layout, the packing
  formula, the rdtime stamps, the wrap-to-1, the base counter, the
  cold tail) with the RVC decoder cross-checked 4/4; the label
  resolution (the strings above); the L2 window structure (dispatch,
  copies, per-branch trace formats, ebreak guards); the partner body
  (the line-number-tagged mechanism, 0x8b/0xa8 = the __LINE__ pattern);
  the stride census numbers; the fingerprint round-trip selftest.
- HYPOTHÈSE: the partner @0x1b4da4c = a lock/owner-tracking primitive
  (the store @obj+0xA0, the recursion check, the global-flag test);
  tag = varargs+1 (consistent across every decoded site); the opaque
  region = the trace string table (the mechanism is proven, the
  tenant reading is the parsimonious one).
- INDECIDABLE-BY-BYTES: the true TLS offset T (link-time relocation);
  the MclkProg value byte's write site (outside ±0x400); the L2 ways
  store target; which 0x4C walker (if any) parses the timing table;
  where the parsed records live at runtime (the §5 dump decides).
- REFUSED: none — nothing was turned, nothing was flashed, no machine
  action was taken.
