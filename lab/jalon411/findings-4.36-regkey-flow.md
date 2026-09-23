# 4.36 — the regkey→knob flow map, the function-level owners, and the slice resolution

**Date:** 2026-09-24 · **Branch:** `pass/4.36-regkey-flow` (from main
0c96a6f) · **PR-only, no merge.**

The 4.35 queue named three items: the regkey→state flow for the
shortlist, the function-level attribution of the knob owner regions,
and the 7 branched-path sites of 4.34. This pass pays all three and
lands a campaign-level verdict: **the static hunt has reached its
floor** — the SAFE regkey lane is real (4.35), but the regkey→knob
canal is RUNTIME (config tables + RPC handlers), not statically
traceable. The road forward is the host experiment, not more bytes.

## 1. TASK A — the regkey→knob flow (v436a)

**Question:** for each shortlist knob site, does the function (or the
covered region) containing the site ALSO consume a host regkey
string? A YES would name the key that tunes the knob without a patch.

Method: the law and the map base re-asserted first (512 windows + 7
sites + claim7, opcode-discriminated base); the pair census re-run
with the banked rules — the 4.32 counts reproduce exactly AND the
stored v435a site cards are re-derived subsets (rd verified per
card); the 36 c.lui-100000 re-censused with a byte-probed decoder
(below) and site-equal to v434b; the regkey counts 864/251/366
reproduced; the cited RmValidateClientData xref re-decoded
(`auipc ra, 2` @0x1bf47fe + `jalr ra, ra, -0x4c` @0x1bf4802); the PIC
edge census rebuilt = **148,249 canonical auipc+jalr pairs** (the
v433b 148,848 minus the 600 direct jal — the two censuses agree) with
the banked callee 0x188EF44 fan-in = **50 exactly**; 331 distinct
regkey xrefs windowed ret-bounded.

**The c.lui byte-probe (a 4.36 instrument lesson):** C.LUI lives in
QUADRANT 1 (bits[1:0]=01), funct3=011, with a FULL 5-bit rd at
[11:7] — the site 0x16898 = word16 0x6a61 → rd=10100=x20=s4, imm
[16:12]=11000 at [6:2], imm[17]=0 at bit 12. The 4.34 lesson ("no rd
at [11:7]") was about the padded-32-bit reading, not the quadrant
layout; the probe settles it on the bytes.

**Verdict: 0/12 shortlist knobs carry a regkey xref in their
ret-bounded function; 0/12 at covered-REGION level either** (the
wider net: xref region == site owner region, zero pairs). The 56
shortlist sites split into 3 with a detectable function window and 53
inside functions larger than the 0x4000 walk (or retless leaves) —
the negative result is not a window artifact: at the region level
(knob regions up to ~143 KiB) the regkey consumers are still absent.

**What the field flow found anyway (STATE-DEFAULT sites):** the store
targets are cartographed — e.g. 400000 → `sd a5, -0xa0(s0)` @0x5dcfc8
with **5 same-field stores** in-window (a config record shape), 400000
→ `sd a5, -0xf0(s0)`/`-0xe8(s0)` @0x2b297e/0x2b2fc2, 1250000 →
`sw a5, 0x274(a0)`/`0x27c(a0)` @0x16ec62/0x16ecd4 (two adjacent
fields), 500000 → `sw a2, -0x1f8(a5)` @0x15b12e. Zero ret-stores of
a0 into any of these fields (the lookup-result→field shape never
occurs in-window) — confirming the canal is not in-situ.

## 2. TASK B — the function-level owner map (v436b)

The 60 knobs re-censused (selftests as above) and windowed at the
function level: **18/300 sites get a ret-bounded window; every one of
them has PIC fan-in 0** — the sites live in leaf fragments and
value-blocks (window spans of 18–600 B), not in call-entered
prologues. The RPC-anchor cross (v420 shapeA key tables inside the
owner regions) ties **zero** regions to a dispatch ID; the
name-pointer cross ties **zero** regions to an Rm* string table. The
4.35a region cards remain the finest static attribution of the knobs;
the function level adds the leaf-fragment fact, nothing more.

## 3. TASK C — the interrupted slices resolved (v436c)

The 11 (re-derived: 12, delta 1 documented) slice-interrupted
c.lui-100000 sites re-attacked with a FORKING CFG slice (fork at each
conditional branch, u-jump hops followed, 8 arms × 80 insns):

- **5 sites: BOTH-ARMS-AGREE:ARITH-CHAIN** — @0x124f934, 0x124fa46,
  0x1280da4, 0x12c42f0, 0x12c596c. These are the 4.34 proven
  value-blocks (confirmed now at CFG level: the read lives in the
  shared tail past the c.j) **plus one newly promoted site**
  (0x1280da4).
- **7 sites: UNRESOLVED-ALL-ARMS with a dead arm** — @0x11f7cc2,
  0x122a054, 0x124f602, 0x1250066, 0x1281032, 0x12bbc24, 0x1855a0a.
  The mechanism is now cited: their windows are dominated by BACKWARD
  conditional edges (polling loops) — the rd is consumed in a later
  loop iteration, so any bounded static slice that refuses backward
  edges (anti-loop) cannot close them. The honest HYPOTHESIS label
  stands, with the loop shape as the reason.

## 4. The campaign verdict (why this pass closes the static hunt)

Three independent probes (regkey co-residency function AND region;
RPC-anchor ties; function-level fan-in) all return zero: the knob
values are not reached by any static nameable path from the surfaces
the RM exposes. Combined with the banked record — the 250000 sites =
TIME (4.32), the tick = 1 ns (4.34), the lanes B/C/D mapped (4.33),
the knob cards + the SAFE regkey lane proven (4.35) — the static
program of the optimization hunt is COMPLETE:

- the SAFE lane = the host regkey experiments on STOCK firmware (one
  key, one boot, one counter delta) — the top tunables are named in
  4.35 (RML2MaxWaysSysmem, RmClk2Enable, RMUseTc0NonCoherent,
  RMForcePcieConfigSave…);
- the GATED lane = the knob cards (4.35a) — every turn gated by its
  card, the owner question now answered: no static owner exists;
- the REAL data = the 4.26 recv-hook capture (the instrument is
  armed) — it will show the regkeys the driver actually sends and the
  live EDPp object values in one boot;
- the 280 W rm.elf lane stays CLOSED (the 4.34 REVERT verdict).

## 5. Instrument lessons banked

1. **The byte-probe before the bit-layout faith** — the C.LUI
   quadrant-1 layout (full 5-bit rd) was settled by ONE 4-byte probe;
   two passes of docstrings had it half-wrong.
2. **The census u32-view trap** — a two-parity auipc census that reads
   the wrong view for parity 2 silently halves the edge count
   (75,068 vs 148,249); the parity probe caught it.
3. **The flat-result equality must match the stored FORMAT** — the
   v435a site_cards are capped at 6 (counts live in the metadata) and
   the int/hex duality bites twice; the asserts now compare counts
   plus subset-rd, and convert.
4. **Fork-less slices under-report loops** — the 7 unresolved sites
   are loop-shaped; a slice that refuses backward edges must SAY so
   instead of implying death (v434b's "0 dead" was the honest one).
5. **A negative cross is a result** — 0/12 function AND region level,
   with the counts banked, kills the in-situ canal for good; the
   experiment budget goes to the host lane.
6. **Write the instruments in echo-proof heredocs** — several mangled
   byte-sequences in this pass' toolchain (the `[m`/`[h`-swallowing)
   produced silently-corrupted Python; the AST re-parse + the
   banked-count selftests caught every one before any verdict.
