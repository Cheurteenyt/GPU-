# 4.33 — the firmware optimization hunt: where the closed GSP-RM can
# and cannot be optimized — the four-lane map

Substrates: `tools/analysis/gsp-extract/rm-full.elf` (the map
coordinates, image at p_offset 0x40) and
`tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin`, byte-identical
code under the proven law **`B_file = A_img − 0x38`** (re-asserted in
every instrument: 512 sampled windows + the six 4.30 patch sites + the
7th site, 0 fails; the map base A_img re-proven at the OPCODE level —
both coordinate probes hold seen bits, the discriminating bytes are
lui `0x37` at A 0x1a062 vs bltu `0x63` at the B-phase address; the
v432e line-172 smoke assert re-verified as a different real start,
non-load-bearing). Instruments: `lab/jalon411/v433c_knobs.py`,
`v433b_callfanin.py`, `v433a_dupcode.py`, `v433d_layout.py` (+ their
JSONs). All self-tests pass; the lessons caught mid-pass are banked
in §7.

## Verdict first

The mission asked WHERE the GPU firmware can be optimized. For a
closed binary the answer splits into four lanes, each measured:

| lane | what it asked | what the bytes say | verdict |
|---|---|---|---|
| A — policy knobs | which constants bound runtime behavior, and can a byte patch turn them? | 60 round knob values classified (COMPARE/DIVIDE/STORE/CALL-ARG), the µs ladder re-confirmed, the 36 c.lui-100000 attributed to 34 function bodies, the 4.30 patched container = **6/7 INCOHERENT** | the knobs are PATCHABLE IN BYTES but the semantics gate every turn — the 4.32 lesson, now quantified per knob |
| B — duplicated code | how much of the image is the same instructions twice? | **145,117 exact families, 918,518 windows (27% of all instruction starts), run-merged shareable ≥ 12.2 MB**; the top family = ONE 16-B accessor idiom present **26,060 times** | PROVEN at the byte level; reclaimable only by a rebuild/relink — but it taxes every binary patch (the 4.32 7th-site lesson, quantified) |
| C — hot paths | where would a change have the most effect? | **148,848 direct call sites, 7,084 distinct targets**; the top-2 functions absorb 52,114 and 31,329 calls; the ecall-0x25 gate has 7,284 callers; a 24-B flag predicate has 2,100 | the hot map is banked; every patch target should be checked against it |
| D — layout waste | how much of the delivered bytes is dead weight? | the ELF is already compact (0 inter-LOAD file gaps); 575,808 B of zero runs (3.8%) sit BETWEEN code regions; the booter file is **96.3% zeros — and that is STRUCTURAL** (the GFW boot-area bias law) | nothing reclaimable without re-deriving the container grammar; the waste census closes the "shrink the image" lane |

**The global answer: OUI — the firmware is optimizable, but only
through lane A's knob table (behavior) and only behind per-knob
semantic confirmation; lanes B/C are the evidence base a rebuild or an
aggressive patch campaign would need; lane D is closed.** The
immediate actionable defect is not an optimization but an
incoherence: the 4.30 patched container rewrites six 250000 sites to
280000 while the 7th split-form site keeps 250000 (4.32e) — a binary
that is half-turned. Complete it to 7/7 or revert it; do not boot it
as-is (its semantic is TIME anyway — 4.32).

## 1. The method (what "optimization" means here)

No source, no compiler, no linker — the only levers on a closed
firmware are (a) the compile-time constants that survive into the
code image (lane A), (b) the structure the compiler left behind —
clones, hot callees, padding (lanes B/C/D) — relevant to a future
rebuild and to the COHERENCE of any binary patch. Every census below
re-asserts the coordinate law and the map base before counting, and
the anchors are the banked 4.32 counts (the discipline since 4.19:
the flat results re-derived before every new pass).

## 2. LANE A — the policy-knob table (v433c_knobs)

The census scans every lui+addi/addiw pair (all even offsets, gaps
{2,4} and independently {6,8} with the banked clobber rules — exactly
v432e's two passes) plus the compressed c.lui+addi form, then keeps
the ROUND values (|v| ≥ 1000, divisible by 1000): **60 knob values**.
The full-form pre-filter found 138,636 lui candidates; pass-24 yields
1,688 distinct values (v432_allpairs' 1,695 counted WITHOUT the
funct3==0 filter — 7 of its values are non-addi pairs; the census
delta is named, the question-value counts reproduce exactly).

**Selftest (hard asserts):** the banked pair counts reproduce
exactly — 250000=6, 500000=25, 1000000=123, 4000000=15, 100000000=17,
−250000=1, −1000000=3, −500000=5, 100000=0, 240000=0, 280000=0 — and
the c.lui-100000 census finds **36** real sites (the 4.32e count).

### 2.1 The knob table (top values, with the first-consumer class)

| value | full24 | full68 | c.lui | dominant use (first ≤90 sites) | reading |
|---|---|---|---|---|---|
| 1000000 | 123 | 37 | 0 | COMPARE 7 / ARITH 3 / STORE 2 | the µs ladder's 1 s (4.32) + conversions |
| 1000000000 | 76 | 24 | 0 | DIVIDE 2 / STORE 2 / ARITH 3 | the ns↔s conversion denominator |
| 10000000 | 40 | 3 | 0 | COMPARE 6 / DIVU / ARITH | the 10 ms conversion step (cited below) |
| 100000 | 0 | 0 | **36** | ARITH 4 / UNRESOLVED 8 (of 12 sampled) | 34 function bodies — §2.3 |
| 500000 | 25 | 6 | 0 | COMPARE 9 | the 4.32 clamp (s4, cited there) |
| 50000000 | 27 | 2 | 0 | COMPARE 9 | the 50 s ladder arm |
| 20000000 | 24 | 2 | 0 | COMPARE 8 / STORE 1 | the 20 s ladder arm |
| 2700000 | 19 | 3 | 0 | COMPARE 9 / STORE 1 | an id AND a state-field store — §2.2 |
| 5000000 | 18 | 3 | 0 | DEAD-at-ret 6 / COMPARE 2 | mixed subsystems |
| 1620000 | 16 | 3 | 0 | COMPARE 10 | an identification chain — §2.2 |

(The use class = the first consumer of the materialized register
within 40 instructions, decoded from the addi forward; the histogram
covers the first ≤90 sites per value. Coarse by design — the per-site
windows are in the JSON.)

### 2.2 The cited windows: the same magnitude, three different semantics

The banked lesson (4.32's 0x441F0 note: read the role before counting
the family) applied knob by knob — three sites, all "round", three
different meanings:

**a conversion constant** (10000000, VA 0x1019844):
```
0x1019848: addi     a2, a2, 0x680        # ┐
0x101984c: bgeu     a2, a4, +0x98        # │ 10,000,000
0x1019850: divu     a3, a2, a6           # │ a DIVIDE + clamp idiom
0x1019854: lui      a4, 0x4c5            # │
0x1019858: addi     a4, a4, -0x4c0       # ┘ 0x4c4b40 = 5,000,000
0x101985c: c.addw   a5, a3
0x101985e: sw       a5, 0x728(a0)
```

**a state-field store** (2700000, VA 0x11568e4 — the state shape's
banked −0x688 field, 4.17's top dispatch offset):
```
0x11568e8: addi     a4, a4, 0x2e0        # ┐ 2,700,000
0x11568f0: sw       a4, -0x688(a5)       # ┘ into the state frame
0x11568f4: c.lui    a4, 7                # the NEXT slot formation
```

**an identification chain** (1620000, VA 0x12056e4 — a value
DISCRIMINATOR, not a threshold; the ladder 1,620,000 → 2,700,000 →
5,400,000):
```
0x12056e8: addi     a4, a4, -0x7e0       # ┐ 1,620,000
0x12056ec: beq      a5, a4, +0xa4        # ┘
0x12056f0: lui      a4, 0x293            # ┐ 2,700,000
0x12056f4: addi     a4, a4, 0x2e0        # ┘
0x12056f8: beq      a5, a4, +0x94
0x12056fc: lui      a4, 0x526            # ┐ 5,400,000
0x1205700: addi     a4, a4, 0x5c0        # ┘
0x1205704: beq      a5, a4, +0x90
```

**Verdict (LANE A):** the knob table is the optimization surface —
every turnable constant is in the JSON with its site, register, form,
use class and body — but the three windows above are the proof that
NO blanket interpretation ("all round values are timeouts") survives
the bytes. Each knob turn = one semantic investigation + the 4.26
capture or the boot experiment. The µs ladder family
{±250000, ±500000, 1000000, 4000000, 100000000} stays the only
scale-PROVEN set (the rdtime anchor, 4.32 §3.3); 1000000000 =
conversion denominators (the DIVIDE sites); the 1.62e6/2.7e6/5.4e6
chains = identifiers. The tick rate stays HYPOTHÈSE (4.32's open
question) — nothing in this pass contradicts it.

### 2.3 The 36 c.lui-100000 sites: the 4.32e queue item, paid

Every one of the 36 real c.lui+addi 100000 sites is now attributed:
**34 distinct function bodies** (the ret-bounded walk; two bodies
carry two sites each), **3 sites inside the s2/s3 regions** (the
0.1 s neighbors of the 0.25/0.5 s band, the queue's open question) —
the body spans and the region map are in
`v433c_knobs.json:clui_100000_attribution`. The semantic (what 100000
bounds in those 34 bodies) is the NEXT queue item — it needs the same
per-site treatment s0-s5 got in 4.32, and it is the last unexplored
knob family of the time lane.

### 2.4 The 4.30 patch incoherence (the actionable defect)

The 4.30 patched container rewrites the SIX full-form sites to
280000; the SEVENTH site (the gap-8 split at A 0xB99C82, 4.32e) keeps
250000. The result: a firmware where six copies of a constant say
280000 and one says 250000 — the band structure 4.32 proved
([250000, 500000] with the −250000 deadband) is now internally
inconsistent (280000 outside the s2 deadline math, inside the s4/s5
clamp flow). Whatever the eventual semantic, a one-boot experiment
must run on a COHERENT binary: either 7/7 to 280000 or a revert to
the stock six. This pass registers the incoherence; the choice (and
the boot) stays the founder's.

## 3. LANE B — the duplicate-code census (v433a_dupcode)

Method: 16-byte windows at every SEEN instruction start (3,400,942
windows, both parity classes, tail-truncated windows excluded — the
first run's false-collision lesson), polynomial-64 hash, byte-level
partitioning inside every hash group (the hash only pre-filters;
families are DEFINED by the raw bytes), filler separation
(all-zero / nop `13 00 00 00` / c.nop `01 00` patterns), and
RUN-merging of overlapping windows (a repeated pattern yields one
window per 2-byte step — window counts inflate the estimate; the
first run's 12.4 MB became 12.2 MB real after filler separation and
run merging, with the booter's NOP sea isolated).

**The census:**
- **145,117 exact duplicate families** (byte-verified), **918,518
  member windows = 27.0% of all instruction starts**;
- filler: only 3,572 windows in 18 physical runs (~7.4 KB) — the
  linker padding is negligible;
- the run-merged shareable lower bound (each copy beyond the first
  counted at the 16-B floor): **12,202,400 B ≈ 11.6 MiB**;
- the top-40 families, extended to their true common prefix:
  **4,328,848 B**.

**The #1 family — the RM's cloned accessor idiom (PROVEN bytes):**
one 16-B sequence appears **26,060 times** across 186 distinct 64 KB
buckets (median inter-copy gap 168 B — the idiom is a per-function
insert):
```
0x100d27a: addi     a3, a4, 0x52c
0x100d27e: c.add    a3, a5
0x100d280: c.lw     a1, 0(a3)
0x100d282: lui      a0, 0x400
```
26060 copies × 16 B = 417 KB for ONE idiom; the runner-up families
(the JSON's top_families) are the same idiom's phase-shifted
overlaps (26,060 members each at ±2 B phases — the run-merging keeps
the estimate honest). The next distinct families are 3,350/2,733
copies deep. The same idiom families surface in the NON-COVERED
regions too (lane D's data census finds ×350/x348/x341 — the clones
extend into the islands the descent never verified).

**Verdict (LANE B):** the duplication is REAL, byte-proven, and
massive — the compiler cloned the RM's accessor/idiom substrate
across the object hierarchy (consistent with 4.16-4.19's
dispatch-driven, derivation-graph architecture). It is NOT
reclaimable by binary patching (no linker exists inside the image);
it is the evidence base for a future rebuild AND the operational tax
on every patch: **~27% of instruction starts sit inside an exact
duplicate — a binary edit must check every copy of its context, the
quantified version of 4.32's 7th-site lesson.**

## 4. LANE C — the static call census and the hot fan-in (v433b_callfanin)

The probe first: at seen starts, **300,245 auipc / 148,314 jalr /
only 600 jal** — this firmware does NOT call with direct jal; it
calls in adjacent PIC pairs. The census counts the canonical edge
(auipc+4 = jalr, funct3 0, rs1 == auipc.rd, rd ∈ {ra, zero},
target in-image):

- **148,848 direct call sites** = 145,922 calls (rd=ra) + 2,327
  tail-jumps (rd=zero) + 600 direct jal;
- **7,084 distinct targets**; the PIC call targets carry the seen bit
  at **100.0%** (the census × map mutual validation — hard assert);
  tails 99.2%, jal targets 45.7% (jumps enter uncovered islands —
  reported, not asserted);
- the 4.16 comparison is OBSERVATIONAL by unit: its 81,871 = distinct
  (caller-FUNCTION, callee) tuples, recursive-descent-validated — a
  different unit than sites; the delta is definitional, not a
  contradiction (v416_rdescensus.json:edges.distinct re-read).

**The hot list (top fan-in, prologues cited):**

| VA | fan-in | body walk | what the prologue shows |
|---|---|---|---|
| 0x1a9e624 | **52,114** | 160 B | `c.addi16sp sp, -0x60; c.sdsp s0...` — a small frame, one region cluster |
| 0x1b4da4c | **31,329** | 126 B | `c.addi16sp sp, -0x40; 4× c.sdsp` — the same shape |
| 0x1aa3444 | 7,284 | 32 B | **`addi t0, zero, 0x25; ecall` — the ecall-0x25 gate** |
| 0x1be4224 | 3,518 | 182 B | a 7-save prologue |
| 0x18c3f80 | 2,822 | 218 B | `c.beqz a0, +0xda` — an early-exit guard |
| 0x1a91e74 | 2,100 | 24 B | **`auipc; lbu a5, 0x10e(a5)` — a global-flag predicate** |

- the callee 0x188EF44 (the s1/s2 shared timeout worker, 4.32) has
  fan-in **50** (hard assert ≥ 2);
- the top region [0x1a9b678, 0x1aa344c] (31.5 KiB) absorbs **60,466
  call edges = 1,922/KiB** — the RM's service cluster (it contains
  both top functions and the ecall gate).

**Verdict (LANE C):** the hot map is banked. The two 24-32 B stubs
(the ecall gate, the flag predicate) with 7,284/2,100 callers are the
kind of function a rebuild would inline or the semantics would cache
— unprovable without the CFG, registered as the inlining candidates.
For patch work: touching the top-2 functions touches the execution
of 83K call sites — the risk ranking is now measurable.

## 5. LANE D — the layout-waste census (v433d_layout)

**The ELF (gsp-rm-17MB.bin, e_machine 0xf3 re-asserted):** 2 LOADs —
code R-X [0x0, 0xe9b000) @VA 0x1000000 (the law's image), data R-W
[0xe9b000, 0xeb8500) @VA 0x4000000, plus PT_GNU_STACK and a
PT_LOOS+ note. **Inter-LOAD file gaps = 0 B** — the ELF is already
compact; the "shrink the container" lane starts closed.

**Zero runs (≥ 64 B):** the code image carries 1,691 runs totaling
575,808 B (3.8%) — only 7,464 B touch covered bytes (in-code padding
is rare; the zeros live BETWEEN the verified regions). The container
census agrees.

**The booter (bootloader.bin, 446,464 B):** 2 zero runs = **430,168 B
= 96.3%** (a 118,893-B run @0x3f93 and a 311,275-B run @0x21015) —
the real booter content ≈ 150 KB against a fixed 0x6d000 boot area.
BUT the boot-area size is STRUCTURAL: the GFW directory's bias law
(true = load_off + 0x6d000, 4.30) and the container's exact zero-gap
tiling are built on it. The zeros are load-bearing coordinates, not
waste — reclaiming them = re-deriving the GFW grammar, refused as
out of scope. (4.31's NOP-safe patch methodology operates inside the
real content; it is unaffected.)

**Duplicated data (16-B aligned blocks, non-covered bytes):** 10,045
exact families, 815,552 B — the top family = the 4-byte pattern
`d4d856ff` repeated **666 times** at [0x1c50130...] (a descriptor
table of identical entries); the runner-ups are the lane-B idiom
families inside the uncovered islands (×350/x348/x341 — the clone
mass extends beyond the verified code).

**Strings:** 239 duplicated strings ≥ 8 chars in rm-strings.txt,
~7,593 B wasted (the top: subsystem-name prefixes).

**Verdict (LANE D):** CLOSED. The image wastes nothing a binary
optimization could reclaim: no file gaps, 3.8% inter-region zeros
(compress to nothing and are outside the code), the booter's zeros
are structural. The 4.29 LZ floor (51-58%) already covers the
DELIVERED size question.

## 6. The global verdict — the optimization plan

1. **The one-boot candidate (lane A, blocked on coherence + semantics):**
   the knob table is the firmware's turnable surface. The µs ladder is
   scale-proven; every other knob needs its s0-s5-style per-site
   semantic before a turn. The 4.30 container is 6/7 INCOHERENT —
   complete to 7/7 (one 8-byte window, the v432e split pattern) or
   revert before ANY boot experiment.
2. **The patch-coherence rule (lane B, immediate):** any future binary
   patch runs the v433a census against its context window — with 27%
   of instruction starts inside exact duplicates, "the bytes appear
   once" is now a PROVEN-checkable claim, not an assumption.
3. **The hot-risk rule (lane C, immediate):** a patch inside the
   top-fan-in functions (52K/31K callers) or the service cluster
   carries measurable blast radius; the JSON ranks it.
4. **The rebuild option (lanes B+C, prospective):** 11.6+ MiB of clone
   mass and two 24-32 B stubs with 5-7K callers are what a relink
   would target — registered for the day a rebuild pipeline exists
   (it does not today).
5. **The closed lanes:** layout waste (lane D) — nothing to reclaim;
   the LZ container (4.29) — already at the floor.
6. **The next semantic queue (lane A):** the 34 bodies of the
   c.lui-100000 family (§2.3), then the tick rate (4.32's residual) —
   the last two names the time lane needs.

## 7. The instrument ledger and the lessons banked

| instrument | selftest anchors | status |
|---|---|---|
| v433c_knobs.py | the law (519 windows) + the map base by OPCODE + the 11 banked pair counts + the 36 c.lui | PASS |
| v433b_callfanin.py | the law + the s1 callee 0x188EF44 (auipc arithmetic AND fan-in ≥ 2) + PIC targets 100% seen | PASS |
| v433a_dupcode.py | the law + byte-partitioned families + the avalanche control 512/512 | PASS |
| v433d_layout.py | the law + the ELF magic/e_machine + the container phdr parse | PASS |

Lessons caught by the bytes mid-pass (the discipline: named, not
hidden): (1) the map-base probes both hold seen bits — a coincidence
of two real starts; the OPCODE discriminates (lui 0x37 vs bltu 0x63);
(2) a seen-start-only pre-filter undercounts vs the banked
full-image census (s0 lives in an uncovered island) — the census
coverage is ALL even offsets, seen reported per site; (3) 16-B
windows near the image end truncate and masquerade as hash collisions
— full-window filtering first; (4) the XOR-hash "collisions" were
never byte-real — the byte partitioning makes the hash a pre-filter
only; (5) the booter's NOP sea yields 26,060-member "families" of
OVERLAPPING windows — filler separation + run-merging before any
shareable estimate; (6) the direct-jal premise was wrong (600 hits) —
the firmware calls in auipc+jalr PIC pairs (300,245/148,314), the
census follows the bytes, not the assumption.
