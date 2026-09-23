# 4.37 — the break-day package: the data-twin xref probe (the one reachability probe the campaign never ran), the regkey experiment cards, and the capture runbook

Substrate: the container `tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin`
(the real 2-LOAD ELF of 4.35c — code LOAD 0xE9B000 @VA 0x1000000, data
LOAD 0x1D5000 @VA 0x4000000), the map `v416_map.bin` (zlib-packed),
the banked JSONs (v435a knobcards, v435b regkeys, v434b bodies,
v435c datacensus). Instruments delivered: `v437a_data_twin_xrefs.py`
(+JSON), `v437b_regkey_cards.py` (+JSON), `tools/edpp/runbook-426.sh`.
Every number in this file was re-derived from the bytes in this pass;
the six selftests of v437a reproduce the banked evidence exactly
(the law 519 windows 0 fails, the 4.32 pair counts, the 36 c.lui,
T1 22/22 positions, the d4d856ff run ×1019, the T3b ladder head
{524288×3, 0, 1048576×3, 0}).

## 1. The question — the probe 4.36 never ran

The 4.36 campaign verdict: three probes (regkey co-residency, RPC
anchors, function fan-in) all return zero — the knob values are not
reached by any static nameable path. But every one of those probes
started FROM code. The 4.35c data twins were never asked the reverse
question: **which CODE references the banked data tables?** A code site
that materializes a table's address is the loader — the init path that
copies compiled defaults into runtime state — and naming it would tell
the 4.26 capture exactly which RPC event to watch. The targets: the
22×1000000 compiled-default table (T1 @0x404b4b0-0x404b7f8, data LOAD),
the 8000000 data-only pair (T2), the 2^n ladders (T3a/T3b), the
duplicated config blocks (T4a/b/c), the 16-entry 1435840000 clock
twin (T5), the d4d856ff fill-value top run (T6).

## 2. Part A — the code-side probes ALL return zero (and the idiom trap is closed)

Four independent code-side probes, each over the full image (all
offsets, both u32 parities — the 4.36 lesson held):

- **probe 1** (absolute `lui+addi` pairs, the banked census rules:
  gaps {2,4}+{6,8}, clobber checks): **0** pairs produce a value in any
  target window.
- **probe 1b** (`lui` + direct access — the dominant RV64 global
  idiom where the %lo rides the load/store itself, invisible to the
  pair census; pre-filter = the 12-bit reach union of all windows):
  **0** refs, and **0** page-bases even in reach.
- **probe 2** (PIC: `auipc` + {`addi`|`add`|`ld`} partner, first
  consumer wins): **0** refs into any window.
- **probe 5** (indexed access: any `lui` whose value lands in the data
  LOAD, followed by a base access or an `add rd3,rd,rs2` → access):
  **0** resolved accesses within the 8-insn scan.

The widened diagnostic (one-off, `scripts/v437_diag.py`, all-offsets):
**24 distinct `lui` values land inside the FULL data LOAD — 232 sites
total** (`0x4000000` ×180 = the segment base, `0x4090000` ×14,
`0x4040000` ×2 = T1's 4 KB page, 21 more pages 1-4 sites each), while
`auipc+addi` into the data LOAD = **0 over all 416,206 auipc** (the
4.35b all-offsets census count, reproduced) — **the data LOAD is
never PIC-addressed at all**; every data reference is absolute-page
or indirect. The code-side verdict: **the banked tables have no
statically-resolvable code reference — the 4.36 zero extends from the
code constants to the data twins themselves.**

## 3. Part B — probe 3: THE RESULT — the defaults are descriptor-referenced

The data-side probe (u64 scan of the whole data LOAD against all nine
windows) returns **25 hits — all into T1**, none into the islands:

- 25 u64 pointers at data VAs 0x40400d8…0x404b290 point into
  0x404b4a8-0x404b7e8 — **every pointer lands on one of the
  compiled-default records**, at each record's own address (the cited
  22 hit VAs of 4.35c = these records; the stride pattern between the
  holding structures runs {0xa0-0xb0 ×5, 0x650-0x890 ×10,
  0x7b0-0xe60 ×5, 0x2088, 0x828 ×2} — three structural families).
- 24 of the 25 point at a record head cited by 4.35c ("cited"
  universe); the 25th (0x404b290 → 0x404b4a8) points 8 B BEFORE the
  first cited record — a record whose first u32 is not 1000000 (a
  header field), the shifted-universe tolerance caught it honestly.

**The reading (labeled INTERPRETATION):** T1 is not a loader-copied
default array — it is the compiled per-resource default blob of a
descriptor family: each static descriptor (one per RM resource/class
instance) carries a pointer to ITS OWN default record {1000000, …}.
The 1000000 value stays what the 4.34/4.35a cards said (the 1-s
time-conversion family, DO-NOT-TOUCH-BLIND) — the descriptor finding
does not change the knob card, it names the MATERIAL the defaults live
in: **instance descriptors in the data LOAD, linked at object
creation — i.e. the RPC object-create path at runtime, exactly the
path the 4.26 capture watches.**

## 4. Part C — the regkey experiment cards (the SAFE-lane pack, 17 cards)

`v437b_regkey_cards.py` builds the founder's break-day pack from the
banked evidence only (selection rule: pic_xrefs ≥ 3 → 20 candidates,
minus the semantic REFUSED gate → **17 cards**):

- The top of the pack by xrefs: RMForcePcieConfigSave (×19, SAFE — the
  observable = the config-save cycle via nvidia-smi/lspci),
  RmDisableDecompOnlyLce (×9, SAFE), RmClk2Enable (×8, SAFE),
  RMUseTc0NonCoherent (×7, **CAUTION** — L2/TC0 coherence: validate
  with memtest before load), RMAcrUseCeForShadowCopy, RmStreamMemOps,
  RmLpwrCacheStatsOnD3, RMNvLinkMinionControl (×4, SAFE),
  RMEnableQoSRunlistIntr + RML2MaxWaysSysmem (×4, **CAUTION** — the
  L2-way partitioning knob: watch the bandwidth delta).
- The REFUSED gate (never run): RmClockUprocSecurityCheck,
  RmAllowChannelCreationOnPendingReset, RmDisableFbflcnDevinitBoot —
  each with the reason named (security check / reset path / devinit).
- Every card carries: the host path (the standard nvlddmkm service-key
  DWORD, the osReadRegistryDword pattern cited at rpc.c:1637 in 4.25),
  the test value (enable-flip 0→1 or a one-unit step — never a blind
  big turn), the concrete observable, the HYPOTHESIS-labeled
  prediction, and the risk class. The protocol: **one key, one boot,
  one counter delta, STOCK firmware.**

## 5. Part D — runbook-426.sh: the capture day, scripted

The break-day script (`tools/edpp/runbook-426.sh`, the runbook-280
pattern): `prereq` (the STOCK firmware sha check — the 6/7 container
refused here as everywhere), `patch` (the 4.25 recv hook, byte-exact
+ the send hook if present, the revert always available), `restore`
(the proven byte-exact revert), `initramfs` (the RpcDump=1 /
RpcRecvMode=2 / EdppForceGet=1 plumbing notes), `capture` (the journal
harvest → the analyzer --predict → the real-log verdict — the §7.2
checklist: len 96, the triplet {100000, 240000, 250000} @ {40, 44,
48}, paramsSize 24, the zero residue — with the honest negative named
if the SBIOS bit never comes), and `regkeys` (the 4.37b pack printed
for the day-2 experiments). **No step of this runbook touches the card
from the lab side — every boot gesture is the founder's, the law 2
boundary holds.**

## 6. The campaign consequence

The 4.36 verdict stands and now has its full shape: the knobs are not
reached by any static nameable path — neither from the code side
(4.36) nor from the data side as a code-addressed default array
(4.37, probes 1/1b/2/5). What 4.37 ADDS is the material finding: the
compiled defaults are **descriptor-linked** (25 pointers), so the
runtime that fills the knobs = the object-create/consume path. The
founder's two break days are now fully armed: **day 1 = the 4.26
capture** (runbook-426, the recv hook, the §7.2 verdict + the
descriptor-path watch), **day 2 = the regkey experiments** (the 4.37b
pack, one key one boot one delta). The static program stays closed;
the instruments are the deliverable.

## 7. The instrument lessons (banked)

1. **The idiom trap, closed:** the lui+addi pair census is NOT the
   global-address census — the %lo can ride the access itself
   (lui+load). v437a probes BOTH, and the reach pre-filter makes the
   full-image lui+access scan cheap.
2. **The window probe must cite its universe:** the 0x38 shift puts
   every "cited VA" two universes apart; v437a pads both and the one
   shifted-0x38 pointer (→ 0x404b4a8) was caught BY the padding, not
   missed by it.
3. **The census VA lists are hit positions, not layouts:** the "22×
   1000000 table" is a record region (varying stride) — verifying at
   the cited positions (22/22) instead of assuming a dense array
   saved the selftest from a false alarm (the first T1 check read
   {1000000, 1, 1, …} and refused).
4. **A zero needs its widened twin:** the four window probes = 0
   would have been under-reported without the full-segment diagnostic
   (24 pages, 232 sites, 0 PIC) — the negative is banked WITH its
   boundary.
5. **The probe order is evidence:** code-side zeros BEFORE the
   data-side 25 made the descriptor reading forced, not chosen.
6. **The cards cite, they do not invent:** every 4.37b field comes
   from a banked JSON row; the prediction row stays HYPOTHESIS by
   construction.

## Discipline

No boot was executed, no card was written, no firmware was modified
in this pass (the law 2). The runbook is the founder's instrument;
the regkey pack is advice labeled HYPOTHESIS; every static claim
carries its probe and its count. The PR is opened to main WITHOUT
merge, per the standing rule.
