# 4.52 — the write lane: the Libos walker, the heap walker, the route-H
# builder + the writer, the PCIe calibration, the WPR2 v2 probe design

Pass: 4.52 (stacked on main `356406b` — the 4.51 stack is MERGED).
Date: 2026-09-25.
Trigger: the founder's directive — « PASSE 4.52 — branche
pass/4.52-write-lane, PR sans merge… T1 le parseur Libos, T2 le walker
du heap, T3 le builder route-H (le cœur), T5 la calibration PCIe de
pillarB-sysmem, T4 le design de la sonde WPR2 v2 »; the order T1 → T2 →
T3 → T5 → T4; the rules unchanged (the evidence against the EXACT
610.57.04 tree, INDECIDABLE if the bytes do not decide, the banked
counts reproduced first, nothing writes outside the gated, the
rollback = driver alone).
Deliverables: `lab/jalon411/v452a_libos_walk.py` (the S4 parser),
`lab/jalon411/v452b_heap_scan.py` (the heap walker),
`lab/jalon411/v452c_hpatch_build.py` (the signed plan builder),
`tools/edpp/gsp_hpoke.c` (the v2 writer),
`tools/edpp/runbook-452.sh` (the gated day),
`tools/edpp/pillarB-sysmem.py` v452 (the calibrated battery), this
file + the INDEX row.
Environment note: the workspace was RESET between the 4.51 session and
this pass — the repo re-cloned, the EXACT tree re-fetched, and the
baseline gate re-run on the fresh clone (the 4.51 precedent, repeated).

Baseline gate: ALL banked counts reproduced FIRST on the fresh clone —
**auipc 416,206 + the coordinate law 512/512 ✓ (v450b), the v431
census 17/17 ✓, the fingerprints 8/8 ✓, the emu selftest 5/5 ✓,
TT 11/11 ✓, TF 9/9 ✓, TR 18/18 ✓, TT-T 5/5 ✓, v451a 4/4 embed + 4/4
control ✓, v437a (the 519-window law 0 fails, the 4.32 pair counts
exact, the c.lui census 36/36) ✓, the map covered_regions = 671 ✓
(v435a; the 4.51 findings named 670 — the fresh-run count is 671,
drift noted, the instrument is the truth)**.

## §1 T1 — the Libos region walker (v452a): the S4 grammar from the EXACT header

The grounding, read from the tree (`open-gpu-kernel-modules @
610.57.04`, e4a5faa) — NOT from memory:

- `src/common/uproc/os/common/include/libos_init_args.h` — the struct:
  `{LibosAddress id8; LibosAddress pa; LibosAddress size; NvU8 kind;
  NvU8 loc}` = **32 bytes** (6 pad), `kind` = NONE/CONTIGUOUS/RADIX3,
  `loc` = NONE/SYSMEM/FB, and **LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX
  = 4096 BYTES** — the table is 4096 bytes total (= 128 slots × 32 B),
  NOT 4096 entries. The allocation confirms it
  (`kernel_gsp_tu102.c:152-175`: the descriptor = MAX bytes, contiguous
  UNCACHED SYSMEM, zeroed at setup).
- `kernel_gsp.c:6201-6233` (`kgspSetupLibosInitArgs_IMPL`) — the host
  writes: the log entries (kind=CONTIGUOUS, loc=SYSMEM, pa =
  `pTaskLogBuffer[1]` — the GPA the driver stored INSIDE the log
  buffer, size = memdescGetSize) then ONE more entry, "RMARGS".
- `kernel_gsp.c:3219-3233` (`_kgspGenerateInitArgId`) — **the names ARE
  the ids**: up to 8 ASCII chars packed big-endian into the u64
  ("RMARGS" → 0x00524D41524753). The walker's name decode = the exact
  inverse (`struct.pack('>Q', id8)`, NUL-left-stripped).

The instrument: walks all 128 slots, decodes every record (name, pa,
size, kind, loc), flags kind/loc outside the enums (FLAGGED — decoded
anyway, never guessed), treats the zero tail as EMPTY, and picks the
heap region as the SYSMEM CONTIGUOUS record whose size matches the S5
dump size — UNRESOLVED on a miss, AMBIGUOUS on two matches, never the
"largest region" guess. Truncated dumps refuse with an error.

**The selftest 27/27 ✓** — including the TREE GUARD: when
`.ogkm-610-cache` is present the selftest re-reads the header LIVE and
asserts the struct members + the 4096-BYTE constant against it (the
exact members, not plausible names — the 4.51 lesson made structural);
the codec round-trips, the 9-entry + zero-tail shape, the full
128-slot table, the FLAGGED record, the heap pick (match/miss/
ambiguous), the truncation refusal.

## §2 T2 — the heap walker (v452b): the crossing, the plan map, the floor

The patterns are **IMPORTED from v451a** (`build_patterns`, `find_all`,
`classify`, the floor discipline) — never re-transcribed; the banked
pattern set stays the single source.

- **The crossing** (the brief's verbatim rule): a heap hit whose bytes
  also appear in S1/S2 = HEAP+STATIC (route-H with the echo named); a
  heap hit found NOWHERE in the statics = HEAP-ONLY (the cleanest
  route-H); a hit in S1 ALONE = STATIC-ONLY — **NOT the route H** (the
  v451b IMG refusal: the booter verifies that surface), reported, never
  planned.
- **The plan-ready map** (the byte positions PROVEN, nothing else):
  - the verbatim raw76 record: rc @+0, rfc @+1 (the pair is byte-true
    in the VBIOS record, banked 4.51); ras/faw/rrd = NO banked
    in-record positions (the packed grammar = the ring-33/34 target) —
    INDECIDABLE;
  - the vec fingerprint: the fields at +i·lane in the VECTOR order;
    the launch vector = (rc, rfc, ras, rp, cl) → rc/rfc/ras
    plan-ready; **faw/rrd have no launch-vector slot** (INDECIDABLE);
    rp/cl are NOT in the retight table (no vendor proof — never
    touched);
  - the pair: rc+rfc only; the colo walk: evidence, never positions.
- **Plan eligibility** (the floor discipline carried to the plan): only
  verdict == HIT writes; SUSPECT = the human review (never a write); a
  2-byte pair alone can NEVER reach the HIT bar on a realistic heap —
  the pairs corroborate, they do not plan.
- **The landmine**: `is_landmine(record_id, old_bytes)` — the id-19
  all-zero record refuses, id-agnostic on the bytes; the last-line
  defense = the writer's pre-verify (§3). The raw76 pattern set
  (id6/id26) can never surface id19 by itself — the guard is a
  function so it is testable without pretending the pattern exists.

**The selftest 23/23 ✓** — and it caught 3 real bugs before the
founder (the 4.51 lesson, repeated: the selftest runs BEFORE the
merge): (1) the landmine was tested through a pattern that can never
exist in the set — restructured into the direct guard function + the
no-crash/no-candidate/no-plan embed test; (2) a unique 2-byte pair hit
in 1 MiB was expected as a candidate — the FLOOR discipline correctly
classifies it as noise (the test now asserts SUSPECT on a 64 KiB heap
with 12 embeds AND plan_eligible=False); (3) `plan_eligible` did not
exist — the verdict/count logic now names it explicitly.

## §3 T3 — the route-H builder (v452c), the writer (gsp_hpoke.c v2), the day (runbook-452)

### The builder

`v452c_hpatch_build.py` turns the v452b verdict into the SIGNED write
plan:

- ONLY plan_eligible candidates; **old-bytes = the bytes the candidate
  FOUND** (the runtime truth — not the expected values), new-bytes =
  the v451b LHR values (rc 70, rfc 175, ras 44, faw 20, rrd 5 — the
  vendor's own retightening);
- **ONE entry per selector** (RmGspHPoke=<sel>: 1=rc, 2=rfc, 3=ras,
  4=faw, 5=rrd): a selector collision between candidates = REFUSED
  (AMBIGUOUS — the human reviews and re-runs with --pick; a name-only
  pick that cannot separate two offsets stays refused, by design);
- the fields without proven positions = **named null targets** in the
  plan (INDECIDABLE, never guessed byte positions);
- `verify_after` on EVERY entry;
- **the signature**: plan_sha16 = sha256(the canonical entries
  JSON)[:16] — the C table embeds it and the writer prints it in dmesg
  NEXT TO the verify results: any drift between the reviewed plan and
  the compiled table (or a re-scan that moved the offsets) is visible
  in the boot ledger.

**The selftest 18/18 ✓** — the verbatim route (rc @+0 old=4e new=46;
rfc @+1 old=d2 new=af), the vec route (u32 lanes, ras @+8), the
SUSPECT refusal, the landmine refusal, the gated null plan (0 entries,
stable sha), the collision refusal, and — **the C emission byte-exact
tested vs python (gcc compiles the emitted table and dumps its bytes;
the dump == the python plan, the 4.44 lesson executed, 3 plans tested
including the null one)**.

### The writer

`tools/edpp/gsp_hpoke.c` — the drop-in, grounded on the tree:

- **the gate**: `osReadRegistryDword(pGpu, "RmGspHPoke", &sel)` —
  SEPARATE from the 4.51 dump key (the two instruments coexist on one
  boot); absent/0 = the file does nothing; >5 = the dmesg refusal;
- **UN FIELD PAR BOOT**: the selector picks THE ONE plan entry; no
  loop, no batch, no retry — the next field = the next boot;
- **the order of defense**: the regkey gate → the selector filter →
  the PRE-VERIFY (the runtime bytes must equal the plan's old bytes —
  a moved record or the id-19 landmine aborts BEFORE any write, the
  STALE-PLAN verdict) → the byte-lane write → the POST-VERIFY (the
  readback must equal the new bytes, the VERIFY-FAIL verdict printed,
  never retried, never hidden) → the dmesg ledger for every verdict;
- **the map anchor**: `memdescMap(pSysmemHeapDescriptor, 0, sz,
  NV_TRUE, NV_PROTECT_WRITEABLE, &pVa, &pPriv)` — the PROVEN radix3
  pattern @kernel_gsp.c:6028; the unmap = the 4-arg pattern (the
  state-monitor teardown, kernel_gsp.c ~4033, banked 4.51);
- **the coherence note** (the tree): the sysmem heap = a CONTIGUOUS
  UNCACHED SYSMEM allocation (kernel_gsp_tu102.c:214) — a CPU write to
  the uncached mapping is coherent with the GSP's reads (no stale
  CPU-cache question on this surface);
- the offset bound check (the plan offset + len vs the heap size)
  refuses a plan built for another heap size;
- the stub-compile PASS (the TU compiles and links against a stub
  header surface with the GATED null plan; the machine's dkms build
  stays the REAL judge — the build = the judge, the 4.44-machine
  lesson).

One selftest-class catch during the writing: the selector initially
traveled in a reused struct member — caught and fixed into a dedicated
`sel` member BEFORE the merge (the same « chemin jamais exécuté »
class the 4.51 lesson names; the stub compile executes the path).

### The day

`tools/edpp/runbook-452.sh` (bash -n clean; the sections idempotent):

- **§0** the guards + the anchor greps (pSysmemHeapDescriptor,
  kgspStartLogPolling, memdescMap/Unmap, osReadRegistryDword,
  kgspSetupLibosInitArgs — 6 anchors, ≥5 required) + the banked
  batteries (the reproduction FIRST, every v452x selftest included);
- **§1** the PCIe CALIBRATION FIRST (T5 — the honest baseline before
  any A/B);
- **§2** the parse: v452a on libosinit.bin (+ --s5) → the region map;
  v452b on sysmemheap.bin + the statics → the candidates. **GATED: no
  451-day blobs → REFUSÉ, the day stops** (the v451b pattern: the
  targets stay null until the bytes decide);
- **§3** the plan: v452c + the byte-exact gate (the header installs
  ONLY on a PASS) + THE HUMAN REVIEW step named;
- **§4** the poke boot: the drop-in + the plan header + the ONE hook
  line (`gsp_hpoke_schedule(pGpu, pKernelGsp);` next to the 4.51
  hook) + dkms + limine-mkinitcpio (the UKI lesson) + the conf
  `NVreg_RegistryDwords="RmGspHPoke=<sel>"` + the post-boot verify
  (the dmesg ledger + the judge battery ×2 + zero-Xid);
- **§5** the revert boot: the key removed, the battery ×2 — the A/B
  closes (the proof, not just a cleanup);
- **§6** the ledger + the rollback: **the DRIVER ONLY** (git checkout
  kernel_gsp.c, rm gsp_hpoke.c + the plan header, dkms,
  limine-mkinitcpio, the conf removal, reboot; ~10 min, the banked
  ritual). The firmware file NEVER touched (the §0 sha guard).

## §4 T5 — the PCIe calibration (pillarB-sysmem v452): the baseline made honest

The first machine-day numbers (h2d 8.3, d2h 8.8, device_warm 57.7 GB/s
= ~25 % of the PCIe4 x16 nominal) diagnosed, with the founder's three
suspects — two of them MEASURED signatures, not guesses:

1. **The launch overhead** (the device_warm killer, arithmetic): the
   4.51 warm rows timed 200 SEPARATE python-side launches; the pybind
   call floor ~30 µs/launch → ~6 ms for the 400 MiB payload →
   400 MiB / 6 ms ≈ 57 GB/s — the measured 57.7 IS that floor. THE
   FIX: the extension gains `bw_read_loop` (the C++ side launches the
   N kernels inside ONE call) — the overhead leaves the bandwidth;
   the JSON reports `per_launch_us` SEPARATELY (the honest
   decomposition, never folded into a GB/s).
2. **The link power management** (the copy-path killer): ASPM L1 +
   an unlocked P-state put the link and the copy engine to sleep
   between reps. THE FIX: the battery RECORDS the diagnostics
   preamble (the width/gen, the SM/mem clocks, the P-state, the ASPM
   policy — every probe optional, "unknown" never a crash) and the
   CALIBRATION VERDICT names the cause when the copies sit below
   ~60 % of the nominal (P-state, width, gen, ASPM — each from the
   recorded data); the runbook §1 prints the fix gestures as
   ENVIRONMENT steps (the clock lock, the ASPM policy — reversible,
   driver/firmware untouched).
3. **The transfer size**: 2 GiB already amortizes; the 256 MiB row is
   ADDED as the sensitivity probe (a big gap = an overhead signature,
   recorded).

**The selftest 24/24 ✓** — and the 4.51 lesson got its confirmation
run: the stub-torch path (the battery logic without a GPU) required
THREE never-executed-path fixes before it ran — (a) the inner
`from torch.utils.cpp_extension import load_inline` resolves through
sys.modules (a plain object graph does NOT resolve sub-module paths —
the import machinery is not getattr), (b) the `torch.float32` dtype
attribute access, (c) the diagnostics parser fixture must match the
REAL unquoted nvidia-smi CSV shape. Both code paths now execute on
every selftest run; the no-torch fallback ran for real (no torch in
the workspace). The selftest gates EVERY battery run (quiet-mode
transcript on stderr, stdout stays pure JSON for the runbook to
parse).

## §5 T4 — the WPR2 v2 probe design (READ FIRST — design only, gated)

The question: can the host READ the FB FW heap (the Libos core heap,
WPR2-locked) CPU-side? The route-W verdict depends on it (the v451b
route table: read first, write second, the seal's CPU-write behavior
INDECIDABLE until a read passes). THE DESIGN ONLY — nothing built
this pass (the brief: « le design seul, gated sur la sonde de
lecture »).

**The inputs (already banked)**: the S8 dump (wpr2meta.bin) = the
GspFwWprMeta layout — magic 0xdc3aae21371a60b3 (@gsp_fw_wpr_meta.h:64),
the FB map @109-116+: gspFwRsvdStart, nonWprHeapOffset/Size,
gspFwWprStart (128K aligned), **gspFwHeapOffset, gspFwHeapSize**,
gspFwOffset, bootBinOffset, frtsOffset, gspFwWprEnd (128K aligned).
The ReBAR 8192 MiB standing = BAR1 covers the whole FB.

**Route B1 (the BAR1 read — the least machinery)**: the WPR2 heap at
FB PA (gspFwWprStart + gspFwHeapOffset .. + gspFwHeapSize) maps to
BAR1 + the same offset when BAR1 is the linear 8192 MiB window. The
probe: ioremap/mmap resource0, read the first 4 KiB, dump, compare
against the plausibility guards (see below). NO RM machinery, no
driver patch REQUIRED — a root-only userspace reader over
/sys/.../resource0 suffices for the FIRST read (the runbook gesture:
cat/dd into a file, sha256 it). The named risks: the WPR2 firewall
may fault/DENY or return garbage for CPU-side reads of locked pages
(the anti-tamper precedent: a DENY persists — one fire per power
cycle, the cert20 lesson); the BAR1 linear-window assumption needs
the lspci confirmation (the BAR1 size == 8192 MiB AND the base ==
0).

**Route MD (the memdesc-over-phys — the in-tree API, the design the
brief asks for)**: the anchors AROUND kgspCreateRadix3, read from the
exact tree:

- `memdescCreateExisting(pMemDesc, pGpu, Size, AddressSpace,
  CpuCacheAttrib, Flags)` — @g_mem_desc_nvoc.h:943 (initialize a
  CALLER-SUPPLIED descriptor — a stack struct, no allocation);
- `memdescDescribe(pMemDesc, ADDR_FBMEM, Base, Size)` — @:1009 (fill
  it with an EXISTING physical range: Base = gspFwWprStart +
  gspFwHeapOffset, Size = gspFwHeapSize);
- `memdescMap(pMemDesc, 0, Size, NV_TRUE, NV_PROTECT_READABLE, ...)`
  — @:990, the exact call shape of the PROVEN radix3 map
  @kernel_gsp.c:6028 (the only difference = READABLE for the probe —
  the WRITEABLE variant is the same call, banked);
- `memdescUnmap` — @:994, the 4-arg pattern @~4033.

The probe pseudo-shape (the v2 drop-in, gated `RmGspWpr2Read=1`):
a work item (+8 s, the 4.51/4.52 constant) → CreateExisting +
Describe + Map (READABLE) → copy the first 4 KiB into a debugfs blob
+ the dmesg ledger (the phys base, the size, the first-u64 hex, the
plausibility verdict) → Unmap. Plausibility guards (a read that
returns all-zeros / all-FF / a constant pattern = the seal answered,
NOT the heap content — recorded as the named negative, never parsed
as data): the first u64 == the GSP-RM ELF magic or a plausible heap
header, the 4-KiB entropy non-degenerate, the sha16 recorded for the
cross-read against route B1.

**The decision table of the v2 day**: route B1 clean + route MD clean
→ route W OPENS (the write probe = the same path WRITEABLE, ONE field
per boot, the same defense order as §3); B1 faults / MD faults → the
seal DENIES CPU reads (the named negative — route W closes honestly,
the ROP route stays the last resort, the 4.45 chain); one route clean
→ the disagreement IS the data (the firewall granularity — the
finding).

**The honesty**: the seal's CPU-read behavior = INDECIDABLE-BY-BYTES
until the probe runs (no tree code reads WPR2-locked FB CPU-side —
the driver maps the WPR META from SYSMEM @kernel_gsp_tu102.c:120-140,
and the radix3 tables from SYSMEM @kernel_gsp.c:6004-6010; the FB FW
heap itself is NEVER CPU-mapped in this driver — the ABSENCE of an
in-tree precedent is itself banked evidence, cited).

## §6 The honesty ledger

- **PROUVÉ** (the tree, cited): the S4 grammar (32-B records, the
  4096-BYTE table, the id8 = the big-endian ASCII name, the host
  writes logs + RMARGS only); the heap = contiguous UNCACHED SYSMEM
  (tu102:214); the radix3 WRITEABLE map pattern (kernel_gsp.c:6028);
  the WPR meta fields (gsp_fw_wpr_meta.h:109-116); the memdesc-over-
  phys APIs (CreateExisting @943, Describe @1009, Map @990, Unmap
  @994); the v451a patterns byte-true (imported, not re-transcribed).
- **PROUVÉ** (the selftests, every path executed): v452a 27/27 (the
  tree guard included), v452b 23/23, v452c 18/18 (the C byte-exact
  vs python, gcc), pillarB-sysmem 24/24 (the stub-torch path + the
  no-torch path + the parser fixtures), gsp_hpoke.c stub-compile
  PASS, runbook-452 bash -n clean. The selftests caught 6 bugs this
  pass BEFORE the founder (2 × v452b, 1 × v452c, 3 × pillarB) — the
  4.51 lesson banked as discipline.
- **PROUVÉ** (the arithmetic): the device_warm 57.7 GB/s signature =
  the launch-overhead floor (200 × ~30 µs over a 400 MiB payload).
- **HYPOTHÈSE**: that the parsed timing records live in the S5 heap
  (the 451-day dump decides — unchanged from 4.51); that the retight
  delta on the parsed copies moves the DRAM efficiency envelope (the
  route-H experiment decides).
- **INDECIDABLE-BY-BYTES**: the in-record byte positions of
  ras/faw/rrd (the packed grammar — the null targets in every plan);
  the faw/rrd positions on the vec route (no launch-vector slot);
  the WPR2 seal's CPU read/write behavior (the v2 probe, §5); the
  machine's final link state (the §1 calibration decides on the
  day).
- **REFUSED-BY-CARD**: rp/cl retargets (not in the vendor's retight
  table — no proof); a write on any SUSPECT/FLOOR verdict (only HIT
  plans); the id-19 record (the landmine, three layers deep); the
  image patch (the v451b IMG refusal stands); the machine EXECUTION
  (nothing ran on the GPU — this pass armed the day).

## §7 The queue (what the day decides)

1. **The J-452 day** (runbook-452 §0-§6): §1 the calibration (the
   honest baseline — h2d/d2h ≥ ~60 % of the nominal or the named
   cause) → §2 the parse of the 451-day blobs (the region map + the
   candidates) → §3 the plan (the human review named in the runbook)
   → §4-§5 the poke A/B (ONE field, the quad gate) → §6 the rollback
   (driver only).
2. If §2 finds NO route-H candidate: the v2 probe (§5 design) gets
   its build day — the read decides the route-W verdict.
3. Between-days: the 0x85C4/0x85E4 reader hunt (the 4.50 parked
   lane) — unchanged, still queued.
