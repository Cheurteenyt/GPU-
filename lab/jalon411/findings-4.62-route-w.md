# findings-4.62 — ROUTE W: lire le heap FB — the WPR2 decoder, the two
# read probes (B1 the BAR1/ReBAR, MD the memdesc-over-phys), the scan

**Branch**: `pass/4.62-route-w` (stacked on main `2cde0ed` — the 4.61
merge). Nothing ran on the GPU — the probes = the armed instruments,
the day = runbook-462.sh (ACK-gated: even the READS are gated, the
4.54 discipline). The batteries = **v462a 31/31 + v462b 72/72 +
v462c 18/18, host-only**.

## §0 The mission and the lane

The 4.61 plan gate = MISS on every host-reachable surface (the v461a
scan of the 4.51-day dumps found no base-marker object) — the bases
live in the FB/WPR2 heap. THE MISSION = READ that heap: the 4.52 §5
design executed (read first — « the read decides the route-W verdict »),
two probes in the mission's order:

- **T1 — probe B1**: the BAR1/ReBAR read (8192 MiB standing — banked
  ring 18), ZERO driver patch, the v454b PROT_READ pattern. The FB
  addresses = OUR data: the S8 `wpr2meta.bin` captured on the 4.51
  verdict day carries the FB layout (the mission's captured pair
  0x1f2d000/0x1ffee00).
- **T2 — probe MD**: the memdesc-over-phys two-sided instrument —
  `memdescCreateExisting` + `memdescDescribe(ADDR_FBMEM)` +
  `memdescMap` READABLE (the 4.52 anchors).
- **T3 — the scan**: the v451a floor + the v454a marker family
  (0x0EE6B280 = the 250 W base = the shape-match) over the reads.
- **T4 — the selftests + runbook-462.sh**.
- The plausibility guards: all-zeros/FF = **the seal answered** (the
  negative NAMED, never parsed as data).

The rule unchanged: the bytes decide. The environment note (the banked
precedent, repeated): the workspace was RESET before this pass — the
repo re-cloned from origin (main @ 2cde0ed), the EXACT 610.57.04 tree
re-fetched from the NVIDIA tag for the re-assertions below.

## §1 T1 — the decoder and the window math (v462a, 31/31)

**The grammar** (committed `gsp_fw_wpr_meta.h` @610.57.04, gcc
re-asserted through offsetof — the tree guard, 20 fields + the 3
header magics): `GspFwWprMeta` = **256 B** (the header's own "exactly
256 bytes" law, gcc-confirmed), magic@0 = 0xdc3aae21371a60b3,
revision@8 = 1, gspFwRsvdStart@88, nonWprHeapOffset@96,
nonWprHeapSize@104, **gspFwWprStart@112 (128K-aligned)**,
**gspFwHeapOffset@120, gspFwHeapSize@128**, gspFwOffset@136,
bootBinOffset@144, frtsOffset@152, frtsSize@160, **gspFwWprEnd@168
(128K-aligned)**, fbSize@176, bootCount@200, **verified@248**
(0xa0a0a0a0a0a0a0a0 = the booter locked it in WPR2).

**The absolute-vs-relative question, settled honestly**: the header
diagram draws the FB-layout fields as absolute; the ONLY field the
tree NAMES relative = `gspFwHeapFreeListWprOffset` (the resume-path
comment @gsp_fw_wpr_meta.h:95-96 — they had to SAY it, which is
evidence the others are not); the host expression
`fbSize - gspFwRsvdStart` @kernel_gsp.c:4449 (the fetched exact tree)
only parses with BOTH absolute. **But the mission's captured pair
0x1f2d000/0x1ffee00 quotes no field names** — and the instrument
never guesses on a narrative. THE DESIGN: `compute_windows` emits
BOTH candidate readings, scored by the structural invariants:

| window | the reading | the base |
|---|---|---|
| W_ABS | the raw-field form (the header diagram) | `gspFwHeapOffset` |
| W_REL | the 4.52 §5 formula, verbatim | `gspFwWprStart + gspFwHeapOffset` |
| W_S4 | the GSP's OWN boot map (the cross-input) | the loc=FB region pa from v452a.walk_s4(libosinit.bin) |

scored by: the WPR2 containment ([gspFwWprStart, gspFwWprEnd]), the
FB bound (≤ fbSize), the page alignment, and the diagram-order
corroboration (WprStart ≤ HeapOffset ≤ FwOffset ≤ BootBin ≤
FrtsOffset ≤ WprEnd in the reading's own frame). The SURVIVORS = the
windows the probe reads (read-only — reading both costs nothing);
the scan decides which held the data. **ZERO survivors = INDECIDABLE
— the day stops** (the table printed, never a guessed address). An S4
FB region overlapping an S8 survivor = the corroboration recorded on
that survivor; an S4 region matching no S8 window = a window
candidate ITSELF (the GSP booted with that map — the strongest
grounding a heap address can carry).

**The probe** (`read_window`): mmap the sysfs resource PROT_READ
(the single protection literal — the selftest asserts the source
stays write-free, the v454b law "the code IS the guarantee"), ONE
u32 LE per 4-B step, NO polling, NO repeat. The guards: the BAR1
size == 8192 MiB (the banked ReBAR standing — the linear-window
assumption named, the runbook checks it first), the window within
the resource. The ACK: `ROUTE_W_462_ACK=1` (exit 2 without). The
synthetic mode (`--resource <file>`) = the SAME code path against a
regular file — the real device never needed for the selftest.

**The plausibility classifier** (`classify_bytes` — the integer
semantics, mirrored VERBATIM in the C probe, the float-free form so
the two implementations agree by construction): the 256-bin
histogram + the first u64 + distinct + top-count;
SEAL-ZERO (all 0x00) / SEAL-FF (all 0xFF) / SEAL-CONSTANT (one byte
≥ 255/256) = **the seal answered**; WPRMETA-MAGIC / ELF-MAGIC = the
window math off by one window (the named lead); HEAP-FREELIST (the
first u64 == 0x4845415046524545, the `GspFwHeapFreeList` magic from
the committed header) = **the heap signature, a POSITIVE**;
DEGENERATE (≤ 4 distinct values) = the seal's constant pattern;
LIVE-UNKNOWN = the content is live — the sha16 + the scan decide.

The selftest caught **7 real bugs before the founder** (the
discipline pays again): the fixture hex-typo family (8-digit vs
9-digit FB addresses — the invariant containment caught it), the
S4 record-shape mismatch (loc_raw/kind_raw, the v452a record), the
255/256 constant-bar fixture, the zero-filled synthetic blob
(SEAL-CONSTANT, correctly), the self-referential write-law check
(the needle inside the checker), the `%llx`-in-Python emission, the
missing nvtypes shim in the C-emission test.

## §2 T2 — the MD probe: the two-sided port (gsp_wpr2_read.c + patch_nv_462.py, the battery 72/72)

**The anchors re-asserted on the exact tree** (fetched from the
610.57.04 tag this pass, the files cached and cited):
`memdescCreateExisting` @g_mem_desc_nvoc.h:943 (« Initialize a caller
supplied memory descriptor for use with memdescDescribe() » — the
stack struct, NO allocation), `memdescDescribe` @:1009 (« a
description of a preexisting contiguous memory allocation »),
`memdescMap` @:990 (the EXACT call shape of the proven radix3 map
@kernel_gsp.c:6028 — WRITEABLE there, **READABLE** here, the 4.52 §5
wording), `memdescUnmap` @:994 (the 4-arg pattern, banked 4.51).

**The RM TU** (zero linux headers — the v455a-class battery greps
and FAILS if the trap returns): the gate `RmGspWpr2Read` = the window
selector {1..PLAN_N} (ONE window per boot — the one-variable-per-
transition law), the PLAN GATE AT ARM TIME (the GATED NULL plan
refuses BEFORE the selector — the defense order refined from 4.61:
nothing arms, nothing reads), then the chain
CreateExisting(stack) → Describe(ADDR_FBMEM, base, size) →
Map(0, readLen, NV_TRUE, NV_PROTECT_READABLE) → the one-pass copy
into the state blob (≤ 1 MiB, the plan caps readLen) → the integer
classifier → Unmap. The MAP-FAIL verdict = **THE SEAL NAMED** (the
read refused mechanically — recorded, never retried, never hidden).
The CpuCacheAttrib = NV_MEMORY_UNCACHED (the FB CPU-access family;
the radix3 SYSMEM twin = NV_MEMORY_CACHED @6017 — the attribute the
seal prefers = INDECIDABLE-BY-BYTES, the real dkms build = the
judge).

**The write-free law** (the probe's defining property, in code): the
mapped FB pointer appears ONLY as the copy source — the battery
greps `pSrc[i] =` and refuses any left-side occurrence. One map, one
copy, one unmap; the rollback = driver only.

**The nv.c side** (patch_nv_462.py, the v9-scanner pattern): the
delayed work (8 s), the call through pLateFn, the NVRM-462 ledger
printk (sel/win/base/size/len/verdict/class/first/distinct/top — one
line, dmesg-persistent), **the debugfs blob publication** (the 4.51
dump pattern: `/sys/kernel/debug/gsp_wpr2_read/win/window<sel>.bin`)
— **the sha16 = computed in USERSPACE from the blob** (zero crypto
in-kernel; the cross-read key vs B1). The Wpr2ReadMarker, idempotent,
coexists with the 4.51 DmemDumpMarker + the 4.52 HpokeMarker + the
4.61 DmemWriteMarker.

**The battery (v462b, 72/72)** — the v461b pattern, the plan variants
GENERATED BY v462a ITSELF (the cross-instrument guard): G1 the RM
hygiene + the write-free law; G2 the mirror text (the verdict codes
×8 AND the plausibility classes ×8, (name, value) pairwise + the two
names tables); G3 the logic battery (the off gate, the bad selector,
the happy path — the byte-exact copy through the described-base map
chain, the map/unmap pair, the primitives — **the 8 plausibility
classes on planted fixtures**, the MAP-FAIL with the unmap never
called, the one-shot, the no-GPU, the NULL plan refused AT ARM, the
second window with the per-window base); G4 the layout mirror (gcc,
sizeof + offsetof ×18 members — the 1 MiB blob included, identical);
G5 the patcher dry-run (the fixture nv.c twin + the stub linux
headers, the anchors, the worker AFTER its declarations — the banked
lesson banked twice — the idempotency byte-identical, gcc -Wall
-fsyntax-only); G6 the cross-side link (the RM TU + the consumer
against the patcher's mirror, the linker-level contract).

## §3 T3 — the scan (v462c, 18/18)

The v451a floor discipline + the v461a object scan + the v454a marker
family — ALL IMPORTED (zero re-transcription; the pattern set stays
the single source; the asserts re-arm the shapes 0x0EE6B280 /
0x0E4E1C00 / 0x10B07600). THE SEAL GATE FIRST: any degenerate surface
= the named negative, **the scan refuses it — a marker inside a seal
is still the seal** (the trap fixture proves it). The live surfaces
run the v461a machinery: the exact-marker POWER-BASE-MATCH rows (the
v454c EXACT-FIRST precedence), the u64-pair law, the 0x10-stride
object fingerprint + the f18 quad, the object-base inference with the
consistency gate (a lone hit = a LEAD, never plan-eligible).

The output = **the target map** {surface, adresse, offset objet
(obj+0x618+k*0x10), rôle (base[k], the group key), valeur trouvée} —
and the verdict table:
OBJECT-FOUND → **the bases ARE in the FB heap** (the write-lane
input NAMED — this pass writes NOTHING: naming ≠ writing, the v454c
law; the write = the NEXT pass, ONE field per boot, the marker
pre-verify = the 4.61 law); LEAD/CANDIDATE → the bigger window or the
fresh dump decides; MISS → the honest close (the falcon-internal
negative or the window math — the re-decode day).

## §4 T4 — the day (runbook-462.sh, bash -n clean)

§0 the guards (the ACK, the device 0x2488, the firmware sha
c0156954 = NEVER touched, the three batteries, **THE PLAN GATE = the
S8 decode — no window survives = the REFUSAL before any patch**,
the ReBAR 8192-MiB check) → §1 **the B1 probe HOT** (zero patch,
zero boot, the ACK still required; the zero-Xid check after) → §2
the scan of the B1 dumps → §3 the MD patch (the 8 anchors ≥ 7, the
drop-in + the plan header + the ONE hook line next to the 4.51/4.52/
4.61 hooks, patch_nv_462 + the marker refusal, **dkms remove +
install --force**, limine-mkinitcpio, **THE VERIFICATION LAW: nm the
DATA SYMBOL gspWpr2ReadState + the NVRM-462 bytes**) → §4 the MD
boot (the ACK per boot, `RmGspWpr2Read=<sel>`, the SEMICOLON
multi-key law, the ledger + the debugfs blob + the userspace sha16)
→ §5 **THE DECISION TABLE, in code** (below) → §6 the rollback
(**DRIVER ONLY**, the ritual).

**The decision table (the 4.52 §5 law, executable)**:

| B1 | MD | the verdict |
|---|---|---|
| clean | clean | **ROUTE W OPENS** — the write lane = the same path WRITEABLE (the next pass); the sha16 equality = the two routes read the SAME memory |
| seal | MAP-FAIL | **the seal REFUSES CPU reads** — route W closes honestly; the ROP lane = the last resort (the 4.45/4.57 sweep); the falcon-internal negative CONFIRMED |
| seal | clean | **the disagreement = the data** — the firewall granular (the memdesc CPU map reads, the BAR1 aperture sealed); the MD lane = THE route |
| the rest | — | the mixed state = the ledger + the scans = the evidence |

## §5 The contingencies (named, in code)

1. **the seal negative** (all-zeros/FF/constant on every window): the
   negative = NAMED with the class + the sha16; the MD boot decides
   the granularity; the honest close = the falcon-internal or the
   ROP lane.
2. **the window math wrong** (WPRMETA-MAGIC/ELF-MAGIC on a read):
   the read = live but off by one window — the S4 cross-input + the
   re-decode day decide; NEVER a write on a lead.
3. **the INDECIDABLE decode** (no window survives): the day stops at
   §0 — the fresh dump day (the SEMICOLON multi-key is REFUSED by
   design: the dump boot and the read boot stay separate, one
   variable per transition).

## §6 The honesty ledger

- **PROUVÉ** (the tree, cited + fetched this pass): the GspFwWprMeta
  grammar (256 B, gcc offsetof ×20 + the 3 magics, the committed
  header); the memdesc anchors (:943/:1009/:990/:994); the radix3
  map shape (kernel_gsp.c:6028); the fbSize−gspFwRsvdStart absolute
  pair (:4449); the free-list relative exception (:95-96); the
  FB-heap-never-CPU-mapped absence (the banked 4.52 §5 evidence).
- **PROUVÉ** (the batteries, every path executed): v462a 31/31 (the
  tree guard + the synthetic read + the C emission byte-exact),
  v462b 72/72 (the plans generated by v462a itself), v462c 18/18
  (the rehearsal + the seal traps), runbook-462 bash -n clean + the
  ACK refusal tested.
- **PROUVÉ** (the arithmetic): 0x1ffee00 = 33,509,376 ≈ 32 MiB (the
  plausible gspFwHeapSize form of the mission's captured pair); the
  128K-alignment law; the 8192 MiB BAR1 = the whole-FB aperture.
- **HYPOTHÈSE**: the mission pair's field naming (gspFwHeapOffset/
  gspFwHeapSize as (0x1f2d000, 0x1ffee00) — plausible, never
  asserted: the decoder names the fields from the REAL dump at run
  time, the narrative never decides); the BAR1 linear-window
  identity (the ReBAR standing + the size guard, the first read
  decides); the WPR2 heap = the base-marker home (the 4.61 banked
  model — the scan decides).
- **INDECIDABLE-BY-BYTES**: the seal's CPU-read behavior on the
  WPR2-locked FB (the probes exist precisely to decide it; the
  anti-tamper precedent warns the DENY persists — one fire per power
  cycle); the gspFwHeapOffset absolute-vs-relative reading (BOTH
  windows emitted, the survivors decide); the CpuCacheAttrib the
  seal prefers (UNCACHED named, the build judges).
- **REFUSÉ**: the machine execution (nothing ran — this pass armed
  the day); any write (the write-free law, in code, grepped); a read
  without the ACK (even the reads are gated); a plan from anything
  but the S8 structural survivors (the GATED NULL); the image patch
  (the v451b IMG refusal stands); the firmware file (the §0 sha
  guard).

## §7 The queue (what the day decides)

1. **the J-462 day** (runbook-462 §0-§6): the plan gate → the B1
   hot read → the scan → the MD boot → THE DECISION TABLE — the
   route-W verdict = the campaign's answer or the honest close.
2. If ROUTE W OPENS: **the write lane = the next pass** — the same
   path WRITEABLE, ONE field per boot, the plan = the bytes v462c
   found (the marker pre-verify = the 4.61 law, the old bytes = the
   plan's restore).
3. If the seal refuses: the ROP lane (the 4.45 chain, the 4.57
   transpose, the 4.59 geometry table) = the remaining road — the
   position × bias × ra_value sweep.
4. The 4.61 f18 lane (the PERSISTENT class) = unchanged, the
   alternative route if the heap write opens AND the base proves
   volatile.
