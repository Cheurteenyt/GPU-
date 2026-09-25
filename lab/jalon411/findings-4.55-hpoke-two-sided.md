# findings-4.55 — THE TWO-SIDED CONVERSION: the gsp_hpoke debt paid

**Branch**: `pass/4.55-hpoke-two-sided` (base = `pass/4.54-read-probe`,
f5a690f). Nothing ran on the GPU. The battery = 44/44, host-only.

## §0 The debt, named three times, paid once

The debt was THE 3rd occurrence of the same trap: `#include
<linux/workqueue.h>` at gsp_hpoke.c:79 in a file INCLUDED BY
kernel_gsp.c — the RM TU = the OS-abstracted environment, ZERO linux
headers (the port layer only). The identical fail killed the 4.51 v1
monolith (the build = the judge, the machine-day pre-flight catch) and
was paid there by the TWO-SIDED pattern (gsp_dmem_dump.c +
patch_nv_451.py) — machine-proven (4 boots, 0 Xid). Pass 4.55
replicates that pattern for the writer, with the mirror contract
promoted to a TESTED surface.

## §1 The conversion (what moved where)

**The RM side (gsp_hpoke.c, in kernel_gsp.c's TU) — all RM-portable:**
- the regkey gate (osReadRegistryDword `RmGspHPoke`), the selector
  filter {1..5}, the plan table (gsp_hpoke_plan.h — the v452c
  emission, untouched), the radix3 WRITEABLE map
  (kernel_gsp.c:6028), the PRE-VERIFY, the byte-lane write, the
  POST-VERIFY, the unmap (~4033). Zero linux headers — THE v455a
  battery greps the STRIPPED code for linux/workqueue/delayed_work/
  printk/debugfs and FAILS if the trap ever returns.
- the work function = `gsp_hpoke_late(void)`, called BY POINTER via
  the shared state's `pLateFn` (the gc-sections law: the live
  schedule stores the pointer, the nv.c side calls through it, NO
  cross-TU symbol — the 4.51 v4 mechanics, boot-proven).
- the verdicts = RECORDED into the state (11 codes
  `GSP_HPOKE_V_*`), the hex renders included — the 4.51 lesson (the
  RM NV_PRINTF = level-gated; the reliable ledger = the nv.c
  printk). The RM NV_PRINTF lines = kept (the RM-debug bonus, never
  the reliance).
- the hook line contract UNCHANGED: `gsp_hpoke_schedule(pGpu,
  pKernelGsp);` next to the 4.51 instrument's.

**The nv.c side (patch_nv_452.py, the v9-scanner pattern):**
- the delayed work (INIT_DELAYED_WORK + 8 s) armed at module init
  after `nv_memdbg_init()` (the anchor robust to the 4.51 patch
  order), the worker calls through `pLateFn` (the guard verbatim),
  then prints the LEDGER: sel/field/offset/len/verdict/verify/seen/
  want/new/sha16 — one line, dmesg-persistent.
- idempotent (HpokeMarker), coexists with the 4.51 DmemDumpMarker in
  either application order (both anchor sets stay unique — asserted
  by the battery on the fixture, the order-independence by anchor
  count).
- NO new include (workqueue arrives via nv-linux.h — the patcher
  adds none; asserted).

**The shared state (the layout MIRROR contract):** the struct text
exists twice (the RM file + the patcher) BY DESIGN (the 4.51
pattern); the drift risk = answered by the battery: G4 compiles BOTH
with the same gcc and asserts sizeof + offsetof for EVERY member;
G6 links a TU compiled against the PATCHER's mirror with the RM TU
and reads the written state through it (the extern contract at the
linker level). The verdict codes + the names table = extracted from
both files and compared (name, value) pairwise.

## §2 The battery (v455a_hpoke_two_sided.py — 44/44)

- G1 the header-hygiene guard (7 forbidden greps on the STRIPPED
  code + 5 required symbols + the non-static state).
- G2 the mirror text (the codes x10 both sides, the names order, no
  linux include added).
- G3 the stub-compile + the logic battery, TWO plan variants (ok +
  the GATED null): the off gate, the bad selector, the happy path
  (the bytes byte-exact, the OTHER entry untouched, the map/unmap
  pair, the ledger hex), the one-shot, the STALE-PLAN abort
  (NOTHING written), the selector miss, the bounds, the map fail,
  the null descriptor, the pre-executed guard, the defense
  NOT_SCHEDULED branch.
- G5 the patcher dry-run on the fixture nv.c (the anchor twin): the
  patch applies, the marker, the worker AFTER its declarations, the
  idempotency (byte-identical), and gcc -Wall -Werror=format
  -fsyntax-only on the PATCHED file (the format strings judged by
  the compiler — the printf attribute trick; the 4.51
  backslash-n-in-C-string lesson executed).
- G6 the cross-side contract + the 2-TU link (the mirror reads the
  state the RM TU wrote) + the patched nv.c carries NO RM primitive.
- G4 the layout mirror byte-for-byte.

**11 bugs caught by the battery before the founder** (the discipline
pays again): (1) the G1 auto-reference — the check grepped its own
documentation (the comments MAY discuss the forbidden words; the
grep = on the stripped code); (2) the KGSP descriptor wiring absent
in the test driver (every path = NO_HEAP_DESC); (3) the entry-1
prefill missing (the happy path = STALE-PLAN); (4) worker_pos = the
forward declaration, not the body (the order check weakened);
(5) the missing `gsp_hpoke_schedule` prototype in the link TU;
(6) the call_late recursion — the python substring replace rewrote
the guard INSIDE the helper into a self-call (the stack overflow
ASan located in one run); (7) the `extern GSP_HPOKE_STATE
gspHpokeState;` absent from the link TU (the typedef alone declares
the type, not the variable); (8) the test-1 expectations wrong twice
(the guard semantics: pLateFn NULL ⇒ the call skipped, the verdict
stays OFF — NOT_SCHEDULED = the defense-in-depth branch, now tested
directly by forcing the impossible state); (9) the reset_all first
line lost in an edit (the heap = uninitialized malloc); (10) the
OTHER-entry check read 0xA5 where the prefill wrote 0x03; (11) the
same substring replace hit TU2's guard (call_late undefined there).

## §3 The integration contract (runbook-452 §4, updated)

- the §4 patch step now APPLIES patch_nv_452.py before the dkms and
  HARD-REFUSES if the HpokeMarker is absent from nv.c — the build
  would still pass without it (the RM side is self-contained) and
  the poke would be a SILENT NO-OP (worse than a build fail).
- the §6 rollback gains the nv.c line (git checkout
  kernel-open/nvidia/nv.c — the 4.55 marker and the 4.51 marker
  leave together). The rollback = STILL driver-only.
- bash -n clean.

## §4 The ledger

- **PROUVÉ** (the battery, 44/44): the RM TU compiles clean of linux
  headers; every verdict path executes; the pointer mechanics (the
  gc-sections law) hold; the mirror = byte-for-byte at the offsetof
  level AND at the link level; the patcher = idempotent,
  order-independent vs 4.51, compiler-judged; the cross-side
  contract = grepped both directions.
- **PROUVÉ** (the tree, cited): the grounding unchanged from 4.52
  (the radix3 map @6028, the UNCACHED sysmem heap @tu102:214, the
  4-arg unmap @~4033, the regkey pattern @312).
- **INDECIDABLE-BY-BYTES**: unchanged from 4.52 — the in-record
  positions of ras/faw/rrd; the machine's link state (the §1
  calibration); whether the plan's old bytes still match the runtime
  (the STALE-PLAN verdict decides on the day, in code).
- **REFUSÉ**: the machine execution (nothing ran — this pass = the
  debt, not the day); any write before the read-test row (the O5
  discipline, 4.54); the silent no-op (the marker refusal, §3).
- **The debt ledger**: gsp_hpoke.c:79 = PAID (the conversion, the
  pattern = the 4.51 proof). pillarB = runbook-452 §1 = STILL OPEN
  (the machine day).

## §5 What the founder does with it

1. Review (the diff = the RM conversion + the patcher + the battery
   + the runbook §4/§6 + this file).
2. On the NEXT machine day (r2a and/or the read day — the same boot
   windows if wanted): the §4 order = the drop-in + the plan header
   + the hook line + patch_nv_452.py + the dkms; the runbook
   REFUSES without the marker.
3. The dmesg ledger on the poke boot = the nv.c printk line (one
   line, the full verdict) — the NVRM-452 grep unchanged.
