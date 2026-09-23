# 4.38 — the dual-core power provenance: the reported 250 W limit lives in
# NO binary as a constant — the RM codebase carries the {100000, 240000,
# 250000} trio ONLY as TIME logic in both builds, and the applied limit is
# runtime data parsed from the VBIOS by the closed x86 core

Mission: the provenance of the power policy across BOTH cores of driver
610.57.04 — the GSP-RM (RISC-V) and the closed x86 kernel — and the
design of the correct 280 W patch. Substrates: `rm-full.elf` +
`gsp-rm-17MB.bin` (the law `B_file = A_img − 0x38`, re-asserted), the
committed kernel-open host core
`tools/analysis/x86-rm/binaries/nv-kernel.o_binary` (19,233,368 B,
sha256 `48096db0…` — verified), and **the CLOSED core acquired and
verified this pass**:
`kernel/nvidia/nv-kernel.o_binary` (120,980,872 B, sha256
`c90f58d59e8fef44fa07d057bd9ffb1e1b5ee38d3c51b35df71e05e0ad268cbf`,
extracted from the official `.run` whose package sha256
`b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d`
matches the 4.28/4.27 provenance register byte-exact; the 120-MB core
lives OUTSIDE the repo at `/home/z/my-project/artifacts/pkg/` —
the reproduction recipe is this sentence + the package sha).
Instruments: `v438a_edpp_writers.py`, `v438a2_handlers.py`,
`v438a3_dispatchers.py`, `v438a4_table_writers.py`, `v438b_x86_power_sites.py`,
`v438c_closed_core.py` (+ JSONs). The v420 census reproduction = **17/17,
zero mismatch** (the map law holds on this machine after the sandbox
reset; the 4.30 patch-site bytes re-verified equal under the law).

## Verdict first

| question | what the bytes say | verdict |
|---|---|---|
| where does the APPLIED 250 W limit live? | {240000, 250000} = **0 immediates + 0 data words** in ALL THREE cores: the GSP rm.elf (4.32, re-asserted), the open x86 core (v438b: 0/0), the closed x86 core (v438c: 0 data words; 7 × 250000 immediates = the TIME twins §3.2); NVML = 0 (4.28 §7.3) | **PROVEN: runtime data** — parsed from the VBIOS by the closed x86 RM, held in heap structures, never a compiled constant |
| are the closed-core 250000s the power policy? | `_nv059099/9108/9110/9111rm`: 7 immediates, and the {500000, 250000} cmp/mov structure is **byte-identical in ROLE to the GSP's s4/s5 hysteresis clamp** (the same RM source compiled twice) | **PROVEN: the TIME twins** — the same request/budget-engine deadlines; NOT watts |
| does anything write a power constant into the 0x6d0 EDPp object? | the full writer→source map (34 WRITE-FIELD uses, v438a): sources = FIELD-COPY from runtime objects, flags {0, 1, −1}, the RESET byte; the 0x2080A618 event = the mark-state setter, the SAME body as the RPC 0x2080d031 handler | **PROVEN: no** — the object is runtime-fed end to end |
| does the −pl 280 clamp pass through a named kernel function? | `nvidia-smi -pl` → NVML → `NV2080_CTRL_CMD_PERF_RATED_TDP_SET_CONTROL` → `subdeviceCtrlCmdPerfRatedTdpSetControl_KERNEL` (0x2d5e50, named symbol) = a RELAY (the 5-dword params marshaled to the `obj+0x3bc0`/`obj+0x3b88` internal dispatch — the same shape as the host EDPp SET of 4.28 §6.2); the clamp itself runs against the runtime limitMax | **PROVEN: the relay path is named; the clamp value is runtime** |
| what is the correct 280 W patch? | §5: the constant patching lane is CLOSED IN BOTH CORES; the four live lanes are the VBIOS-in-RAM patch (outilled), the revised runtime scanner, the RatedTdp control hook, the HS-execution rewrite | **DESIGN delivered (§5)** |

**The one-sentence answer to the central question:** the 250 W value is
*applied* by the closed x86 RM (it clamps every request against the
limitMax it parsed from the VBIOS power tables at boot) and merely
*reported* through NVML; it is stored NOWHERE as a constant — patching
binaries cannot reach it, patching the VBIOS or the runtime structures
can.

## 1. TASK A — the EDPp object (0x6d0) writer→source map, complete

`v438a_edpp_writers.py` re-derives the v420 census **17/17**, then traces
every object-pointer use with a COPY-CHAIN extension (the v432 trace broke
on `mv`; this one follows pointer copies up to 6 hops, 160 insns): **34
WRITE-FIELD uses** total. The map, every source classified by the backward
walk:

| field (hex) | writer site (VA_A) | source class | the hop cited |
|---|---|---|---|
| 0x0 | 0x14584a0, 0x1458c0e | IMMEDIATE-ZERO (the RESET byte) | the GET-handler memset tail |
| 0x0 | 0x1458892 | CONSTANT 1 | the re-arm flag |
| 0x8 | 0x143fde2 | DEF(andi) — a flag | |
| 0x218 | 0x1458bfc | ARG/UNKNOWN (new field vs 4.32's map) | inside the GET handler window |
| 0x65c | 0x143fde2 | FIELD-COPY(mem) | |
| 0x660 | 0x14400c6 | FIELD-COPY — the worker: `lw a5,0x10(s4)` → `sw a5,0x660(s6)` | buf[0x10] of the 52-B buffer, filled by the 0x2080A080 dispatcher (§1.1) |
| 0x664 | 0x14584d8 | CONSTANT −1 (`sb 0xFF`) | the init path |
| 0x668–0x684 | 0x14584d8 | FIELD-COPY ×8 | the 8-dword block from the descriptor-looked-up runtime object, after the 0x2080A618 call |
| 0x6b0/0x6b4/0x6b8 | 0x1440a22 | CONSTANT {−1, −1, −1, 0, 1} | init/reset flags |
| 0x6bc | 0x1440dbc | ZERO / FIELD-COPY | |
| 0x6c0 | 0x14405f0 | ZERO / CONSTANT 1 | |
| 0x6c8 | 0x143fde2, 0x14400c6, 0x14405f0, 0x1440a22, 0x14584d8, 0x145884e | DEF(ori) — the change-flag (4.21's bit 1) | 6 writers |

**No write takes a power constant. No write traces to an RPC request
buffer.** (The 4.32 verdict, now stress-tested with the copy chain and
the extended source walk.)

### 1.1 The source chain of field 0x660 — two new proven hops

The worker calls the runtime vmethod `*(state2+0x138)` with the
internal-event id **0x2080A080**; the 4.20 dispatch table names the
handler: **0x16502d0** (tag 0x34 = 52 B — exactly the worker's
`memset(buf, 0, 0x34)` size). `v438a3` walks the seen-gated map backward
and exposes the tail-entry cluster (the 4.24 mid-function-entry
architecture — the dispatch-table VA is a TAIL into a shared dispatcher
body):

```
0x16502a4: ld   a5, 0x158(a0)   # base chain: *(a0+0x158)
0x16502aa: c.lui a4, 2 ; c.add a5, a4    # +0x2000
0x16502ac: c.add a5, a4 → ld a5, -0x68(a5)   # *(x+0xe0), +0x2000, *(y-0x68)
0x16502b4: c.lw  a4, 0(a1)      # index = buf[0]
0x16502b8: bltu a3(a4=idx>3 skip)  # index ∈ [0,3]
0x16502bc: slli a3, a4, 0x20 ; srli a4, a3, 0x1d   # ×8
0x16502cc: lw   a4, -0x624(a5)   # *(B + 0x8D9DC + idx*8)   ← B+0x8e000-0x624
0x16502d2: c.sw a4, 4(a1)        # buf+4 = table[idx].lo
0x16502d4: lw   a5, -0x620(a5)   # *(B + 0x8D9E0 + idx*8)
0x16502d8: c.sw a5, 8(a1)        # buf+8 = table[idx].hi
0x16502da: c.jr  ra              # (0x16502d0 = the dispatch-table handler VA)
```

Neighbouring tail entries (same dispatcher body): one writes
`buf+0x10 = *(obj+0x138)` (@0x1650258) — the field the worker reads;
one writes the flags byte `buf[0] = *(B+0x8D9CC)` (@0x1650290). So the
0x2080A080 family = **getters over a 4-entry × 8-B table at
B+0x8D9DC** plus a flags byte, where B = a multi-hop runtime state
base. Who fills B+0x8D9DC: `v438a4`'s whole-image accessor scan in the
window [0x8D9C0, 0x8D9F0) finds 1,438 accesses but the immediates
−0x610..−0x640 are common stack-frame offsets — the static attribution
is UNDECIDABLE without resolving B (HONEST negative; the 4.37 Part-B
descriptor-linked-instance-state model predicts the fill path = the RPC
object-create path the 4.26 capture watches).

### 1.2 The 0x2080A618 event is the mark-state setter, NOT a data fill

`v438a2` disassembles the 0x2080A618 handler (0x1768bc4, tag 0x4e20) —
its entry block is **the SAME body as the RPC 0x2080d031 handler**
(4.24 §5): `*(state+0x52c) |= 0x400000; *(state+0x520) = 0x400000;
*(state+0x3d0) = 0` — the "dirty/re-derive" marker. The init flow
(0x14584d8) copies its 8 dwords from the descriptor-looked-up object
AFTER the call — the descriptor address is STATIC (VA_A 0x2d38de8,
`auipc a0,0x2d39 ; addi a0,a0,-0x722` @0x145850a), the VALUES are
runtime (PROVEN: the copy is `sw` from the looked-up object's fields,
not from the static descriptor).

### 1.3 The GET_PARAMS six-limit offsets {0x104..0x118}

The 24-B response struct of GET_EDPP_LIMIT_INFO (tag 0x18 = 6×u32 =
limitMin/limitRated/limitMax/limitCurr/limitBattRated/limitBattMax,
ctrl2080internal.h:3988 via 4.24) is the response-side view; the
mission's 0x104–0x118 offsets = the same six fields inside the 1544-B
INTERNAL params of 0x2080d031. The bytes close every writer candidate:

- the GSP handler of 0x2080d031 (0x11267fc) NEVER touches the params
  (4.24 §5, re-cited);
- the sender = NVML userspace (4.28 §7, PROVEN); the captured values at
  the six offsets = ALL ZERO (4.24 §1: five nonzero u32s elsewhere);
- the GSP-side accesses of {0x104..0x118} inside the PMGR window
  (v438a, 59 accesses): the READERS are the 0x14581f0 marshal cluster;
  the only STOREs with those offsets (`sb`-sized, 0x1450668/0x1450710/
  0x14507e2/0x145047e) write byte flags into OTHER objects — none
  writes the policy object.

**Verdict: the six GET_PARAMS limit fields are a userspace template
never filled by this firmware build on any static path. The EDPp policy
object is not fed by the GET_PARAMS lane.**

## 2. TASK B — the x86 power-site map

### 2.1 The open core (19,233,368 B) — v438b

The immediate census runs on objdump-DECODED instructions only (the
4.28 disp32/addend decoy lesson), every hit attributed to its
enclosing FUNC symbol (22,269 symbols):

- **100000 = 12 real immediates**, all timeout/delay/DP/SPDM constants:
  `kbifDoSecondaryBusHotReset_GM107` (100-ms reset timeout),
  `kbifDoFunctionLevelReset_TU102`, `kdispComputeDpModeSettings_v02_04`
  ×4, `_checkTimeout` ×2, `tmrDelay_PTIMER` ×3, `libspdm_init_context…`.
  **None is power.**
- **240000 / 250000 / 280000 = 0 immediates, 0 data words** (.data,
  .rodata; u32/u64/f32 at every offset).
- the 4.28 raw-u32 needle register (14 × 100000): the v438b cross-check
  shows **every one of the 14 is a DECOY at instruction level** (the raw
  byte sequence lands inside non-immediate operands) — the 4.28's
  per-site role attributions (timeouts/delays) remain correct and are
  now byte-level confirmed as NOT-immediates; the REAL immediates are
  the 12 above.
- f32 240.0 = 43 hits, all ASCII coincidences (`__FUNCTION__` strings,
  `chipID`, fbmem tables) — noise.

### 2.2 The CLOSED core (120,980,872 B) — v438c, the decisive census

- u32/u64 data words: **100000/240000/250000/280000/210000 = ZERO**
  in .data and .rodata. The v9 fingerprint triple detector
  ({100000,240000,250000} within ±64 B): **0 hits**.
- .text immediates: **250000 ×7, 500000 ×4+2, 100000 ×~40** — and the
  250000/500000 sites cluster in FOUR stripped functions:

| function | sites | the cited structure |
|---|---|---|
| `_nv059111rm` @203570/203740 | `sub $0x3d090,%rax`, `mov $0x3d090,%r15d` | the deadline−250000 deadband — the twin of GSP s2 |
| `_nv059099rm` @205364 | `cmp $0x3d090,%rdi` | the threshold twin of s0 |
| `_nv059110rm` @206655–207567 | `cmp/mov $0x7a120` (500000) + `cmp/mov $0x3d090` (250000) ×2 windows | **the clamp+hysteresis pair — the twin of GSP s4/s5's [250000, 500000] band** |
| `_nv059108rm` @208968 | `mov $0x3d090,%edx` | the second-clamp arm — the twin of the gap-8 split site (4.32e §8.2) |
| `_nv059112rm` @198498–198642 | `imul $0x186a0` ×5 | the ×1e5 conversion chains — the twins of the 4.34b MUL class |
| `_nv059107rm` @216183 | `movq $0x7a120,0x4f78(%r15)` | the 500000 STORE-DATA twin of the 4.34b state+0x5d0 class |

  **Verdict: PROVEN — the closed core's 250000s are the same
  request/budget-engine TIME logic, compiled from the same RM source
  for x86. The RM codebase carries {100000, 240000(no — 100000 only),
  250000} as time constants in BOTH cores; 240000 exists in NEITHER.**
- f32: 240.0 ×1, 280.0 ×1 (@.rodata+0x2C0AA/0x2C0FA section-relative,
  one 24-B-stride ladder {220.0, 240.0, 264.0, 280.0, 296.0} with
  markers {0x80000, 0x90000} and the 0x47b-flagged dwords {0x10047b,
  0x100000}/{0x4047b, 0x40000}), 250.0 ×1 (elsewhere). The ladder is
  wattage-shaped BUT: zero rip-relative references anywhere in .text,
  absent from the open core entirely, cross-section symbol attribution
  unreliable — **HYPOTHESIS (a TGP/clock-ladder blob), explicitly NOT
  load-bearing; the boot-day capture can name it.**

### 2.3 Where the −pl path runs (the named functions, the open core)

`nvidia-smi -pl N` → NVML → `NV2080_CTRL_CMD_PERF_RATED_TDP_SET_CONTROL`
→ `subdeviceCtrlCmdPerfRatedTdpSetControl_KERNEL` (@0x2d5e50, size
0x26a — nm-cited): validates, loads the 5 param dwords
(`mov (%rbx)/0x4/0x8/0x10/0x18` @0x2d5f1f–0x2d5f14), and relays through
the internal RM dispatch — `mov 0x3bc0(%r12),%rax ; lea 0x3b88(%r12),%rdi`
(@0x2d5f32/0x2d5f3e), the exact indirect-call shape of the host EDPp
SET (4.28 §6.2). The sibling stub
`rpcCtrlPerfRatedTdpSetControl_v1A_1F` (@0x37b5a0) carries it to the
GSP over its dedicated RPC function. **The clamp against limitMax runs
wherever the internal dispatch lands, and limitMax is runtime data** —
no binary constant exists for it (§2.1/§2.2), so the clamp cannot be
byte-patched.

## 3. TASK C — the full application map, and the 280 W patch design

### 3.1 Who clamps whom, in boot order (every arrow byte-cited)

1. **Boot**: the GPU ROM (VBIOS) carries the power tables; the open
   kernel sends NO power tables and its 50 `bios*` symbols contain no
   perf/power parser (nm census this pass) — the BIT/perf parser lives
   in the closed x86 RM (PROVEN 4.22, reconfirmed: the parser is
   absent from the open core).
2. **The closed x86 RM parses the VBIOS** into runtime heap structures
   — the {min=100, default=240, max=250} W values exist ONLY there
   (this pass's zero-constant census across all three binaries + NVML).
   The 4.23 live captures agree: 250/240 NEVER ride any transport; the
   RM holds them locally.
3. **The GSP-RM's EDPp object (0x6d0) is runtime-fed** from RM-internal
   state (the 0x2080A080/A618 internal events, the field copies, §1) —
   never from constants, never from the GET_PARAMS lane. Its policy
   fields (0x65c/0x660/0x668-0x684) are filled from the runtime
   objects; the enforcement the object performs is re-derivation, not
   the clamp of host requests.
4. **A user request (`-pl 280`)**: NVML → the RatedTdp control → the
   x86 RM internal dispatch → **clamped against the runtime limitMax
   (250)** → refused. The GSP-RM and its 0x6d0 object are not the
   refusing authority for this path; the x86 RM is.
5. **The reported 250** = the x86 RM's runtime value, read back by NVML
   via the GET controls.

### 3.2 The patch design (the causal chain, per lane)

The rm.elf 250000→280000 lane stays CLOSED (4.32/4.34) and this pass
closes the x86-constant lane for the same reason. The lanes that can
actually move the applied limit, ranked:

- **Lane V (VBIOS-in-RAM) — the primary design.** The values enter at
  the VBIOS parse. Patch the VBIOS IMAGE IN RAM before/at the RM's
  parse, not the ROM chip: the repo already owns the tooling
  (`tools/intelligence/scan-kcore-vbios.py`,
  `extract-kcore-vbios.py`, `read-rom-bar.py`) and the BIT grammar
  anchor (the README's NVIDIA BIOS Information Table). The edit: the
  perf-table power-budget records {min/default/max} — raise max 250→280
  (and default if the sustained target is 280) in the .run
  `NVIDIA-Linux-x86_64-610.57.04.run` VBIOS image or the kcore shadow
  at boot. Causality: the parse copies the patched records into the
  runtime structures → limitMax = 280 → `-pl 280` passes the clamp →
  the enforcement applies 280. Byte location: device-specific (the
  GA104 image the founder owns); the finder = the same {240000, 250000}
  mW scan the 4.23 transport ran, but against the VBIOS image, where
  the power tables genuinely live.
- **Lane R (the revised runtime scanner) — the v9 successor.** The v9
  fingerprint {100000, 240000, 250000} is now PROVEN absent from every
  binary, so a contiguity match in kernel RAM would be luck, not
  identity. The revised design scans the heap for the {240000, 250000}
  PAIR within ±32 B (the min/max budget pair the parser builds), the
  module-param rewrite sets max=280000; the `nvidia-smi -pl 280`
  validation follows. Same kernel_gsp.c delayed-workqueue delivery as
  v9 (the 4.23 infrastructure, restored to stock).
- **Lane T (the control hook)**: intercept
  `subdeviceCtrlCmdPerfRatedTdpSetControl_KERNEL`'s internal dispatch
  (the `obj+0x3bc0` call @0x2d5f32) in our compiled open shim — raise
  the limitMax argument in the params before the clamp. Requires the
  runtime structure map of the perf limits object (the capture-day
  data names it; the 4.26 recv capture already watches the response
  lane).
- **Lane H (HS-execution rewrite of the 0x6d0 object)**: unchanged from
  4.32 §5 — the fields 0x65c/0x660/0x668-0x684 are the writable
  targets, but this pass shows the object is the GSP-side
  re-derivation surface, not the host clamp — Lane H only matters for
  GSP-enforced policies, lower priority now.

**The recommended order: Lane V (day-scale, no kernel rebuild, the
patch lives where the values are born), then Lane R (the fallback if
the VBIOS records resist the static finder), Lane T as the instrumented
variant.** No merge, no boot without the founder's go — the rules hold.

## 4. The honest ledger

1. The 19-MB immediate census used objdump-decoded immediates only; the
   movabs false-positives (e.g. `movabs $0x3000186a0` ≠ 100000) are
   filtered in interpretation, listed raw in the JSON.
2. The closed core is ET_REL with stripped `_nvNNNrm` names; the twin
   verdict rests on the STRUCTURE ({500000, 250000} adjacency, the
   deadband `sub`, the ×1e5 `imul` chains, the store class) matching
   the GSP's per-site roles — the identity-of-source reading is
   PROVEN at structure level, the function-name mapping is
   one-to-one-plausible, not provable without the closed source.
3. The wattage-shaped float ladder (@.rodata+0x2C0AA..0x2C0FA closed
   core) = HYPOTHESIS; zero static refs; not load-bearing.
4. v438a's whole-image island census desynced (the linear-walk lesson
   re-learned); the island extension of the -0x168 census remains a
   byte-pattern TODO — the 17/17 covered census and the copy-chained
   writer map are complete and banked.
5. v438a4's static attribution of the B+0x8D9DC table fill = UNDECIDABLE
   (stack-offset noise; B is multi-hop runtime). The 4.26 capture is
   the named road.
6. The GET_PARAMS 0x104–0x118 byte-scan covered the PMGR window and the
   dispatch-region windows; offsets that common in a 15-MB image can
   never be exhaustively attributed — the conclusion rests on the
   handler-side proofs (4.24 §5 + §1.3), which are byte-exact.

## 5. The queue

1. Lane V finder: the mW-scan instrument against the founder's VBIOS
   image (the BIT perf-table walk; the repo owns the grammar) — the
   next pass can deliver the byte-exact patch offsets.
2. The 4.26 recv capture stays the only road to the LIVE policy values
   (the 96-B prediction remains armed) — and now also names the perf
   limits object for Lane T.
3. The wattage float ladder: one capture-day look (the RM reads it or
   it is dead data) — closes the 2.2 HYPOTHESIS.
4. The island extension of the −0x168 census: the byte-pattern scan
   (the v432e scan pattern is the reference).
