# 4.28 — the x86 substrate: the hunt CLOSED — the five fields named, the sender proven userspace

Status: **hunt CLOSED by wave 4.** The five captured values {255, 3, 257, 257,
250000} of the 1544-B `0x2080d031` params struct are **NAMED** (section 8.4):
the struct is the RM **clock-VF-offset table** — 8-B header {flags,
domain-bitmask} + 32 clock-domain entries x 48 B {version 1.1, flag byte, the
offset value} — and the senders are `nvmlDeviceSetGpcClkVfOffset` /
`nvmlDeviceSetMClkVfOffset` (NVML) and the Xorg driver's twin (nvidia_drv.so,
committed this wave). The kernel side (BOTH package cores) never builds these
params: the naive kernel hunt is falsified (wave 2), the issuer is proven
userspace (wave 3), the mechanism and the naming are closed (wave 4) — and
the 4.24 "250000 = the EDPp 250-W class" semantic is CORRECTED (a
clock-offset value rides that lane, not power). The wave history: part 1
(sections 1-5, the substrate landing + census), wave 2 (section 6, the
host pfmreqhndlr cluster), wave 3 (section 7, the NVML issuer), wave 4
(section 8, the completion — which supersedes the section 7.3 residual-stack
hypothesis, honestly marked there and corrected in 8.0).

## §1 — the substrate (PROVEN)

`tools/analysis/x86-rm/binaries/nv-kernel.o_binary` — ELF64, **x86-64 (machine
62)**, **ET_REL (type 1)**, 19,233,368 bytes,
sha256 `48096db025a439328592250b1c79e7f27943b37b733583778407f3cf46bca251`,
extracted verbatim from the official `NVIDIA-Linux-x86_64-610.57.04.run`
(package sha256 and reproduction recipe in `tools/analysis/x86-rm/PROVENANCE.md`).
This is NVIDIA's pre-linked closed host RM — the object the open shim links
against to build `nvidia.ko`. PR #10's queue item 1 (« land the substrate »)
is executed; the refinement is recorded: the substrate is `nv-kernel.o_binary`
(the closed RM before shim-linking), not a built `.ko` — the `.ko` is
derivable from it plus the open shim sources if a later ring needs it.
Repo-law check (AGENTS.md 1): sha256 + provenance committed alongside; the
repo already commits analysis binaries of comparable size
(`tools/analysis/gsp-extract/binaries/gsp-rm-17MB.bin`).

## §2 — the census (PROVEN, register frozen by selftest)

Instrument: `lab/jalon411/v428_x86_substrate_census.py`; register:
`lab/jalon411/v428_x86_substrate_census.json`; `selftest` re-derives the
anchors and exits 2 on drift. Facts:

- **sections (13, none compressed):** `.text` 4,021,333 B; `.rodata`
  9,870,893 B; `.data` 68,318 B; `.bss` 163,632 B; `.symtab` 23,713 symbols
  (23,705 named); `.rela.text` 139,145 relocs (R_X86_64_PC32 ×82,311,
  R_X86_64_32S ×56,834); `.rela.data` 1,746; `.rela.rodata` 24,323 (all
  R_X86_64_64). Nothing is compressed: every raw-byte scan below covers the
  whole payload of every section.
- **instrument correction banked:** the first draft of the family scanner
  read the candidate dword at `prefix_pos − 1`; the little-endian layout of
  `0x2080dXYZ` is bytes `[YZ, dX, 80, 20]`, so the dword base is
  `prefix_pos − 2`. The numpy calibration run (3 distinct values) versus the
  census (0) caught the misalignment; corrected, re-run, register frozen.
  The audit's discipline applies to the auditor — again.

## §3 — the first hunt facts (raw u32 scans, section-attributed)

| needle | hits | sections | reading |
|---|---|---|---|
| `0x2080d031` (the EDPp cmd) | **0** | — | the control id never appears as a 32-bit value anywhere in the closed host RM |
| `0x20809004` / `0x20809030` (the 1544-B closed siblings, PR #10 trio) | **0** / **0** | — | same absence for the whole size-trio |
| family `0x2080d0xx` (all dwords in range) | **3 distinct, 4 sites** | `.rodata` only | the INTERNAL ids that DO appear live as **data in tables** (`0x2080d2a5` ×1, `0x2080d2e9` ×2, `0x2080d338` ×1) — and `0x2080d031` is **not** among them |
| `1544` (`0x608`, the params size) | **35** | `.text`, `.rodata`, `.rela.*`, `.symtab` | the size constant IS present — attribution is the open work |
| `100000` (`0x186a0`) | **14** | `.text` **only** | fourteen code sites embed the EDPp quantum as an immediate — the hunt's primary target list |
| `240000` (`0x3a980`) | **0** | — | consistent with the capture (zero occurrences) and with the GSP-side finding |
| `250000` (`0x3d090`) | **0** | — | the host RM does not hardcode the 250-W class either (the GSP side had it code-only: 4 lui+addi sites, PR #10) |

## §4 — what this does to the 4.25-x86 ledger

The five values stay **HYPOTHESIS** — unchanged. The premise is REFINED:
PR #10 held that « the only static namer is the host marshal's field-offset
copy graph, which lives in nvidia.ko, absent ». The substrate is now present,
and its first scan already **falsifies the hunt's naive form**: no
`mov r32, 0x2080d031` immediate exists to find. The corrected hunt routes
through (a) the 35 × `1544` sites, (b) the 14 × `100000` `.text` sites — the
transport value the capture never carries is embedded fourteen times in host
code — (c) symbol-guided attribution (23,705 named symbols: the object is not
stripped), and (d) if still negative, the userspace extension of the same
official package (`libnvidia-ml.so.610.57.04`, `libnvidia-eglcore.so…`) —
NVML being the known EDPp surface, the cmd may travel as data from userspace
through the ioctl into the RPC, which would explain the kernel-side absence.

## §5 — queue

1. ~~Disassemble and attribute the 35 × `0x608` sites and the 14 × `0x186a0`
   sites~~ — DONE (§6, instruments v428b).
2. ~~Symbol census + cluster disassembly~~ — DONE (§6, v428c/d/e).
3. Userspace substrate: same needles over `libnvidia-ml.so.610.57.04` and
   `libnvidia-eglcore.so.610.57.04` (same package, same provenance law) —
   re-download in progress (sandbox reset wiped the local extraction; the
   committed substrate survived via the branch).
4. v428f (queued): dump the `__nvoc_*` metadata objects of
   `PlatformRequestHandler` (export_info / metadata / class_def / castinfo @
   0xbfcdb0..0xbfce70) — the FINN name resolution path.
5. The copy-graph naming attempt on whatever sites survive — the five fields
   get PROVEN/FALSIFIÉ verdicts there or nowhere.

## §6 — wave 2: the pfmreqhndlr cluster disassembled (PROVEN, v428b/c/d/e)

### §6.1 — the cluster (59 symbols; every range re-derived from `.symtab`)

The closed host x86 RM carries the **full host-side PlatformRequestHandler
object** — the same RM codebase as the GSP build, compiled for x86:

| symbol | range | role |
|---|---|---|
| `pfmreqhndlrHandlePlatformGetEdppLimit_IMPL` | 0x338610..0x3386f3 | host GET |
| `pfmreqhndlrHandlePlatformSetEdppLimitInfo_IMPL` | 0x338700..0x33881c | host SET |
| `pfmreqhndlrHandleEdppeakLimitUpdate_IMPL` | 0x338480..0x338549 | update |
| `pfmreqhndlrHandlePlatformEdppLimitUpdate_IMPL` | 0x338550..0x338607 | update |
| `_pfmreqhndlrHandlePlatformSetEdppLimitInfoWorkItem` | 0x337080..0x33719c | work item |
| `_pfmreqhndlrCallPshareStatus` | 0x338820..0x338cb2 | **the hub** |
| `_pfmreqhndlrPmgrPmuPostLoadWorkItem` | 0x335c60..0x335dc0 | PMU post-load |
| `_PfmreqhndlrControlTable` (OBJECT, .data) | 0x3e2e00..0x3e2e30 | `__nvoc` table |

### §6.2 — the host EDPp semantics (disassembly, cited by address)

- **host GET** (`HandlePlatformGetEdppLimit_IMPL`): `osCallACPI_DSM` with
  sub-function **0x2c**, in-buffer `{4, 0x2c, 0x100}`, OUT = **one dword**
  written to the caller's pointer (0x338680..0x338683). The host-side
  GET_EDPP_LIMIT is a **local ACPI call returning 32 bits** — NOT the RPC'd
  1544-B control of the capture.
- **host SET** (`HandlePlatformSetEdppLimitInfo_IMPL`): indirect RM call
  through `[obj+0x3bc0]` with the **cmd as an immediate**
  (`mov ecx, 0x20800afd` @0x338757) and **params size as an immediate**
  (`mov r9d, 0x18` = 24 B @0x33873d), arg shape
  `(rdi=params @obj+0x3b88, esi=[obj+0x3b64], edx=[obj+0x3b6c], ecx=cmd,
  r8=&status, r9d=size)` — then three qwords of OUT cached at
  obj+0x6e0/0x6e8/0x6f0 and a work item queued.
- **updates**: `mov ecx, 0x20800ad0`, size 8 (`r9d=8`,
  @0x3384c5/0x3385ab); the hub also issues `mov ecx, 0x20800ad2`, size 1
  (@0x338954).
- **the hub** (`_pfmreqhndlrCallPshareStatus`): calls `pfmreqhndlrCallACPI`,
  bit-tests the status dword (bits 0x2000000 / 0x4000000 / 0x200000 / 22 /
  20 → obj+0x6a9..0x6ac), then dispatches the four EDPp handlers (xref sites
  0x338aa9, 0x338ad7, 0x338bd2, 0x338c65) and the PMU post-load work item
  calls two of them (0x335d1f, 0x335d55). **The EDPp entry points are the PMU
  post-load work item and the PSHARE status path.**

### §6.3 — the origin verdict, upgraded (the decisive negative)

The host RM marshals every control it issues with **cmd + size immediates**
(§6.2). Exhaustive scans say:

- `0x2080d031`: **0** as immediate, **0** as data dword (raw, uncompressed
  sections), **0** in the `__nvoc` control table;
- `0x608` in `.text`: 19 sites, **none** inside any `pfmreqhndlr*` /
  PlatformRequestHandler function (PLL/hot-reset/DP/timeout/timer/spdm/
  unrelated struct offsets — register `v428_site_attribution.json`);
- `100000`: 14 `.text` sites, **none** EDPp-related;
- the FINN-name string `PmgrPfmReqHndlrGetEdppLimitInfo` exists @0xc06ef8 but
  **zero relocations reference it** (exact + ±0x200 windows, PC32
  section-symbol decoding — v428e) → the name resolves at RUNTIME
  (HYPOTHÈSE: the `__nvoc` export metadata walk; v428f queued).

**Verdict (PROVEN, negative): the closed host x86 RM never issues
`NV2080_CTRL_CMD_INTERNAL_PMGR_PFM_REQ_HNDLR_GET_EDPP_LIMIT_INFO`
(0x2080d031) with its 1544-B params.** The captured RPC request was built
outside this binary. Remaining issuers: (a) **userspace NVML** (decisive
needle test queued — libnvidia-ml), (b) the `__nvoc` by-name runtime path,
(c) an open-kernel/client passthrough carrying the cmd as data. The 4.25-recv
§7.2 prediction stays armed and is orthogonal to the issuer question.

### §6.4 — instrument corrections banked this wave

- v428c/d: RELA `file_off` must be **TARGET-section-relative**
  (`sh_info` names the target); the first draft used the RELA section's own
  `sh_offset` — call targets went unresolved and the table windows were
  misaligned. Corrected, re-run, registers rewritten.
- v428b: same correction applied to its call resolver.
- v428e: the FINN xref requires PC32 section-symbol arithmetic
  (`effective = addend + r_off + 4`); plain addend matching is a silent
  false-negative. Documented in the register.

## §7 — wave 3: the issuer is NVML (PROVEN) — the marshal caught byte-level

Substrate: `libnvidia-ml.so.610.57.04` (2,654,168 B, sha256 `50feda0f…`,
extracted verbatim from the same official package — sha256 of the `.run`
re-verified `b2e935c6…` after the sandbox reset). Committed at
`tools/analysis/x86-rm/binaries/` per the repo's binary precedent.

### §7.1 — the cmd+size pair (PROVEN, addresses cited)

`0x2080d031` occurs **exactly twice** in the whole package's user/kernel
binaries scanned so far — both in NVML, both in the same marshaling shape
(two branches of one function):

```asm
; site 1 @0x108513                      ; site 2 @0x108bea
mov  r9d, 0x608        ; 0x1084c9       mov  r9d, 0x608        ; 0x108ba9
mov  r12d, 0x3e7       ; 0x1084cf       mov  r12d, 0x3e7
mov  r8, r15           ; params         mov  r8, r15
mov  ecx, 0x2080d031   ; 0x108512       mov  ecx, 0x2080d031   ; 0x108be9+1
mov  esi, [rax+0x8c]   ; subdevice h.   ...
call 0x9e560           ; NVML RM ctl    call ...
```

`0x608` = **1544** — the params size of the captured control. The size
immediate sits 0x43–0x48 bytes before each cmd immediate. `r12d = 0x3e7`
(999) rides along as an argument; after the call, `cmp eax, 0x66` opens the
error path. `libnvidia-eglcore.so` carries **zero** `0x2080d031`; the closed
kernel RM carries zero (§6.3).

### §7.2 — the copy graph, first named write (PROVEN as code, value HYPOTHÈSE)

Immediately before each marshal, the request buffer is fed:

```asm
imul  eax, eax, 0x64            ; ×100
idiv  dword ptr [rbp-0x644]     ; ÷ N (runtime)
imul  eax, eax, 0x3e8           ; ×1000
mov   dword ptr [rbp+rcx-0x630], eax   ; → the params area
```

with `rcx = idx*3*16` — a **48-byte-stride per-entry record** (flag byte at
entry+0, dword at entry+4): a **milliwatt-scale conversion written INTO the
1544-B request**. The exact stack-frame-to-wire offset map (which of the five
captured offsets {0, 4, 8, 12, 104} each store lands on) is the v428g ring
(function frame reconstruction — the function is huge, multiple branches).

### §7.3 — where 250000 is NOT, and what that means

- `250000` (0x3d090): **0 occurrences in NVML**; `240000` (0x3a980): **0 in
  NVML** (4 adjacent dwords in eglcore @34618728..34618772 — unqualified,
  likely another domain).
- The captured REQUEST carried `250000` @offset 104 (4.24: unique occurrence
  in the capture). NVML cannot have embedded it as an immediate.
  **HYPOTHÈSE (strong, now testable): the request's 1544-B buffer is a stack
  frame that NVML only partially initializes — the captured 250000@104 is
  residual stack content** left by a previous call on the same stack (e.g. a
  prior SET request or another control), NOT an IN field of GET_EDPP_LIMIT_INFO.
  This explains the 4.24 uniqueness finding and does NOT contradict the
  4.25-recv prediction (the RESPONSE is where the GSP writes the
  {100000, 240000, 250000} triplet).
- `100000` (0x186a0): **28 occurrences in NVML** (clusters at 1045789..1045971,
  1057734..1058109, 1064731..1066271) — the power-conversion candidates for
  v428g classification.

### §7.4 — the verdicts after wave 3

| question | verdict |
|---|---|
| who issues the captured RPC 0x2080d031/1544 | **PROVEN: NVML (userspace)** — the only cmd+size pair in the package |
| does the closed kernel RM issue it | **PROVEN: no** (§6.3) |
| is the 1544-B buffer fully initialized by the issuer | **PROVEN: no** (rep stosq 0x71 qwords = 904 B zeroed; conversion stores land in a 48-B-stride sub-area) — the rest is stack residue |
| the five captured fields {255, 3, 257, 257, 250000} | still **HYPOTHÈSE** — 255/257 have hundreds of matches (can't be immediates-only); the frame map (v428g) or the live capture (4.26) decides |
| the EDPp host-side handlers (kernel) | **PROVEN: local ACPI paths** (DSM 0x2c → 1 dword; controls 0x20800ad0/ad2/afd) — a DIFFERENT lane than the RPC'd GSP control |

Queue: v428g = full frame map of the NVML marshaler (stack offsets → wire
offsets), classify the 28 × `0x186a0`, resolve `call 0x9e560` (the NVML RM
dispatcher) and the `[global+0x8c]` handle cache; then the 4.26 live capture
checks the response triplet against §7.3's hypothesis.

---

## §8 — wave 4: the completion — the struct NAMED, the mechanism decoded (PROVEN, v428_x86_site_attributor / v428_x86_copygraph / v428_userspace_scan)

### §8.0 — the deltas vs waves 2-3 (read first)

Complementary registers to the wave-2 `v428_site_attribution` (the 53-site
roll-up below closes over the whole census, both instruments agree on the
non-EDPp classification), and three corrections that complete wave 3:

1. the two NVML sites sit in **two twin functions** ([0x108250..0x108550]
and [0x108930..0x108c20], .eh_frame_hdr bounds), not two branches of one —
and their own log strings name them: **nvmlDeviceSetMClkVfOffset** and
**nvmlDeviceSetGpcClkVfOffset** (source `dmal/common/common_clock.c`).
2. the request buffer is NOT partially-initialized: the OUTER function
zeroes all **1544 B** (`rep stosq` ecx=0xc1 at rbp-0x640); the 904-B
memset (ecx=0x71) of section 7.3 belongs to the HELPER's own local
buffer (the 904-B = 8+32x28 query twin).
3. the captured {255 @0, 257 @8, 257 @56} are therefore NOT residual
stack — they are the **0x20809030 RESPONSE echoed back** (the mechanism
below, proven by contradiction), and the naming closes.

### §8.1 — the corrected hunt, kernel side: every site attributed, the naive form FALSIFIED (PROVEN)

Instruments: `v428_x86_site_attributor.py` (+ register, selftest = full
re-derivation) and `v428_x86_copygraph.py` (+ register). All 53 census sites
(35 x 1544, 14 x 100000, 4 family) are attributed and classified; the roll-up
closes with zero unclassified sites.

- **the 14 x 100000 `.text` sites — the "EDPp quantum embedded in host code"
  reading is FALSIFIED.** Every site is a timeout/delay/display constant:
  `kbifDoSecondaryBusHotReset_GM107` + `kbifDoFunctionLevelReset_TU102`
  (`mov edi, 0x186a0` — a 100-ms reset timeout), `_checkTimeout` x2 and
  `tmrDelay_PTIMER` x3 (100-ms/100-us timeout+delay constants),
  `kdispComputeDpModeSettings_v02_04` x4 (DisplayPort mode arithmetic),
  `nvswitch_init_pll_config_lr10/ls10` x2 (64-bit PLL constant overlaps),
  `libspdm_init_context_with_secured_context` x1 (an SPDM context field at
  +0x108). None is a power value; none touches any EDPp path.
- **the 35 x 0x608 sites — none is the d031 marshal.** The REAL (IMM/DISP)
  sites: hal function-table slots (`__nvoc_init_funcTable_KernelFalcon_1`,
  nvswitch hal x2 — vtable offsets), rcdb record sizes (`krcWatchdogInit_IMPL`
  x2 — the watchdog record, its windows show the rcdb magics `0xdeaf0006` and
  `0x314159xx`; `rcdbDumpSystemInfo_IMPL`; the nocat journal x2 —
  source-PROVEN: `subdeviceCtrlCmdNvdGetNocatJournalRpt_IMPL` iterates
  `journalRecords[]` at subdevice_ctrl_nvd.c:162-210, the 1544-B stride =
  sizeof(NV2080_NOCAT_JOURNAL_RECORD), ctrl2080nvd.h:201-208), a vgpu record
  (`kvgpumgrGuestUnregister`), member offsets (kbus/kgmmu/bar2/vgpu-task),
  nvswitch platform code, and **one marshal-class site**:
  `rpcCtrlSubdeviceGetP2pCaps_v21_02` — decoded end to end in section 7.
  The artifacts: 3 jcc disp32 overlaps, 12 `.rela.text` r_offset offset
  coincidences (the nvoc objCreate/dtor cluster at .text 0x608xx), 2
  `.symtab` st_value coincidences (`__nvoc_dtor_RsShared`,
  `__nvoc_objCreateDynamic_RsResource`), and the 2 `.rodata` sites.
- **the census's family reading is refined:** the three family dwords
  (0x2080d2a5, 0x2080d2e9 x2, 0x2080d338) sit INSIDE GSP firmware bindata
  blobs (`kgspBinArchiveBooterUnloadUcode_AD102…`,
  `kgspBinArchiveGspRmCcFmcGfwProdSigned_GH100…`,
  `kgspBinArchiveConcatenatedFMC_GH100/GR100…`) — random-image coincidences,
  not "data tables". The conclusion stands and sharpens: `0x2080d031`
  appears nowhere in the committed core — not as an immediate, not in a
  table, not in `.data`.
- **the five-value store probe** (captured immediates {255, 3, 257, 250000}
  as stores, and stores at the five captured poffs) across every REAL-site
  function: 9 hits, all in the rcdb/spdm/nvswitch lanes — **no host function
  builds the captured pattern.** The honest kernel-side negative, banked.
- instrument corrections banked (the audit's discipline applies to the
  auditor): the copygraph first draft read relocations only at instruction
  starts (call rel32 relocs sit at +1) and probed the store's destination
  for the immediate instead of the source; both caught, corrected, re-run.

### §8.2 — the two RPC lanes, and the one marshal-class site calibrated (PROVEN)

The host RM object holds a **626-symbol RPC stub family** (`rpc<Api>_vNN_NN`
+ `_STUB` pairs). These are NOT fn=76: each stub sends a DEDICATED RPC
function — `rpcCtrlSubdeviceGetP2pCaps_v21_02` (vgpu/rpc.c:6338, OPEN source)
calls `rpcWriteCommonHeader(pGpu, pRpc, NV_VGPU_MSG_FUNCTION_CTRL_SUBDEVICE_
GET_P2P_CAPS, sizeof(rpc_ctrl_subdevice_get_p2p_caps_v21_02))` — in machine
code `mov edx, 0xbf` + `mov ecx, 0x608`: function **191** (rpc_global_enums.h
:201 `X(RM, CTRL_SUBDEVICE_GET_P2P_CAPS, 191)`) and params size **1544**
(= sizeof the GetP2pCaps v21_02 struct, g_sdk-structures.h:4239). The stub
then `portMemCopy`s the caller's params and calls the generated
serialize/deserialize pair — the field-offset copy graph for THAT control.
No stub exists for anything d031-shaped (the rpc symbol census: Subdevice
stubs = GetLibosHeapStats, GetP2pCaps, GetVgpuHeapStats only; the perf/power
stubs = PerfBoost, RatedTdpGet/Set, GetLevelInfo).

**The lane law:** the captured `0x2080d031` rode **fn=76**
(`X(GSP, GSP_RM_CONTROL, 76)` — rpc_global_enums.h:86), the GENERIC lane
(`rpcRmApiControl_GSP`, vgpu/rpc.c:10659 — the 4.25-x86 citation, path
corrected from "rpc.c" to the tree's actual `src/nvidia/src/kernel/vgpu/
rpc.c`), where the cmd is a runtime parameter from the client. A control
absent from every kernel table and stub can only enter that lane from the
client — userspace.

### §8.3 — the userspace extension: the origin PROVEN, the mechanism decoded (PROVEN)

Instruments: `v428_userspace_scan.py` (+ register, selftest). Substrates
committed with the same provenance law (package sha256
`b2e935c6…b116d` verified on download against the 4.27 acquisition
register): `libnvidia-ml.so.610.57.04` (2,654,168 B, `50feda0f…`),
`libnvidia-eglcore.so.610.57.04` (39,091,248 B, `afd79b7f…`),
`nvidia_drv.so` (3,627,376 B, `28ae0bf0…`).

- **the package sweep (190 files >50 KB):** `0x2080d031` lives in
  libnvidia-ml.so **x2** (.text, `mov ecx, imm32`), nvidia_drv.so **x1**
  (.text, `mov esi, imm32`), the GSP firmware images (their dispatch
  entries — the v425 whole-image census), eglcore **zero** — and, the
  discovery of this pass, **kernel/nvidia/nv-kernel.o_binary x1**.
- **the two cores:** the package ships BOTH `kernel-open/nvidia/
  nv-kernel.o_binary` (19,233,368 B — the committed substrate, ZERO d031)
  and `kernel/nvidia/nv-kernel.o_binary` (**120,980,872 B**, sha256
  `c90f58d5…8cbf` — the CLOSED driver's core, not committed: over the
  100-MB limit, hash-documented in the register + PROVENANCE). The closed
  core's single d031 is a `.rodata` **table row** at 0x666b110, stride 0x20
  {u32 cmd, u32 tag, u64 0, u64 0x44}: 0x2080d02d->4116, 0x2080d031->1544,
  0x2080d036->… — the HOST twin of the GSP dispatch table (v425-x86
  section 3: same rows, same 0x44). Routing metadata, NOT a marshal: no
  code immediate exists even there. **In both cores the params build is
  userspace-only** — the origin verdict is independent of which core the
  rig links.
- **NVML deep dive (the two senders, named by their own log strings):**
  functions [0x108250..0x108550] and [0x108930..0x108c20] reference
  `'cDeviceSetMClkVfOffset'` and `'cDeviceSetGpcClkVfOffset'` with the
  source path `'dmal/common/common_clock.c'` and line numbers 5855/5861/5866
  — **nvmlDeviceSetMClkVfOffset / nvmlDeviceSetGpcClkVfOffset**. The flow:
  zero the 1544-B stack table (`rep stosq`, ecx=0xc1), query the current
  table (the helper 0x107820 sends **0x20809029**, params 904 B = 8 + 32 x
  28 — the 32-entry/28-B query twin; parses the domain mask and the
  entries; writes `params[4] = mask`), then the outer function patches
  entry[i] and sends d031 with size 0x608. The helper also sends
  **0x20809030** (the second 1544-B sibling of the v425-x86 trio) on its
  own path.
- **nvidia_drv.so deep dive (the mechanism, PROVEN):** function
  [0x77920..0x77a50] — memset 1544 B; `params[4] = dev->[+0x5fc]` (the
  domain mask); **send 0x20809030 whose RESPONSE FILLS the buffer** —
  proven by contradiction: the very next instruction checks
  `byte [rsp + 48*i + 9] == 1` (the entry's version-minor), which can only
  pass if the send populated the zeroed buffer; patch entry[i]
  (`byte@+4 = 0`; `dword@+8 = int(offset / (devField / 100.0) * 1000.0)`);
  **send 0x2080d031**. The two `.rodata` constants of the formula are
  **100.0 and 1000.0** (so value = offset x 100000 / devField); NVML's
  integer twin uses 100 and 1000 — the same conversion in two codebases.
  The callers are two NV-CONTROL-style attribute handlers (tail-jumps at
  0x3a1ba with esi=1 and 0x3a2a7). This is the Xorg driver's
  clock-VF-offset setter — the path nvidia-settings/Coolbits drives.
- **eglcore side observations (banked, uninterpreted):** d031 = 0;
  250000 x5 `.text`, 240000 x4 `.rodata`, 100000 x6 — power-class values
  in the GL core, no d031 linkage.

### §8.4 — the naming: the five captured fields (the deliverable)

**The struct law (PROVEN three ways):** the 1544-B params =
**8-B header + 32 entries x 48 B** (the memset count 0xC1 qwords; the
48-stride stores `lea rcx,[i+i*2]; shl rcx,4`; the 32-entry domain table
of the 0x20809029 query twin, mask-checked `bt`/loop-to-0x20).

| poff | captured | the field | verdict |
|---|---|---|---|
| 0 | 255 (0xFF) | the table **flags** dword — GSP-authored (rides the 0x20809030 response) | layout **PROVEN** / semantics **HYPOTHESIS** (an all-valid-domains flags shape) |
| 4 | 3 | the **clock-domain bitmask** (userspace writes it from the device's domain mask; the helper writes `params[4] = mask` from the query) | **PROVEN** (bit 0+1 = the two active domains) |
| 8+48i | 257 (x2) | **entry[i] version = {major=1, minor=1}** (0x101) — GSP-authored; the X driver *checks* minor==1 before patching | **PROVEN** (the 4.25-x86 "version-pair shape ((1<<8)\|1)" reading confirmed and named) |
| 12+48i | 0 | entry[i] **flag byte** (userspace patches 0) | layout **PROVEN** / semantics **HYPOTHESIS** |
| 16+48i | 250000 | entry[i] the **clock VF-offset value** = offset x 100000 / devField (the 100.0/1000.0 formula; NVML's integer twin) | lane **PROVEN** / exact input units **HYPOTHESIS** (a x1000 milli-scale — a kHz-class offset; the devField divisor [+0x628/+0x638] is not decoded) |

The captured message was therefore a **Set*VfOffset send targeting
entry[1]** (domain index 1; mask 3 = domains 0+1) with the offset value
250000 — the 250-W-shaped number is a **clock offset**, not an EDPp limit.

### §8.5 — the ledger reconciliation (4.23 / 4.24 / 4.25)

1. **4.23 "the transport never carries the EDPp limits" — CONFIRMED and
   SHARPENED**: the one 250000 that rides the CPU->GSP transport is a
   clock-VF-offset value in the SetClkVfOffset lane. No power limit rides
   the send side anywhere in this pass's evidence.
2. **4.24's poff64 semantics ("the EDPp 250-W class in mW") — FALSIFIED as
   to lane** (a seductive numerical coincidence, now explained); the
   "CARRIED, not consumed" mechanics stand and strengthen — the GSP
   handler ignores the params, and the carried shape is the GSP's own
   echoed table format plus the userspace patch.
3. **4.24's "two versioned sub-blocks @8/@56, 48 B apart" — CONFIRMED and
   NAMED**: entry[0]/entry[1] version pairs of the 48-B domain entries.
4. **4.25-x86's 1544-B census — refined, not overturned**: the fn=76
   dispatch trio {0x20809004, 0x20809030, 0x2080d031} is the
   clock-VF-offset table control family (query twin 0x20809029, 904 B,
   added); the dedicated lane ALSO has a 1544-B struct
   (NV2080_CTRL_GET_P2P_CAPS_PARAMS_v21_02, sizeof PROVEN by the stub's
   ecx + rpc.c source) — a size-class coincidence with a different shape.
   The open-SDK "no shipped 1544-B sibling" claim stands.
5. **4.28 part-1's own readings — corrected in place**: the family dwords
   are firmware-bindata coincidences (not "data tables"); the "100000 x14
   primary target list" is falsified (timeouts/delays).
6. **the section 7.2 GET_EDPP prediction — UNTOUCHED**: it concerns the
   0x20800afd RESPONSE path (the 4.26 live capture), not this send-side
   payload; the d031 red herring is now removed from the ledger.

### §8.6 — queue

1. **the 4.26 live capture** (boot RpcDump=1 + RpcRecvMode=2, the armed
   instruments of PR #11) — now the ONLY road to the EDPp limits
   themselves; the d031 payload is cleared of the power question.
2. optional: decode the offset-value units fully (the devField divisor
   [+0x628/+0x638] and the NV-CONTROL attribute ids of the two drv
   callers) — a documentation nicety, no longer load-bearing.
3. optional: 0x20809004 (the third 1544-B sibling) — likely another table
   variant of the same family.
4. observed only: eglcore's 250000 x5 / 240000 x4 / 100000 x6.
