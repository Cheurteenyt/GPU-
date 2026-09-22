# 4.28 — the x86 substrate: `nv-kernel.o_binary` landed, censused, the hunt opened

Status: **hunt OPENED, not closed.** The five captured values {255, 3, 257, 257,
250000} of the 1544-B `0x2080d031` params struct remain **HYPOTHESIS** — this
pass does not name them. This pass (1) lands the substrate PR #10 declared
absent, (2) freezes its census behind a selftest, (3) collects the first
hunt facts, (4) falsifies the hunt's naive form and names the corrected one.

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
