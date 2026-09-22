# 4.25 — the x86 marshal hunt: the substrate premise FALSIFIED (win.elf = the RISC-V window artifact), the closed x86 RM absent from the repo, the interface-0x2080d0 family mapped (19 controls), the five offsets held at HYPOTHESIS

Substrate: every closed binary the repo actually holds —
`tools/analysis/gsp-extract/win.elf` (the named substrate, audited first),
`rm-full.elf` / `binaries/gsp-rm-17MB.bin` (the GSP-RM RISC-V image), the
nvflash executable set (`tools/flash/**`), the archives
(`nvflash-5.867.zip`, the 27 `day0/vfio-flash-*/vm-initramfs.cpio.gz`),
the payload `tools/edpp/edpp_payload_1616.bin`, the 4.16 boundary map,
and the raw open-gpu-kernel-modules **tag 610.57.04** ctrl2080 headers
(fetched once, sha256-pinned in the register). Instruments:
`v425_x86_marshal.py` (+ `v425_x86_marshal.json`).

The task (the 4.24 queue): find the interface-0x2080d0 marshal in "the
closed x86 blob = tools/analysis/gsp-extract/win.elf", read its field-
offset copy graph, name the 1544-B params struct of 0x2080d031 —
especially the field @64 that carries 250000.

## 1. The headline (honest): the marshal hunt could not run — the named substrate is not x86, and the real one is not in the repo

The 4.24 queue item pointed this pass at `win.elf` as "the closed x86
RM" — that pointer is **falsified at the byte level**:

1. `win.elf` is an ELF with **machine = 243 (UCB RISC-V, RVC)** — not
   x86 (3) nor x86-64 (62). 888 bytes total = 64 (ELF header) + 56
   (one phdr) + **768 bytes of window**.
2. The 768-byte window is a verbatim slice of
   `binaries/gsp-rm-17MB.bin` at **file offset 0xa9e200** — and
   re-executing the committed generator's recipe (`win-disasm.py`
   `disasm_window()`: the 64-byte header, the phdr, the slice)
   reproduces `win.elf` **byte-identically**. win.elf is a leftover
   disassembly *window* ("win" = window, not Windows) around a
   memset/memcpy-shaped leaf routine — HYPOTHESIS on the routine's
   identity, PROVEN RISC-V GSP-RM code. It contains zero family-id
   dwords and zero 250000 dwords (byte-step-1).
3. **The coordinate by-product**: win-disasm's `off2va` labels the
   window VA 0x1a9e200, but the 4.16/4.20 map convention puts the same
   bytes at **0x1a9e238** — win-disasm sits **0x38 below** the map
   convention (gsp-rm-17MB.bin offset + 0x78 = rm-full.elf file
   offset, proven on the raw 0x2080d031 dispatch-entry anchor). Any
   future work on the raw 17-MB image must use
   `gsp_off + 0x38 + 0x1000000` to land on map VAs.
4. The actual closed x86 host RM — where the interface-0x2080d0
   marshal would live — is the **unpacked nvidia.ko (27.7 MB,
   findings-4.22 §3)**, and a full census of every ELF/PE committed in
   the repo proves it is **not here**: the only non-RISC-V executables
   are the nvflash set (x86, x64, PPC64, AArch64 — five distinct
   builds) and busybox; the zip holds only the four nvflash binaries;
   the 27 initramfs archives (18..37 entries each) hold busybox +
   nvflash and **no .ko, no .sys, no .dll**.

Per the task's own rule — "si le marshal est introuvable : ledger
honnête" — the pass banks the falsification as the headline and
redirects every derivation it CAN honestly make onto the closed
substrates that ARE present.

## 2. The x86 census (all negative, instruction-aware — no fabricated hits)

| binary | family ids 0x2080d000–d0ff (step-1) | exact 0x2080d031 | real 250000 values |
|---|---|---|---|
| flash/x64/nvflash (+5.867 twins, patched) | 0 | 0 | 0 (20 artifacts) |
| flash/x86/nvflash | 0 | 0 | 0 (24 artifacts) |
| flash/nvflash-5.792-k4 (+k4-vv) | 0 | 0 | 0 (6 artifacts) |
| flash/ppc64/nvflash | 0 | 0 | 0 |
| flash/aarch64/nvflash | 3 — all unaligned | 0 | 0 |
| flash/busybox | 0 | 0 | 0 |

- The "250000" hits in the x86/x64 binaries are **not the value**: each
  begins at a modrm byte (0x90, mod=10) preceded by an opcode — the
  overlap shape of `call [rax+0x3d0]` (`FF 90 D0 03 00 00`); the true
  displacement is 0x3d0, and the classifier reports it per hit.
- The three aarch64 "family hits" (0x2080d000) are unaligned
  cross-instruction overlaps — context-disassembled as
  `adrp x2, #0x8d8000` + `add x0, x4, #0x888` address pairs, not the
  constant.
- **Verdict: no committed x86 binary marshals interface 0x2080d0, and
  none carries 250000 as a value.** The host-side producer of the @64
  field is in nvidia.ko — absent.

## 3. The interface-0x2080d0 family on the GSP-RM (the closed substrate present)

From the 4.20 dispatch table (@0x1c183b8, 1,156 entries, stride 0x20;
entry layout calibrated in 4.24 §4) — **19 controls** on the interface:

| id | tag = paramsSize | handler | sz0 |
|---|---|---|---|
| 0x2080d01c | 2108 | 0x10f46d8 | 0x44 |
| 0x2080d020 | 19416 | 0x1105044 | 0x44 |
| 0x2080d024 | 66060 | 0x1118d84 | 0x44 |
| 0x2080d028 | 6288 | 0x10cc1e0 | 0x44 |
| 0x2080d02d | 4116 | 0x10cb91c | 0x44 |
| **0x2080d031** | **1544** | **0x11267fc** | 0x44 |
| 0x2080d036 | 1164 | 0x10da978 | 0x44 |
| 0x2080d041 | 648 | 0x1119b40 | 0x44 |
| 0x2080d047 | 8264 | 0x113ef44 | 0x44 |
| 0x2080d055 | 332 | 0x10d8364 | 0x10244 |
| 0x2080d067 | 4 | 0x1148fec | 0x44 |
| 0x2080d069 | 76 | 0x1116c80 | 0x44 |
| 0x2080d073 | 14316 | 0x1105f5c | 0x44 |
| 0x2080d07c | 392 | 0x1106844 | 0x44 |
| 0x2080d080 | 44 | 0x11072ac | 0x44 |
| 0x2080d084 | 3096 | 0x1113358 | 0x44 |
| 0x2080d088 | 136 | 0x112dfcc | 0x44 |
| 0x2080d0a3 | 524 | 0x11275d0 | 0x44 |
| 0x2080d0b3 | 812 | 0x162785c | 0x48 |

1. **Each control owns its params struct** (19 distinct tags, 4 B …
   66,060 B) — 0x2080d031's 1544-B struct is its own, not a shared
   interface-wide shape.
2. **The handler cluster**: 18 of 19 handlers sit in
   0x10cb91c..0x1148fec (~510 KB of code — one module); the outlier
   0x2080d0b3 → 0x162785c. Interfaces sharing that code region:
   0x208008 (BIOS), 0x20800b (INTERNAL_2), 0x20802a (CE) — named via
   the FINN comments of the raw tag — plus closed-only 0x208009,
   0x208088, 0x208090, 0x2080c7.
3. **pA is GLOBAL**: all 1,156 entries — not just this family — share
   pA = 0x1c23870. The 4.24 pass I-d "family descriptor" reading is
   corrected: it is the dispatcher's own context, not interface
   metadata.
4. **The whole-image census** (byte-step-1): every family id appears
   exactly ONCE in the 15.3-MB image — its dispatch entry. And the
   code-immediate census (`lui hi=0x2080d` + `addi/addiw`, same rd,
   next insn): **zero sites** — the firmware never materializes the
   family ids as constants. Pure table dispatch, consistent with the
   4.19 wall.
5. **The closed-interface census**: the table holds **61** distinct
   0x2080-namespace interfaces; the raw tag ships 34 with commands
   (38 FINN interface-ID names — the 4.24 §1 "38" reconciled as the
   FINN-name count; max interface 0x2080a7 re-derived exactly);
   **30 interfaces are closed-only** (in the table, in no shipped
   header) — 0x2080d0 among them, and 15 lie beyond the open maximum.
   `rm-strings.txt`: zero "2080d0" occurrences.

## 4. The tag == sizeof(params) law — and the 1544-B sibling census

The open↔closed join (385 named open commands × their dispatch tags)
proves **tag = sizeof(params struct)** on three independent anchors:

- GET_EDPP_LIMIT_INFO (0x20800afd): tag 24 = 6 × u32
  (limitMin/Rated/Max/Curr/BattRated/BattMax — ctrl2080internal.h:3988);
- UPDATE_EDPP_LIMIT (0x20800ad0): tag 8 = 2 × u32 ({bEnable,
  clientLimit});
- FIFO_QUERY_CHANNEL_UNIQUE_ID (0x20801124): tag 1540 = 4 ×
  (128 + 128 + 1 + 128) — the header's own arithmetic
  (NV2080_CTRL_CMD_FIFO_MAX_CHANNELS_PER_TSG = 128).

On that law, the **whole-table 1544-B census**: exactly THREE controls
carry 1544-B params — 0x20809004 and 0x20809030 (interface
**0x208090 — closed-only**, handlers 0x10da03c / 0x10ddc34 *inside the
0x2080d0 family's code region*) and our 0x2080d031. **No open sibling
exists** — the nearest named shapes (1540/1552 B, the FIFO batch-query
arrays) are channel-batch structs, weak analogies for a power struct.
The two closed siblings are the honest 4.26 companions for the hunt.

## 5. The 250000 question, on the closed side actually present

- **GSP-RM**: zero 0x3D090 data dwords in the whole image; **four
  code sites** build it as `lui 0x3d + addi 0x90` — 0x11f09e0 and
  0x1b99cc8 boundary-verified on the 4.16 map, 0x17c46b4 and 0x1b99bec
  unverified. The contexts are arithmetic, not marshaling: a
  bound-check margin (`add a4, a5, a2; bgeu`), a quantization
  (`divuw 250000/x` packed with x), a max-window clamp
  (`max(v, 500000) + 250000`), and a loop-carried value. Reading:
  power-budget-shaped arithmetic — **HYPOTHESIS** on function
  identity; **PROVEN**: none of it touches the 0x2080d031 params (the
  handler ignores them — 4.24 §5 — and request params are host-built).
- **x86 side**: zero real 250000 values anywhere (§2 — all
  instruction artifacts).
- The @64 producer — "table, VBIOS, or constant?" — therefore stays
  **OPEN**: it rides the closed x86 host RM (nvidia.ko), whose VBIOS
  'P'-table parse (4.22 §4) remains the source candidate, unchanged.

## 6. The struct ledger — the five offsets

| poff | captured value | status | the honest reading |
|---|---|---|---|
| — | size = 1544 B | **PROVEN** | tag 0x608 == declared paramsSize (4.24 §4) == sizeof (the §4 law) |
| 0 | 255 (0xFF) | **HYPOTHESIS** | a full-byte shape — mask/all-lanes/percentage-class field |
| 4 | 3 | **HYPOTHESIS** | a small integer — index/type/count-class field |
| 8 | 257 (0x101) | **HYPOTHESIS** | the version-pair shape ((1<<8)\|1) — an embedded sub-block header |
| 56 | 257 (0x101) | **HYPOTHESIS** | the same version shape, 48 B after the first — a second sub-block |
| 64 | 250000 (0x3D090) | **PROVEN carried / HYPOTHESIS semantics** | the EDPp 250-W class in mW (4.24 §1/§5) — +8 into the second sub-block |
| all other | 0 | **PROVEN zeros** | 4.24 §3 (the send-side marshal zero-fills; OUT values ride the response) |

The structured reading — two versioned sub-blocks (@8 and @56, 48 B
apart), the 250-W value at +8 of the second — is **HYPOTHESIS,
explicitly**: the only static namer of these fields is the field-offset
copy graph embedded in the host marshal's machine code, and that code
is in the closed x86 RM which the repo does not hold. No fabricated
names.

## 7. What this changes for the campaign

1. **The 4.24 queue's substrate pointer is corrected** (win.elf ≠ the
   closed x86 RM) — banked the way the citation audit banks its
   corrections; the queue item itself was sound, its pointer was not.
2. The struct naming is **blocked on a missing substrate**, not on
   analysis effort — the honest wall of this pass.
3. Interface 0x2080d0 is a real **19-control module** in one code
   region; 0x2080d031's 1544-B params are its own — and it has exactly
   two same-size siblings, both closed, both in-region.
4. The closed-only interface space is now **enumerated** (30
   interfaces; 15 beyond the open max) — the map for any future
   closed-interface work.
5. The pA sharpening (global dispatcher context) and the coordinate
   reconciliation (win-disasm 0x38 below the map convention) are both
   reusable corrections.

## Queue for 4.26

- **Land the substrate, then rerun the hunt**: commit the unpacked
  nvidia.ko (the 27.7-MB closed x86 blob of 4.22 §3 — it exists on the
  lab machine) under `tools/analysis/host-rm/` with its sha256 +
  provenance in the acquisitions REGISTER (AGENTS.md law 1). Then
  rerun this instrument's section B against it: hunt the immediates
  `B8/BA 31 D0 80 20` (mov r32, 0x2080d031) and 0x608-size constants
  near the control routing — the copy graph at the hit (`mov
  [reg+off]` walks) names the five fields. That is the marshal hunt,
  on the real substrate.
- The response-path dump (the recv hook) — carried from 4.24,
  unchanged: the OUT values are where a GET-type control's filled
  limits would appear.
- The v9 scanner boot verdict — carried, unchanged.
- Optional: walk the two 1544-B siblings' handlers (0x20809004 /
  0x20809030 — same region, same size class) if a reason emerges to
  expect shared shape across the closed 0x208090/0x2080d0 pair.

## Discipline

Every claim above carries its byte, its table row, or its raw-tag URL
(per-file sha256 in the register). The falsification is the headline.
The five field names stay HYPOTHESIS — the instrument that would name
them needs a substrate the repo does not hold; the queue names exactly
how to land it.
