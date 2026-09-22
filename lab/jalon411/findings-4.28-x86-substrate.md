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

1. Disassemble and attribute the 35 × `0x608` sites and the 14 × `0x186a0`
   sites (capstone, symbol-guided), classify each site (size-of / compare /
   table stride), and walk the neighbors for the params copy pattern.
2. Userspace substrate: same needles over `libnvidia-ml.so.610.57.04` and
   `libnvidia-eglcore.so.610.57.04` (same package, same provenance law).
3. The copy-graph naming attempt on whatever sites survive — the five fields
   get PROVEN/FALSIFIÉ verdicts there or nowhere.
4. Only after that: reconcile the verdicts into the 4.24/4.25 ledger and
   re-score the §7.2 prediction dependencies.
