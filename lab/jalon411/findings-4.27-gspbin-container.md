# 4.27 — the gsp_ga10x.bin container: the official artifact acquired, the fwimage.bin provenance PROVEN, the compression question CLOSED, the byte-exact rebuildeur delivered

Substrate: the official NVIDIA driver package 610.57.04, the campaign's
`tools/analysis/gsp-extract/` artifact set, `findings-4.24-gsp-lz.md`
(whose §4 queue this pass executes). Instruments:
`lab/jalon411/v427_gspbin_container.py`, `lab/jalon411/v427_gsp_sections.py`
(+ `.json`), `tools/gsp-container/gspbuild.py` (+ `tests_gspbuild.py`).

## Verdict first

1. The campaign's `binaries/fwimage.bin` **IS the `.fwimage` section of the
   official 610.57.04 `gsp_ga10x.bin`** — full byte-exact containment at
   gsp offset 0x40 and sha256 equality (`85213b87db131c17…`). The
   provenance question is CLOSED. Coordinate law: **gsp_off = fw_off + 0x40**.
2. The container is an **ELF64 wrapper (EM_RISCV, no program headers) with
   19 sections**: one `.fwimage`, `.fwversion` (`610.57.04\0`), a GNU
   build-id note, **twelve `.fwsignature_*` blobs (0x1000 each)**, and the
   symtab/strtab pair whose symbol names encode the NVIDIA build path.
3. **There is NO compressed stream in the load path** — zero LZ4-frame and
   zero zstd-frame magics in both images; the only `1f 8b 08` patterns are
   data artifacts that inflate to 512 KiB of zeros each. The 4.24 §4
   queue item ("locate ONE genuine NVIDIA-compressed component stream")
   resolves to **UNTESTABLE-BY-ABSENCE**: the byte-exact re-encode claim
   cannot even be formulated here. `tools/gsp-lz/lz4block.py` remains the
   ready decode path if a stream ever surfaces.
4. The **byte-exact container rebuildeur is delivered and proven**:
   `rebuild(no-patch) == original` on all 84,310,168 bytes (test R3), and
   a same-size patch provably changes EXACTLY its byte range and nothing
   else (tests T3/R10). Suite: **26 PASS / 0 FAIL** (13 synthetic + 13 real).

## 1. The acquisition (the provenance chain, now complete)

| Item | Value |
|---|---|
| URL | `https://us.download.nvidia.com/XFree86/Linux-x86_64/610.57.04/NVIDIA-Linux-x86_64-610.57.04.run` |
| Size | 463,025,450 B (== the server content-length, byte-checked) |
| sha256 | `b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d` |
| Extraction | makeself `-x --target` (archive integrity OK) |
| GSP firmware | `firmware/gsp_ga10x.bin` 84,310,168 B — sha256 `c0156954f3e048d56011524e0c2ae2881bb6db8173b53f9b2f4eb94197f02999` |
| (sibling, out of scope) | `firmware/gsp_tu10x.bin` 29,381,504 B — sha256 `d157e3b7dd5da2ca8d1ccb6ca98958f9e35d10a9ef7326277ebac133e4b0d1a7` |

The GA104 campaign card consumes `gsp_ga10x.bin`. Inside it:

- `.fwversion` = `610.57.04\0` — the exact mission tag.
- `.note.gnu.build-id` = `GNU\0` + `4f09703c5c7d57baa527d6a189bb6d118bc60e49`.
- `.strtab` symbol names encode the build:
  `_binary__dvs_p4_build_sw_rel_gpu_drv_r610_r610_85_drivers_resman_build_gsp__out_Linux_amd64_release_LibOS_riscv64_release_firmware_ga10x_firmware_bin_{start,end,size}`
  → the Perforce build **r610_85**, LibOS riscv64 release, ga10x.

## 2. The container anatomy (PROVEN, byte-derived)

ELF64: `e_type=1, e_machine=0xf3 (RISC-V), e_entry=0, e_phnum=0`,
19 section headers, `e_shoff=0x050673d8` — the table is the **LAST 1216
bytes of the file** (`e_shoff + 19*64 == file size`, byte-checked).

| # | Name | Offset | Size | Content |
|---|---|---|---|---|
| 1 | `.fwimage` | 0x40 | 0x0505b000 | the GFW archive == campaign `fwimage.bin` |
| 2 | `.note.gnu.build-id` | 0x0505b040 | 0x24 | `4f09703c…` |
| 3 | `.fwversion` | 0x0505b064 | 0xa | `610.57.04\0` |
| 4–15 | `.fwsignature_{cc_gr10x, gr10x, gb20y, cc_gb20x, gb20x, cc_gb10x, gb10y, gb10x, cc_gh100, gh100, ad10x, ga10x}` | 0x0505b06e… | 0x1000 each | the per-silicon SEC2 signature blobs |
| 16–18 | `.symtab` (3 syms), `.strtab`, `.shstrtab` | 0x05067070… | — | the `_binary_…` build-path symbols |

Coverage of the data region: exact except two alignment slivers
(+2 B @0x0506706e, +4 B @0x050673d4) — copied verbatim by the rebuilder.
`.fwsignature_ga10x` head: `01 00 02 00 c8 08 00 00 0c 00 00 00 01 01 00 00
00 02 00 00` then payload (1542/4096 bytes non-zero) — a structured blob,
not randomized padding.

**The consumer side**: the closed RM kernel blob (`kernel/nvidia/nv-kernel.o_binary`
in the package) contains the literal strings `.fwimage` and `.fwversion`
(1 hit each), and the prefixes `fwsignature_`, `fwsignature_cc_`,
`fwsignature_spdm_lite_` — the loader parses sections BY NAME and
**assembles the signature section name at runtime** (prefix + silicon
family). Honest framing: this is a byte/string census of the closed blob
(names present — PROVEN); the prefix+family construction is the
parsimonious reading of why only prefixes appear (labeled reading, not
decompiled control flow).

## 3. The compression question is CLOSED (the 4.24 §4 queue, executed)

- LZ4-frame magic (`04 22 4d 18`): **0 hits** in gsp_ga10x.bin, 0 in fwimage.bin.
- zstd-frame magic (`28 b5 2f fd`): 0 hits in both.
- The 12 `1f 8b 08` patterns (gsp 0xe087f0…0xe0c408; the same +0x40-shifted
  set in fwimage): each, read as a gzip header + raw DEFLATE, inflates to
  **exactly 524,288 bytes of zeros** — stored-block data artifacts inside
  the RM image's data territory, not container compression, not on the
  load path.
- The 13th ELF magic candidate @0x1cefb3e: `7f 45 4c 46 0d …` — class
  byte 0x0d is invalid; a data coincidence.

**Verdict**: for 610.57.04/ga10x the firmware load path is UNCOMPRESSED
end to end — the GFW archive stores every component FLAT inside
`.fwimage` (agreeing with findings-4.24-gsp-lz.md §1b, now proven on the
OFFICIAL artifact rather than the campaign's copy alone). "Our compressor
matches NVIDIA's exact encoding choices" is not false — it is
**formulable nowhere**: there is no NVIDIA-produced stream to diff
against. The honest closure of the LZ lane; the codec stays banked.

## 4. The rebuildeur (the deliverable the campaign lacked)

`tools/gsp-container/gspbuild.py` — dependency-free reader/verifier/
extractor/patcher/rebuilder. Every guarantee is a test
(`tests_gspbuild.py`, **26 PASS / 0 FAIL**):

- **R3** `rebuild(no-patch) == original`, all 84,310,168 bytes — the
  from-parts round-trip is BYTE-EXACT on the official artifact.
- **R6** extracted `.fwimage` == campaign `fwimage.bin` (sha256 equality).
- **T3/R10** a same-size patch differs from the source on **exactly the
  patched range** (contiguity machine-checked), nothing else.
- **R11** the patched container re-parses structurally valid.
- **T4** no-op patches, out-of-range patches, and size-changing section
  overrides are all REJECTED (the size-changing lane raises by design).
- **T5** tamper detection: a corrupted `.fwversion` and an overlapping
  section size are both caught by `verify()`.

Demo (recorded, artifact NOT committed): 8-byte tag `GSP42701` at
fwimage+0x126000 (an all-zero window inside the init.elf load region —
inert, never flashed, never loaded) → container sha256
`84851ba7abf43f3ad307ee8033090c65e227e4bad2fc7a796c8f417539aa2a87`,
diff vs source = 8 bytes @0x126040–0x126047, re-parse VALID.

## 5. The honest ledger

1. **The signature sections are copied verbatim.** A patched `.fwimage`
   predictably fails the SEC2 signature check on stock load paths — the
   wall documented in STATE.md stands; building signatures is OUT OF
   SCOPE (the campaign's lane is driver-side). gspbuild is the
   byte-precise packaging half, and only that.
2. **Same-size patches only.** A size-changing rebuild would re-layout
   the section offsets after the modified section and re-emit `e_shoff`
   — designed, NOT exercised.
3. `gsp_tu10x.bin` unexamined (the campaign card is GA104 — out of scope).
4. The two alignment slivers carry no structural meaning; the rebuilder
   copies them from the source (the honest from-parts policy).
5. The loader-side evidence is a string census of a closed blob, not
   decompiled logic — see §2's framing.
6. Two test-suite bugs were caught and fixed during the pass (a bytearray
   slice-assignment resize that silently shrank the fixture; a strtab
   off-by-one for the empty name) — recorded here because the fixture
   builder is part of the proof chain.

## 6. What this means for the EDPp lane

Any future same-size GSP-RM patch — the u32-class edit that pass 4.25's
recv-hook hunt may eventually name — has, from today, a byte-precise
packaging tool whose minimal-diff property is machine-checkable. The
remaining wall is unchanged and now precisely localized: twelve
per-family signature blobs, the `ga10x` one at gsp 0x0506606e, consumed
by a loader that constructs its name at runtime. The LZ4 codec
(`tools/gsp-lz/`) stays banked for any future compressed-stream lane.
