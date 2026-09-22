# 4.30 — the gsp.bin pipeline end to end: the GFW archive mapped to the last byte, the signature hunt decided at the byte level, the 250000→280000 patch landed and proven, the load path documented from the driver source

Substrate: the official 610.57.04 package (sha256 re-verified
`b2e935c6…eb116d` in-instrument), `tools/analysis/gsp-extract/binaries/`
(the campaign artifact set), `tools/gsp-container/gspbuild.py` (extended,
42 PASS / 0 FAIL), the open kernel sources shipped in the same package
(`kernel-open/`), the Zenodo paper 20916112 ("A Canary in the Crypto
Mine", Jon Pry, 2026-06-26, sha256 of the PDF
`16cb3551d5c9620ed698fb3f94a74704f398f5b40f1f37d27d6e4c0e61ef392c`).
Instruments delivered: `lab/jalon411/v430_run_provenance.py` (+`.json`),
`lab/jalon411/v430_gfw_map.py` (+`.json`),
`lab/jalon411/v430_sig_hunt.py` (+`.json`),
`lab/jalon411/v430_patch_run.py` (+`.json`).

## Verdict first

1. **TASK 1 (provenance) — DONE, byte-exact.** The `.run` payload starts
   at byte offset **160,635 (0x2737b)** — `tail -n +1022` starts at LINE
   1022, a 1-based subtlety that the first probe got wrong — and is one
   zstd stream to EOF; the decompressed tar (1,189 members,
   1,808,865,280 B) carries `./firmware/gsp_ga10x.bin` at tar data
   offset **0x400** and `./firmware/gsp_tu10x.bin` at **0x5068000**;
   both re-extracted byte-exact against the makeself reference and the
   4.27 hashes. "Offsets in the .run" beyond 0x2737b do not exist (one
   compressed stream) — the member offsets live in the decompressed-tar
   coordinate, and the register says so.
2. **TASK 2 (the GFW map) — DONE, complete.** The directory grammar is
   decoded (13 records, 30 regions, a linked list with 3-u64 cursors)
   and the map tiles the image with **zero gaps**: boot area
   [0, 0x6d000) = `bootloader.bin` byte-exact, directory [0x6d000,
   0x6e000), the flat components [0x6e000, 0x12d1000), `rm.bindata.bin`
   [0x12d1000, EOF). The 4.24 register's "region heads" were read at the
   WRONG offsets (the un-biased coordinates); the true law is
   **true = directory_field + 0x6d000**, proven on twelve ELF magics and
   five byte-exact component containments.
3. **TASK 3 (the signature hunt) — DONE, at the byte level.** The only
   signature material in the container = twelve per-family
   `.fwsignature_*` sections (0x1000 each; four 0x180-B — RSA-3K-sized —
   high-entropy blocks per blob + tail tables). The GFW directory has
   **no per-component signature or hash field** (flags = the ELF phdr
   p_flags mirror; the NOTE regions are all-zero), and NO sha256/sha1
   digest of any component or unit appears anywhere in the clear. The
   coverage question (which unit each of the four blocks signs) is NOT
   decidable from the package bytes (no public key, no stored digest) —
   the per-component verdict table is §4, and the paper comparison is
   §5.
4. **TASK 4 (the patch) — DONE, with the mission's premise corrected
   twice by the bytes.** The "six u32 sites of 250000" is FALSIFIED: the
   pattern `90 d0 03 00` occurs **zero times** in the whole 84,258,816-B
   image. The REAL encoding: **six `lui+addi/addiw` instruction pairs**
   (the mission's VA list matches `rm-full.elf`, whose code LOAD has
   `p_offset 0x40`; `gsp-rm-17MB.bin` carries the same six sites at a
   uniform −0x78 shift). The patch rewrites both words per site
   (6×8 = 48 B); the bytes that actually DIFFER are the immediate bytes
   only: **18 bytes** (6×3), not the mission's 24. Delivered:
   `gspbuild.py patchrm` + `patch_rm_constant()` + the synthetic and
   real tests (T6/T7, R14–R17); suite 42 PASS / 0 FAIL including the
   mission's (a) the non-patched rebuild byte-exact on all 84,310,168
   bytes and (b) the patched-rebuild minimal-diff proof,
   encoding-derived.
5. **TASK 5 (the load design) — DONE, source-proven where possible.**
   The driver file selection is proven from `kernel-open`:
   GA10X (the GA104 = RTX 3070) loads **`gsp_ga10x.bin`** — the
   mission's `gsp_tu10x.bin` is a TU10X/GA100-family file, corrected —
   at `/lib/firmware/nvidia/<version>/gsp_ga10x.bin` via
   `request_firmware` (`nv.c:27`, `nv-firmware.h`). The verification
   chain = TASK 3's findings; the decision tree (direct path vs the
   bypass) is §7, and it cites the campaign's own hardware-proven
   bypass (STATE.md: the `kernel_gsp.c::_kgspCreateSignatureMemdesc`
   driver patch + the ROP chain, 7+ runs, the SEC2 Falcon spin at
   V=0x4a7 on THIS GA104).

## 1. The container map (TASK 2, the full grammar)

Directory header @0x6d000 (6 u64s):
`{magic 0x81b26a705c10e14d, 0x18, 0x4fee000, 0x30, 0x48, 0xb8}` —
`0x4fee000 == fwimage_size − 0x6d000` (the load-area size, checked) and
`{0x30, 0x48, 0xb8}` = the first record's cursor. Every record:

- name: NUL-terminated, zero-padded to the 8-boundary strictly after the
  NUL (16-char names therefore pad 8 more — the pad is NOT a field);
- REGIONS, each SEVEN u64s:
  `{vaddr, comp_off, align, load_off, size, flags, next_region_ptr}`
  (next_region_ptr absolute in load-area coords, 0 = last region);
- a trailing 3-u64 cursor `{next_record, next_record_first_field,
  next_record_trailing}`; the last record's = {0,0,0}.

**The bias law**: the region `load_off` is a LOAD-AREA coordinate;
true fwimage offset = load_off + 0x6d000. The 4.24 pass read the
un-biased offsets (zeros/stray data — its register's odd entropies
explained). Proven here on: twelve `\x7fELF` magics at the biased
region-1 offsets, five byte-exact containments, and the exact tiling
(no gap, no overlap) of [0x6e000, 0x505b000).

The 13 records (name, true fw off, sizes, flags):

| record | regions | true fw off | sizes | flags |
|---|---|---|---|---|
| kernel_ga10x.elf | 2 | 0x6e000 | 0xd000 + 0x19000 | 5, 6 |
| kernel_gh100.elf | 2 | 0x94000 | 0xd000 + 0x1a000 | 5, 6 |
| kernel_gb10x.elf | 2 | 0xbb000 | 0xd000 + 0x1c000 | 5, 6 |
| kernel_gb10y.elf | 2 | 0xe4000 | 0xd000 + 0x1c000 | 5, 6 |
| kernel_gb20x.elf | 2 | 0x10d000 | 0xe000 + 0x1b000 | 5, 6 |
| kernel_gb20y.elf | 2 | 0x136000 | 0xe000 + 0x1a000 | 5, 6 |
| kernel_gr10x.elf | 2 | 0x15e000 | 0xd000 + 0x1c000 | 5, 6 |
| debug.elf (= pmu-wdt-41KB.bin) | 3 | 0x187000 | 0x8000+0x2000+0x1000 | 5, 6, 0xe |
| init.elf | 3 | 0x192000 | 0x8000+0x4000+0x1000 | 5, 6, 0xe |
| rm.elf (= gsp-rm-17MB.bin) | 3 | 0x19f000 | 0xe9b000+0x1d5000+0x1000 | 5, 6, 0xe |
| vgpu.elf (= comp-725KB.bin) | 3 | 0x1210000 | 0xa2000+0xf000+0x1000 | 5, 6, 0xe |
| mnoc.elf (= comp-58KB.bin) | 3 | 0x12c2000 | 0x5000+0x9000+0x1000 | 5, 6, 0xe |
| rm.bindata.bin | 1 | 0x12d1000 | 0x3d8a000 (to EOF) | 0 |

Byte-exact containments (this pass, all five): `bootloader.bin` ==
fw[0, 0x6d000) (the campaign name stays — the directory does not cover
the boot area); `pmu-wdt-41KB.bin` == **debug.elf** (the campaign's old
name is a misnomer — the directory says debug.elf); `gsp-rm-17MB.bin`
== rm.elf; `comp-725KB.bin` == vgpu.elf; `comp-58KB.bin` == mnoc.elf.

**The flags field decoded**: the region flags mirror the flat
component's ELF program-header `p_flags` EXACTLY (checked per region on
the four components with full phdrs: vaddr, p_offset = comp_off,
filesz/memsz = size, flags equal — `0x5` = R-X code LOAD, `0x6` = R-W
data LOAD, `0xe` = the NOTE regions (p_flags 0x6 + bit3), `0x0` = the
raw bindata blob). **No compression bit, no signature bit** — and the
storage is flat (the five containments re-prove it). The mission's
"rm.elf = one LOAD RWX" is falsified at the phdr level: p_flags 5 =
R-X.

## 2. The acquisition (TASK 1)

| field | value |
|---|---|
| `.run` | 463,025,450 B, sha256 `b2e935c6…eb116d` (re-verified streaming) |
| packaging | makeself 1.6.0-nv9, `skip=1022`; extraction line verbatim: `tail -n +$skip $0 \| zstd -d \| UnTAR` |
| payload | ONE zstd stream, byte offset **0x2737b** to EOF (magic byte-checked) |
| decompressed | POSIX tar, 1,808,865,280 B, 1,189 members walked |
| gsp_ga10x.bin | 84,310,168 B @ tar data 0x400, sha256 `c0156954…02999` (byte-exact vs the reference extraction) |
| gsp_tu10x.bin | 29,381,504 B @ tar data 0x5068000, sha256 `d157e3b7…d1a7` (idem) |

Landed in `tools/analysis/x86-rm/PROVENANCE.md` (the campaign's
provenance file), register `v430_run_provenance.json`.

## 3. The signature inventory (TASK 3, the bytes)

- The twelve `.fwsignature_*` sections (4.27's census, now anatomized):
  header {ver 0x00020001, 0x8c8, 0xc, 0x101, 0x200}, then FOUR
  0x180-byte high-entropy blocks at 0x200 stride (entropy 7.42–7.47 —
  signature-shaped, RSA-3K-sized), then two small u32 tables
  ({1,1,1,1} @0x810; {0,0,0,1,0x204,1} @0x870). All twelve blobs share
  the structure and differ from `ga10x` by ~1,527–1,537 bytes (the four
  blocks are per-family DIFFERENT; the framing bytes are shared).
- The GFW directory: no signature/hash field anywhere (the flags =
  p_flags); the per-component NOTE regions (0x1000 each) are ALL-ZERO
  (no hashes there either).
- The decisive experiment: sha256 AND sha1 of every plausible covered
  unit — the whole fwimage, the load area, the boot area, the bindata,
  each of the six flat components, bootloader.bin — searched in the
  ga10x blob, the union of all twelve blobs, the boot area, the bindata
  and the whole container: **zero hits**. In a standard RSA scheme the
  signed digest is recomputed at verify time and never stored, so this
  is the EXPECTED shape — it means the package alone cannot tell which
  unit is covered; the coverage decision needs the verifier (the boot
  ROM / the SEC2 booter) or NVIDIA's public key.

## 4. The per-component verdict (the honest table)

| component | signature material in the package? | verdict |
|---|---|---|
| boot area (bootloader.bin) | none in the load area; the paper (§2.2/§5.4): the SEC2 boot ROM RSA-3K-checks the booter code image | covered by the boot-chain verification — WHICH of the four blobs' blocks is not byte-decidable |
| rm.elf (the RISC-V GSP kernel) | none: no directory field, zero NOTE content, no digest anywhere | coverage by one of the four 0x180-B blocks = HYPOTHÈSE; the campaign's wall table says "SEC2 Boot ROM, fused keys: patch = rejected at load" (the stock path treats it as covered) |
| vgpu/init/mnoc/debug/kernel_* | idem | idem (same HYPOTHÈSE status) |
| rm.bindata.bin (the HS falcon images) | the images are ENCRYPTED (4.24); their LS signatures live inside the encrypted space / WPR metadata | not inspectable in the clear; the paper §5.5: the LS verification consumes a WPR-metadata signature blob |
| the container itself | twelve per-family blobs, 4 × RSA-3K-sized blocks each | the ONLY signature material in the package |

The mission's question — "does booterVerifyLsSignatures_TU10X cover the
rm.elf itself or only the Falcon blobs?" — is answered honestly: **the
paper does not carry that symbol name** (full-text searched; its
references are envytools and the open kernel modules), and its text
says: the boot ROM RSA-3K covers the booter (§5.4), the booter's
LS-verification covers the falcon app images via WPR metadata (§5.5),
and the resource-manager blob is a separate image (§5.5's second
canary). The RISC-V rm.elf is not a Falcon LS image; whether one of the
four `.fwsignature` blocks covers it (directly or via a hash chain)
cannot be decided from the package bytes — this lane stays
**UNDECIDABLE-BY-BYTES** with the experiment that would decide it (§7).

## 5. The paper, precisely cited

"A Canary in the Crypto Mine: Defeating Stack Protection in a GPU
Secure Coprocessor", Jon Pry, Zenodo 20916112 (2026-06-26). Facts used:
the HS entry = the immutable boot ROM verifying an RSA-3K signature
over the code image (§2.2); the vendor's own signed booter passes that
check and the exploit lives INSIDE the signed code (§5.4); the LS
signature-verification routine DMA-copies an adversary-controlled
signature blob into a fixed buffer with an unbounded length taken from
WPR metadata (§5.5) — the overflow that defeats the stack canary and
gives HS program-counter control; the exhibit = the SEC2 booter of a
CMP 170HX (GA100 die). The campaign's own hardware work (STATE.md)
fired the SAME bug class on THIS GA104 via the host driver patch
(`kernel_gsp.c::_kgspCreateSignatureMemdesc`, the 0xF800 signature
memdesc → the unbounded DMA), 7+ runs, the SEC2 Falcon spins at
V=0x4a7 — so the bypass technique is PROVEN on this card, in its
driver-patch variant.

## 6. The patch (TASK 4)

The premise corrections (all byte-proven, in order):

1. **The six sites are real — but they are not u32 words.** The pattern
   `90 d0 03 00` occurs ZERO times in gsp-rm-17MB.bin, rm-full.elf AND
   the whole 84,258,816-B fwimage. The real encoding: six
   `lui+addi/addiw` pairs materializing 250000 = 0x3D090 as
   imm hi=0x3d / lo=0x090 (the canonical RV64 `li` decomposition; an
   exhaustive 2-byte-step scan — two of the six sites sit at 2 mod 4,
   illegal for a 4-step scan — finds EXACTLY six in both builds).
2. **The mission's VAs belong to rm-full.elf**, whose code LOAD has
   `p_offset 0x40` (VA = file − 0x40 + 0x1000000): all six match
   exactly. In gsp-rm-17MB.bin (p_offset 0) the same six sites sit at a
   uniform −0x78 shift: rm-relative offsets
   `{0x190c6, 0x1a02a, 0x1f09a8, 0x7c467c, 0xb99bb4, 0xb99c90}`
   (rd = 15, 12, 12, 15, 15, 18; the 0x7c467c site uses `addiw`).
3. **The diff arithmetic.** The patch rewrites both words per site
   (6×8 = 48 B); the bytes that actually differ are only the immediate
   bytes — two in `lui` (the 0x3d→0x44 hi byte and one rd-adjacent
   byte) and one in `addi` (0x09→0x5c) — i.e. **18 bytes differ**. The
   mission's "identical except exactly 24 bytes (6×4)" rested on the
   falsified u32 premise; the corrected, encoding-derived numbers are
   frozen in the tests.

The delivered mode (`tools/gsp-container/gspbuild.py`):

- `riscv_split(value)` — the canonical signed-12-bit lui+addi split;
- `riscv_lui_addi_sites(blob, value)` — the exhaustive census (rd != 0,
  funct3=ADD, rd==rs1, both opcodes, 2-byte steps);
- `patch_rm_constant(fw, rm_off, rm_size, old, new, expected_sites)` —
  per-site re-decode + verify before write, rd/opcode preserved,
  same-size rebuild, wrong-site-count and non-ELF-window rejections;
- CLI: `gspbuild.py patchrm <container> <rm_off> <rm_size> <old> <new>
  <out> [sites=N]`.

The tests (`tests_gspbuild.py`, 42 PASS / 0 FAIL): T6/T7 synthetic
(decoys rejected: wrong lo, rd2 != rd, lui x0; the unaligned site
found; the diff set == encoding-derived); the real lane: **R3 the
non-patched rebuild == the original on all 84,310,168 bytes** (the
mission's (a)); **R14 the census == 6 sites at the exact offsets**;
**R15 the patched container differs on EXACTLY 18 bytes, all inside
the 6×8 rewritten windows, every window fully re-encoded** (the
mission's (b), corrected); R16 re-parse VALID + fwversion unchanged +
all pairs decode 280000; R17 the negatives rejected.

The real run (`v430_patch_run.json`): the patched container
`gsp_ga10x_280000_610.57.04.bin` produced OUTSIDE the repo (>5 MB
rule), sha256 `6a3c1a060e9c280965aebd77eb48c2161cf99aa40fd5d99c77c40a3a
85c9859d`, re-parse VALID, the fwimage identical before 0x19f000 and
after the rm window. Reproduce:

```bash
python3 tools/gsp-container/gspbuild.py patchrm \
  <gsp_ga10x.bin> 0x19f000 0x1071000 250000 280000 <out.bin>
```

The semantic caveat (the ledger): this pass proves the BYTES (six
`li`-materializations of 250000, rewritten to 280000, nothing else
touched). The SEMANTIC — that these six are the EDPp/power policy
constant the mission calls "250 W → 280 W" — is NOT proven by this
pass: the 4.28 pass re-attributed the CAPTURED 250000 (in the NVML
userspace lane) to a clock-VF value, and the RM sites' own neighborhood
shows 500000/279024/1000000/4000000 nearby (clock- or power-scale
values are both consistent). The confirmation path: boot the patched
container and observe (§7), or the 4.26 recv capture.

## 7. The load design (TASK 5)

**The file selection — source-proven** (`kernel-open/`, shipped in the
same package):

- `common/inc/nv-firmware.h`: `NV_FIRMWARE_CHIP_FAMILY_GA10X` →
  `"gsp_ga10x"`; TU10X/TU11X/GA100 → `"gsp_tu10x"`. **The RTX 3070
  (GA104) is GA10X → the driver loads `gsp_ga10x.bin`** — the
  mission's `gsp_tu10x.bin` corrected (it is the Turing/A100-family
  file).
- `nvidia/nv.c:27`:
  `#define NV_FIRMWARE_FOR_NAME(name) "nvidia/" NV_VERSION_STRING "/" name ".bin"`
  → the runtime path **`/lib/firmware/nvidia/610.57.04/gsp_ga10x.bin`**.
- `nvidia/nv.c:4114` `nv_get_firmware()`: plain
  `request_firmware()` — the open shim does NO verification of the file
  itself (the libspdm crypto in the tree is the device-attestation
  lane, not the firmware-load lane).
- The open-modules build requires GSP-RM (no non-GSP path); the closed
  build gates it with `NVreg_EnableGpuFirmware` /
  `rm_firmware_active` (deprecated alias).

**The load procedure (the patched container):**

1. Back up the stock file and its hash:
   `cp /lib/firmware/nvidia/610.57.04/gsp_ga10x.bin{,.stock}` +
   `sha256sum` both (the stock hash = `c0156954…02999`).
2. Install the patched container (sha256
   `6a3c1a06…859d`) at the canonical path.
3. Reload the driver (or reboot): the shim requests the file, hands it
   to the closed core, which parses the container BY NAME (`.fwimage`,
   `.fwversion`, `.fwsignature_<family>` — the 4.27 string census) and
   drives the GPU boot chain.
4. **The rollback is mandatory and trivial**: restore the stock file
   (+ hash check). A rejected/failed GSP load on these chips means no
   working driver until restored — the procedure never leaves the
   machine in that state.

**The verification chain (what TASK 3 established):**

- The stock chain treats the container as covered: the per-family
  `.fwsignature_ga10x` blob travels WITH `.fwimage`, and the campaign's
  wall table (proven in earlier hardware work) reads "SEC2 Boot ROM,
  fused keys: patch = rejected at load". The coverage detail is
  UNDECIDABLE-BY-BYTES (§4), so the DIRECT path's success cannot be
  promised — but it is CHEAP to decide empirically (steps 1–4 above,
  one boot, dmesg read) and it is the FIRST experiment: if the
  verifier hashes only a unit the patch does not touch (e.g. the boot
  area), the patched container boots with NO bypass at all.
- If the direct path is rejected (the expected outcome per the wall
  table), the bypass = the campaign's PROVEN-on-this-card route: the
  host driver patch (`kernel_gsp.c::_kgspCreateSignatureMemdesc`, the
  0xF800 signature memdesc → the unbounded DMA — the same bug class the
  paper documents inside the signed booter) → the ROP chain → HS PC
  control (the SEC2 Falcon spin at V=0x4a7, 7+ hardware runs). That
  route bypasses the load-time wall from the DRIVER side; with HS
  execution the verification of the swapped gsp.bin and/or the runtime
  EDPp policy object become the next writable targets — the campaign's
  documented next lane. The pure-gsp.bin route (a patched container
  that carries its own valid signatures) stays OUT OF SCOPE: no public
  key, no signer — the campaign's lane is driver-side.

**The decision tree:**

```
patched gsp_ga10x.bin installed
  ├─ stock boot accepts it  → DONE (no bypass; the coverage question
  │                            resolved empirically: the rm.elf was NOT
  │                            in the signed set)
  └─ rejected at load
       → restore the stock file (mandatory rollback)
       → the driver-patch bypass (proven on this GA104: the
         _kgspCreateSignatureMemdesc route, STATE.md)
       → with HS PC control: re-load the patched container / rewrite
         the EDPp policy (the next lane)
```

## 8. The honest ledger

1. **The coverage question stays open at the byte level.** Four
   RSA-3K-sized blocks per family, no stored digest, no public key:
   which unit each block covers is not decidable from the package. The
   report treats the stock chain as COVERED (the wall table + the boot
   chain) and arms the one-boot experiment that would settle it.
2. **The patch's semantic is NOT claimed.** Six constant sites exist
   and are rewritten byte-precisely; that they are the power-limit
   policy is HYPOTHÈSE (the 4.28 clock-VF correction in the userspace
   lane cautions exactly this conflation). The live boot decides.
3. **The mission's two premises corrected by the bytes** (the u32
   encoding, the 24-byte diff) and one coordinate correction (the VAs =
   rm-full.elf). All documented with the full evidence chain in §6.
4. The boot area's internal structure (bootloader.bin, 446,464 B of
   raw RISC-V code — `auipc/addi` prologue, no ELF header, no
   signature-shaped 0x180-B window) was mapped as a unit but not
   reversed; its own directory (if any) is a next-lane item.
5. The paper comparison is textual (the PDF fetched from Zenodo,
   hash-pinned); the symbol `booterVerifyLsSignatures_TU10X` does not
   appear in its text — cited here so the mission's attribution is not
   silently inherited.

## 9. The queue

1. The one-boot experiment: the patched container + the stock driver
   (the direct-path decision; the rollback ready). Whatever the dmesg
   says, the coverage question converts from HYPOTHÈSE to observed.
2. If rejected: the driver-patch route (the proven chain) with the
   patched container as the target payload — the campaign's next lane.
3. The boot area reversal (the bootloader.bin internal directory, the
   boot ROM's expected image format).
4. The bindata LS-descriptor hunt (inside the encrypted space — needs
   the HS route first).
