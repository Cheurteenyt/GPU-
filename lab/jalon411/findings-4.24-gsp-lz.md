# 4.24 — pass III: the GSP-component LZ compressor — the envytools citation FALSIFIED, the flat-storage premise FALSIFIED, a verified LZ4 codec delivered

Substrate: the envytools tree (master + remote branches + wiki), the
campaign artifact set (`tools/analysis/gsp-extract/`), the open kernel
modules 610.57.04 (the bindata machinery). Instruments:
`lab/jalon411/v424_gfw_directory.py` (+ `.json`),
`tools/gsp-lz/lz4block.py`, `tools/gsp-lz/tests_gsplz.py`.

## 1. The pass brief's premise, tested honestly — both parts falsified

The brief: *"the rm.elf component of the gsp.bin firmware uses an LZ
format partially documented by envytools (the lz*.rst files) —
investigate the exact format and implement a compatible compressor."*

**1a. The envytools lz\*.rst files DO NOT EXIST.**

- Full clone of `envytools/envytools` (master, f102b82): 267 `.rst`
  files enumerated — none named `lz*` (the full basename census run).
- Content grep across the whole tree for `lz4`, "LZ compression",
  "LZ-compressed", "compressed ucode": ZERO hits. The only "compress"
  hits in docs = the G80 VRAM color-compression pages.
- All 5 remote branches (`ed2`, `more_tables`, `revert-201-fcommon-fix`,
  `wwa-gm107-wip`, master) checked — no LZ docs added anywhere.
- The repo has NO wiki (`envytools.wiki.git` = 404), and the
  readthedocs mirror carries the same falcon pages as the tree
  (arith/branch/crypt/data/.../xfer — no LZ page).
- GitHub code search (`filename:lz.rst envytools`): 0 results.

The likely confusion: envytools documents the falcon ISA and the G80
VRAM compression, but NEVER a firmware ucode LZ format. The format the
campaign's own `lz-probe.py` already assumed for the bindata streams —
**the LZ4 raw block format** — is documented elsewhere (the LZ4 Block
Format spec + the reference `lz4` implementation).

**1b. The rm.elf is NOT compressed in this campaign's artifact set.**

`v424_gfw_directory.py` decodes the `.fwimage` component table (the
GFW directory @~0x6d500-0x6d780) and tests every region:

| component | region-1 (vaddr 0x1000000, flag 5) | region-2 (vaddr 0x4000000, flag 6) |
|---|---|---|
| init.elf | fwimage @0x125000, 0x8000 | @0x12d000, 0x4000 |
| rm.elf | @0x132000, **0xe9b000** | @0xfcd000, 0x1d5000 |
| vgpu.elf | @0x11a3000, 0xa2000 | @0x1245000, 0xf000 |

The rm.elf region-1 size **0xe9b000 = EXACTLY the flat RM image**
`rm-full.elf`'s single LOAD (vaddr 0x1000000, filesz==memsz — the 4.20
fingerprint). And the containment test:

- `gsp-rm-17MB.bin` (the full 17,236,632 B dev ELF, 4 phdrs, entry
  0x1a9e1c0) is present in fwimage **byte-exact @0x19f000**;
- `comp-725KB.bin` (the 725,616 B RISC-V ELF, 4 phdrs, entry 0x75604)
  is present **byte-exact @0x1210000**.

Both ELF files sit FLAT in the image. No LZ4/deflate signature, no
entropy anomaly in the rm.elf regions (code entropy ~5.8, the bindata
region carries plaintext strings "IMEOUT", "NV_UCODE..."). The 4.23
queue's reading "the rm.elf compressed 725 KB→17.7 MB inside the GFW
archive" is FALSIFIED for this artifact set: the 725 KB file is a
component ELF stored flat (it is NOT a compressed stream — it starts
with `\x7fELF`), and the "→17.7 MB" was the load-expansion of the
image, not decompression.

The region-2 blobs (vaddr 0x4000000) = the bindata/signature space; the
booter HS images (the `g_bindata_kgspGetBinArchiveBooterLoadUcode_*`
arrays in the open driver) are high-entropy because they are
**ENCRYPTED** (the HS crypt), not compressed — indistinguishable from
ciphertext, unusable as compression ground truth.

## 2. What was delivered instead — the verified codec

The task's verifiable core survives: implement the LZ codec the
campaign actually needs, to the brief's byte-exactness standard.
`tools/gsp-lz/lz4block.py` = a dependency-free LZ4 raw-block
compressor + decompressor (the exact format `lz-probe.py` assumed; the
right container for the firmware-loader shape, where the component size
comes from the directory and no frame header exists):

- `compress(data)` — greedy hash-table matcher, the exact sequence
  grammar of the block spec (token / literal-ext / literals / 16-bit
  offset / match-ext, the last-5-bytes-literal end rule, overlap copies
  for offset<length).
- `decompress(block, uncompressed_size)` — the documented algorithm,
  hardened end conditions.

`tools/gsp-lz/tests_gsplz.py` — the verification suite, ALL PASS:

- **T1 round-trip**: ours→ours byte-exact on every case.
- **T2 reference-decodes-ours**: our streams decoded by the REFERENCE
  `lz4.block` codec — byte-exact. (This is the compatibility property
  the gsp.bin path would need: a stream WE produce satisfies the
  standard decoder.)
- **T3 ours-decodes-reference**: reference streams decoded by our
  decoder — byte-exact.
- **T4 adversarial**: empty / 1-3 bytes / min-match runs / RLE
  offset 1-2-3 / all-byte-values ramp / 1 MiB incompressible /
  literal- and match-length 15/255/270 boundary runs.
- **T5 the campaign artifact**: a 1 MiB slice of the rm image code
  (0x267fc, the 4.24 pass I handler neighborhood) compresses
  1,048,576 → 637,700 B and round-trips byte-exact BOTH directions;
  the 4 MiB zero-heavy image head 1,048,576-scale round-trip too.

## 3. What is still missing (the honest ledger)

1. **No NVIDIA-produced LZ4 stream exists in the campaign artifacts**,
   so "our compressor matches NVIDIA's exact encoding choices" is NOT
   proven — it CANNOT be, without a reference stream. What is proven:
   our streams are valid LZ4 blocks per the spec, and both directions
   of decoding match the reference implementation byte-exactly.
2. If a compressed stream ever surfaces (e.g., the driver-package
   `gsp.bin` variant, or a future component), the decode path is ready:
   `lz4block.decompress(stream, size_from_directory)` — the test suite
   is the acceptance harness.
3. The envytools citation should be corrected in the campaign notes:
   the LZ documentation lives in the LZ4 spec, not envytools.

## 4. Queue

- If the gsp.bin fallback lane ever reopens: locate ONE genuine
  NVIDIA-compressed component stream, decode it with T2-verified
  tooling, then re-encode and diff against NVIDIA's encoding choices
  (the compressor's parser choices are ours; a byte-identical
  re-encode is a separate, stronger claim).
- The `g_bindata_*` HS images stay out of scope: encrypted ≠ compressed.
