# 4.29 — the LZ lane on the REAL components: the pair premise FALSIFIED at phdr level, the codec needs no fix, the real-bytes round-trip made permanent, the send↔recv analyzer delivered

Substrate: `tools/analysis/gsp-extract/binaries/` (the six component
binaries), `tools/gsp-lz/lz4block.py` + `tests_gsplz.py` (the codec —
UNCHANGED byte-for-byte this pass), `tools/edpp/` (the capture hooks +
the real 4.23 send corpus). Instruments delivered:
`lab/jalon411/v429_lz_pair_forensics.py` (+`.json`),
`lab/jalon411/v429_lz_conventions.py` (+`.json`),
`lab/jalon411/v429_lz_package_hunt.py` (+`.json`),
`tools/edpp/recv76_analyze.py`.

## 1. The brief's premise, tested on the bytes — FALSIFIED (harder than 4.24)

The brief: *"comp-725KB.bin (725,616 B) = the RM component COMPRESSED as
embedded in gsp.bin; gsp-rm-17MB.bin (17,236,632 B) = the decompressed
RM."* The fresh byte verdict (no appeal to the 4.24 conclusions):

- **Identity: BOTH are plaintext ELF64 RISC-V EXEC files** (`\x7fELF`,
  machine 243): comp entry `0x1075604`, rm entry `0x1a9e1c0`. A
  compressed stream does not carry an ELF identification.
- **The phdr identity (the new, sharper fact):** comp's two PT_LOADs
  (`0x1000000`/663,552 B + `0x4000000`/61,440 B) are the GFW
  directory's **vgpu.elf** row EXACTLY (0xa2000/0xf000, the 4.24
  pass III-a table); rm's two PT_LOADs (0xe9b000 + 0x1d5000) are the
  **rm.elf** row EXACTLY. The pair is (vgpu.elf, rm.elf) — two
  DIFFERENT components of the image, not two states of one stream.
- **Containment:** both files sit byte-exact inside `fwimage.bin` at
  `0x1210000` and `0x19f000` (disjoint windows) — flat storage,
  re-proven live on this branch.
- **The decode attempts (the brief's step 1):** `lz4block.decompress`
  raises `ValueError("zero offset")` in BOTH directions (725,616→17 MB
  and 17 MB→725,616); the REFERENCE decoder raises
  `LZ4BlockError: … Error code: 18`. No codec correction can apply —
  the failure is the premise's, not the codec's.
- **The ratio sanity:** LZ4-block on the real rm.elf compresses to
  9,910,094 B (ours) / 10,034,004 B (reference default) / 8,812,653 B
  (HC9) — 51–58 % of 17.2 MB. A 725,616-B stream (4.2 %) is out of
  reach of ANY LZ4-block encoder on this data. The premise was never
  physically possible.

Register: `v429_lz_pair_forensics.json` (selftest re-derives every
anchor, exit 2 on drift). One instrument bug banked: the phdr parse
initially read the table as a read-continuation from offset 0 instead
of seeking `e_phoff` (p_type came back as the `\x7fELF` magic) — caught
on review BEFORE the freeze, named in a comment, corrected, re-frozen.

## 2. The verbatim comparison, executed

`ours.compress(rm.elf)` = 9,910,094 B in 7.42 s (sha256 `ecca1f2e…`);
`comp-725KB.bin` = 725,616 B (sha256 `5c072ef3…`). `byte_exact = false`
— and §1 shows it CANNOT be true. The brief's
"iterate until byte-exact" leg closes here; the
"document every remaining gap" leg is §3 + §4.

## 3. The convention study the bytes DO support — ours vs the reference

With NVIDIA's encoder absent (§4), the observable convention space is
ours vs the reference implementation. Both streams of the real
17,236,632-B rm.elf were tokenized per the block grammar and validated
by reconstruction (literals+matches == 17,236,632 for all three):

| encoder | stream B | sequences | literal B | match B | offsets >4096 |
|---|---|---|---|---|---|
| ours (hash table 2^16) | 9,910,094 | 1,114,363 | 6,410,487 | 10,826,140 | 350,761 |
| reference default | 10,034,004 | 727,301 | 7,666,216 | 9,570,411 | 87,819 |
| reference HC level 9 | 8,812,653 | 1,038,397 | 5,541,408 | 11,695,219 | 371,644 |

- **Ours BEATS the reference default by 123,910 B**: the bigger match
  table keeps more history — more match coverage (10.83 MB vs 9.57 MB)
  and far more distant matches (350,761 offsets >4096 vs 87,819), paid
  for in more, smaller sequences.
- The **first divergence is at sequence 1** (sequence 0 identical):
  the literal-run boundaries differ first. The encoders share the
  grammar; they differ in the choice function.
- NVIDIA's compressor conventions: **ABSENT-BY-BYTES**. Not
  "unknown", not "estimated" — there is no NVIDIA-encoded stream in
  1.81 GB of official payload (§4). Register:
  `v429_lz_conventions.json` (selftest; two lessons banked in-code: a
  wall-clock field can never re-derive — normalized out of the frozen
  comparison; tuples become lists through JSON — compared as lists).

## 4. The package-wide hunt: no NVIDIA LZ4 stream exists in 1.81 GB

The whole official 610.57.04 payload (1,123 files, 1,807,971,040 B;
`.run` sha256 re-verified `b2e935c66b83bb00…eb116d` in-instrument)
scanned for the frame magics of every plausible component codec (LZ4
frame/legacy/skippable, zstd, gzip, xz, bzip2):

- `lz4_frame`: **7 hits, ALL inside userspace CUDA libraries**
  (libcuda, opencl, ptxjitcompiler, rtcore + the 32-bit twins); every
  one FAILS the plausibility check (`lz4.frame.decompress` raises
  RuntimeError from the hit offset) — chance 4-byte collisions in
  code, zero real streams.
- `lz4_legacy`: 0. `fwimage.bin` re-scanned explicitly: **0 LZ4
  anything** (the 4.27 compression closure re-banked live).
- The zstd/gzip/xz/bzip2 counts (29/188/36/20) are chance-level for
  3–4-byte magics over 1.8 GB or live in out-of-scope userspace
  blobs; the GSP component path carries none of them.

The 4.24 ledger item 1 ("no NVIDIA-produced LZ4 stream exists") now
rests on a package-wide scan, not on the artifact set's bounds.
Register: `v429_lz_package_hunt.json` (selftest re-derives in ~23 s;
loud SKIP exit 3 without the package tree — the lab's degradation
convention).

## 5. The codec verdict: NO fix needed — and the permanent test delivered

`tools/gsp-lz/lz4block.py` is **untouched byte-for-byte**. The decode
failures of §1 are the premise's; the codec's own round-trip passes on
every real component. What changed is the verification standard:
`tests_gsplz.py` gains **T6 — the REAL component round-trip battery**
(the brief's "the round-trip on the real component must be a permanent
test"): 5 component binaries (bootloader, comp-58KB, comp-725KB,
gsp-rm-17MB, pmu-wdt-41KB) × 3 properties (T1 ours round-trip, T2
reference-decodes-ours, T3 ours-decodes-reference), presence-gated,
~20 s for the whole suite. **ALL PASS**, including
`gsp-rm-17MB.bin` 17,236,632 → 9,910,094 → 17,236,632 byte-exact.
Scope note (honest): T6 validates the codec ON the real bytes; it does
NOT claim any component is a compressed stream (§1 says the opposite).

## 6. Task B: `tools/edpp/recv76_analyze.py` — the send↔recv path

- **Reassembly** per (side, seq): sparse offset assignment
  (out-of-order chunks fine, duplicates idempotent), hole detection
  against the declared `len=`, dict-indexed (a hostile 2^32−1 seq
  allocates nothing — the sibling analyzer's list-prealloc pattern
  would not survive that line).
- **Both line families**: `RPCDUMP76` (send — the 4.23 hook's own
  counter, NOT the header sequence, per findings-4.25 §2) and
  `RPCRECV76`/`RPCRECVINFO` (recv — the authoritative header
  sequence).
- **Correlation**: P1 seq+cmd consistency (labeled HYPOTHÈSE while the
  send hook prints its own counter — the §6.4 one-line refinement of
  4.25 would upgrade it) and P2 cmd+journal-order (HYPOTHÈSE,
  labeled); orphans reported by name with the likely cause.
- **The response-field hunt** (the brief's "les valeurs retournées par
  le GSP"): per pair, the u32-aligned delta map send→recv (what the
  GSP overwrote), named where the source allows — the 40-B prefix
  (`g_rpc-structures.h:1423-1435`), the EDPp GET/UPDATE params
  (`ctrl2080internal.h:3988-3995` / `:3238-3241`), the d031 struct =
  8-B header {flags, domain-bitmask} + 32 × 48-B entries
  (findings-4.28-x86-substrate.md §7) — plus the mW-like census (the
  4.23 labels, with the 4.28 clock-VF re-attribution carried in the
  label) and the 32-B residue law check.
- **Robustness (`--selftest`, ALL PASS)**: the REAL 4.23 send corpus
  (`edpp_payload_1616.bin` — byte-exact reassembly, cmd 0x2080d031,
  paramsSize 0x608 decoded) + interleaving / out-of-order / duplicate
  chunks / truncation holes / junk lines / giant seq + one SYNTHETIC
  §7.2-shaped pair through the full pipeline (correlation → delta map
  naming limitMin/Rated/Max/Curr → residue law; labeled
  instrument-check, never banked as a capture). One robustness lesson
  banked: the sibling parsers' `group(4).split()` explodes on
  space-less hex (`int("deadbeef",16)` overflows) — recv76 normalizes
  the hex (spaced/unspaced/mixed).
- No recv capture exists yet (the 4.26 boot); nothing is banked as
  observed.

## 7. The honest ledger

- **BYTE-EXACT (the brief's task A): NOT ACHIEVED — and proven
  UNACHIEVABLE as stated.** comp-725KB.bin is not an encoding of
  gsp-rm-17MB.bin (it is vgpu.elf, flat, ELF-identified; no decoder
  accepts it as a stream; no LZ4 encoder can reach 4.2 % on this
  data). Declared here per the brief's own rule.
- **BYTE-EXACT (what IS proven):** the codec round-trips every real
  component byte-exact in both directions (T6, 15 checks), our
  streams are reference-decodable, reference streams ours-decodable —
  now permanently, on the real artifacts, not just synthetics.
- **Plan B is NOT blocked** — it never depended on this: the 4.27
  pass proved the components sit FLAT in fwimage; a patched component
  re-embeds flat via `gspbuild.py` (the byte-exact container). The LZ
  lane's real consumer would be a future NVIDIA-compressed stream;
  the decode path is ready and the absence is now SCANNED (§4), not
  assumed.
- The recv lane stays armed: `recv76_analyze.py` +
  `rpcdump_recv_analyze.py` + the §7.2 prediction wait for the 4.26
  boot.

## 8. Queue

1. The 4.26 boot (the recv capture) — `recv76_analyze.py` is the
   correlation half; the send hook's one-line seq refinement (§6.4 of
   4.25) upgrades the P1 pairing from HYPOTHÈSE to PROVEN.
2. If a genuine NVIDIA LZ4 stream ever surfaces (any package or
   channel): decode through the T2-verified path, re-encode, diff
   per-sequence — §3's method is the template, byte-exact becomes
   decidable.
3. The zstd hits in the CUDA userspace libraries: out of scope here
   (the GSP component path carries none); noted for any future
   PTX-blob lane.
