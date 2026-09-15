# findings-gx2 — the second ring: BIT opens, memory decodes, the LHR seam

Scope: the three verified GA104 specimens, one instrument (`gx2-bit.py`),
the grammar imported file-by-file from envytools `nvbios/bit.c` (2012,
cross-checked against nvidia-bios-reader `src/nvbios_reader.cpp`), zero
hardware writes. Selftest green (0 failures) after one correction that the
doctrine predicted: the first memory decoders were transcribed from memory
and WRONG — code 9 read "GDDR5" on a GDDR6 card; the source decided, the
table is now the verbatim import, and the lesson is banked in a comment.

## What is measured

**The BIT table.** @0x93B0 in every specimen (image-rel 0x1B0), version 1.0,
hlen 12, rlen 6, checksum validates to zero, **17 tokens**:

```
2 i2c  B biosdata  C clock  D dfp-panel  I nvinit  M memory  N nop
P power  S string  T tmds  U display  V virtual-strap  x mxm  d dp
p pmu-falcon  u uefi  i info
```

The 'P' power token (@0x94E0, 0xE8 bytes) is the first candidate for the
power-limit lens — the 240/250 W question measured live on the machine
should land there; that decode is ring 3, with the envytools
`parse_bit_P` grammar and the open-gpu-doc anchors.

**The memory grammar.** Token 'M' v2: 14 physical strap groups translated
onto 8 logical profiles + 8 unused records; the info table sits INSIDE the
legacy image (@0xD326 primary) — not in the dense tail. Every profile is
**GDDR6**, and the three vendors are named by nibble: Samsung / Micron /
Hynix (0xF = Micron, not "unknown" — the first reading mis-named it before
the source correction). Density codes 5/6, organization 2.

**The generation is one object at this layer.** Primary vs launch-era:
token sequence IDENTICAL, all 17 table lengths IDENTICAL, translation
table IDENTICAL, descriptor set IDENTICAL — the only measured change in
the 'M' layer is **the record format: rlen 14 → 22 bytes at the LHR
transition** (info table @0xD356 → @0xD326, 16 records both sides). The
BIT skeleton is generation-invariant; the LHR seam lives inside the memory
record format.

## The prior-art position (the founder's point, measured)

The envytools grammar is from 2012 — it still decodes 2020 silicon
byte-exactly (checksum zero, 17/17 tokens named). nvidia-bios-reader
already walked the same structures for GA104 (its regression set). The
neighborhood is real; what no neighbor ships is the register/gate/pair-law
methodology around it, the live-machine cross-checks, and the
vendor-verified acquisition ledger — that is the lane's advance, the same
advance the sibling lab proved on AM4.

## Open questions (handed to ring 3)

1. The 'P' power table: decode the power/thermal entries; confront the
   live 250 W written state (240 W factory default) with the VBIOS-declared
   limits — the GPU edition of the ring-49 chain.
2. The 'C' clock table and the 'i' info table (chip code GA104 expected
   at the reader's family/die encoding).
3. The dense tail @0x2FA00: still unowned. The 0x30-strided 55AA run and
   the `3s2bwb` vocabulary are NOT the memory table (that lives in the
   legacy image); candidates are UEFI runtime data and init payloads.
4. The 8 extra bytes per memory record at the LHR seam: which fields grew?

## The spec decides (the spec-fresh anchor, imported from the cloned open-gpu-doc)

NVIDIA's own BIOS Information Table Specification
(`open-gpu-doc/BIOS-Information-Table/`) confirms the imported grammar
byte-for-byte — ID 0xB8FF, "BIT\0", BCD 0x0100, header size 12, token size
6, zero-sum checksum — and adds three facts envytools and the reader never
state:

1. **'P' is BIT_TOKEN_PERF_PTRS, "Performance Table Pointers"** — the
   official name of the ring-3 target where the power-limit question must
   land ('p' is Falcon Ucode Data, 'u' UEFI Driver Data, 'M' is "Memory
   Control/Programming Pointers").
2. **The pointer-adjustment rule**: `if pointer > legacy image length,
   adjusted = pointer + UEFI image length` — pointers may reach past the
   UEFI image, which is how BIT tables can own data in the dense tail.
3. **The NVGI head is spec-legitimate**: "A GPU firmware file may contain
   data for HW consumption preceding the PCI Expansion ROM contents" —
   the ring-1 NVGI markers at 0x0/0x2000 are exactly that region, named
   by NVIDIA, semantics still unmeasured.

## Honesty ledger

- Proven: BIT geometry and tokens on 3/3; memory decode 3/3 with the
  corrected verbatim decoders; the rlen 14→22 seam; selftest 0 failures.
- Inferred: the power-limit reading of the 'P' token (named by envytools,
  not yet decoded); the LHR attribution of the record-format change
  (correlated with the launch→LHR build dates, not proven causal).
- Unknown: the dense tail's owner; the meaning of the 8 grown bytes;
  whether the erased slack is flashed that way or capture-trimmed.
