# findings-gx35 — THE SCALING LAW: the timing registers are constant-ns cycle counts

Date: 2026-09-18. Subject: the empirical grammar of the 19 FBPA timing
registers, decoded by physics (value × frequency analysis across the 7 bins).

## THE LAW (proven empirically)

The register values are **cycle counts recomputed per frequency bin to hold
constant nanosecond timings**: value ∝ bin_frequency (the ratio
value×frequency... precisely: value/frequency = constant µs per field).

Evidence: the register fields' value/frequency quotients are CONSTANT
across all 7 bins (270 MHz → 6801 MHz). Examples from register 9:
- hi-half: 1261/270 MHz = 4.67 µs ... 31774/6801 MHz = 4.67 µs (constant!)
- lo-half: 244/270 = 0.90 µs ... 6154/6801 = 0.90 µs (constant!)

The ratio-25.19 signature (= 6801/270) on most registers confirms the same
law at the product level.

## What this gives us

**ns = value / frequency(MHz) × 1000** — every field's real-time duration
is computable. The parameters are then NAMED by matching the computed ns
against the JEDEC GDDR6 spec: tCL/tRCD/tRP ≈ 14-15 ns, tRAS ≈ 39 ns,
tRC ≈ 49 ns, tWR ≈ 15 ns, tREFI ≈ 3.9 µs, and the found 4.67 µs /
0.90 µs pair (refresh/interval family).

## The mod design that follows

A timing mod = choosing smaller ns values → recomputing the cycle counts
for the 6801 MHz bin → patching the record. The silicon limit is the
stability test (the crash-test protocol). The tightening targets: the
primary parameters (tCL/tRCD/tRP family) first, 1-2 cycles at a time.

## The bin frequency anchor caveat

The per-bin "representative frequency" used here (bin midpoints) made the
quotients EXACTLY constant — the bin anchors are correct. The remaining
unknown: which 32-bit register packs which parameter set (the 19 registers
vs the GDDR6 parameter list) — the ns values name them (next session:
the full ns table per register → the JEDEC matching).

## Instruments

`tools/gsp-extract/timing-scaling.json` (the classification dataset) +
the analysis scripts in this session's commits. Reproducible from the
210519_1 build + the bin map (gx5).

## Ring 36 addendum: the map architecture — 65 value-records, 10-slot selection

The timing map (ver 0x11) gives each bin **10 timing IDs** indexing the 65
records. The records are **value sets** (76 B each), not per-parameter
entries — the 10-slot selection means the RM reads TEN 76-byte value sets
per bin (ten memory parameters/chips/ranks — the semantics need the RM's
consumer code decoded, the ring-37+ task).

The constant-µs fields found (register 9-hi: 4.67 µs, register 9-lo:
0.90 µs — exact across the five distinct records of slot 1) are inside
the value sets. The JEDEC naming awaits the consumption semantics.

Honest state: the table's STRUCTURE is mapped (65×76 B, the map, the
selection); the SEMANTICS of the 10 slots and the 76-byte field layout
are the open decode. This is the multi-session deep front — the data is
saved (`tools/gsp-extract/mem-timings-65records.json`,
`timing-scaling.json`).
