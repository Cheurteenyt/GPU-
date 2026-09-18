# findings-gx34 — the timing record structure: 19 × 32-bit FBPA registers

Date: 2026-09-18. Subject: the GDDR6 timing-record grammar, first decode.

## Proven (empirical, this session)

1. The 76-byte timing records = **19 packed 32-bit registers** (76/4 = 19) —
   the FBPA timing register bank per frequency bin (the NVIDIA memory-
   controller timing registers, one set per bin).
2. Scaling classification across the 7 frequency bins (270 MHz → 6801 MHz),
   per byte position (dataset: `tools/gsp-extract/timing-scaling.json`):
   - bytes 0-3 of slot-1/4/6/9 records scale **with frequency** → the
     primary cycle-count timings (tCL/tRCD/tRP family);
   - ~40 bytes are **constant across bins** → configuration/markers;
   - slot 8's record is a different register bank (29 ns-constant fields).
3. Slot 1, 4, 6 and 9 reference the SAME record content (the primary
   timing set); slots 2/5 share another; slot 8 is distinct.

## The decode path (next session)

The bit layout of the 19 registers is the **FBPA::Timing** grammar —
public documentation exists for earlier generations (Nouveau/envytools
FBPA timing registers); the GDDR6/Ampere variant follows the same
register-naming scheme with shifted field boundaries. Imported grammar,
never transcribed from memory: pull the envytools FBPA documentation,
map each 32-bit register to its fields, anchor on the known values
(tCL ≈ 14-15 ns at 6801 MHz → the register whose field reads ~20 cycles).

## Honesty

The cycle/ns interpretation of bytes 0-3 did NOT resolve cleanly across
bins yet (22 ns vs 11 ns between the slowest and fastest bin for byte 0) —
either the units differ per bin or byte 0 is not tCL. No timing
modification is designed yet; the structure discovery is the session's
result. The 280 W flash and the dial tests are unaffected by this front.
