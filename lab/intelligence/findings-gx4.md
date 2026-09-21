# findings-gx4 — the fourth ring: the memory ladder decoded, the live cross closed

Scope: the three verified GA104 specimens, one instrument (`gx4-clocks.py`),
grammar imported from the open-gpu-doc MemoryClockTable spec (2018) and the
nvidia-bios-reader `parse_timings` grammar, pointer offsets anchored on the
ring-3 register. Selftest green (0 failures).

## What is measured

**The memory frequency ladder (P+0x04).** Version 0x11 — the 2018 spec's
format — with the fields where the spec puts them: 10 entries, each
min/max frequency u16 [13:0] MHz, plus a per-strap variant array. The
GA104 header has GROWN against the 2018 spec (base entry 20→86 B, strap
entry 26→44 B) — a measured Ampere delta; the frequency fields did not
move. The ladder, identical on all three MSI boards:

```
bin 0:     0–540 MHz    bin 3: 4700–5250    bin 6: 6301–16383 (sentinel top)
bin 1:   541–1249       bin 4: 5251–5799
bin 2:  2005–4699       bin 5: 5800–6300
```

The top bin covers the founder's live **6801 MHz** (day-0 runtime
snapshot) — the table-to-machine cross is closed for memory. The gap
1249–2005 carries no bin. Bins 2–6 share one config (`4040800c05e444ff`);
bins 0–1 each carry their own.

**The strap coherence closes across rings.** The table's variant count is
14 — the exact length of the ring-2 memory translation (14 physical
straps). The spec calls the variants "Strap Entries"; the reader calls
the extended bytes "timing IDs"; the arithmetic is identical. One object,
two grammars, one meaning: **frequency range × memory strap → config**.

**The timing table (P+0x08), under the reader's grammar.** Version 0x20,
header 6 B, base record 76 B, extended 12 B × 0, **65 records**. (The
ring-4 first reading "count 12" mis-took the extended_length field for
the count — corrected by importing the reader's field order, the
from-memory lesson of ring 2 repeating at the interpretation layer.)
65 timing records × 76 B is the original research subject of
nvidia-bios-reader; its record decode is ring 5.

**The virtual P-state table (P+0x38), honestly unknown.** The spec
documents v0x10 (GF11X–GM20X) and warns that Pascal+ changed the
structure. The GA104 table reads **v0x20**, header 21 B
(`20 15 01 11 04 0a 00 02 01 03 09` + ten 0xFF bytes), entry region
starting `0f bd 46 af 01`. Registered raw at its spec-named offset
(@0x89A1E primary); no interpretation attempted. The launch-era build
carries hlen 19 vs 21 — the header moved once across the generation.

**The PERFORMANCE table (P+0x00, v0x60) and the FAN tables** stay raw
records with their bytes registered — no public spec, and the envytools
fan grammar predates the multi-cooler shape (2 coolers × 26 B here, the
Trio's twin-fan signature; values 100/1000/3250/5000 sit in the records
as RPM-class candidates, marked inferred, never asserted).

## Consequences

1. The memory optimization surface is now a named, gated object: a
   7-bin ladder with per-strap variants, byte-stable across the MSI
   generation, and pinned to the live machine by the 6801 MHz cross.
2. The 65×76 B timing table has its exact geometry — ring 5 can decode
   records against the reader's TimingFields grammar (rc/rfc/ras/...)
   without re-deriving anything.
3. The live graphics clock 1890 MHz (another written state; stock
   boost 1770) now has its candidate object: the PERFORMANCE v0x60
   records and the v0x20 vP-state table — both registered, both open.

## Open questions (handed to ring 5)

1. Timing records: decode the 65 × 76 B records (reader's TimingFields).
2. FAN COOLERS / FAN POLICY records: find or derive the Ampere field
   grammar; the two coolers' records differ in exactly a few bytes.
3. vP-state v0x20: structure unknown; the 10-FF block and the entry
   region invite the open-gpu-kernel-modules/nouveau source as the next
   import source.
4. PERFORMANCE v0x60: same hunt.

## Honesty ledger

- Proven: memclk geometry + ladder 3/3, monotone, live-cover on the
  primary; strap coherence 14 = 14 across rings 2 and 4; timing-table
  geometry 3/3 under the reader's field order; selftest 0 failures.
- Inferred: RPM-class reading of fan-record u16s; the "bin" reading of
  the memclk entries (spec-named fields, semantics from the 2018 doc).
- Unknown: vP-state v0x20 and PERFORMANCE v0x60 structures; fan record
  fields; whether the erased slack is flashed that way or capture-trimmed.
