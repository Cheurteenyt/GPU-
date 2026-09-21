# findings-gx5 — the fifth ring: the timing layer, decoded, with a stock landmine

Scope: the three verified GA104 specimens, one instrument (`gx5-timings.py`),
grammar imported verbatim from nvidia-bios-reader `decode_timing_fields`
(six u32 words → 18 fields), pointer offsets anchored on the ring-3
register. Selftest green (0 failures).

## What is measured

**The map.** The P+0x04 table (v0x11 — ring 4's "memory clock ladder") is
also the timing MAP: each of its 10 frequency bins carries **one timing-ID
byte per strap** (14 straps — the ring-2 translation length, the
cross-ring gate holds). The IDs form per-vendor-family series: 0–8,
10–19, 20–26, 30–38 — four series for the four logical memory profiles
the strap translation serves.

**The table.** P+0x08 (v0x20): 65 records × 76 B; the referenced subset is
**28 records**, decoded into 18 named fields (rc, rfc, ras, rp, cl, wl,
rd_rcd, wr_rcd, rpre, wpre, cdlr, wr, w2r_bus, r2w_bus, faw, refresh,
rrd, wrcrc — controller cycle counts, not nanoseconds). The values scale
monotonically with the frequency bins: the top-bin record (id 6, the bin
that serves the founder's live 6801 MHz) reads rc=78, rfc=210, ras=52,
rp=26, cl=24.

**The census.** 140 (bin × strap) pairs: **100 with records, 40 with 0xFF
(no timing at all)** — the FF block is exactly straps 10–13 across all
bins: physical straps the translation accepts but the timing map never
backs. A board strapped there would run memory with no timing record —
the physical straps presumably make that unreachable, but the firmware
leaves the hole visible. **One referenced record is ALL-ZERO: id 19,
referenced by bin 6 × strap 7** — the stock-firmware instance of the
exact pathology nvidia-bios-reader was built to find (their density-mod
instability: a used timing range with no real record behind it). On a
stock card, strap 7 is reachable per the translation (logical profile 7,
Micron density 6). This is the lane's first registered landmine.

**The pair law.** Primary (LHR era) vs launch-era: the ID matrix is
IDENTICAL; 24 of the 28 referenced records are field-identical; **the 4
Hynix-series records moved at the LHR seam — and tightened**: id 26
(the top-bin Hynix record) rc 76→70, rfc 210→175, ras 49→44, faw 28→20,
rrd 7→5 (launch → LHR), ids 22/23/24 refresh 6→3. Same bins, same
descriptors — the LHR build tuned the Hynix timing records tighter.
The first measured between-build performance delta on this lane.

## Consequences

1. The full memory-timing surface is now a named, gated object: map
   (bins × straps → IDs), table (65 records), decoded fields, coverage
   census — with selftest gates on the ID matrix, the referenced set,
   the decoded fields, the FF census, and the strap coherence.
2. The optimization question has its last piece: any memory-timing
   modification now knows which object to study, what the stock values
   are, and where the vendor itself changed them across releases.
3. The zero-record landmine (id 19) is registered — worth confronting
   against which strap the founder's card actually uses (needs the
   runtime strap, a deeper gesture).

## Open questions (handed forward)

1. The 37 unreferenced records of the 65: factory spares or dead weight?
2. Which physical strap is the live card strapped to (no userspace path)?
3. The meaning of the per-field units (cycle counts vs controller
   register fields) — the open-gpu-kernel-modules memory-controller
   docs would name them.

## Honesty ledger

- Proven: map geometry + ID matrix 3/3; 28 referenced records decoded
  3/3; the census; the 4-record LHR delta; selftest 0 failures.
- Inferred: the vendor-family reading of the ID series (correlates with
  the ring-2 vendor per profile, not proven per-series); the "board
  straps never land on 10–13" reading.
- Unknown: the live strap; the units' exact semantics; whether id 19's
  zero record is reachable on any shipping board.
