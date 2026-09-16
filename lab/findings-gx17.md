# findings-gx17 — the seventeenth ring: the perf table is a generation constant, and the public hunt is exhausted

Scope: the three verified GA104 acquisitions, the open-gpu-doc corpus,
GitHub code search, the gsp.bin plaintext layer, and the imported
kepler-ada pattern. Plus the B550 SPI-wall instruments committed on the
sibling lane. Zero hardware writes.

## What is measured

**The PERF table (P+0x00, v0x60, hlen 10, rlen 5, count 7) is a
GENERATION CONSTANT.** The cross-board experiment at the corrected
addresses (the launch-era copy lives at 0x85CD5, the LHR copies at
0x8984D): **all 35 record bytes are identical on all three boards** —
launch 2020 and LHR 2021, Trio and Ventus. The table predates the LHR
seam (unlike the memory record growth, the fan duty split, the budget
rlen growth and the PMU growth, all measured at that seam) and belongs
to no board. Together with ring 15's identical vP-state profiles, the
clock envelope of the whole RTX 3070-class GA104 generation is shared,
in-file, byte-exact.

**The records carry the vP-state values** (ring 16's correlation, now
seen on all three boards): 420/600/405 (the deep-idle profile's three
values) as u16s, plus clean /2^15 fixed-point windows. The exact field
order of the 5-byte records remains open — but the bytes are now proven
generation-invariant, so any future decode effort works on a corpus
that cannot drift.

**The public hunt for the v0x60 grammar is exhausted:**
- GitHub code search for `PerfCfPwrModelTablePtr` (a name only a modern
  parser would know): **zero results** — nobody implements it.
- open-gpu-doc: only MemoryClockTable and virtual-p-state-table exist;
  no PERF-record document.
- the kepler-ada pattern: names the P-pointer fields, stops at the
  record internals.
- gsp.bin's plaintext layer: the RM's semantic vocabulary is visible
  (PERF_CF_CONTROLLER_DRAM/GPC/NVD/XBAR min/max, JPAC_PSTATE_MIN/MAX,
  BOOST_LOW, DEEP_IDLE, PERFORMANCE_CAP0/1) — the runtime language above
  the table, while the VBIOS parser stays behind the packing.

**The ScriptListPtr domain hunt** (ring 12's unresolved pointer): five
candidate bases tested with the self-validating walker — none lands on
a clean walk. The memory-clock scripts either use a grammar outside the
INIT set or a pointer domain outside the candidates. Registered, not
guessed.

## The B550 side-lane (no root required by it)

The founder's fresh vendor download
(`TUF-GAMING-B550-PLUS-WIFI-II-ASUS-3644.CAP`, 0x800 AMI-capsule header
+ exactly 32 MiB body) is stored as `vendor-acq-3644-download.CAP` — its
full-file hash DIFFERS from the ring-44 acquisition (c3db78fe… vs
5f7a0e43…): ASUS re-packages. The body is the reference for the day-0
identity court when the chip dump lands. The faillock incident (10
botched sudo attempts from a tooling bug) pauses the in-system SPI
finale until the window expires or the machine reboots.

## Honesty ledger

- Proven: the 3/3 byte-identical records (addresses re-derived per
  board from each board's own P+0x00 pointer), the vP-value u16s, the
  zero public implementations, the gsp plaintext vocabulary.
- Inferred: the generation-level role of the table (from the
  invariance); the /2^15 encoding (clean-value argument).
- Unknown: the v0x60 field order; the ScriptListPtr domain; the packed
  RM parser; whether 0x60-level records also serve other dies unchanged.
