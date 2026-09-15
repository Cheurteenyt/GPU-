# findings-gx3 — the third ring: the power budget decoded, the tail owned

Scope: the three verified GA104 specimens, one instrument (`gx3-perf.py`),
grammar imported from envytools `nvbios/power.c` (the P2 pointer nameplate,
`envy_bios_parse_power_budget`) and the pointer rule from NVIDIA's own BIOS
Information Table Specification. Selftest green (0 failures).

## What is measured

**The 'P' Performance table is the map of the optimization universe.**
58 dword pointers per specimen: 39 named by envytools (PERFORMANCE,
MEMORY TIMINGS MAPPING, MEMORY TIMINGS, POWER SENSE, POWER BUDGET, BOOST,
FAN COOLERS, POWER FAN_MGMT, OVERCLOCKING, the LOW POWER family, the
THERMAL and VOLTAGE families...), 19 beyond the envytools nameplate.

**The pointer domain is the spec's own rule, and it lands in the tail.**
Raw values (~0x69xxx–0x72xxx) exceed the legacy image (0xFE00); per the
NVIDIA spec, `pointer > legacy length → + UEFI image length`. After the
adjustment, **39 pointers land at 0x88xxx–0x91xxx — inside the dense tail
that ring 1 could not own**. The tail is the modern table farm: the
PERFORMANCE table sits at its middle (@0x8984D), the power/fan/voltage
families at its end. 12 pointers are NULL (VOLTAGE, THERMAL, BOOST,
CSTEP among them — features this board's VBIOS does not carry), 3 are
image-relative, 4–5 unresolved (POWER BASE CLOCK among them — its header
does not match the hlen/rlen/count shape; open).

**The power budget, decoded, agrees with the machine.** POWER BUDGET
(v0x30, hlen 44, rlen 71, 20 entries, cap_entry 2) at @0x8FB48: the cap
entry reads **min 100000 / avg 240000 / peak 250000** — milliwatts:
**100 W floor, 240 W default, 250 W maximum**. The live machine measured
Default 240 W / Max 250 W / current 250 W: the VBIOS→driver→runtime chain
is closed at the byte level, and the founder's 250 W "written state" is
exactly the driver holding the budget's peak instead of its avg. Several
sibling entries carry 5001000 (a sentinel for unbounded), 150000/175000
and 226800/252000 (per-rail budgets — the power-topology cross is ring 4).

**The budget is a BOARD marker, not a generation marker.** Primary
(Gaming Trio Plus) and the launch-era Gaming X Trio both read
240000/250000 — while the same-build-date Ventus 3X OC reads
**220000/220000: a 220 W cap with zero headroom**. Same silicon, same
date, different board = different budget. This is the ring-48
orthogonality law, GPU edition. The budget record itself also moved at
the LHR seam (rlen 67 → 71), second seam after the memory format.

**The other geometries**, identical across the three specimens:
PERFORMANCE v0x60 hlen 10 rlen 5 **7 entries** (the P-state table —
the virtual-p-state-table doc is its spec anchor, ring 4); FAN COOLERS
v0x10 rlen 26 **2 coolers**; POWER FAN_MGMT v0x20 rlen 51, 8 entries;
OVERCLOCKING v0x10 rlen 5, **2 entries** @0x91FE9 — the overclocking
surface exists and is small.

## Consequences

1. The 240/250 W question is CLOSED at the VBIOS level: where it lives
   (@0x8FB48, cap entry 2), what it says (240000/250000), and how the
   live 250 W state relates to it (peak vs avg). Any "optimization" of
   the power envelope now starts from a named, gated, byte-exact object.
2. The dense tail is no longer unowned territory: it is the table farm
   reached by spec-adjusted pointers. Ring 4 inherits a MAP, not a void.
3. The fan question (the founder's cooling interest) has its objects:
   FAN COOLERS (2 × 26 B) and POWER FAN_MGMT (8 × 51 B), both decoded to
   geometry, records pending.

## Open questions (handed to ring 4)

1. PERFORMANCE v0x60, 7 × 5 B: the P-state clocks — decode against the
   open-gpu-doc virtual-p-state-table + MemoryClockTable anchors.
2. FAN COOLERS + POWER FAN_MGMT records: the fan curves in firmware.
3. The per-rail budget reading (20 entries ↔ POWER TOPOLOGY @0x8F642-ish).
4. The 4–5 unresolved pointers and the 19 unnamed dwords.
5. MEMORY TIMINGS @0x8B880 — the timing-record grammar from
   nvidia-bios-reader (its original research subject).

## Honesty ledger

- Proven: pointer domains 58/58 per specimen (register-gated); budget
  decode 3/3 with the live-machine cross on the primary; geometries 3/3.
- Inferred: the milliwatt unit (confirmed by the live 240/250 cross, but
  the spec text itself was not re-read for a unit statement); the
  per-rail reading of sibling budget entries; the sentinel reading of
  5001000.
- Unknown: the 4–5 unresolved pointers; the 19 unnamed dwords; whether
  the erased slack is flashed that way or capture-trimmed.
