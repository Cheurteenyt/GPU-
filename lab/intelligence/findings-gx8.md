# findings-gx8 — the eighth ring: the nameplate completed by the community

Scope: the three verified GA104 specimens, one instrument (`gx8-named.py`),
grammar imported from the open-source ImHex pattern
"kepler-ada-nvidia-vbios-visualizer" 2025_02 (TechPowerUp forums thread
322299, fetched to `imports/kepler-ada-vbios-visualizer-2025_02.hexpat` —
the founder's GitHub-hunch, borne out on a forum mirror). Selftest green
(0 failures).

## What is measured

**The P-pointer nameplate is complete: 58 of 58 dwords named.** envytools
stopped at 0x98 (39 names); the pattern carries the modern RM names for
the rest — LpwrNvlink, PerfCfSensor/Topology/Controller/Policy/PwrModel/
PmSensor, NneVars/Layers/Descs, IllumDevice/Zone, LpwrAp/GcOff/GrRg/Ei,
FanArbiter, FanAcousticsQual, ThermalPolicyOvrd. On our specimens: 46
pointers set, 12 null. The card carries the full modern table farm —
including the PERF_CF and NNE (neural) tables of the AI-era firmware —
and the two board families differ in exactly which legacy-era pointers
are null (the Ventus's PowerControl slot is null where the Trio's is
set, and vice versa on ThermalDevice).

**The "POWER BUDGET" of envytools is officially PowerCapping** — the
ring-3 table (240 000/250 000 mW cap) gets its RM-era name, and the
naming collision class (envytools name ≠ spec name ≠ RM name for the
same offset) is now documented by three agreeing sources.

**The Memory Clock Table header is fully named** (the Ampere growth that
ring 4 measured as "base entry 20→86 B"): Flags=0, **FBVDDSettleTime=64
µs**, CfgPwrdVal=0, FBVDDQHigh/Low=0, **ScriptListPtr=0x84dd (3 scripts),
CmdScriptListPtr=0x84e9 (2 scripts)** — identical on all three boards.
The reserved bytes were the memory power-delivery timing and the perf
script lists.

**The Falcon ucode inventory is located and partially decoded.** The 'p'
token (v2, 4 B) holds a u32 to the falcon table (@0x91F83, version 0x01,
16 slots × 6 B, descriptors 48 B, DescVersion 0x01). With the spec's
pointer rule applied recursively to the DescPtr, three microcodes
validate: **PRE_OS/PMU (34 308 B), LS_UDE/PMU (83 680 B), and one
0x07/0x06 ucode (64 364 B)** — identical across the LHR pair. The
launch-era build carries the same inventory with a **smaller PMU: 33 216
and 77 228 B** — the PMU firmware grew at the LHR seam, the third
measured cross-release delta after the memory-record and power-budget
record formats. The remaining 13 slots read as empty or unresolved
(application IDs outside the pattern's enums) — flagged, not forced.

**The open-ecosystem frontier, now precise.** open-gpu-kernel-modules
contains no VBIOS table parsing (GSP-RM territory, closed); nouveau's
parsers stop at perf v0x40; the ImHex pattern names structure and
pointers but not the v0x60 perf records or the v0x20 vP-state entries.
Those two remain the lane's true unknowns — everything around them is
named, gated and cross-checked by three independent grammars.

## Honesty ledger

- Proven: the 58-name nameplate 3/3; the memclk named header 3/3; the
  falcon table header 3/3; 3 sane ucode descriptors per specimen; the
  PMU growth 33 216→34 308 B; selftest 0 failures.
- Inferred: the falcon DescPtr's recursive spec_adjust (validated by 3
  sane reads, the mechanism that would confirm it is one more grammar);
  the "PMU grew for LHR" causality (correlated with the seam, as ever).
- Unknown: the 13 unresolved falcon slots; PERF v0x60 records; vP-state
  v0x20 entries; the live strap.
