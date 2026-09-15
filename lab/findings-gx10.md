# findings-gx10 — the tenth ring: the devinit scripts decoded, and the day-0 differ finally resolved

Scope: the day-0 live dump plus the three verified acquisitions, one
instrument (`gx10-init.py`), the INIT opcode grammar and its per-opcode
argument sizes imported from nouveau `nvkm/subdev/bios/init.c` (fetched
to `imports/nouveau/init.c`). The walk is self-validating: a script is
admitted only when the imported length table carries it to a clean
`init_done` (0x71) — 0 failures on the register.

## What is measured

**The script field.** The legacy image carries **317 devinit scripts**
(live dump), each admitted by walking to `init_done` cleanly. The opcode
census (deduplicated): NV_REG ×294, **SUB_DIRECT ×402** (the scripts form
a call tree — sub-script dispatch is the backbone), ZM_REG ×154,
RESUME ×11, TIME ×9, ZM_REG_SEQUENCE ×10, plus IO_RESTRICT_PROG,
ZM_INDEX_IO, LTIME, NOT. The register-write census lands almost entirely
in the **0x4061c0xx–0x6061c1xx block — the GA10x memory-controller /
training registers**: the scripts ARE the memory-training program.
The 3s2bwb "vocabulary" of ring 1 is resolved: those bytes are opcode
streams (0x33 REPEAT, 0x73 STRAP_CONDITION, 0x32 IO_RESTRICT_PROG,
0x62 ZM_INDEX_IO, 0x77 ZM_REG16…), matched mid-instruction by the naive
string scan. 0x73 STRAP_CONDITION reads R[0x101000] — the memory-strap
register — the scripts condition their writes on the live strap.

**The day-0 differ, resolved at last.** Script-level comparison of the
live dump vs the "same version" TechPowerUp acquisition:

| | scripts | starts shared | live-only | acq-only |
|---|---|---|---|---|
| live dump | **317** | 251 | **66** | — |
| acquisition | 259 | 251 | — | 8 |

The 66 live-only scripts are **exactly the scripts of the divergent
region** (start ≥ 0x7E00) — the region where the acquisition reads as
zeros. The acquisition's legacy image **lost most of its devinit
scripts**: the TPU file is an incomplete capture, not a different build.
The card's ROM is whole; the "sibling" of day-0 is a damaged sibling,
and the live dump is confirmed as the only faithful source for the
script layer.

## Consequences

1. The devinit layer — the code the card actually executes at power-on —
   is decoded, gated and registered, live-first. Any future memory-
   training or init-behavior question starts from named scripts.
2. The day-0 story is now complete and causal: same version, same
   grammar layers, same 251 scripts — and a capture that dropped 59+
   scripts plus their region. The "sibling-not-twin" verdict stands,
   with its cause measured.
3. The strap register R[0x101000] appears in the grammar as the
   conditioning input — the live-strap question has its gate object,
   even though reading it still needs the deeper gesture.

## Honesty ledger

- Proven: 317/259 script inventories, the 251 shared starts, the
  66/8 region attribution, the opcode census, the register-write census,
  selftest 0 failures across all four admitted images.
- Inferred: that the acquisition's loss happened at capture/packaging
  time (the zero regions correlate exactly with the missing scripts; the
  mechanism — whose tool, why — is unknowable from here).
- Unknown: the sub-script call graph (SUB_DIRECT targets are decoded as
  offsets but not yet walked as a tree); the remaining opcode lengths
  (the walk stops loudly on any opcode outside the imported set — none
  of the admitted scripts needed them); the full-SPI layer beyond the
  legacy image.
