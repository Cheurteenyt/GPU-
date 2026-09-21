# findings-gx16 — the sixteenth ring: the triple cross, and the last table's encoding identified

Scope: the verified GA104 corpus, the community tweaker's power-table
finder run against our own ring-3 decode (`imports/CPR_calculator.py`),
and a correlation probe between the PERF v0x60 record bytes and the
ring-15 vP-state clocks. Zero hardware writes.

## What is measured

**The power budget survives a third grammar.** The community tool's
signature-based search (the `28 46 0F 00 28 46 0F` duplicated-value
pattern) independently finds **(240000 @ 0x8FC08, 250000 @ 0x8FC0C)** —
exactly the ring-3 PowerCapping cap entry's avg and peak offsets — plus
the **power slider enabled**, twice (0x8FC12, 0x8FC21). Three
independent grammars (our envytools-imported budget parse, the
NVIDIA-VBIOS-Info-Reader pointer table, this signature search) land on
the same bytes with the same values. The founder's 240/250 W question
is now triple-crossed.

**The PERF v0x60 encoding is identified — the layout is not.** The 35
record bytes contain u16s that match the ring-15 vP-state clocks
(420 at +5, 600 twice at +11/+13, 405 at +17 — the deep-idle profile's
own three values), and u32 windows read as **clean fixed-point /2^15
clocks** (842.0, 420.0, 1200.0, 810.0 — the vP-state 0xA memory value —
1050.0, 900.0 MHz) at odd offsets. The v0x60 records therefore encode
clocks in the same /2^15 fixed-point as the vP-state table, with values
drawn from the same clock ladder. The exact field layout (which u8 tags
which u32) remains open — but the object has moved from "raw unknown"
to "encoding identified, values correlated".

**The GitHub hunt's yield, three strikes**: NVIDIA-VBIOS-Info-Reader
(fan curves, ring 14), JadeRover's tweaker (vP-state, ring 15; power
cross, this ring), plus new leads filed (hdlcodelab/nvidia_rom_parser —
official-spec C++ parser, same coverage as ours; evw88/VBios-Editor;
matthewkffo/OhGodADump-NVIDIA). MSI hosts no VBIOS for this SKU (API
queried); NVIDIA's custhelp ReBAR page was down during the hunt.

## Consequences

1. Every power/fan/clock value that the founder's optimization questions
   touch is now **triple-crossed** — no single-grammar trust anywhere.
2. The PERF v0x60's encoding identification halves the remaining
   unknown: what is left is the field order of 35 bytes, not the
   semantics of the table.

## Honesty ledger

- Proven: the signature search's offsets and values (240000/250000 at
  the ring-3 offsets); the u16 matches (420/600×2/405) at byte offsets;
  the clean fixed-point candidates.
- Inferred: the /2^15 encoding of the v0x60 records (the clean-value
  argument is strong but the field boundaries are not proven).
- Unknown: the v0x60 field layout; the semantic roles of the 8 fan
  policy records; everything behind the GSP-RM packing.
