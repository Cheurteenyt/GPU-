# findings-gx7 — the seventh ring: who the ROM says it is

Scope: the three verified GA104 specimens, one instrument (`gx7-identity.py`),
grammars imported from nvidia-bios-reader `parse_info` and the NVIDIA BIOS
Information Table Specification (BIT_BIOSDATA v2, Data Range Table), pointer
offsets anchored on the ring-3 register. Selftest green (0 failures).

## What is measured

**The info table ('i', v2, 0x6E B) names the chip and the version.** The
first five bytes read, per the reader's grammar, version `94.04.46.00.EB`
(primary) / `.F0` / `.C5` — identical to the version strings found at
image-rel 0xC1 — and the chip code `0x9404` = **GA104 on all three
specimens**. The ROM's own identity block agrees with lspci, with the
reader's chip table, and with itself.

**BIOSDATA v2 ('B', 0x25 B) decodes against the spec — and the OEM
version byte is the version suffix.** `bios_version_u32` = 0x94044600
("94.04.46.00"), and the OEM-version byte reads 0xEB / 0xF0 / 0xC5 —
**exactly the trailing suffix letters as hex values**. The spec's own
note said it: the OEM string is "the last radix in the combined version
string". The suffix that TechPowerUp truncates and that we flagged in
ring 1 is a first-class version field at BIOSDATA+0x04.

**The image checksum is self-consistent.** The declared checksum field
reads 0 and the legacy image's byte-sum reads 0 — the build inserted a
checksum that satisfies itself (the gate now verifies it live).

**The timing spares census closes the ring-5 question.** Of the 65
timing records, 28 are referenced and **37 are not: 27 all-zero, 10 with
real data** — factory spares, never called by any (bin × strap) pair.
The 40 FF map pairs (straps 10–13) and the zero record (id 19) stay the
only coverage holes among *referenced* objects.

**The live-window scope is now precisely bounded.** The sysfs window
(byte-stable, day-0) contains the BIT layer and the M-memory grammar
layer (byte-equal to the acquisition); the timing map's pointer
(0x6a0fa — identical in both, the BIT layer being byte-equal) targets
the region beyond the legacy image that the window does not carry. The
window shows one page; the map lives on another.

**One honest flag**: the Data Range Table decodes consistently on all
three specimens, but its first field reads 0xEB7F where the spec
promises "image start = 0x0000" — the pointer anchoring is therefore
suspect (or the Ampere v2 layout grew). Measured, registered, not
interpreted.

## Consequences

1. The identity layer is closed: chip, full version, OEM suffix, and
   self-consistent checksum — all register-gated live re-derivations.
2. The version-suffix mystery of ring 1 is resolved structurally: it is
   the OEM version byte, and three builds of the same 94.04.46.00 line
   differ in it (EB/F0) exactly as TPU's truncated listings hinted.
3. The spares census completes the timing story: 28 used, 10 real
   spares, 27 zeroed — the table is a factory with empty shelves.

## Open questions (handed forward)

1. The DRT anchoring (spec-vs-measured discrepancy).
2. The module_map_external_0 byte reads 0x36 on all three — bits set
   that the spec labels reserved; semantics unknown on Ampere.
3. The GSP-RM-side grammars (PERF v0x60, vP-state v0x20, topology
   32×22, fan_mgmt 8×51) — the standing frontier.

## Honesty ledger

- Proven: info decode 3/3; BIOSDATA fields 3/3 with the OEM-suffix law;
  the checksum self-consistency; the spares census; the live-window
  map-pointer bound.
- Inferred: the OEM-suffix reading (three-for-three correlation, spec
  note agrees); the spares' "factory spare" status.
- Unknown: the DRT anchoring; module_map_external_0 bits; the GSP-RM
  territory; whether any shipping board can strap into the FF holes.
