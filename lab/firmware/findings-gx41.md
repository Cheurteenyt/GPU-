# findings-gx41 — THE ARCHITECTURAL DISCOVERY: the host parses the VBIOS, the GSP consumes the parsed data

Date: 2026-09-18. Subject: the VBIOS-table consumption architecture, proven
by absence.

## The proof by absence

"BIT\0" (the VBIOS BIT-table signature) appears **ZERO times** in the
entire 17 MB rm.elf — the GSP Resource Manager does NOT parse the VBIOS
BIT structure. Combined with the vague 4.6 finding ("52 encrypted format
tables" = the formats of the init data), the architecture is:

**The host driver (closed nvidia.ko) parses the VBIOS tables → passes the
parsed data to the GSP RM through the init RPC → the RM consumes the
PARSED structures in its heap.**

Consequences:
1. The timing table's consumption semantics live in the **closed host
   driver** — the rm.elf side receives the parsed form. The 10-slot
   semantics decode requires the host-side trace (or the empirical
   differential method).
2. The VBIOS table EDITS still propagate: the host parses the EDITED
   table → the edited values reach the RM. **The timing/vP-state mods
   remain valid without knowing the consumer.**
3. The RPC boundary is the reason the RM has no BIT magic, no VBIOS
   offsets, and why the capability objects are built from host-passed
   data (vague 4.9's transitive wiring).

## The strategic picture (the honest hierarchy)

- The VBIOS mods (power, vP-state caps, timings) remain the direct
  firmware lever — unsigned, flashable, and the host parsing propagates
  them.
- The RM internals (the capability machinery, vague 4.4-4.9) remain the
  deep-knowledge layer — the dials drive it from the host side.
- The encrypted bindata = the boot components (solved — the bin-archive
  system), not the performance path.

## Ring 42 continuation: the empirical timing grammar

The field-grammar decode proceeds WITHOUT the consumer: the 65 records
span the speed grades — the byte diffs between adjacent grades match the
GDDR6 timing progressions (the JEDEC grade ladder as the known-plaintext
ladder). Next session: the grade-ladder diff, the field naming, the
tightened-timing design.
