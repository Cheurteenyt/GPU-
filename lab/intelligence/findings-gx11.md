# findings-gx11 — the eleventh ring: every token owned

Scope: the three verified GA104 specimens, one instrument (`gx11-small.py`),
grammar imported from the NVIDIA BIOS Information Table Specification
(BIT_STRING_PTRS v2, BIT_I2C_PTRS, BIT_TMDS_PTRS, BIT_DISPLAY_PTRS,
BIT_CLOCK_PTRS v2, and raw-registered heads for DFP/DP/Virtual/MXM/UEFI).
Selftest green (0 failures). **All 17 BIT tokens are now decoded or
registered against a named grammar.**

## What is measured

**The ROM signs its board — twice.** The Sign-On message reads
`PG142 SKU 12 VGA BIOS \r\n MSINV390MH.670` (primary and Ventus) and
`PG142 SKU 10 VGA BIOS \r\n MSINV390MH.142` (launch-era). **PG142 is the
NVIDIA board design number; the SKU (10 vs 12) distinguishes the boards
more finely than the subsystem ID did.** The copyright string signs the
build year (`1996-2021` vs `1996-2020`), the version string carries the
full `94.04.46.00.EB` — the identity chain (chip code, board design,
SKU, board config, version, copyright year) is now closed end-to-end
inside the file, all spec-anchored.

**The display flags are production-clean**: no diagnostic overscan, no
no-display coprocessor bit, no FPGA flag — the spec's own honesty bits
confirm a shipping desktop card.

**The clock token**: PLL info table @0x4FCA; the VBE mode PCLK table
pointer is NULL — the legacy VGA mode list does not exist on this ROM,
the spec's deprecation made visible at the byte level.

**The UEFI token reads v0.0 with a zero virtual-memory size** — the
Ampere ROM keeps its UEFI driver data elsewhere (the EFI image's own
headers, ring 1); the token is a vestige, registered honestly.

## Consequences

1. Token coverage is complete: 17/17 with a named grammar each (spec,
   envytools, nvidia-bios-reader, nouveau, or the ImHex pattern). The
   BIT layer of this ROM has no unowned bytes.
2. The identity chain is vendor-signed inside the file: any future
   "which board is this really" question starts from PG142-SKU, not
   from marketing names or truncated listings.

## Honesty ledger

- Proven: the string decodes 3/3 (register-gated), the SKU split, the
  copyright years, the display flags, the NULL VBE pointer.
- Inferred: that PG142-SKU maps 1:1 to retail boards (two-for-two here).
- Unknown: the UEFI token's real payload location; the unused small
  tokens' (MXM/DP/Virtual) target tables — heads registered, bodies
  out of scope for this ring.
