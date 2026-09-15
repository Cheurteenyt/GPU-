# findings-gx1 — the first ring of the GPU lab: the tail was never slack

Scope: three vendor-verified GA104 specimens (the primary `94.04.46.00.EB`
from the founder's own card, a same-build-date Ventus 3X OC `94.04.46.00.F0`,
and the launch-era Gaming X Trio `94.04.25.40.C5`), one instrument
(`gx1-anatomy.py`), zero hardware writes. The grammar was imported, never
transcribed: the PCI image walk and the BIT signature pattern come
file-by-file from nvidia-bios-reader `src/nvbios_reader.cpp:213-241`, the
entropy atlas is the ring-19 method of the sibling lab.

## What is measured

**The anatomy.** Every specimen is 999,424 B (0xF4000) and carries the same
skeleton:

| Region | Offset | Content |
|---|---|---|
| NVGI container head | 0x0 | `NVGI` magic + 0x40 bytes captured in the register |
| NVGI marker #2 | 0x2000 | a second `NVGI` — before ANY PCIR image |
| legacy x86 image | 0x9200 | 55AA, PCIR @0x9370, 10de:2488, code type 0, length 0xFE00 |
| version string | 0x92C1 | `94.04.46.00.EB` (primary), same offset in all three |
| BIT signature | 0x93B0 | `FF B8 'B''I''T' 00`, inside the legacy image, after PCIR |
| EFI image | 0x19000 | 55AA, PCIR @0x1901C, 10de:2488, code type 3, length 0x16A00 |
| the dense tail | 0x2FA00 | ~400 KiB of structured, mostly high-entropy material |
| identification region | 0xC0A00 | LOW entropy, board/memory id strings |
| true erased slack | 0xA0000–0xBFFFF, 0xD0000–0xEFFFF | ~128 KiB of pure 0xFF |

**The tail was never slack.** The first gate assumed the post-image region
was erased flash; the selftest refused the assumption on all three
specimens (ff_share ≈ 0.50, the ring-21 lesson reproduced: the imported
expectation dies by measurement). The census replaces it: the tail holds a
~0x62000-byte dense region, at least one 55AA/PCIR-like embedded structure
(@0x3C68D primary), a 17-occurrence repeated vocabulary `3s2bwb…`
(@0x3D420..0x5AEF3), and a run of 55AA candidates at an exact 0x30 stride
(ten consecutive records @0x82B93 primary) — the shape of a 48-byte-record
table, the first candidate for the ring-2 memory/timing lens.

**The board signs its ROM.** The identification region names the board and
its memory, per specimen: `MSINV390MH.670` (primary) / `.680` / `.142`,
`G001.0000.03.03` (constant), Samsung module configs
`SAMSUNG-SNTBVV-11_x-2_y6` / `SA24CN-08_x2_y8` / `SNNCZR-08_x-2_y7`, and
`0V39020_LC1B052419` / `0V39010_M61B289982`. The V390 board family is
visible by name inside the file.

**The version-string trap, GPU edition.** TPU lists `94.04.46.00.F` and
`94.04.25.40.C`; the ROMs carry `94.04.46.00.F0` and `94.04.25.40.C5`.
A version number never identifies an image — and now a listed version never
even names the string.

## The acquisition protocol that worked

curl/wget hit the JS bot wall (the ring-12 WAF-header playbook does NOT
transfer); the working path is a page-context fetch inside a real browser
session, then on-disk assembly, then admission by published-hash match —
3/3 VERIFIED, zero unverified bytes in the corpus.

## Consequences for day-0 (the live dump)

The register's primary is the founder's exact version; the pending sysfs
dump becomes a pure H3 identity check against `41a0860f8abfcfa7` — the
ring-44 pattern (question resolved by acquisition before the dump existed)
reproduced on the GPU lane. If the live dump differs from the acquisition,
the differ (ring 34 method) localizes it before any interpretation.

## Open questions (handed to ring 2)

1. What does the NVGI container actually declare (its 0x40-byte heads are
   captured at 0x0 and 0x2000; no interpretation attempted yet)?
2. What is the 0x30-strided 55AA table — memory entries, timing records,
   straps? (nvidia-bios-reader's MemoryEntry grammar is the import source.)
3. What packs the dense tail — BIT tables, devinit, Falcon payloads, or a
   container of their own? (envytools bit.c is cloned for the grammar.)
4. The `3s2bwb` vocabulary: init-table bytecode or compression artifact?

## Honesty ledger

- Proven: every offset above, on 3/3 specimens, gates green (0 failures).
- Inferred: the "memory/timing table" reading of the 0x30-strided records
  (shape only — no grammar applied yet); the board-model attributions come
  from the TPU entries, to be confirmed against the live dump.
- Unknown: NVGI semantics; the tail's container format; whether the erased
  slack is flashed that way or trimmed by the capture.
