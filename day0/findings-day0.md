# findings-day0 — the founder's card, read live: a sibling, not a twin

Scope: the sysfs rom read of the live MSI RTX 3070 Gaming Trio Plus (the
human's sudo gesture, read-only), confronted to the vendor-verified
acquisition `41a0860f8abfcfa7` through the ring-1/2 instruments. Zero
writes to the card.

## What is measured

**The window.** The driver exposes 0xF400 bytes (62,464) — the legacy x86
image only, PCIR-declared by the dump itself (10de:2488, code type 0,
length 0xF400). No NVGI head, no EFI image, no table farm: the "HW
consumption" preamble the NVIDIA spec names and the entire region where
rings 3–4 decoded the power budget, the memory ladder and the timings are
beyond this window.

**The identity.** The version string `94.04.46.00.EB` sits at image-rel
0xC1 and the board string `MSINV390MH.670` at image-rel 0x80 — both at
exactly the acquisition's offsets. The BIT layer is byte-equal: same
offset 0x1B0, same 17-token sequence, checksum zero; the M memory grammar
is byte-equal (info table at the same image-rel 0x4126, 16 descriptors,
14-strap translation, identical). The code core (0x300–0x2300,
0x2A00–0x7E00, ~30 KiB) is byte-identical at the same offsets.

**The divergence.** The head 0x0–0x300, 23 bytes around 0x2300–0x2A00,
and the whole 0x7E00–0xF400 region: on the card, dense init/code/pattern
data (entropy 6.87 — 0x66-prefix push/pop runs, 55AA/dd77/1818 pattern
tables); in the acquisition, sparse code islands in a sea of zeros
(entropy 0.74). The live tail's needles appear NOWHERE in the acquisition
file. The acquisition's legacy PCIR declares 0xFE00 — 2,560 bytes the
card's own PCIR does not claim.

## The verdict

**Sibling, not twin.** Same version number, same board string, same
grammar layers, same code core — different bytes. The version-string trap
(same number ≠ same image), already measured between TPU listings and ROM
strings (ring 1) and between same-version boards (ring 47 of the sibling
lab), now reaches its final form: even version + subsystem + board string
+ a byte-equal grammar layer do not certify image identity. No GPU oracle
was pre-registered, so nothing is scored as a miss — but the ring-44
pattern ("the acquisition certifies the dump") is measured NOT to
transfer to the GPU lane.

Practical consequence: the live dump becomes the PRIMARY object of study;
the acquisition is reclassified as a close sibling specimen. Every
ring-3/4 reading (power budget 240/250, the 7-bin memory ladder, the
fan/timing maps) remains valid AS A READING OF THE ACQUISITION, and its
grammar-layer identity with the card (BIT + memory byte-equal) is strong
evidence the tables transfer — but the card's own table farm sits beyond
the sysfs window and only a full-flash read (nvflash, root) would measure
it on the card itself.

## The day-0 gates

| Gate | Status |
|---|---|
| version string found | PASS |
| size multiple of 512 | PASS (0xF400 = 122 × 512) |
| sha stable across second read | **PASS** — second read byte-identical (cmp, 21:57) |

## Honesty ledger

- Proven: every offset and percentage above, computed on the actual
  bytes; the two PCIR declarations; the byte-equal layers; the
  nowhere-found needles.
- Inferred: the cause of the acquisition's zero regions (capture
  artifact vs different build — undecidable from here); that the
  card's SPI carries the same table farm the acquisition shows.
- Unknown: the card's full SPI content beyond 0xF400; whether a second
  read returns the same 0xF400 bytes.
