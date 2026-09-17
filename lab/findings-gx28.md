# findings-gx28 — the fwimage memory map is complete; the LZ suspect is a 4 KiB blob

Date: 2026-09-17. Subject: full coverage map of the GSP bootloader and the
bindata format negatives.

## The complete fwimage map (proven)

| Region (fw offset) | Content |
|---|---|
| 0x0 – 0x4000 (VA 0x100000) | bootloader code: entry, stack setup, directory pointer (a4=0x16d000), parser jump to 0x101e0a |
| 0x4000 – 0x20000 | 112 KiB of pure zeros |
| 0x20000 – 0x21000 (VA 0x120000) | **4 KiB of dense code — the LZ prime suspect** |
| 0x21000 – 0x6c000 | 296 KiB of pure zeros |
| 0x6c000 – 0x6e000 | section directory (13 named entries) |
| 0x6e000 – 0x12d0270 | 12 embedded ELF images (7 per-chip kernels, rm.elf 17.2 MB, PMU watchdog, 2 components) |
| 0x12d0270 – 0x12d1000 | zero padding |
| 0x12d1000 – end | the bindata stream (entropy 8.000, no standard framing) |

The "446 KB bootloader" is really ~20 KB of code plus 408 KB of reserved
zeros — probably a BSS-style workspace reservation.

## Format negatives (proven, do not retry)

- Not raw LZ4-block at any of the first 24 stream offsets (decoder-written,
  rejects before any output).
- Not raw deflate at the first 8 offsets.
- No plaintext chunks of rm.elf inside the stream (known-plaintext probe).
- The two "SES" byte-triples in the tail are coincidences inside compressed
  bytes.

## Corrections (same session, honesty first)

- The "4 KiB LZ suspect" at VA 0x120000 was a **coverage-map misread**:
  those pages hold 11 spurious instructions decoded inside zero padding.
  The real bootloader code is the **16 KiB block 0x100000-0x104000**
  (5,357 instructions, dense).
- The zero regions are **runtime workspace**, not padding: auipc targets
  land inside them (0x104000-0x120000, 0x122000-0x16c000) — 112 KiB and
  296 KiB buffers the loader uses at runtime (LZ window/state candidates).
- **No hardcoded bindata address** (zero auipc refs to 0x13d000): the
  stream address is computed from the directory record fields at runtime.
- Directory references cluster at 0x100310-0x101c96 and the parser entry
  0x101e0a — the record walk that decides "plain copy vs LZ" lives there.
- Byte-op clusters (copy-loop candidates): 0x100c00 (the width dispatch),
  0x102400-0x1024fa, 0x101000-0x1010e8.

Ring 29: walk 0x101e0a's record parser, identify the compression flag in
the record fields, trace the call into the LZ routine, and reverse its
4 KiB-scale core. The oracle: decompressed output must start with a valid
ELF header (rm.elf's, most likely).

## Honesty

No decompressed output yet. The negatives above are real evidence — they
narrow the search to exactly one code blob — but the format is still
unknown. Multi-session RE continues; nothing in the mod pipeline depends
on it.
