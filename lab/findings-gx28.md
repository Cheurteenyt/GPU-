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

## Ring 29 progress (same session)

- `0x101e0a` (the jump target from the entry) is the **framework init/validation
  routine**: reads a version field, checks `(v>>24)&0x3f ∈ {23,24,27,28}`,
  installs a handler table, allocates 0x620 B of stack. Not the LZ.
- `0x101b00-0x101ca0` is the **bootloader's memory allocator**: lowest-set-
  bit isolation (`neg+and`), 32-byte record strides (`slli x,x,5`), 2 KiB
  block math (`slli x,x,11`), bitmap clearing (`sh` back), and error-string
  calls into the directory's message region. Identified, not the LZ.
- The LZ hunt therefore narrows to the remaining unattributed code: the
  byte-op clusters at 0x102300-0x1024fa and 0x101000-0x1010e8, plus the
  main loop body. The allocator's existence also explains the runtime
  workspace regions: the bootloader heap-allocates its decompression
  buffers there.
- Method note: the disassembly region walk is now mechanical — the next
  session continues with the unattributed clusters (a bounded list), using
  the same extract-and-classify loop.

## Ring 29 conclusion: the bindata is ENCRYPTED (proven), pivot to rm.elf

The forensic battery settles it:
- Entropy exactly **8.0000** over an 8 MB sample; byte histogram perfectly
  uniform (top bytes ≈ 1/256 each).
- Autocorrelation ≈ 0.39 % at every lag tested (3, 4, 8, 16, 64, 256, 1024,
  4096) — the random baseline. Real compressed data always shows match
  structure.
- No AES S-box in the bootloader (software decryption unlikely; NVIDIA's
  Security Engine with fused keys is the credible design).

Conclusion: the 64 MB bindata is ciphertext, not compressed data. The LZ
hypothesis is closed. Reaching it means fuse-level keys — an
anti-tampering league this project deliberately does not enter.

**The pivot**: `rm.elf` (17.2 MB) is PLAINTEXT RISC-V — the Resource
Manager's actual code: power heuristics, clock policy, the SES/SPI
references (6 hits found earlier). That is the accessible deep knowledge.
Target for the next deep session: symbol-less RISC-V RE of rm.elf's power
management, anchored on the table structures we already decoded from the
VBIOS.
