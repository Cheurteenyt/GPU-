# findings-gx26 — the power mod is built (step A), and the GSP LZ frontier

Date: 2026-09-17. Subject: the pivot the founder asked for — the reverse
engineering becomes modification. Plus reconnaissance of the deep target.

## Proven (offline, zero risk, GPU untouched)

1. **`tools/vbios-power-mod.py`** — the power-budget mod builder. It
   re-derives the P token and the power table from scratch (never trusts a
   hardcoded offset), refuses unexpected layouts, enforces a 100–300 W
   sanity ceiling, patches the cap entry, verifies by re-decoding with the
   same grammar, and writes NEXT TO the original (never over it).
2. **The 280 W mod exists**: `acquisitions/MSI.RTX3070.8192.210519_1-mod-280W.rom`
   — entry 2 (cap): min 100 / avg 265 / peak **280 W** (stock: 100/240/250).
   Six bytes changed at 0x8fc08-0x8fc0e; verified by an independent tool
   (`hwtruth tables` reads back 100/265/280). The GPU was not touched — the
   flash step (C) requires the live-USB procedure and the real chip read
   (B) first.
3. **The table anatomy**: 20 entries of 0x47 B. Entry 2 = the enforcement
   cap (what NVML mirrors). Entry 13 = a second power definition (avg
   227/peak 252 W — likely the board-total sense point). Entries 5–10 are
   per-rail budgets (66/78, 150/175, 150/175, 11/12, 23/25, 28/31 W).
   Any credible mod must keep these coherent — a peak without rail
   headroom is a lie the VRM will not honor.

## The GSP LZ frontier (ring 27 target, recon done)

4. The bindata stream starts **page-aligned at 0x12d1000** (fwimage
   offsets), entropy 8.000, no standard framing. Between the ELF images'
   end (0x12d0270) and the stream: a ~3.5 KiB uncompressed table (mostly
   zeros + structure) — almost certainly the bindata section metadata.
5. The bootloader (0x0-0x6d000, 446,464 B) holds the decompressor.
   `llvm-objdump` is available for RISC-V — the RE is now toolable.
6. Sober expectations, stated in advance: the LZ may be standard LZ4-block
   with a custom frame, or NVIDIA-proprietary. If proprietary, the honest
   fallback remains: the tables we mod are in the CLEAR region (the power
   table at 588 KiB is outside bindata), so the mod pipeline does not
   depend on beating it — the LZ is the deep-knowledge track, not a
   blocker.

## The pipeline state

| Step | Status |
|---|---|
| A. build the mod | ✅ this ring — modded ROM verified offline |
| B. real chip read (976 KiB) | ⏸ live USB ready, 5 min, founder executes |
| C. flash to the secondary BIOS + verify | ⏸ after B, with the dual-BIOS switch as the net |
| D. prove in a real game (MangoHud) | ⏸ after C |

Every flash in step C will be preceded by a byte-exact comparison between
the chip content and the build the mod was made from (the 210519_1
identity), and the stock image is retained for instant rollback.

## Addendum (same session): the blockers inventory — every lock, mapped

1. **Internal ROM signatures: NONE.** Full-image scan: zero ASN.1/RSA
   structures, zero NVSIGN/SIGNATURE markers, zero embedded ELFs. The
   power table region is not signature-covered — the mod is structurally
   legitimate. (This was the one blocker that could have killed the whole
   pipeline; it does not exist.)
2. **The cap entry, byte-mapped** (entry 2 @ 0x8fc02): min @+2, avg @+6,
   peak @+0xA (u32 LE, mW). Six bytes are the entire 280 W mod. Remaining
   fields (+0x10, +0x24, +0x28) have unknown semantics and stay untouched
   in v1 — conservative by design.
3. **nvflash board-matching and signature checks at flash time**: solved
   by flashing on the same board the build came from (our case) with
   `--protectoff`; the community fork nvflashk is the fallback.
4. **LACT/NVML caps**: they mirror the ROM tables — after the flash the
   power range will read up to 280 W by itself. No extra tooling needed.
5. **The flash procedure** is scripted: `tools/vbios-flash-kit.sh`
   (preflight → verify → protectoff → flash → re-verify), gated on the
   dual-BIOS switch at the SECONDARY position and on step B (the real
   chip read) matching build 210519_1 byte-for-byte.
